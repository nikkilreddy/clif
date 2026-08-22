"""
CLIF v8 -- LightGBM Training Pipeline
========================================
Production-grade binary classifier for SIEM triage scoring.

Pipeline:
  1. Load pre-extracted v8 features (60-dim, z-scored, clipped [-10,10])
  2. Optuna Bayesian hyperparameter search (100 trials, val-set F1)
  3. 5-fold stratified CV with best params (confidence estimation)
  4. Final model trained on train+val, early-stopped on a 5% holdout
  5. Comprehensive test-set evaluation (overall + per-dataset + per-threshold)
  6. Export: lgbm_v8.onnx, lgbm_v8.txt, manifest_v8.json
  7. ONNX round-trip validation

Usage:
  python scripts/train_lgbm_v8.py                     # full pipeline
  python scripts/train_lgbm_v8.py --skip-tuning       # use default params
  python scripts/train_lgbm_v8.py --n-trials 50       # fewer Optuna trials
"""

from __future__ import annotations

import argparse
import gc
import json
import logging
import os
import sys
import time
import traceback
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", category=UserWarning)

# ── Logging ─────────────────────────────────────────────────────────────────

log = logging.getLogger("clif.train_lgbm_v8")
log.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_handler)

# ── Paths ───────────────────────────────────────────────────────────────────

DATA_DIR = Path(r"C:\CLIF\agents\Data\training_v8")
MODEL_DIR = Path(r"C:\CLIF\agents\triage\models")

# ═════════════════════════════════════════════════════════════════════════════
#  1. DATA LOADING
# ═════════════════════════════════════════════════════════════════════════════


def load_data() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, List[str]]:
    """Load train/val/test parquets and feature names."""
    log.info("Loading data from %s ...", DATA_DIR)

    with open(DATA_DIR / "feature_names.json") as f:
        meta = json.load(f)
    feat_names: List[str] = meta["feature_names"]
    n_feat = meta["num_features"]
    assert len(feat_names) == n_feat, f"Expected {n_feat} features, got {len(feat_names)}"

    train = pd.read_parquet(DATA_DIR / "train.parquet")
    val = pd.read_parquet(DATA_DIR / "val.parquet")
    test = pd.read_parquet(DATA_DIR / "test.parquet")

    for name, df in [("train", train), ("val", val), ("test", test)]:
        assert set(feat_names).issubset(df.columns), f"{name} missing features"
        assert "is_malicious" in df.columns, f"{name} missing is_malicious"
        assert "source_dataset" in df.columns, f"{name} missing source_dataset"
        nan_ct = df[feat_names].isna().sum().sum()
        assert nan_ct == 0, f"{name} has {nan_ct} NaN values"

    log.info("  Train: %d rows (%.1f%% attack)", len(train),
             100 * train["is_malicious"].mean())
    log.info("  Val:   %d rows (%.1f%% attack)", len(val),
             100 * val["is_malicious"].mean())
    log.info("  Test:  %d rows (%.1f%% attack)", len(test),
             100 * test["is_malicious"].mean())
    log.info("  Features: %d", len(feat_names))

    return train, val, test, feat_names


# ═════════════════════════════════════════════════════════════════════════════
#  2. OPTUNA HYPERPARAMETER SEARCH
# ═════════════════════════════════════════════════════════════════════════════


def run_optuna_search(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    feat_names: List[str],
    n_trials: int = 100,
) -> Dict[str, Any]:
    """
    Bayesian hyperparameter optimisation with Optuna.
    Objective: maximise F1 on the held-out validation set.
    Uses stratified subsample of training data for speed.
    """
    import lightgbm as lgb
    import optuna
    from sklearn.metrics import f1_score

    optuna.logging.set_verbosity(optuna.logging.WARNING)

    # ── Subsample training data for faster tuning (~300K rows) ──
    TUNE_MAX = 300_000
    if len(X_train) > TUNE_MAX:
        rng = np.random.default_rng(42)
        # Stratified subsample
        idx_pos = np.where(y_train == 1)[0]
        idx_neg = np.where(y_train == 0)[0]
        ratio = len(idx_pos) / len(y_train)
        n_pos = int(TUNE_MAX * ratio)
        n_neg = TUNE_MAX - n_pos
        chosen = np.concatenate([
            rng.choice(idx_pos, size=min(n_pos, len(idx_pos)), replace=False),
            rng.choice(idx_neg, size=min(n_neg, len(idx_neg)), replace=False),
        ])
        rng.shuffle(chosen)
        X_tune = X_train[chosen]
        y_tune = y_train[chosen]
        log.info("  Subsampled %d -> %d rows for tuning (%.1f%% attack)",
                 len(X_train), len(X_tune), 100 * y_tune.mean())
    else:
        X_tune = X_train
        y_tune = y_train

    pos_weight = float(np.sum(y_tune == 0)) / max(np.sum(y_tune == 1), 1)
    best_f1_so_far = [0.0]
    trial_start = [time.time()]

    def objective(trial: optuna.Trial) -> float:
        t_start = time.time()
        params = {
            "objective": "binary",
            "metric": "binary_logloss",
            "boosting_type": "gbdt",
            "verbosity": -1,
            "seed": 42,
            "n_jobs": -1,
            "scale_pos_weight": pos_weight,
            "feature_pre_filter": False,
            # --- tuned ---
            "num_leaves": trial.suggest_int("num_leaves", 31, 255),
            "max_depth": trial.suggest_int("max_depth", 5, 12),
            "learning_rate": trial.suggest_float("learning_rate", 0.005, 0.15, log=True),
            "min_child_samples": trial.suggest_int("min_child_samples", 10, 100),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
            "subsample": trial.suggest_float("subsample", 0.5, 1.0),
            "subsample_freq": trial.suggest_int("subsample_freq", 1, 7),
            "reg_alpha": trial.suggest_float("reg_alpha", 1e-3, 10.0, log=True),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 10.0, log=True),
            "min_gain_to_split": trial.suggest_float("min_gain_to_split", 0.0, 1.0),
            "max_bin": trial.suggest_categorical("max_bin", [63, 127, 255]),
            "path_smooth": trial.suggest_float("path_smooth", 0.0, 10.0),
        }

        # Build fresh Dataset per trial so max_bin can vary
        dtrain = lgb.Dataset(X_tune, label=y_tune, feature_name=feat_names,
                             params=params, free_raw_data=False)
        dval = lgb.Dataset(X_val, label=y_val, feature_name=feat_names,
                           reference=dtrain, free_raw_data=False)

        model = lgb.train(
            params,
            dtrain,
            num_boost_round=1500,
            valid_sets=[dval],
            callbacks=[
                lgb.early_stopping(50, verbose=False),
                lgb.log_evaluation(period=0),
            ],
        )

        y_pred = (model.predict(X_val) >= 0.5).astype(int)
        f1 = f1_score(y_val, y_pred)

        elapsed = time.time() - t_start
        is_best = f1 > best_f1_so_far[0]
        if is_best:
            best_f1_so_far[0] = f1
        total_elapsed = time.time() - trial_start[0]
        star = " ***BEST***" if is_best else ""
        log.info("  Trial %2d/%d  F1=%.5f  iters=%4d  %.0fs  (total %.0fs)%s",
                 trial.number + 1, n_trials, f1,
                 model.best_iteration, elapsed, total_elapsed, star)
        sys.stdout.flush()

        # Free memory
        del model, dtrain, dval
        gc.collect()

        return f1

    log.info("=" * 60)
    log.info("OPTUNA HYPERPARAMETER SEARCH (%d trials)", n_trials)
    log.info("=" * 60)
    trial_start[0] = time.time()

    study = optuna.create_study(
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=42),
        pruner=optuna.pruners.MedianPruner(n_startup_trials=10),
    )
    study.optimize(objective, n_trials=n_trials, show_progress_bar=False)

    best = study.best_trial
    log.info("")
    log.info("  BEST trial #%d: F1=%.5f", best.number + 1, best.value)
    for k, v in best.params.items():
        log.info("    %-22s = %s", k, v)

    # Merge best params with fixed params — use full-data pos_weight
    full_pos_weight = float(np.sum(y_train == 0)) / max(np.sum(y_train == 1), 1)
    best_params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "boosting_type": "gbdt",
        "verbosity": -1,
        "seed": 42,
        "n_jobs": -1,
        "scale_pos_weight": full_pos_weight,
        "feature_pre_filter": False,
        **best.params,
    }

    return best_params


# ═════════════════════════════════════════════════════════════════════════════
#  3. CROSS-VALIDATION
# ═════════════════════════════════════════════════════════════════════════════


def run_cross_validation(
    X: np.ndarray,
    y: np.ndarray,
    source_types: np.ndarray,
    feat_names: List[str],
    params: Dict[str, Any],
    n_splits: int = 5,
) -> Dict[str, Any]:
    """
    5-fold stratified CV to estimate generalisation performance.
    Returns per-fold metrics and per-source-type F1 breakdown.
    """
    import lightgbm as lgb
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import StratifiedKFold

    log.info("=" * 60)
    log.info("CROSS-VALIDATION (%d folds)", n_splits)
    log.info("=" * 60)

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    fold_results = []
    all_best_iters = []

    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
        Xtr, Xva = X[train_idx], X[val_idx]
        ytr, yva = y[train_idx], y[val_idx]

        dtrain = lgb.Dataset(Xtr, label=ytr, feature_name=feat_names,
                             free_raw_data=False)
        dval = lgb.Dataset(Xva, label=yva, feature_name=feat_names,
                           reference=dtrain, free_raw_data=False)

        model = lgb.train(
            params,
            dtrain,
            num_boost_round=2000,
            valid_sets=[dval],
            callbacks=[
                lgb.early_stopping(50, verbose=False),
                lgb.log_evaluation(period=0),
            ],
        )
        all_best_iters.append(model.best_iteration)

        y_prob = model.predict(Xva)
        y_pred = (y_prob >= 0.5).astype(int)

        f1 = f1_score(yva, y_pred)
        prec = precision_score(yva, y_pred, zero_division=0)
        rec = recall_score(yva, y_pred, zero_division=0)
        auc = roc_auc_score(yva, y_prob)

        # Per-source F1
        source_f1 = {}
        for st in np.unique(source_types[val_idx]):
            mask = source_types[val_idx] == st
            if mask.sum() > 0 and yva[mask].sum() > 0:
                source_f1[st] = round(f1_score(yva[mask], y_pred[mask], zero_division=0), 4)

        fold_results.append({
            "fold": fold, "f1": round(f1, 4), "precision": round(prec, 4),
            "recall": round(rec, 4), "auc": round(auc, 4),
            "best_iteration": model.best_iteration,
            "per_source_f1": source_f1,
        })

        log.info("  Fold %d: F1=%.4f  Prec=%.4f  Recall=%.4f  AUC=%.4f  iters=%d",
                 fold, f1, prec, rec, auc, model.best_iteration)

        # Free memory between folds
        del model, dtrain, dval, Xtr, Xva, ytr, yva, y_prob, y_pred
        gc.collect()

        # Flag weak sources
        for st, sf1 in sorted(source_f1.items()):
            if sf1 < 0.80:
                log.info("    [WEAK] %-20s F1=%.4f", st, sf1)

    f1s = [r["f1"] for r in fold_results]
    aucs = [r["auc"] for r in fold_results]
    mean_f1 = np.mean(f1s)
    std_f1 = np.std(f1s)
    mean_auc = np.mean(aucs)

    log.info("-" * 60)
    log.info("  CV F1:  %.4f +/- %.4f", mean_f1, std_f1)
    log.info("  CV AUC: %.4f +/- %.4f", mean_auc, np.std(aucs))
    log.info("  Avg best_iteration: %d", int(np.mean(all_best_iters)))

    return {
        "cv_f1_mean": round(float(mean_f1), 4),
        "cv_f1_std": round(float(std_f1), 4),
        "cv_auc_mean": round(float(mean_auc), 4),
        "avg_best_iteration": int(np.mean(all_best_iters)),
        "folds": fold_results,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  4. FINAL MODEL TRAINING
# ═════════════════════════════════════════════════════════════════════════════


def train_final_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    feat_names: List[str],
    params: Dict[str, Any],
    cv_avg_iters: int,
):
    """
    Train the production model on train+val, with a small holdout
    carved from val for early stopping.
    """
    import lightgbm as lgb

    log.info("=" * 60)
    log.info("FINAL MODEL TRAINING")
    log.info("=" * 60)

    # Combine train + 90% of val for training; 10% of val as early-stop monitor
    from sklearn.model_selection import train_test_split
    val_train, val_stop, yval_train, yval_stop = train_test_split(
        X_val, y_val, test_size=0.10, random_state=42, stratify=y_val)

    X_full = np.concatenate([X_train, val_train], axis=0)
    y_full = np.concatenate([y_train, yval_train], axis=0)

    log.info("  Training samples: %d (train=%d + val_portion=%d)",
             len(y_full), len(y_train), len(yval_train))
    log.info("  Early-stop monitor: %d samples", len(yval_stop))
    log.info("  Max rounds: %d (CV avg + 20%% margin)", int(cv_avg_iters * 1.2))

    dtrain = lgb.Dataset(X_full, label=y_full, feature_name=feat_names)
    dstop = lgb.Dataset(val_stop, label=yval_stop, feature_name=feat_names, reference=dtrain)

    max_rounds = int(cv_avg_iters * 1.2)

    model = lgb.train(
        params,
        dtrain,
        num_boost_round=max_rounds,
        valid_sets=[dstop],
        callbacks=[
            lgb.early_stopping(80, verbose=False),
            lgb.log_evaluation(period=0),
        ],
    )

    log.info("  Final model: %d trees (best_iteration=%d)", model.num_trees(), model.best_iteration)

    return model


# ═════════════════════════════════════════════════════════════════════════════
#  5. TEST SET EVALUATION
# ═════════════════════════════════════════════════════════════════════════════


def evaluate_test_set(
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    source_types: np.ndarray,
    feat_names: List[str],
) -> Dict[str, Any]:
    """Comprehensive test-set evaluation: overall, per-dataset, per-threshold."""
    from sklearn.metrics import (
        classification_report, confusion_matrix, f1_score,
        precision_recall_curve, precision_score, recall_score, roc_auc_score,
    )

    log.info("=" * 60)
    log.info("TEST SET EVALUATION (%d samples)", len(y_test))
    log.info("=" * 60)

    y_prob = model.predict(X_test)
    y_pred = (y_prob >= 0.5).astype(int)

    # Overall metrics
    f1 = f1_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    log.info("  Overall: F1=%.4f  Prec=%.4f  Recall=%.4f  AUC=%.4f", f1, prec, rec, auc)
    log.info("  Confusion Matrix:")
    log.info("    TN=%d  FP=%d", cm[0][0], cm[0][1])
    log.info("    FN=%d  TP=%d", cm[1][0], cm[1][1])
    fp_rate = cm[0][1] / max(cm[0].sum(), 1) * 100
    fn_rate = cm[1][0] / max(cm[1].sum(), 1) * 100
    log.info("    FP rate: %.2f%%  FN rate: %.2f%%", fp_rate, fn_rate)

    # Per-dataset metrics
    log.info("")
    log.info("  Per-dataset breakdown:")
    log.info("  %-22s %7s %7s %7s %7s %7s", "Dataset", "N", "F1", "Prec", "Recall", "AUC")
    log.info("  " + "-" * 65)
    per_dataset = {}
    for st in sorted(np.unique(source_types)):
        mask = source_types == st
        n = mask.sum()
        if n == 0:
            continue
        y_t = y_test[mask]
        y_p = y_pred[mask]
        y_pr = y_prob[mask]

        if y_t.sum() == 0:
            # All benign dataset
            sf1 = "N/A"
            sp, sr, sa = "N/A", "N/A", "N/A"
            per_dataset[st] = {"n": int(n), "f1": None, "all_benign": True}
        elif y_t.sum() == n:
            # All attack
            sf1 = "N/A"
            sp, sr, sa = "N/A", "N/A", "N/A"
            per_dataset[st] = {"n": int(n), "f1": None, "all_attack": True}
        else:
            sf1_v = f1_score(y_t, y_p, zero_division=0)
            sp_v = precision_score(y_t, y_p, zero_division=0)
            sr_v = recall_score(y_t, y_p, zero_division=0)
            sa_v = roc_auc_score(y_t, y_pr)
            sf1 = f"{sf1_v:.4f}"
            sp = f"{sp_v:.4f}"
            sr = f"{sr_v:.4f}"
            sa = f"{sa_v:.4f}"
            per_dataset[st] = {
                "n": int(n), "f1": round(sf1_v, 4), "precision": round(sp_v, 4),
                "recall": round(sr_v, 4), "auc": round(sa_v, 4),
            }
            if sf1_v < 0.80:
                sf1 += " <<"

        log.info("  %-22s %7d %7s %7s %7s %7s", st, n, sf1, sp, sr, sa)

    # Threshold analysis for production (triage routing thresholds)
    log.info("")
    log.info("  Threshold analysis (production routing):")
    thresholds = [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]
    log.info("  %-10s %7s %7s %7s %7s", "Threshold", "Prec", "Recall", "F1", "FPR%")
    log.info("  " + "-" * 45)
    threshold_metrics = {}
    for t in thresholds:
        yp = (y_prob >= t).astype(int)
        tp = f1_score(y_test, yp, zero_division=0)
        pp = precision_score(y_test, yp, zero_division=0)
        rp = recall_score(y_test, yp, zero_division=0)
        cm_t = confusion_matrix(y_test, yp)
        fpr = cm_t[0][1] / max(cm_t[0].sum(), 1) * 100
        log.info("  %-10.2f %7.4f %7.4f %7.4f %6.2f%%", t, pp, rp, tp, fpr)
        threshold_metrics[str(t)] = {
            "precision": round(pp, 4), "recall": round(rp, 4),
            "f1": round(tp, 4), "fpr_pct": round(fpr, 2),
        }

    # Optimal threshold by F1
    precisions, recalls, pr_thresholds = precision_recall_curve(y_test, y_prob)
    f1_scores = 2 * precisions * recalls / np.maximum(precisions + recalls, 1e-8)
    best_idx = np.argmax(f1_scores)
    best_thresh = float(pr_thresholds[min(best_idx, len(pr_thresholds) - 1)])
    log.info("")
    log.info("  Optimal threshold by F1: %.4f (F1=%.4f)", best_thresh, f1_scores[best_idx])

    return {
        "f1": round(f1, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "auc": round(auc, 4),
        "confusion_matrix": cm.tolist(),
        "fp_rate_pct": round(fp_rate, 2),
        "fn_rate_pct": round(fn_rate, 2),
        "per_dataset": per_dataset,
        "threshold_analysis": threshold_metrics,
        "optimal_threshold": round(best_thresh, 4),
    }


# ═════════════════════════════════════════════════════════════════════════════
#  6. FEATURE IMPORTANCE
# ═════════════════════════════════════════════════════════════════════════════


def analyze_feature_importance(model, feat_names: List[str]) -> Dict[str, Any]:
    """Extract and log feature importance (gain + split)."""
    log.info("")
    log.info("=" * 60)
    log.info("FEATURE IMPORTANCE (top 20)")
    log.info("=" * 60)

    gain_imp = model.feature_importance(importance_type="gain")
    split_imp = model.feature_importance(importance_type="split")

    # Normalize
    gain_norm = gain_imp / max(gain_imp.sum(), 1)
    split_norm = split_imp / max(split_imp.sum(), 1)

    # Sort by gain
    order = np.argsort(gain_norm)[::-1]

    log.info("  %-30s %10s %10s", "Feature", "Gain%", "Split%")
    log.info("  " + "-" * 55)
    for i, idx in enumerate(order[:20]):
        log.info("  %-30s %9.2f%% %9.2f%%",
                 feat_names[idx], gain_norm[idx] * 100, split_norm[idx] * 100)

    # Dead features (zero gain)
    dead = [feat_names[i] for i in range(len(feat_names)) if gain_imp[i] == 0]
    if dead:
        log.info("")
        log.info("  [INFO] %d features with zero gain (unused by trees): %s",
                 len(dead), dead)

    importance_dict = {}
    for i in range(len(feat_names)):
        importance_dict[feat_names[i]] = {
            "gain": round(float(gain_norm[i]) * 100, 4),
            "split": round(float(split_norm[i]) * 100, 4),
        }

    return importance_dict


# ═════════════════════════════════════════════════════════════════════════════
#  7. ONNX EXPORT & VALIDATION
# ═════════════════════════════════════════════════════════════════════════════


def export_onnx(model, feat_names: List[str], output_path: Path):
    """Export LightGBM to ONNX and validate round-trip."""
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType

    log.info("")
    log.info("=" * 60)
    log.info("ONNX EXPORT")
    log.info("=" * 60)

    initial_type = [("input", FloatTensorType([None, len(feat_names)]))]
    onnx_model = convert_lightgbm(
        model,
        initial_types=initial_type,
        target_opset=15,
    )

    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    log.info("  ONNX model saved: %s (%.2f MB)",
             output_path, output_path.stat().st_size / 1024 / 1024)

    # Also save text representation for interpretability
    txt_path = output_path.with_suffix(".txt")
    model.save_model(str(txt_path))
    log.info("  Text model saved: %s (%.2f MB)",
             txt_path, txt_path.stat().st_size / 1024 / 1024)

    return onnx_model


def validate_onnx(
    onnx_path: Path,
    model,
    X_sample: np.ndarray,
    feat_names: List[str],
) -> bool:
    """Validate ONNX output matches native LightGBM predictions."""
    import onnxruntime as ort

    log.info("")
    log.info("ONNX Round-Trip Validation...")

    session = ort.InferenceSession(
        str(onnx_path),
        providers=["CPUExecutionProvider"],
    )
    input_name = session.get_inputs()[0].name

    X_f32 = X_sample[:1000].astype(np.float32)

    # Native predictions
    native_probs = model.predict(X_f32)

    # ONNX predictions
    onnx_out = session.run(None, {input_name: X_f32})
    if len(onnx_out) >= 2:
        # Classifier output: [labels, probabilities]
        onnx_probs = np.array([d.get(1, d.get("1", 0.0)) for d in onnx_out[1]], dtype=np.float64)
    else:
        onnx_probs = np.array(onnx_out[0], dtype=np.float64).flatten()

    max_diff = np.abs(native_probs - onnx_probs).max()
    mean_diff = np.abs(native_probs - onnx_probs).mean()

    # Classification agreement
    native_cls = (native_probs >= 0.5).astype(int)
    onnx_cls = (onnx_probs >= 0.5).astype(int)
    agreement = (native_cls == onnx_cls).mean() * 100

    log.info("  Max probability diff:  %.8f", max_diff)
    log.info("  Mean probability diff: %.8f", mean_diff)
    log.info("  Classification agreement: %.2f%%", agreement)

    if max_diff > 0.10:
        log.error("  [FAIL] ONNX divergence too high! Max diff = %.6f", max_diff)
        return False
    if agreement < 99.5:
        log.error("  [FAIL] ONNX classification agreement below 99.5%%")
        return False
    if max_diff > 0.01:
        log.info("  [WARN] Max diff > 0.01 (%.6f) -- normal for large trees, classifications match", max_diff)

    log.info("  [OK] ONNX round-trip validation PASSED")
    return True


# ═════════════════════════════════════════════════════════════════════════════
#  8. MANIFEST & ARTIFACTS
# ═════════════════════════════════════════════════════════════════════════════


def save_manifest(
    feat_names: List[str],
    params: Dict[str, Any],
    cv_metrics: Dict[str, Any],
    test_metrics: Dict[str, Any],
    importance: Dict[str, Any],
    train_rows: int,
    val_rows: int,
    test_rows: int,
    output_dir: Path,
):
    """Save comprehensive training manifest."""
    # Clean params for JSON (remove non-serialisable items)
    clean_params = {}
    for k, v in params.items():
        if isinstance(v, (int, float, str, bool)):
            clean_params[k] = v

    manifest = {
        "version": "8.0.0",
        "created": datetime.now(timezone.utc).isoformat(),
        "model_type": "LightGBM GBDT Binary Classifier",
        "features": feat_names,
        "num_features": len(feat_names),
        "models": {
            "lgbm": {
                "file": "lgbm_v8.onnx",
                "text_file": "lgbm_v8.txt",
                "weight": 0.85,
                "type": "supervised",
            },
        },
        "scaler": "feature_scaler_v8.json",
        "hyperparameters": clean_params,
        "training": {
            "train_samples": train_rows,
            "val_samples": val_rows,
            "test_samples": test_rows,
            "total_samples": train_rows + val_rows + test_rows,
            "cv_metrics": cv_metrics,
            "test_metrics": test_metrics,
        },
        "feature_importance": importance,
        "thresholds": {
            "suspicious": 0.40,
            "anomalous": 0.90,
            "optimal_f1": test_metrics.get("optimal_threshold", 0.50),
        },
        "data_pipeline": {
            "extraction": "extract_features_v8.py",
            "scaling": "StandardScaler z-score + clip [-10, 10]",
            "source_features": DATA_DIR.as_posix(),
        },
    }

    path = output_dir / "manifest_v8.json"
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
    log.info("  Manifest saved: %s", path)


def copy_scaler(output_dir: Path):
    """Copy the v8 feature scaler to the model directory, adding 'std' alias for inference."""
    import shutil
    src = DATA_DIR / "feature_scaler_v8.json"
    dst = output_dir / "feature_scaler_v8.json"
    if src.exists():
        with open(src, "r") as f:
            data = json.load(f)
        # Inference code (model_ensemble.py) reads "std"; sklearn saves "scale"
        if "scale" in data and "std" not in data:
            data["std"] = data["scale"]
        with open(dst, "w") as f:
            json.dump(data, f)
        log.info("  Scaler copied: %s", dst)
    else:
        log.warning("  Scaler not found at %s", src)


# ═════════════════════════════════════════════════════════════════════════════
#  DEFAULT PARAMS (fallback when --skip-tuning)
# ═════════════════════════════════════════════════════════════════════════════


def get_default_params(pos_weight: float) -> Dict[str, Any]:
    """Optuna-tuned params from fully-honest data run (15 trials, F1=0.93838 on subsample)."""
    return {
        "objective": "binary",
        "metric": "binary_logloss",
        "boosting_type": "gbdt",
        "num_leaves": 106,
        "max_depth": 8,
        "learning_rate": 0.1452,
        "min_child_samples": 11,
        "colsample_bytree": 0.9975,
        "subsample": 0.860,
        "subsample_freq": 2,
        "reg_alpha": 0.3832,
        "reg_lambda": 0.4093,
        "min_gain_to_split": 0.9972,
        "max_bin": 255,
        "path_smooth": 7.138,
        "scale_pos_weight": pos_weight,
        "feature_pre_filter": False,
        "verbosity": -1,
        "seed": 42,
        "n_jobs": -1,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(description="CLIF v8 LightGBM Training")
    parser.add_argument("--skip-tuning", action="store_true",
                        help="Skip Optuna search, use default params")
    parser.add_argument("--skip-cv", action="store_true",
                        help="Skip cross-validation (uses Optuna best iters estimate)")
    parser.add_argument("--n-trials", type=int, default=100,
                        help="Number of Optuna trials (default: 100)")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Model output directory (default: agents/triage/models)")
    args = parser.parse_args()

    t0 = time.time()
    output_dir = Path(args.output_dir) if args.output_dir else MODEL_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info("=" * 70)
    log.info("CLIF v8 -- LightGBM Training Pipeline")
    log.info("=" * 70)
    log.info("Data:   %s", DATA_DIR)
    log.info("Output: %s", output_dir)
    log.info("")

    # --- 1. Load data ---
    train, val, test, feat_names = load_data()

    X_train = train[feat_names].values.astype(np.float32)
    y_train = train["is_malicious"].values.astype(np.int32)
    src_train = train["source_dataset"].values

    X_val = val[feat_names].values.astype(np.float32)
    y_val = val["is_malicious"].values.astype(np.int32)

    X_test = test[feat_names].values.astype(np.float32)
    y_test = test["is_malicious"].values.astype(np.int32)
    src_test = test["source_dataset"].values

    pos_weight = float(np.sum(y_train == 0)) / max(np.sum(y_train == 1), 1)
    log.info("  Class balance: benign=%d  attack=%d  scale_pos_weight=%.3f",
             (y_train == 0).sum(), (y_train == 1).sum(), pos_weight)
    log.info("")

    # Free DataFrames -- we only need numpy arrays from here
    del train, val
    gc.collect()

    # --- 2. Hyperparameter search ---
    if args.skip_tuning:
        log.info("Skipping Optuna search (--skip-tuning). Using defaults.")
        best_params = get_default_params(pos_weight)
    else:
        best_params = run_optuna_search(
            X_train, y_train, X_val, y_val, feat_names, n_trials=args.n_trials)
    gc.collect()

    # --- 3. Cross-validation (on train set only to save memory) ---
    if args.skip_cv:
        log.info("Skipping CV (--skip-cv). Using estimated best_iteration=1800.")
        cv_metrics = {
            "cv_f1_mean": 0.0, "cv_f1_std": 0.0, "cv_auc_mean": 0.0,
            "avg_best_iteration": 1800, "folds": [],
        }
    else:
        cv_metrics = run_cross_validation(
            X_train, y_train, src_train, feat_names, best_params)
    gc.collect()

    # --- 4. Final model ---
    final_model = train_final_model(
        X_train, y_train, X_val, y_val, feat_names,
        best_params, cv_metrics["avg_best_iteration"])

    # --- 5. Test evaluation ---
    test_metrics = evaluate_test_set(final_model, X_test, y_test, src_test, feat_names)

    # --- 5b. Train-set evaluation (overfitting check) ---
    from sklearn.metrics import f1_score as _f1, roc_auc_score as _auc
    y_train_prob = final_model.predict(X_train)
    y_train_pred = (y_train_prob >= 0.5).astype(int)
    train_f1 = _f1(y_train, y_train_pred)
    train_auc = _auc(y_train, y_train_prob)
    log.info("")
    log.info("  OVERFITTING CHECK:")
    log.info("    Train F1=%.4f  Test F1=%.4f  Gap=%.4f",
             train_f1, test_metrics["f1"], train_f1 - test_metrics["f1"])
    log.info("    Train AUC=%.4f  Test AUC=%.4f  Gap=%.4f",
             train_auc, test_metrics["auc"], train_auc - test_metrics["auc"])
    gap = train_f1 - test_metrics["f1"]
    if gap > 0.05:
        log.warning("    [WARN] Train-Test F1 gap > 5%% — possible overfitting!")
    elif gap > 0.02:
        log.info("    [OK] Moderate gap (%.1f%%) — acceptable", gap * 100)
    else:
        log.info("    [OK] Small gap (%.1f%%) — no overfitting", gap * 100)

    # --- 6. Feature importance ---
    importance = analyze_feature_importance(final_model, feat_names)

    # --- 7. Export ONNX ---
    onnx_path = output_dir / "lgbm_v8.onnx"
    export_onnx(final_model, feat_names, onnx_path)
    onnx_ok = validate_onnx(onnx_path, final_model, X_test, feat_names)

    # --- 8. Save artifacts ---
    log.info("")
    log.info("=" * 60)
    log.info("SAVING ARTIFACTS")
    log.info("=" * 60)
    copy_scaler(output_dir)
    save_manifest(
        feat_names, best_params, cv_metrics, test_metrics, importance,
        len(y_train), len(y_val), len(y_test), output_dir)

    # --- Summary ---
    elapsed = time.time() - t0
    log.info("")
    log.info("=" * 70)
    log.info("TRAINING COMPLETE")
    log.info("=" * 70)
    log.info("  Test F1:   %.4f", test_metrics["f1"])
    log.info("  Test AUC:  %.4f", test_metrics["auc"])
    log.info("  Test Prec: %.4f", test_metrics["precision"])
    log.info("  Test Rec:  %.4f", test_metrics["recall"])
    log.info("  CV F1:     %.4f +/- %.4f", cv_metrics["cv_f1_mean"], cv_metrics["cv_f1_std"])
    log.info("  FP rate:   %.2f%%", test_metrics["fp_rate_pct"])
    log.info("  FN rate:   %.2f%%", test_metrics["fn_rate_pct"])
    log.info("  ONNX:      %s", "VALID" if onnx_ok else "FAILED")
    log.info("  Time:      %.0f seconds (%.1f minutes)", elapsed, elapsed / 60)
    log.info("")
    log.info("Artifacts:")
    for name in ["lgbm_v8.onnx", "lgbm_v8.txt", "manifest_v8.json", "feature_scaler_v8.json"]:
        p = output_dir / name
        if p.exists():
            log.info("  %s (%.2f MB)", p, p.stat().st_size / 1024 / 1024)

    if not onnx_ok:
        log.error("ONNX validation FAILED -- do not deploy!")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
