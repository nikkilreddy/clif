"""
CLIF Triage Agent v8.3 — LightGBM-Only Inference
=================================================
Single-model inference pipeline:
  Global LightGBM (ONNX) — 60-feature universal classifier
  F1=0.9492, AUC=0.9957, ~10µs/event

v8.3: Autoencoder removed (weight was already 0.0).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

import config
from feature_extractor import FEATURE_NAMES, NUM_FEATURES

logger = logging.getLogger("clif.triage.ensemble")


# ── Feature Scaler ──────────────────────────────────────────────────────────

class FeatureScaler:
    """
    Z-score feature normalization with per-feature mean/std.
    LightGBM was trained on z-scored features, so inputs must be scaled.
    """

    def __init__(self, scaler_path: str):
        path = Path(scaler_path)
        if not path.exists():
            logger.warning("Feature scaler not found at %s — using identity", scaler_path)
            self._mean = np.zeros(NUM_FEATURES, dtype=np.float32)
            self._std = np.ones(NUM_FEATURES, dtype=np.float32)
            self._loaded = False
            return

        with open(path, "r") as f:
            data = json.load(f)

        self._mean = np.array(data["mean"], dtype=np.float32)
        self._std = np.array(data["std"], dtype=np.float32)
        # Avoid division by zero
        self._std[self._std < 1e-8] = 1.0
        self._loaded = True

        if len(self._mean) != NUM_FEATURES:
            raise ValueError(
                f"Scaler has {len(self._mean)} features but expected {NUM_FEATURES}"
            )
        logger.info("Feature scaler loaded from %s (%d features)", scaler_path, NUM_FEATURES)

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Scale features: (X - mean) / std. Input shape: (N, 60)."""
        return (X - self._mean) / self._std

    @property
    def is_loaded(self) -> bool:
        return self._loaded


# ── LightGBM ONNX ──────────────────────────────────────────────────────────

class LightGBMONNX:
    """
    LightGBM served via ONNX Runtime for deterministic, batched inference.
    Outputs anomaly probability in [0, 1].
    """

    def __init__(self, model_path: str):
        import onnxruntime as ort

        if not Path(model_path).exists():
            raise FileNotFoundError(f"LightGBM ONNX model not found: {model_path}")

        self._session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"],
            sess_options=self._session_options(),
        )
        self._input_name = self._session.get_inputs()[0].name
        logger.info(
            "LightGBM ONNX loaded: %s (input=%s)",
            model_path, self._input_name,
        )

    @staticmethod
    def _session_options():
        import onnxruntime as ort
        import multiprocessing

        opts = ort.SessionOptions()
        num_cores = multiprocessing.cpu_count()
        opts.inter_op_num_threads = max(2, num_cores // 2)
        opts.intra_op_num_threads = max(2, num_cores // 2)
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        return opts

    def predict_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly probabilities for a batch.

        Args:
            X: shape (N, 60), float32

        Returns:
            scores: shape (N,), float64, probability of class=1 (anomalous)
        """
        if X.dtype != np.float32:
            X = X.astype(np.float32)

        results = self._session.run(None, {self._input_name: X})

        # ONNX LightGBM classifiers output [labels, probabilities_list]
        if len(results) >= 2:
            prob_list = results[1]
            scores = np.array(
                [d.get(1, d.get("1", 0.0)) for d in prob_list],
                dtype=np.float64,
            )
        else:
            scores = np.array(results[0], dtype=np.float64).flatten()

        return np.clip(scores, 0.0, 1.0)


# ── Model Manifest ──────────────────────────────────────────────────────────

def load_manifest(manifest_path: str) -> Dict[str, Any]:
    """
    Load model manifest with version, feature list, training metadata.
    Used for version tracking and train/serve skew detection.
    """
    path = Path(manifest_path)
    if not path.exists():
        logger.warning("Model manifest not found at %s", manifest_path)
        return {
            "version": "v8-unknown",
            "features": FEATURE_NAMES,
            "num_features": NUM_FEATURES,
        }

    with open(path, "r") as f:
        manifest = json.load(f)

    # Validate feature list matches
    manifest_features = manifest.get("features", [])
    if manifest_features and manifest_features != FEATURE_NAMES:
        logger.error(
            "TRAIN/SERVE SKEW: Manifest features (%d) != extractor features (%d)",
            len(manifest_features), NUM_FEATURES,
        )
        mismatched = [
            (i, mf, ef)
            for i, (mf, ef) in enumerate(zip(manifest_features, FEATURE_NAMES))
            if mf != ef
        ]
        for idx, mf, ef in mismatched[:5]:
            logger.error("  Feature %d: manifest=%s, extractor=%s", idx, mf, ef)

    return manifest


# ── Ensemble Orchestrator ───────────────────────────────────────────────────

class ModelEnsemble:
    """
    Single-model inference: Global LightGBM (60 features).
    """

    def __init__(self):
        self._lgbm: Optional[LightGBMONNX] = None
        self._scaler: Optional[FeatureScaler] = None
        self._manifest: Dict[str, Any] = {}
        self._ready = False
        self._load_time_ms = 0.0

    def load(self) -> None:
        """Load all models, scaler, and manifest. Called once at startup."""
        t0 = time.monotonic()

        # Load manifest first (for version validation)
        self._manifest = load_manifest(config.MANIFEST_PATH)
        logger.info("Model manifest: version=%s", self._manifest.get("version", "?"))

        # Feature scaler
        self._scaler = FeatureScaler(config.FEATURE_SCALER_PATH)

        # Global LightGBM
        self._lgbm = LightGBMONNX(config.MODEL_LGBM_PATH)

        self._load_time_ms = (time.monotonic() - t0) * 1000
        self._ready = True
        logger.info("Ensemble loaded in %.1f ms", self._load_time_ms)

    def predict_batch(
        self,
        X: np.ndarray,
        source_types: Optional[List[str]] = None,
        log_types: Optional[List[str]] = None,
    ) -> Dict[str, np.ndarray]:
        """
        Run global LightGBM on a batch of 60-feature vectors.

        Args:
            X: shape (N, 60), float32 — raw (unscaled) feature matrix
            source_types: ignored (kept for API compatibility)
            log_types: ignored (kept for API compatibility)

        Returns:
            Dict with:
                "lgbm_scores":  (N,) float64
                "ae_scores":    (N,) float64 — zeros (kept for API compat)
                "combined":     (N,) float64 — same as lgbm_scores
        """
        if not self._ready:
            raise RuntimeError("ModelEnsemble.load() not called")

        n = X.shape[0]

        # Z-score scale once — all models trained on scaled features
        X_scaled = self._scaler.transform(X)

        # ── LGBM scoring (global model, all 60 features) ─────────
        lgbm_scores = self._lgbm.predict_batch(X_scaled)
        ae_scores = np.zeros(n, dtype=np.float64)

        return {
            "lgbm_scores": lgbm_scores,
            "ae_scores": ae_scores,
            "combined": lgbm_scores.copy(),
        }

    def selftest(self) -> bool:
        """
        Run a self-test with synthetic data to verify model loading.
        Called at startup before accepting Kafka messages.
        """
        try:
            X_test = np.random.randn(10, NUM_FEATURES).astype(np.float32)
            result = self.predict_batch(X_test)

            for key in ("lgbm_scores", "ae_scores", "combined"):
                assert key in result, f"Missing key: {key}"
                assert result[key].shape == (10,), f"Bad shape for {key}"
                assert np.all(np.isfinite(result[key])), f"Non-finite in {key}"

            logger.info(
                "Selftest passed: lgbm=[%.4f,%.4f], combined=[%.4f,%.4f]",
                result["lgbm_scores"].min(), result["lgbm_scores"].max(),
                result["combined"].min(), result["combined"].max(),
            )
            return True

        except Exception as e:
            logger.error("Selftest FAILED: %s", e, exc_info=True)
            return False

    @property
    def is_ready(self) -> bool:
        return self._ready

    @property
    def manifest(self) -> Dict[str, Any]:
        return self._manifest

    def get_stats(self) -> Dict[str, Any]:
        return {
            "ready": self._ready,
            "load_time_ms": self._load_time_ms,
            "manifest_version": self._manifest.get("version", "unknown"),
            "scaler_loaded": self._scaler.is_loaded if self._scaler else False,
            "feature_count": NUM_FEATURES,
        }
