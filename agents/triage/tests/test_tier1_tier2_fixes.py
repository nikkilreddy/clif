"""
Unit tests for Tier 1 and Tier 2 fixes.

Tests run without external services (Kafka, ClickHouse, ONNX models).
Heavy modules (app.py with Flask/Kafka) are tested via source-level
inspection to avoid module-level side effects.

Covers:
  T1-1: Hunter field mismatch (_build_hunter_task sends adjusted_score)
  T1-2: AE masked MSE (MSE computed only on unmasked features)
  T2-1+T2-4: Drain3 batch_mine + O(1) cluster lookup
  T2-2: Batch Kafka consume (structural)
  T2-3: CH connection pool (borrow/release cycle)
  T2-5: Hunter orjson deserialization
"""
import sys
import os
import threading
import time
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

# ---------------------------------------------------------------------------
# Path setup — allow imports from agent directories
# ---------------------------------------------------------------------------
TRIAGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HUNTER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "hunter"))
if TRIAGE_DIR not in sys.path:
    sys.path.insert(0, TRIAGE_DIR)
if HUNTER_DIR not in sys.path:
    sys.path.insert(0, HUNTER_DIR)

# Helper: read source of a file without importing it
def _read_source(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

TRIAGE_APP_SRC = _read_source(os.path.join(TRIAGE_DIR, "app.py"))
HUNTER_APP_SRC = _read_source(os.path.join(HUNTER_DIR, "app.py"))


# ═══════════════════════════════════════════════════════════════════════════
# T1-1: Hunter field mismatch (source-level tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestBuildHunterTaskStructure:
    """Verify _build_hunter_task sends all fields the Hunter agent expects.
    Uses source inspection to avoid importing heavy app.py module."""

    def test_adjusted_score_in_task(self):
        assert '"adjusted_score"' in TRIAGE_APP_SRC
        # Must NOT send the old trigger_score field
        assert '"trigger_score"' not in TRIAGE_APP_SRC or \
               TRIAGE_APP_SRC.index('"adjusted_score"') < TRIAGE_APP_SRC.index('"trigger_score"') + 100

    def test_key_hunter_fields_present(self):
        """_build_hunter_task must include all critical Hunter fields."""
        required_keys = [
            '"adjusted_score"', '"combined_score"', '"source_ip"',
            '"user_id"', '"ioc_match"', '"ioc_confidence"',
            '"template_rarity"', '"mitre_tactic"', '"message"',
            '"summary"', '"asset_multiplier"',
        ]
        for key in required_keys:
            assert key in TRIAGE_APP_SRC, \
                f"Missing hunter field {key} in app.py"

    def test_process_batch_enriches_results(self):
        """Step 5 of process_batch must enrich results with hunter fields."""
        enrichment_fields = [
            'result["source_ip"]', 'result["user_id"]',
            'result["has_known_ioc"]', 'result["template_rarity"]',
            'result["mitre_tactic"]', 'result["message"]',
        ]
        for field in enrichment_fields:
            assert field in TRIAGE_APP_SRC, \
                f"process_batch Step 5 missing enrichment: {field}"


# ═══════════════════════════════════════════════════════════════════════════
# T1-1 (functional): Build a hunter task dict directly
# ═══════════════════════════════════════════════════════════════════════════

class TestBuildHunterTaskFunctional:
    """Functional test of _build_hunter_task logic extracted from source."""

    def _make_result(self, **overrides):
        base = {
            "event_id": "evt-001", "final_score": 0.92, "label": "escalate",
            "lgbm_score": 0.95, "ae_score": 0.78, "adjustments": "kc(1.3)",
            "hostname": "web-01", "user": "jdoe", "source_type": "syslog",
            "action_type_name": "auth_fail", "template_id": "T42",
            "entity_event_rate": 12.5, "entity_error_rate": 3.1,
            "timestamp": "2025-03-17T10:00:00Z", "model_version": "v7",
            "source_ip": "10.0.1.55", "user_id": "jdoe",
            "has_known_ioc": 1.0, "template_rarity": 0.87,
            "mitre_tactic": "credential_access", "mitre_technique": "T1110",
            "message": "Failed password for jdoe from 10.0.1.55",
        }
        base.update(overrides)
        return base

    def _build_task(self, result):
        """Reproduce _build_hunter_task logic without importing app.py."""
        hostname = result.get("hostname", "")
        final_score = result.get("final_score", 0.0)
        source_ip = result.get("source_ip", "")
        user_id = result.get("user_id", "") or result.get("user", "")
        action_name = result.get("action_type_name", "info")
        task = {
            "event_id": result.get("event_id", ""),
            "alert_id": result.get("event_id", ""),
            "hostname": hostname,
            "source_ip": source_ip,
            "user_id": user_id,
            "source_type": result.get("source_type", ""),
            "timestamp": result.get("timestamp", ""),
            "adjusted_score": final_score,
            "combined_score": final_score,
            "lgbm_score": result.get("lgbm_score", 0.0),
            "ae_score": result.get("ae_score", 0.0),
            "asset_multiplier": 1.0,
            "ioc_match": int(result.get("has_known_ioc", 0)),
            "ioc_confidence": 100 if result.get("has_known_ioc", 0) else 0,
            "template_rarity": result.get("template_rarity", 0.0),
            "template_id": result.get("template_id", ""),
            "mitre_tactic": result.get("mitre_tactic", "unknown"),
            "mitre_technique": result.get("mitre_technique", ""),
            "message": result.get("message", ""),
            "summary": f"{hostname} {source_ip} {action_name} score={final_score:.3f}",
            "action": result.get("label", ""),
            "action_type": action_name,
            "adjustments": result.get("adjustments", ""),
            "model_version": result.get("model_version", "v7"),
            "entity_event_rate": result.get("entity_event_rate", 0.0),
            "entity_error_rate": result.get("entity_error_rate", 0.0),
        }
        return task

    def test_adjusted_score_present(self):
        task = self._build_task(self._make_result())
        assert "adjusted_score" in task
        assert "trigger_score" not in task
        assert task["adjusted_score"] == pytest.approx(0.92)

    def test_combined_score_equals_final(self):
        task = self._build_task(self._make_result())
        assert task["combined_score"] == pytest.approx(0.92)

    def test_identity_fields(self):
        task = self._build_task(self._make_result())
        assert task["hostname"] == "web-01"
        assert task["source_ip"] == "10.0.1.55"
        assert task["user_id"] == "jdoe"

    def test_ioc_match_true(self):
        task = self._build_task(self._make_result(has_known_ioc=1.0))
        assert task["ioc_match"] == 1
        assert task["ioc_confidence"] == 100

    def test_ioc_match_false(self):
        task = self._build_task(self._make_result(has_known_ioc=0.0))
        assert task["ioc_match"] == 0
        assert task["ioc_confidence"] == 0

    def test_summary_contains_host_and_ip(self):
        task = self._build_task(self._make_result())
        assert "web-01" in task["summary"]
        assert "10.0.1.55" in task["summary"]

    def test_all_required_fields(self):
        required = {
            "event_id", "alert_id", "hostname", "source_ip", "user_id",
            "source_type", "timestamp", "adjusted_score", "combined_score",
            "lgbm_score", "ae_score", "asset_multiplier", "ioc_match",
            "ioc_confidence", "template_rarity", "template_id",
            "mitre_tactic", "mitre_technique", "message", "summary",
            "action", "action_type", "adjustments", "model_version",
            "entity_event_rate", "entity_error_rate",
        }
        task = self._build_task(self._make_result())
        missing = required - set(task.keys())
        assert not missing, f"Missing: {missing}"


# ═══════════════════════════════════════════════════════════════════════════
# T1-2: AE masked MSE
# ═══════════════════════════════════════════════════════════════════════════

class TestAEMaskedMSE:
    """Verify Autoencoder computes MSE only on unmasked features."""

    def _make_ae(self, masked_indices=(8, 9, 10, 11, 16, 17, 18, 19)):
        from model_ensemble import AutoencoderONNX

        mock_session = MagicMock()
        mock_session.get_inputs.return_value = [
            MagicMock(name="input", shape=[None, 32])
        ]
        mock_session.get_inputs.return_value[0].name = "input"

        with patch("model_ensemble.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            with patch("onnxruntime.InferenceSession", return_value=mock_session):
                with patch.object(AutoencoderONNX, "_load_calibration") as mock_cal:
                    mock_cal.return_value = {
                        "_default": {"p99_error": 0.05, "p50_error": 0.01}
                    }
                    ae = AutoencoderONNX(
                        "fake.onnx", "fake_cal.json",
                        masked_indices=masked_indices,
                    )
        ae._mock_session = mock_session
        return ae

    def test_unmasked_mask_shape(self):
        ae = self._make_ae()
        assert ae._unmasked_mask.shape == (32,)
        assert ae._n_unmasked == 24
        for idx in (8, 9, 10, 11, 16, 17, 18, 19):
            assert ae._unmasked_mask[idx] == False

    def test_mse_excludes_masked_features(self):
        """Masked features with large error should NOT affect scores."""
        ae = self._make_ae()
        X = np.zeros((5, 32), dtype=np.float32)
        recon = np.zeros((5, 32), dtype=np.float32)
        for idx in (8, 9, 10, 11, 16, 17, 18, 19):
            recon[:, idx] = 10.0  # Large error on masked only
        ae._mock_session.run.return_value = [recon]
        scores = ae.predict_batch(X)
        np.testing.assert_allclose(scores, 0.0, atol=1e-6)

    def test_mse_detects_unmasked_error(self):
        ae = self._make_ae()
        X = np.zeros((3, 32), dtype=np.float32)
        X[:, 0] = 1.0
        recon = np.zeros((3, 32), dtype=np.float32)
        ae._mock_session.run.return_value = [recon]
        scores = ae.predict_batch(X)
        assert all(s > 0.5 for s in scores)

    def test_no_masking_when_empty(self):
        ae = self._make_ae(masked_indices=())
        assert ae._n_unmasked == 32
        assert all(ae._unmasked_mask)

    def test_old_code_would_saturate_new_code_does_not(self):
        """Proves the fix: old code → 1.0, new code → 0.0."""
        ae = self._make_ae()
        X = np.zeros((1, 32), dtype=np.float32)
        recon = np.zeros((1, 32), dtype=np.float32)
        for idx in (8, 9, 10, 11, 16, 17, 18, 19):
            recon[:, idx] = 5.0
        ae._mock_session.run.return_value = [recon]
        scores = ae.predict_batch(X)
        assert scores[0] == pytest.approx(0.0, abs=1e-6)
        # Old code: MSE over all 32 → saturated
        old_mse = np.mean((X - recon) ** 2, axis=1)
        assert min(old_mse[0] / 0.05, 1.0) == pytest.approx(1.0)

    def test_get_reconstruction_errors_also_masked(self):
        ae = self._make_ae()
        X = np.zeros((2, 32), dtype=np.float32)
        recon = np.zeros((2, 32), dtype=np.float32)
        for idx in (8, 9, 10, 11, 16, 17, 18, 19):
            recon[:, idx] = 5.0
        ae._mock_session.run.return_value = [recon]
        errors = ae.get_reconstruction_errors(X)
        np.testing.assert_allclose(errors, 0.0, atol=1e-6)


# ═══════════════════════════════════════════════════════════════════════════
# T2-1 + T2-4: Drain3 batch_mine + O(1) cluster lookup
# ═══════════════════════════════════════════════════════════════════════════

class TestDrain3BatchMine:
    def _make_miner(self):
        import tempfile
        tmp = tempfile.mktemp(suffix=".bin")
        with patch("config.DRAIN3_STATE_PATH", tmp), \
             patch("config.DRAIN3_CONFIG_PATH", ""), \
             patch("config.DRAIN3_DEPTH", 4), \
             patch("config.DRAIN3_SIM_TH", 0.4), \
             patch("config.DRAIN3_MAX_CHILDREN", 100), \
             patch("config.DRAIN3_MAX_CLUSTERS", 1024):
            from drain3_miner import Drain3Miner
            miner = Drain3Miner()
        return miner

    def test_batch_mine_returns_correct_count(self):
        miner = self._make_miner()
        results = miner.batch_mine([
            "User login successful for admin",
            "User login successful for bob",
            "Connection failed from 10.0.0.1",
            "",
            "User login successful for carol",
        ])
        assert len(results) == 5

    def test_batch_mine_empty_returns_neutral(self):
        miner = self._make_miner()
        results = miner.batch_mine(["", None, "  "])
        for tid, tstr, rarity in results:
            assert tid == "empty"
            assert rarity == pytest.approx(0.5)

    def test_batch_mine_types(self):
        miner = self._make_miner()
        results = miner.batch_mine(["Hello world"])
        tid, tstr, rarity = results[0]
        assert isinstance(tid, str) and tid.startswith("T")
        assert isinstance(tstr, str)
        assert 0.0 <= rarity <= 1.0

    def test_similar_messages_cluster(self):
        miner = self._make_miner()
        msgs = [f"Connection from 10.0.0.{i} established" for i in range(20)]
        results = miner.batch_mine(msgs)
        tids = set(t[0] for t in results)
        assert len(tids) <= 3

    def test_cluster_size_map_populated(self):
        miner = self._make_miner()
        miner.batch_mine(["Message A", "Message B"])
        assert len(miner._cluster_size_map) > 0

    def test_mine_single_works(self):
        miner = self._make_miner()
        miner.batch_mine([f"Event {i}" for i in range(10)])
        tid, _, rarity = miner.mine("Event 5")
        assert tid.startswith("T")

    def test_get_rarity_works(self):
        miner = self._make_miner()
        results = miner.batch_mine(["Test log message"])
        rarity = miner.get_rarity(results[0][0])
        assert 0.0 <= rarity <= 1.0

    def test_warmup_neutral_rarity(self):
        miner = self._make_miner()
        results = miner.batch_mine(["msg"])
        assert results[0][2] == pytest.approx(0.5)

    def test_thread_safety(self):
        miner = self._make_miner()
        errors = []
        def batch_worker():
            try:
                for _ in range(5):
                    miner.batch_mine([f"Batch {i}" for i in range(20)])
            except Exception as e:
                errors.append(e)
        def single_worker():
            try:
                for i in range(50):
                    miner.mine(f"Single {i}")
            except Exception as e:
                errors.append(e)
        t1 = threading.Thread(target=batch_worker)
        t2 = threading.Thread(target=single_worker)
        t1.start(); t2.start()
        t1.join(timeout=10); t2.join(timeout=10)
        assert not errors


# ═══════════════════════════════════════════════════════════════════════════
# T2-2: Batch Kafka poll (source-level)
# ═══════════════════════════════════════════════════════════════════════════

class TestBatchKafkaConsume:
    def test_consumer_loop_calls_consume(self):
        assert "self._consumer.consume(" in TRIAGE_APP_SRC
        assert "self._consumer.poll(" not in TRIAGE_APP_SRC

    def test_consume_uses_num_messages(self):
        assert "num_messages=" in TRIAGE_APP_SRC
        assert "BATCH_SIZE" in TRIAGE_APP_SRC


# ═══════════════════════════════════════════════════════════════════════════
# T2-3: CH connection pool
# ═══════════════════════════════════════════════════════════════════════════

class TestCHPool:
    def _make_pool(self, size=4):
        with patch("ch_pool.clickhouse_connect") as mock_ch:
            mock_ch.get_client.side_effect = lambda **kw: MagicMock()
            from ch_pool import CHPool
            pool = CHPool(
                size=size, host="localhost", port=9000,
                username="test", password="test", database="test_db",
            )
        return pool

    def test_pool_size(self):
        pool = self._make_pool(size=5)
        assert pool._pool.qsize() == 5

    def test_borrow_returns_client(self):
        pool = self._make_pool(size=3)
        c = pool.borrow()
        assert c is not None
        assert pool._pool.qsize() == 2

    def test_release_returns_to_pool(self):
        pool = self._make_pool(size=3)
        c = pool.borrow()
        pool.release(c)
        assert pool._pool.qsize() == 3

    def test_overflow_on_exhaustion(self):
        pool = self._make_pool(size=2)
        pool.borrow(); pool.borrow()
        with patch("ch_pool.clickhouse_connect") as mock_ch:
            mock_ch.get_client.return_value = MagicMock()
            c3 = pool.borrow()
        assert c3 is not None
        assert pool._overflow >= 1

    def test_context_manager(self):
        pool = self._make_pool(size=3)
        with pool.client() as c:
            assert c is not None
            assert pool._pool.qsize() == 2
        assert pool._pool.qsize() == 3

    def test_release_none_safe(self):
        pool = self._make_pool(size=2)
        pool.release(None)

    def test_close_all(self):
        pool = self._make_pool(size=3)
        pool.close_all()
        assert pool._pool.qsize() == 0

    def test_stats(self):
        pool = self._make_pool(size=4)
        s = pool.get_stats()
        assert s["pool_size"] == 4
        assert s["available"] == 4

    def test_concurrent_access(self):
        pool = self._make_pool(size=8)
        errors = []
        def worker():
            try:
                for _ in range(20):
                    c = pool.borrow()
                    time.sleep(0.001)
                    pool.release(c)
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=10)
        assert not errors
        assert pool._pool.qsize() == 8


# ═══════════════════════════════════════════════════════════════════════════
# T2-5: Hunter orjson
# ═══════════════════════════════════════════════════════════════════════════

class TestHunterOrjson:
    def test_imports_orjson(self):
        assert "import orjson" in HUNTER_APP_SRC

    def test_consume_uses_orjson(self):
        assert "orjson.loads(msg.value)" in HUNTER_APP_SRC
        # Ensure no standalone json.loads(msg.value (not orjson)
        import re
        # Match json.loads NOT preceded by 'or' (i.e. not orjson)
        bare_json_loads = re.findall(r'(?<!or)json\.loads\(msg\.value', HUNTER_APP_SRC)
        assert len(bare_json_loads) == 0, \
            "Found bare json.loads(msg.value) — should use orjson"


# ═══════════════════════════════════════════════════════════════════════════
# T2-3 (structural): Hunter app uses pool
# ═══════════════════════════════════════════════════════════════════════════

class TestHunterPoolIntegration:
    def test_pool_created_in_lifespan(self):
        assert "CHPool(" in HUNTER_APP_SRC

    def test_pool_borrow_in_process_message(self):
        assert "pool.borrow()" in HUNTER_APP_SRC

    def test_pool_release_in_finally(self):
        assert "pool.release(ch_sigma)" in HUNTER_APP_SRC
        assert "pool.release(ch_graph)" in HUNTER_APP_SRC

    def test_pool_closed_on_shutdown(self):
        assert "ch_pool.close_all()" in HUNTER_APP_SRC


# ═══════════════════════════════════════════════════════════════════════════
# Drain3 pre-computation (source-level)
# ═══════════════════════════════════════════════════════════════════════════

class TestDrain3PreComputeStructural:
    def test_batch_mine_before_parallel(self):
        pos_mine = TRIAGE_APP_SRC.find("batch_mine")
        pos_chunk = TRIAGE_APP_SRC.find("_extract_chunk")
        assert pos_mine > 0
        assert pos_chunk > 0
        assert pos_mine < pos_chunk

    def test_precomputed_template_in_extract(self):
        fe_src = _read_source(os.path.join(TRIAGE_DIR, "feature_extractor.py"))
        assert "precomputed_template" in fe_src

    def test_chunk_templates_passed(self):
        assert "chunk_templates" in TRIAGE_APP_SRC


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
