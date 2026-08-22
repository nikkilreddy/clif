"""
Unit tests for Tier 3 fixes.

Tests run without external services (Kafka, ClickHouse, ONNX models).
Heavy modules (app.py with Flask/Kafka) are tested via source-level
inspection to avoid module-level side effects.

Covers:
  T3-1: Periodic cleanup (baseline, kill-chain, EWMA) in consumer loop
  T3-2: EPS stats calculation fix (_start_time based)
  T3-3: SPC parameterized queries (no SQL injection via _s())
  T3-4: Hunter graceful drain (shutdown_event + pending task drain)
  T3-5: Deprecated asyncio.get_event_loop() replaced
  T3-6: Dead code removal (TriageAgent.start() removed)
"""
import inspect
import os
import sys
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
SPC_SRC = _read_source(
    os.path.join(HUNTER_DIR, "investigation", "spc_engine.py")
)

# Investigation module sources for T3-5 checks
_INVESTIGATION_DIR = os.path.join(HUNTER_DIR, "investigation")
_HUNTER_MODULE_PATHS = [
    os.path.join(HUNTER_DIR, "app.py"),
    os.path.join(HUNTER_DIR, "scoring", "scorer.py"),
    os.path.join(HUNTER_DIR, "monitoring", "drift_detector.py"),
    os.path.join(HUNTER_DIR, "training", "self_supervised_trainer.py"),
    os.path.join(_INVESTIGATION_DIR, "spc_engine.py"),
    os.path.join(_INVESTIGATION_DIR, "campaign_detector.py"),
    os.path.join(_INVESTIGATION_DIR, "graph_builder.py"),
    os.path.join(_INVESTIGATION_DIR, "mitre_mapper.py"),
    os.path.join(_INVESTIGATION_DIR, "temporal_correlator.py"),
]


# ═══════════════════════════════════════════════════════════════════════════
# T3-1: Periodic cleanup in consumer loop
# ═══════════════════════════════════════════════════════════════════════════

class TestPeriodicCleanup:
    """Verify that periodic cleanup logic exists and works."""

    def test_consumer_loop_has_cleanup_interval(self):
        """Consumer loop defines a cleanup_interval and last_cleanup."""
        assert "cleanup_interval" in TRIAGE_APP_SRC
        assert "last_cleanup" in TRIAGE_APP_SRC

    def test_run_periodic_cleanup_method_exists(self):
        """_run_periodic_cleanup method exists in triage app source."""
        assert "def _run_periodic_cleanup(self" in TRIAGE_APP_SRC

    def test_cleanup_calls_fusion(self):
        """Periodic cleanup calls fusion.cleanup()."""
        assert "_fusion.cleanup()" in TRIAGE_APP_SRC
        # Specifically inside _run_periodic_cleanup
        method_start = TRIAGE_APP_SRC.index("def _run_periodic_cleanup")
        method_end = TRIAGE_APP_SRC.index("def _flush_batch", method_start)
        method_src = TRIAGE_APP_SRC[method_start:method_end]
        assert "_fusion.cleanup()" in method_src

    def test_cleanup_calls_kill_chain(self):
        """Periodic cleanup calls kill_chain.cleanup_stale()."""
        method_start = TRIAGE_APP_SRC.index("def _run_periodic_cleanup")
        method_end = TRIAGE_APP_SRC.index("def _flush_batch", method_start)
        method_src = TRIAGE_APP_SRC[method_start:method_end]
        assert "_kill_chain.cleanup_stale" in method_src

    def test_cleanup_calls_ewma(self):
        """Periodic cleanup triggers EWMA stale entity cleanup."""
        method_start = TRIAGE_APP_SRC.index("def _run_periodic_cleanup")
        method_end = TRIAGE_APP_SRC.index("def _flush_batch", method_start)
        method_src = TRIAGE_APP_SRC[method_start:method_end]
        assert "_ewma._cleanup_stale" in method_src

    def test_cleanup_triggered_in_loop(self):
        """Consumer loop calls _run_periodic_cleanup when interval elapsed."""
        loop_start = TRIAGE_APP_SRC.index("def _consumer_loop(self)")
        loop_end = TRIAGE_APP_SRC.index("def _run_periodic_cleanup", loop_start)
        loop_src = TRIAGE_APP_SRC[loop_start:loop_end]
        assert "_run_periodic_cleanup" in loop_src
        assert "last_cleanup" in loop_src

    def test_cleanup_exception_safe(self):
        """Cleanup errors are caught and logged, not propagated."""
        method_start = TRIAGE_APP_SRC.index("def _run_periodic_cleanup")
        method_end = TRIAGE_APP_SRC.index("def _flush_batch", method_start)
        method_src = TRIAGE_APP_SRC[method_start:method_end]
        assert "except Exception" in method_src

    def test_kill_chain_cleanup_functional(self):
        """KillChainTracker.cleanup_stale removes stale hosts."""
        from kill_chain import KillChainTracker
        kc = KillChainTracker(decay_sec=10.0, score_gate=0.3)
        now = time.monotonic()
        # Add a host
        kc.update("host-a", action_type=1, score=0.5, timestamp=now)
        stats = kc.get_stats()
        assert stats["tracked_hosts"] == 1
        # Cleanup with future timestamp > 2*decay
        removed = kc.cleanup_stale(now + 100.0)
        assert removed == 1
        stats = kc.get_stats()
        assert stats["tracked_hosts"] == 0

    def test_ewma_cleanup_functional(self):
        """EWMATracker._cleanup_stale removes old entities."""
        from ewma_tracker import EWMATracker
        tracker = EWMATracker(
            half_lives=[2.0, 60.0, 600.0],
            max_entities=1000,
        )
        now = time.monotonic()
        tracker.update("entity-1", now, is_error=False, action_type=0)
        stats = tracker.get_stats()
        assert stats["total_entities"] == 1
        # Cleanup with timestamp far in the future
        tracker._cleanup_stale(now + 10000.0)
        stats = tracker.get_stats()
        assert stats["total_entities"] == 0

    def test_baseline_cleanup_functional(self):
        """BaselineTracker.cleanup removes stale entries."""
        from score_fusion import BaselineTracker
        bt = BaselineTracker(max_entities=1000)
        now = time.monotonic()
        # Add 10 updates to pass the count>=10 threshold
        for i in range(15):
            bt.update_and_get_z("host-1", 0.5, now + i * 0.01)
        stats = bt.get_stats()
        assert stats["tracked_entities"] == 1
        # Cleanup with cutoff that removes the entity
        removed = bt.cleanup(now + 200000.0, max_age_sec=1.0)
        assert removed == 1


# ═══════════════════════════════════════════════════════════════════════════
# T3-2: EPS stats calculation fix
# ═══════════════════════════════════════════════════════════════════════════

class TestEPSCalculation:
    """Verify the EPS calculation uses _start_time instead of batch_start."""

    def test_start_time_initialized(self):
        """TriageProcessor stores _start_time at init."""
        assert "self._start_time = time.monotonic()" in TRIAGE_APP_SRC

    def test_eps_uses_start_time(self):
        """EPS calculation references _start_time, not batch_start."""
        # Find the stats logging block
        idx = TRIAGE_APP_SRC.index("if self._batches_processed % 50 == 0:")
        stats_block = TRIAGE_APP_SRC[idx:idx + 500]
        assert "self._start_time" in stats_block
        # Old buggy pattern should NOT be present
        assert "(time.monotonic() - batch_start) * self._batches_processed" not in stats_block

    def test_eps_formula_correct(self):
        """EPS = events_processed / uptime_sec."""
        idx = TRIAGE_APP_SRC.index("if self._batches_processed % 50 == 0:")
        stats_block = TRIAGE_APP_SRC[idx:idx + 500]
        assert "uptime_sec = max(time.monotonic() - self._start_time, 0.001)" in stats_block
        assert "eps = self._events_processed / uptime_sec" in stats_block


# ═══════════════════════════════════════════════════════════════════════════
# T3-3: SPC parameterized queries
# ═══════════════════════════════════════════════════════════════════════════

class TestSPCParameterizedQueries:
    """Verify SPC engine uses parameterized queries, not string interpolation."""

    def test_no_s_sanitizer_function(self):
        """The _s() sanitizer function should be removed."""
        assert "def _s(" not in SPC_SRC

    def test_no_re_import(self):
        """The 're' module is no longer imported."""
        assert "import re" not in SPC_SRC

    def test_entity_baseline_uses_params(self):
        """_query_entity_baseline uses parameterized query."""
        method_start = SPC_SRC.index("def _query_entity_baseline")
        method_end = SPC_SRC.index("def _query_current_count", method_start)
        method_src = SPC_SRC[method_start:method_end]
        # Uses {p_hostname:String} placeholder syntax
        assert "{p_hostname:String}" in method_src
        assert "{p_source_ip:String}" in method_src
        # Passes parameters dict
        assert 'parameters=params' in method_src
        # No _s() calls
        assert "_s(" not in method_src

    def test_current_count_uses_params(self):
        """_query_current_count uses parameterized query."""
        method_start = SPC_SRC.index("def _query_current_count")
        method_src = SPC_SRC[method_start:]
        # Uses {p_hostname:String} placeholder syntax
        assert "{p_hostname:String}" in method_src
        assert "{p_source_ip:String}" in method_src
        # Passes parameters dict
        assert 'parameters=params' in method_src
        # No _s() calls
        assert "_s(" not in method_src

    def test_event_ts_parameterized(self):
        """event_ts is passed via parameter, not string interpolation."""
        method_start = SPC_SRC.index("def _query_current_count")
        method_src = SPC_SRC[method_start:]
        assert "{p_event_ts:String}" in method_src
        assert "p_event_ts" in method_src

    def test_load_baselines_no_user_input(self):
        """_load_baselines only uses config constants, no user-controlled values."""
        method_start = SPC_SRC.index("def _load_baselines")
        method_end = SPC_SRC.index("def evaluate", method_start)
        method_src = SPC_SRC[method_start:method_end]
        # No parameterization needed — only config constants
        assert "_s(" not in method_src


# ═══════════════════════════════════════════════════════════════════════════
# T3-4: Hunter graceful drain
# ═══════════════════════════════════════════════════════════════════════════

class TestHunterGracefulDrain:
    """Verify Hunter agent drains pending tasks on shutdown."""

    def test_shutdown_event_created(self):
        """Lifespan creates a shutdown_event."""
        assert "shutdown_event = asyncio.Event()" in HUNTER_APP_SRC
        assert '"shutdown_event"' in HUNTER_APP_SRC

    def test_consume_loop_checks_shutdown(self):
        """Consume loop checks shutdown_event to stop."""
        loop_start = HUNTER_APP_SRC.index("async def _consume_loop")
        loop_src = HUNTER_APP_SRC[loop_start:loop_start + 1500]
        assert "shutdown_event.is_set()" in loop_src
        assert "while not shutdown_event.is_set()" in loop_src

    def test_pending_tasks_drained(self):
        """Consume loop drains pending tasks before exiting."""
        loop_start = HUNTER_APP_SRC.index("async def _consume_loop")
        loop_src = HUNTER_APP_SRC[loop_start:loop_start + 2000]
        assert "asyncio.wait(pending" in loop_src
        assert "Draining" in loop_src

    def test_shutdown_sets_event_and_waits(self):
        """Lifespan shutdown sets the event and waits for consume_task."""
        shutdown_start = HUNTER_APP_SRC.index("# --------------- Shutdown")
        shutdown_src = HUNTER_APP_SRC[shutdown_start:shutdown_start + 600]
        assert "shutdown_event.set()" in shutdown_src
        assert "await asyncio.wait_for(consume_task" in shutdown_src

    def test_shutdown_has_timeout(self):
        """Shutdown has a timeout for the consume task."""
        shutdown_start = HUNTER_APP_SRC.index("# --------------- Shutdown")
        shutdown_src = HUNTER_APP_SRC[shutdown_start:shutdown_start + 600]
        assert "timeout=30.0" in shutdown_src

    def test_timed_out_tasks_cancelled(self):
        """Tasks that don't finish in time are cancelled."""
        loop_start = HUNTER_APP_SRC.index("async def _consume_loop")
        loop_src = HUNTER_APP_SRC[loop_start:loop_start + 2000]
        assert "t.cancel()" in loop_src


# ═══════════════════════════════════════════════════════════════════════════
# T3-5: Deprecated asyncio.get_event_loop() replaced
# ═══════════════════════════════════════════════════════════════════════════

class TestAsyncioGetRunningLoop:
    """Verify all Hunter modules use get_running_loop() instead of get_event_loop()."""

    @pytest.mark.parametrize("path", _HUNTER_MODULE_PATHS)
    def test_no_get_event_loop(self, path):
        """No Hunter module should use the deprecated get_event_loop()."""
        if not os.path.exists(path):
            pytest.skip(f"File not found: {path}")
        src = _read_source(path)
        basename = os.path.basename(path)
        assert "get_event_loop()" not in src, \
            f"{basename} still uses deprecated asyncio.get_event_loop()"

    @pytest.mark.parametrize("path", _HUNTER_MODULE_PATHS)
    def test_uses_get_running_loop_if_needed(self, path):
        """Modules that call run_in_executor should use get_running_loop."""
        if not os.path.exists(path):
            pytest.skip(f"File not found: {path}")
        src = _read_source(path)
        if "run_in_executor" in src:
            assert "get_running_loop()" in src, \
                f"{os.path.basename(path)} uses run_in_executor without get_running_loop()"


# ═══════════════════════════════════════════════════════════════════════════
# T3-6: Dead code removal (TriageAgent.start())
# ═══════════════════════════════════════════════════════════════════════════

class TestDeadCodeRemoval:
    """Verify dead start() method was removed from TriageAgent."""

    def test_no_start_method(self):
        """TriageAgent should not have a start() method."""
        # Find the TriageAgent class definition up to Flask health endpoints
        class_start = TRIAGE_APP_SRC.index("class TriageAgent:")
        next_boundary = TRIAGE_APP_SRC.index("# ── Flask health endpoint", class_start)
        class_src = TRIAGE_APP_SRC[class_start:next_boundary]
        assert "def start(self)" not in class_src

    def test_main_sets_up_directly(self):
        """main() sets up components directly without calling start()."""
        main_start = TRIAGE_APP_SRC.index("def main():")
        main_src = TRIAGE_APP_SRC[main_start:]
        assert "agent.start()" not in main_src
        # main() manually creates processor, consumer, producer
        assert "TriageProcessor()" in main_src
        assert "create_consumer()" in main_src
        assert "create_producer()" in main_src

    def test_agent_still_has_required_methods(self):
        """TriageAgent retains essential methods."""
        class_start = TRIAGE_APP_SRC.index("class TriageAgent:")
        next_boundary = TRIAGE_APP_SRC.index("# ── Flask health endpoint", class_start)
        class_src = TRIAGE_APP_SRC[class_start:next_boundary]
        assert "def __init__(self)" in class_src
        assert "def _consumer_loop(self)" in class_src
        assert "def _handle_signal(self" in class_src
        assert "def _flush_batch(" in class_src
        assert "def _build_hunter_task(self" in class_src
        assert "def _shutdown(self)" in class_src
        assert "def _run_periodic_cleanup(self" in class_src
