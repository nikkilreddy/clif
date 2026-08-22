"""
CLIF Triage Agent v8.3 — Main Service
========================================
High-throughput Kafka consumer that batches events, extracts 60 features
in parallel, runs LightGBM ONNX inference, fuses scores with kill-chain
and cross-host context, and publishes routing decisions.

Architecture:
    Kafka (4 topics) → Batch Collector (2000 events)
      → Feature Extraction (ThreadPoolExecutor, 4 workers)
      → Model Inference (batched ONNX: LightGBM)
      → Score Fusion (vectorized numpy + kill-chain + cross-host)
      → Kafka Producer (triage-scores, anomaly-alerts, hunter-tasks)
      → Async SHAP (background thread, escalated only)

v8.3 changes:
  - LightGBM-only (autoencoder removed)
  - 60-feature vector (Shared Core 9, Network 15, Auth 8, DNS 8, Web 7, Email 7, Cloud 6)
  - LightGBM: 742 trees, F1=0.9492, AUC=0.9957, ONNX=4.32MB
  - Kill-chain state machine per host
  - Cross-host correlation for campaign detection
  - EWMA entity rate tracking (score fusion only)

Event linkage:
    Deterministic UUID-v5 from topic:partition:offset ensures
    triage_scores.event_id == raw_logs.event_id for joins.

Startup sequence:
    1. Wait for Kafka to become healthy
    2. Load 2 ONNX models + scaler + calibration
    3. Run self-test: synthetic event through full pipeline
    4. Accept real traffic

Health endpoint on HEALTH_PORT (default 8300).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import numpy as np
import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer
from flask import Flask, jsonify

import config
from ewma_tracker import CrossHostCorrelator, EWMATracker
from feature_extractor import FeatureExtractor, FEATURE_NAMES, NUM_FEATURES
from kill_chain import KillChainTracker
from model_ensemble import ModelEnsemble
from score_fusion import ScoreFusion
from shap_explainer import AsyncSHAPWorker, FeatureAttributor

# ── Deterministic event_id ──────────────────────────────────────────────────

_CLIF_EVENT_NS = uuid.UUID("c71f0000-e1d0-4a6b-b5c3-deadbeef0042")

# Regex to extract source IP from syslog message text when structured
# fields are missing.  Matches patterns like:
#   "from 10.0.0.1 port 22"    (SSH auth logs)
#   "Connection from 10.0.0.1"
#   "SRC=192.168.1.5"          (iptables)
#   "rhost=10.0.0.1"           (PAM auth logs)
#   "closed by 10.0.0.1"       (SSH connection closed)
#   "[10.0.0.1]"               (reverse mapping checks)
#   "addr=10.0.0.1"            (systemd/PAM)
import re as _re
_RE_SYSLOG_SRC_IP = _re.compile(
    r"(?:from|SRC=|src[= ]|rhost=|(?:closed|connection)\s+by\s|addr=)"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
_RE_BRACKET_IP = _re.compile(
    r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"
)


def _extract_ip_from_message(message: str) -> str:
    """Best-effort source IP extraction from syslog message body."""
    if not message:
        return ""
    m = _RE_SYSLOG_SRC_IP.search(message)
    if m:
        return m.group(1)
    m = _RE_BRACKET_IP.search(message)
    return m.group(1) if m else ""


def deterministic_event_id(topic: str, partition: int, offset: int) -> str:
    """Derive a stable UUID-v5 from Kafka message coordinates."""
    return str(uuid.uuid5(_CLIF_EVENT_NS, f"{topic}:{partition}:{offset}"))


# ── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("clif.triage.app")


# ── Kafka helpers ───────────────────────────────────────────────────────────

def check_kafka_health() -> bool:
    """Verify Kafka brokers are reachable before subscribing."""
    from confluent_kafka.admin import AdminClient

    max_retries = config.STARTUP_HEALTH_RETRIES
    delay = config.STARTUP_HEALTH_DELAY_SEC

    for attempt in range(1, max_retries + 1):
        try:
            admin = AdminClient({"bootstrap.servers": config.KAFKA_BROKERS})
            metadata = admin.list_topics(timeout=5)
            topic_names = list(metadata.topics.keys())
            logger.info(
                "Kafka healthy (attempt %d): %d topics — %s",
                attempt, len(topic_names), topic_names[:10],
            )
            missing = [t for t in config.INPUT_TOPICS if t not in topic_names]
            if missing:
                logger.warning("Input topics not yet created: %s", missing)
            return True
        except Exception as e:
            if attempt < max_retries:
                logger.warning(
                    "Kafka not ready (%d/%d): %s — retrying in %.1fs",
                    attempt, max_retries, e, delay,
                )
                time.sleep(delay)
                delay = min(delay * 1.5, 30.0)
            else:
                raise RuntimeError(
                    f"Kafka brokers unreachable after {max_retries} attempts: "
                    f"{config.KAFKA_BROKERS}"
                )
    return False


def create_consumer() -> Consumer:
    """Create a Kafka consumer subscribed to the input topics.

    Key design decisions:
      - cooperative-sticky assignment prevents full-group stop-the-world
        rebalances and keeps partitions evenly distributed.
      - Manual offset commit (enable.auto.commit=False) ensures at-least-once
        delivery: offsets are committed only after a batch is fully scored
        and produced to output topics.
      - Deterministic client.id from hostname keeps partition→consumer mapping
        stable across restarts.
    """
    offset_reset = os.environ.get("KAFKA_OFFSET_RESET", "latest")
    client_id = f"triage-{os.environ.get('HOSTNAME', 'standalone')}"
    conf = {
        "bootstrap.servers": config.KAFKA_BROKERS,
        "group.id": config.CONSUMER_GROUP_ID,
        "client.id": client_id,
        "auto.offset.reset": offset_reset,
        "enable.auto.commit": False,
        "partition.assignment.strategy": "cooperative-sticky",
        "max.poll.interval.ms": 120000,
        "session.timeout.ms": 30000,
        "fetch.min.bytes": 1,
        "fetch.max.bytes": 52428800,
        "max.partition.fetch.bytes": 10485760,
    }
    consumer = Consumer(conf)
    consumer.subscribe(config.INPUT_TOPICS)
    logger.info(
        "Kafka consumer: group=%s, client=%s, topics=%s, strategy=cooperative-sticky",
        config.CONSUMER_GROUP_ID, client_id, config.INPUT_TOPICS,
    )
    return consumer


def create_producer() -> Producer:
    """Create a Kafka producer for outputting triage results."""
    conf = {
        "bootstrap.servers": config.KAFKA_BROKERS,
        "linger.ms": 20,
        "batch.num.messages": 50000,
        "compression.type": "lz4",
        "acks": 1,
        "retries": 3,
        "retry.backoff.ms": 100,
        "queue.buffering.max.messages": 200000,
        "queue.buffering.max.kbytes": 262144,
    }
    return Producer(conf)


_delivery_errors = 0


def _delivery_callback(err, msg):
    global _delivery_errors
    if err:
        _delivery_errors += 1
        if _delivery_errors <= 10 or _delivery_errors % 100 == 0:
            logger.error("Delivery failed for %s: %s", msg.topic(), err)


# ── Triage Processor ───────────────────────────────────────────────────────

class TriageProcessor:
    """
    Core processing engine. Holds all stateful components and processes
    batches through the full pipeline.

    Pipeline per batch:
      1. Parallel feature extraction (4 threads)
      2. Batched ONNX inference (LGBM + AE)
      3. Kill-chain state update
      4. Score fusion with adjustments
      5. Async SHAP for escalated events
    """

    def __init__(self):
        # ── Shared stateful components ─────────────────────────────────
        self._ewma = EWMATracker(
            half_lives=[
                config.EWMA_HALF_LIFE_FAST,
                config.EWMA_HALF_LIFE_MEDIUM,
                config.EWMA_HALF_LIFE_SLOW,
            ],
            max_entities=config.EWMA_MAX_ENTITIES,
        )
        self._kill_chain = KillChainTracker(
            decay_sec=config.KILL_CHAIN_DECAY_SEC,
            score_gate=config.KILL_CHAIN_SCORE_GATE,
        )
        self._cross_host = CrossHostCorrelator(
            window_sec=config.CROSS_HOST_WINDOW_SEC,
            min_score=config.CROSS_HOST_MIN_SCORE,
        )

        # ── Feature extractor (v8: stateless, no external deps) ───────
        self._extractor = FeatureExtractor()

        # ── Model ensemble ─────────────────────────────────────────────
        self._ensemble = ModelEnsemble()
        self._ensemble.load()

        # ── Score fusion ───────────────────────────────────────────────
        self._fusion = ScoreFusion()

        # ── Thread pool for parallel feature extraction ────────────────
        self._executor = ThreadPoolExecutor(
            max_workers=config.INFERENCE_WORKERS,
            thread_name_prefix="feat-worker",
        )

        # ── SHAP (synchronous for escalated events) ──────────────────
        self._shap_attributor: Optional[FeatureAttributor] = None
        self._shap_worker: Optional[AsyncSHAPWorker] = None
        self._shap_results: Dict[str, tuple] = {}  # event_id → (json, summary)
        self._shap_lock = threading.Lock()

        if config.SHAP_ENABLED:
            self._shap_attributor = FeatureAttributor(self._ensemble._lgbm)
            self._shap_worker = AsyncSHAPWorker(
                lgbm_model=self._ensemble._lgbm,
                result_callback=self._shap_callback,
                max_queue_size=config.SHAP_QUEUE_SIZE,
            )
            self._shap_worker.start()

        # ── Self-test ──────────────────────────────────────────────────
        self._selftest_passed = True
        if config.SELFTEST_ENABLED:
            self._run_selftest()

        # ── Stats ──────────────────────────────────────────────────────
        self._events_processed = 0
        self._batches_processed = 0
        self._errors = 0
        self._last_batch_time_ms = 0.0
        self._avg_batch_time_ms = 0.0
        self._start_time = time.monotonic()

    def _shap_callback(self, event_id: str, shap_json: str, shap_summary: str):
        """Async SHAP results callback — stores for later retrieval."""
        with self._shap_lock:
            self._shap_results[event_id] = (shap_json, shap_summary)
            # Trim old results
            if len(self._shap_results) > config.SHAP_QUEUE_SIZE * 2:
                keys = list(self._shap_results.keys())
                for k in keys[:len(keys) // 2]:
                    self._shap_results.pop(k, None)

    def _run_selftest(self) -> None:
        """Push synthetic events through the full pipeline."""
        logger.info("=" * 50)
        logger.info("Running startup self-test...")
        logger.info("=" * 50)

        synthetic_event = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "selftest-host",
            "ip_address": "192.168.1.100",
            "user": "selftest-user",
            "severity": "medium",
            "original_log_level": 2,
            "source_type": "syslog",
            "message_body": "Failed password for root from 10.0.0.1 port 22 ssh2",
        }

        try:
            feat = self._extractor.extract(synthetic_event, "raw-logs")
            X = self._extractor.batch_to_numpy([feat])
            log_types = [feat.get("_log_type", "syslog")]
            scores = self._ensemble.predict_batch(X, log_types=log_types)

            logger.info(
                "Self-test: lgbm=%.4f, combined=%.4f",
                float(scores["lgbm_scores"][0]),
                float(scores["combined"][0]),
            )

            results = self._fusion.fuse_batch([feat], scores)
            r = results[0]
            logger.info(
                "Self-test: fusion OK — score=%.4f, label=%s",
                r["final_score"], r["label"],
            )

            logger.info("=" * 50)
            logger.info("Self-test PASSED")
            logger.info("=" * 50)

        except Exception as e:
            logger.error("Self-test FAILED: %s", e, exc_info=True)
            self._selftest_passed = False

    def process_batch(
        self, events: List[Dict[str, Any]], topics: List[str]
    ) -> tuple:
        """
        Process a batch through the full pipeline.

        Returns (results, failed_events):
          - results: list of scored result dicts ready for Kafka produce
          - failed_events: list of events that failed feature extraction
                           or inference, for dead-letter routing
        """
        if not events:
            return [], []

        batch_start = time.monotonic()
        n = len(events)

        # ── Step 1: Parallel feature extraction ────────────────────────
        features_list = [None] * n
        chunk_size = max(1, n // config.INFERENCE_WORKERS)
        futures = {}

        for start in range(0, n, chunk_size):
            end = min(start + chunk_size, n)
            chunk_events = events[start:end]
            chunk_topics = topics[start:end]
            future = self._executor.submit(
                self._extract_chunk, chunk_events, chunk_topics, start,
            )
            futures[future] = (start, end)

        valid_mask = [False] * n
        for future in as_completed(futures):
            start_idx, _ = futures[future]
            try:
                chunk_results = future.result()
                for offset, feat in chunk_results:
                    features_list[offset] = feat
                    valid_mask[offset] = True
            except Exception as e:
                self._errors += 1
                logger.error("Feature extraction chunk failed: %s", e)

        # Collect events that failed feature extraction for dead-lettering
        failed_events = [e for e, ok in zip(events, valid_mask) if not ok]

        # Filter valid
        valid_features = [f for f, ok in zip(features_list, valid_mask) if ok and f]
        valid_events = [e for e, ok in zip(events, valid_mask) if ok]
        valid_topics = [t for t, ok in zip(topics, valid_mask) if ok]

        if not valid_features:
            return [], failed_events

        t_feat = time.monotonic()

        # ── Step 2: Batched model inference ────────────────────────────
        X = self._extractor.batch_to_numpy(valid_features)
        source_types = [f.get("_source_type", "unknown") for f in valid_features]
        log_types = [f.get("_log_type", "syslog") for f in valid_features]

        try:
            model_scores = self._ensemble.predict_batch(X, source_types, log_types=log_types)
        except Exception as e:
            logger.error("Batch inference failed: %s", e)
            self._errors += len(valid_features)
            return [], failed_events + valid_events

        t_infer = time.monotonic()

        # ── Step 3: Kill-chain update + cross-host correlation ──────────
        combined = model_scores["combined"]

        xhost_events = []
        for i, feat in enumerate(valid_features):
            score = float(combined[i])
            hostname = feat.get("_hostname", "unknown")
            action_type = int(feat.get("action_type", 0))

            # Update kill-chain (only advances if score > gate)
            ts = float(feat.get("_epoch", time.time()))
            kc_stage, kc_velocity = self._kill_chain.update(
                hostname, action_type, score, ts
            )
            valid_features[i]["kill_chain_stage"] = float(kc_stage)
            valid_features[i]["kill_chain_velocity"] = kc_velocity

            xhost_events.append((ts, hostname, score))

        # Batch cross-host correlation: O(n+m) instead of O(n*m)
        xhost_counts = self._cross_host.record_batch(xhost_events)
        for i in range(len(valid_features)):
            valid_features[i]["cross_host_correlation"] = float(xhost_counts[i])

        t_kc = time.monotonic()

        # ── Step 4: Score fusion with adjustments ──────────────────────
        results = self._fusion.fuse_batch(valid_features, model_scores)

        t_fuse = time.monotonic()

        # ── Step 5: Enrich results with event metadata ─────────────────
        for i, result in enumerate(results):
            event = valid_events[i]
            feat = valid_features[i]
            result["event_id"] = event.get("event_id", "")
            result["timestamp"] = event.get("timestamp", "")
            result["model_version"] = self._ensemble.manifest.get("version", "v8")
            # Fields consumed by Hunter agent and stored in triage_scores
            source_ip = str(
                event.get("src_ip",
                event.get("source_ip",
                event.get("SrcIP", "")))
            )
            # Fallback: parse IP from syslog message body if structured fields empty
            if not source_ip:
                msg_text = str(
                    event.get("message_body",
                    event.get("message",
                    event.get("description", "")))
                )
                source_ip = _extract_ip_from_message(msg_text)
            result["source_ip"] = source_ip
            result["user_id"] = str(
                event.get("user",
                event.get("user_id",
                event.get("windows_target_user",
                event.get("k8s_user",
                event.get("cloud_user", "")))))
            )
            result["has_known_ioc"] = float(feat.get("has_known_ioc", 0.0))
            result["template_rarity"] = 0.0
            result["mitre_tactic"] = str(event.get("mitre_tactic", "unknown"))
            result["mitre_technique"] = str(event.get("mitre_technique", ""))
            result["message"] = str(
                event.get("message_body",
                event.get("message",
                event.get("description", "")))
            )[:4000]

            # Synchronous SHAP for escalated events — computed BEFORE Kafka produce
            if result["label"] == "escalate" and self._shap_attributor is not None:
                x_single = X[i:i+1].copy()
                try:
                    shap_json, shap_summary = self._shap_attributor.explain(x_single)
                    result["shap_top_features"] = shap_json
                    result["shap_summary"] = shap_summary
                except Exception as e:
                    logger.warning("Sync SHAP failed for %s: %s", result.get("event_id"), e)
                    result["shap_top_features"] = ""
                    result["shap_summary"] = ""

        t_enrich = time.monotonic()

        # Sub-phase timing (every batch for first 20 batches)
        if self._batches_processed < 20:
            logger.info(
                "Phases: %d events | feat=%.0fms infer=%.0fms "
                "kc_xh=%.0fms fuse=%.0fms enrich=%.0fms",
                n,
                (t_feat - batch_start) * 1000,
                (t_infer - t_feat) * 1000,
                (t_kc - t_infer) * 1000,
                (t_fuse - t_kc) * 1000,
                (t_enrich - t_fuse) * 1000,
            )

        # ── Stats ──────────────────────────────────────────────────────
        elapsed_ms = (time.monotonic() - batch_start) * 1000
        self._events_processed += len(results)
        self._batches_processed += 1
        self._last_batch_time_ms = elapsed_ms
        if self._avg_batch_time_ms == 0:
            self._avg_batch_time_ms = elapsed_ms
        else:
            self._avg_batch_time_ms = (
                0.9 * self._avg_batch_time_ms + 0.1 * elapsed_ms
            )

        if self._batches_processed % 50 == 0:
            uptime_sec = max(time.monotonic() - self._start_time, 0.001)
            eps = self._events_processed / uptime_sec
            logger.info(
                "Batch %d: %d events in %.1f ms (avg %.1f ms/batch, "
                "%.1f ms/event, ~%.0f EPS total)",
                self._batches_processed,
                len(results),
                elapsed_ms,
                self._avg_batch_time_ms,
                elapsed_ms / max(len(results), 1),
                eps,
            )

        return results, failed_events

    def _extract_chunk(
        self,
        events: List[Dict[str, Any]],
        topics: List[str],
        start_idx: int,
    ) -> List[tuple]:
        """Extract features for a chunk of events. Returns (global_idx, features)."""
        results = []
        for i, (event, topic) in enumerate(zip(events, topics)):
            try:
                feat = self._extractor.extract(event, topic)
                results.append((start_idx + i, feat))
            except Exception as e:
                logger.warning(
                    "Feature extraction failed for event %d: %s",
                    start_idx + i, e,
                )
        return results

    def shutdown(self):
        """Graceful shutdown."""
        if self._shap_worker:
            self._shap_worker.stop()
        self._executor.shutdown(wait=False)
        logger.info(
            "Processor shutdown: %d events, %d batches, %d errors",
            self._events_processed, self._batches_processed, self._errors,
        )

    def get_stats(self) -> Dict[str, Any]:
        stats = {
            "events_processed": self._events_processed,
            "batches_processed": self._batches_processed,
            "errors": self._errors,
            "last_batch_time_ms": round(self._last_batch_time_ms, 2),
            "avg_batch_time_ms": round(self._avg_batch_time_ms, 2),
            "selftest_passed": self._selftest_passed,
            "extractor": self._extractor.get_stats(),
            "ensemble": self._ensemble.get_stats(),
            "fusion": self._fusion.get_stats(),
            "ewma": self._ewma.get_stats(),
            "kill_chain": self._kill_chain.get_stats(),
            "cross_host": self._cross_host.get_stats(),
        }
        if self._shap_worker:
            stats["shap"] = self._shap_worker.get_stats()
        return stats


# ── Main Agent ──────────────────────────────────────────────────────────────

class TriageAgent:
    """
    Main agent: owns the consumer loop, processor, and producer.
    Implements graceful shutdown via signal handlers.
    """

    def __init__(self):
        self._running = False
        self._consumer: Optional[Consumer] = None
        self._producer: Optional[Producer] = None
        self._processor: Optional[TriageProcessor] = None

    def _dead_letter(self, value: bytes, reason: str, topic: str = "",
                     partition: int = -1, offset: int = -1):
        """Send a failed event to the dead-letter topic for forensic review."""
        if not self._producer:
            return
        envelope = orjson.dumps({
            "reason": reason,
            "source_topic": topic,
            "source_partition": partition,
            "source_offset": offset,
            "timestamp": time.time(),
            "payload_b64": __import__("base64").b64encode(value[:8192]).decode(),
        })
        try:
            self._producer.produce(
                topic=config.TOPIC_DEAD_LETTER,
                value=envelope,
                callback=_delivery_callback,
            )
        except Exception as e:
            logger.warning("Dead-letter produce failed: %s", e)

    def _handle_signal(self, signum, frame):
        logger.info("Signal %d received — shutting down", signum)
        self._running = False

    def _consumer_loop(self):
        """
        Main loop: batch-consume Kafka → process → publish.
        Time-and-size bounded batch collection using consume() for
        efficient multi-message fetching instead of per-message poll().
        """
        batch_events: List[Dict[str, Any]] = []
        batch_topics: List[str] = []
        batch_timeout_sec = config.BATCH_TIMEOUT_MS / 1000.0
        batch_deadline = time.monotonic() + batch_timeout_sec
        last_cleanup = time.monotonic()
        cleanup_interval = 60.0  # seconds between memory cleanups

        try:
            while self._running:
                # ── Periodic memory cleanup ──────────────────────────
                now = time.monotonic()
                if now - last_cleanup > cleanup_interval:
                    self._run_periodic_cleanup(now)
                    last_cleanup = now
                remaining = config.BATCH_SIZE - len(batch_events)
                time_left = max(batch_deadline - time.monotonic(), 0.01)

                # Batch consume: fetch up to `remaining` messages in one
                # call instead of 2000 individual poll() calls.
                msgs = self._consumer.consume(
                    num_messages=remaining,
                    timeout=min(time_left, 0.5),
                )

                for msg in msgs:
                    if msg.error():
                        if msg.error().code() == KafkaError._PARTITION_EOF:
                            continue
                        logger.error("Kafka error: %s", msg.error())
                        continue

                    try:
                        event = orjson.loads(msg.value())
                    except Exception as e:
                        logger.warning("Failed to parse message offset=%d: %s", msg.offset(), e)
                        # Dead-letter unparseable messages instead of silently dropping
                        self._dead_letter(
                            msg.value(),
                            reason=f"json_parse_error: {e}",
                            topic=msg.topic(),
                            partition=msg.partition(),
                            offset=msg.offset(),
                        )
                        continue

                    event["event_id"] = deterministic_event_id(
                        msg.topic(), msg.partition(), msg.offset(),
                    )

                    batch_events.append(event)
                    batch_topics.append(msg.topic())

                # Flush on batch-full or deadline exceeded with pending data
                if (
                    len(batch_events) >= config.BATCH_SIZE
                    or (batch_events and time.monotonic() >= batch_deadline)
                ):
                    self._flush_batch(batch_events, batch_topics)
                    batch_events = []
                    batch_topics = []
                    batch_deadline = time.monotonic() + batch_timeout_sec

        except KafkaException as e:
            logger.error("Fatal Kafka error: %s", e)
        finally:
            if batch_events:
                self._flush_batch(batch_events, batch_topics)
            self._shutdown()

    def _run_periodic_cleanup(self, now: float):
        """Evict stale entries from stateful trackers to bound memory."""
        try:
            # Baseline trackers (host + user z-score baselines)
            if hasattr(self._processor, '_fusion'):
                self._processor._fusion.cleanup()
            # Kill-chain host states
            removed_kc = 0
            if hasattr(self._processor, '_kill_chain'):
                removed_kc = self._processor._kill_chain.cleanup_stale(now)
            # EWMA tracker (has internal cleanup, trigger it explicitly)
            if hasattr(self._processor, '_ewma'):
                self._processor._ewma._cleanup_stale(now)
            if removed_kc > 0:
                logger.info("Periodic cleanup: kc_hosts_removed=%d", removed_kc)
        except Exception as e:
            logger.warning("Periodic cleanup error: %s", e)

    def _flush_batch(
        self, events: List[Dict[str, Any]], topics: List[str]
    ):
        """Process a batch and publish results. Dead-letter any failed events."""
        t0 = time.monotonic()
        results, failed_events = self._processor.process_batch(events, topics)
        t_process = time.monotonic()

        # Dead-letter events that failed feature extraction or inference
        for evt in failed_events:
            self._dead_letter(
                orjson.dumps(evt),
                reason="feature_extraction_or_inference_failure",
            )

        if failed_events:
            logger.warning(
                "Dead-lettered %d events from batch of %d",
                len(failed_events), len(events),
            )

        if not results:
            # Flush dead-letter produces even if no results
            if failed_events:
                self._producer.flush(timeout=5)
            return

        for i, result in enumerate(results):
            payload = orjson.dumps(result)

            # Always publish to triage-scores
            self._producer.produce(
                topic=config.TOPIC_TRIAGE_SCORES,
                value=payload,
                callback=_delivery_callback,
            )

            # Escalated events also → anomaly-alerts + hunter-tasks
            if result.get("label") == "escalate":
                self._producer.produce(
                    topic=config.TOPIC_ANOMALY_ALERTS,
                    value=payload,
                    callback=_delivery_callback,
                )

                # Enrich hunter-task with kill-chain context
                hunter_payload = self._build_hunter_task(result)
                self._producer.produce(
                    topic=config.TOPIC_HUNTER_TASKS,
                    value=orjson.dumps(hunter_payload),
                    callback=_delivery_callback,
                )

            # Periodically poll to process delivery callbacks and avoid buffer pressure
            if (i + 1) % 1000 == 0:
                self._producer.poll(0)

        t_produce = time.monotonic()
        # Non-blocking flush: short timeout to avoid blocking the hot path.
        # At-least-once semantics still hold — undelivered messages will be
        # retried on the next batch via the producer's internal retry logic.
        remaining = self._producer.flush(timeout=5)
        if remaining > 0:
            logger.warning("Producer flush: %d messages still pending after 5s", remaining)
        t_flush = time.monotonic()
        # Async offset commit — reduces blocking; at-least-once still holds
        # because flush() above ensures delivery before commit fires
        try:
            self._consumer.commit(asynchronous=True)
        except KafkaException as e:
            logger.warning("Offset commit failed (will retry next batch): %s", e)
        t_commit = time.monotonic()

        escalated = sum(1 for r in results if r.get("label") == "escalate")
        logger.info(
            "Batch: %d events (esc=%d) | process=%.1fs produce=%.1fs flush=%.1fs commit=%.1fs total=%.1fs | cumul=%d",
            len(events), escalated,
            t_process - t0, t_produce - t_process, t_flush - t_produce, t_commit - t_flush,
            t_commit - t0, self._processor._events_processed,
        )

    def _build_hunter_task(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build hunter-tasks payload with all fields the Hunter agent expects.

        Critical field mapping (triage → hunter):
          final_score   → adjusted_score  (Hunter's primary score field)
          final_score   → combined_score  (used as base_score in fusion)
          has_known_ioc → ioc_match       (integer 0/1)
          user / user_id→ user_id         (Hunter uses user_id)
        """
        hostname = result.get("hostname", "")
        kc_state = self._processor._kill_chain.get_host_state(hostname)
        final_score = result.get("final_score", 0.0)
        source_ip = result.get("source_ip", "")
        user_id = result.get("user_id", "") or result.get("user", "")
        action_name = result.get("action_type_name", "info")

        task = {
            # ── Identity ──────────────────────────────────────────────
            "event_id": result.get("event_id", ""),
            "alert_id": result.get("event_id", ""),
            "hostname": hostname,
            "source_ip": source_ip,
            "user_id": user_id,
            "source_type": result.get("source_type", ""),
            "timestamp": result.get("timestamp", ""),
            # ── Scores (Hunter reads 'adjusted_score' or 'trigger_score') ──
            "adjusted_score": final_score,
            "trigger_score": final_score,
            "combined_score": final_score,
            "lgbm_score": result.get("lgbm_score", 0.0),
            "ae_score": 0.0,
            # ── Triage context for Hunter fusion vector ───────────────
            "asset_multiplier": 1.0,
            "ioc_match": int(result.get("has_known_ioc", 0)),
            "ioc_confidence": 100 if result.get("has_known_ioc", 0) else 0,
            "template_rarity": result.get("template_rarity", 0.0),
            "template_id": result.get("template_id", ""),
            # ── MITRE context (best-effort from raw event) ────────────
            "mitre_tactic": result.get("mitre_tactic", "unknown"),
            "mitre_technique": result.get("mitre_technique", ""),
            # ── Text for Sigma keyword matching and narrative ─────────
            "message": result.get("message", ""),
            "summary": (
                f"{hostname} {source_ip} {action_name} "
                f"score={final_score:.3f}"
            ),
            # ── Action and routing ────────────────────────────────────
            "action": result.get("label", ""),
            "action_type": action_name,
            "adjustments": result.get("adjustments", ""),
            "model_version": result.get("model_version", "v8"),
            # ── v8: entity EWMA rates for Hunter feature vector ───────
            "entity_event_rate": result.get("entity_event_rate", 0.0),
            "entity_error_rate": result.get("entity_error_rate", 0.0),
        }

        if kc_state:
            task["kill_chain_stage"] = kc_state["stage"]
            task["kill_chain_velocity"] = kc_state["velocity"]
            task["kill_chain_history"] = kc_state.get("stage_events", [])

        return task

    def _shutdown(self):
        """Graceful shutdown with final sync commit to preserve at-least-once."""
        logger.info("Shutting down triage agent...")

        if self._processor:
            self._processor.shutdown()
        if self._producer:
            self._producer.flush(timeout=10)
        if self._consumer:
            try:
                self._consumer.commit(asynchronous=False)
                logger.info("Final synchronous offset commit succeeded")
            except Exception as e:
                logger.warning("Final offset commit failed: %s", e)
            self._consumer.close()

        logger.info("Triage agent shutdown complete")


# ── Flask health endpoint ──────────────────────────────────────────────────

flask_app = Flask("clif-triage-agent")
_processor_ref: Optional[TriageProcessor] = None


@flask_app.route("/health")
def health():
    stats = {}
    if _processor_ref:
        try:
            stats = _processor_ref.get_stats()
        except Exception:
            pass
    return jsonify({
        "status": "healthy",
        "service": "clif-triage-agent-v8",
        "events_processed": stats.get("events_processed", 0),
        "batches_processed": stats.get("batches_processed", 0),
        "avg_batch_time_ms": stats.get("avg_batch_time_ms", 0),
    }), 200


@flask_app.route("/stats")
def stats():
    if _processor_ref:
        return jsonify(_processor_ref.get_stats()), 200
    return jsonify({"error": "Processor not initialized"}), 503


@flask_app.route("/ready")
def ready():
    if _processor_ref and _processor_ref._ensemble.is_ready:
        return jsonify({"ready": True}), 200
    return jsonify({"ready": False}), 503


# ── Entrypoint ──────────────────────────────────────────────────────────────

def main():
    global _processor_ref

    logger.info("CLIF Triage Agent v8.3.0")
    logger.info(
        "Config: batch=%d, workers=%d, port=%d",
        config.BATCH_SIZE, config.INFERENCE_WORKERS, config.HEALTH_PORT,
    )
    logger.info(
        "Weights: lgbm=%.2f",
        config.LGBM_WEIGHT,
    )
    logger.info(
        "Thresholds: suspicious=%.2f, anomalous=%.2f",
        config.DEFAULT_SUSPICIOUS_THRESHOLD,
        config.DEFAULT_ANOMALOUS_THRESHOLD,
    )

    # Health server
    health_thread = threading.Thread(
        target=lambda: flask_app.run(
            host="0.0.0.0",
            port=config.HEALTH_PORT,
            debug=False,
            use_reloader=False,
        ),
        daemon=True,
    )
    health_thread.start()
    logger.info("Health endpoint on port %d", config.HEALTH_PORT)

    # Kafka health gate
    check_kafka_health()

    # Initialize and start
    agent = TriageAgent()
    agent._processor = TriageProcessor()
    _processor_ref = agent._processor

    agent._consumer = create_consumer()
    agent._producer = create_producer()
    agent._running = True

    signal.signal(signal.SIGTERM, agent._handle_signal)
    signal.signal(signal.SIGINT, agent._handle_signal)

    logger.info("=" * 60)
    logger.info("CLIF Triage Agent v8 ready — entering consumer loop")
    logger.info("=" * 60)
    agent._consumer_loop()


if __name__ == "__main__":
    main()
