"""
CLIF Triage Agent v8.3 — Configuration
========================================
All configuration via environment variables with production defaults.

v8.3 changes:
  - LightGBM-only (autoencoder removed, weight was already 0.0)
  - 60-feature vector (7 layers: Shared Core, Network, Auth, DNS, Web, Email, Cloud)
  - LightGBM: 742 trees, F1=0.9492, AUC=0.9957
"""

import os
import multiprocessing

# ── Kafka / Redpanda ────────────────────────────────────────────────────────

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "redpanda01:9092")
CONSUMER_GROUP_ID = os.getenv("CONSUMER_GROUP_ID", "clif-triage-agent")

INPUT_TOPICS = [
    t.strip()
    for t in os.getenv(
        "INPUT_TOPICS", "raw-logs,security-events,process-events,network-events"
    ).split(",")
]

TOPIC_TRIAGE_SCORES = os.getenv("TOPIC_TRIAGE_SCORES", "triage-scores")
TOPIC_ANOMALY_ALERTS = os.getenv("TOPIC_ANOMALY_ALERTS", "anomaly-alerts")
TOPIC_HUNTER_TASKS = os.getenv("TOPIC_HUNTER_TASKS", "hunter-tasks")
TOPIC_DEAD_LETTER = os.getenv("TOPIC_DEAD_LETTER", "dead-letter")

# ── ClickHouse ──────────────────────────────────────────────────────────────

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "clickhouse01")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "clif_admin")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "clif_secure_password_change_me")
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "clif_logs")

# ── Models (v8.3: LightGBM only) ───────────────────────────────────────────

MODEL_DIR = os.getenv("MODEL_DIR", "/models")
MODEL_LGBM_PATH = os.getenv("MODEL_LGBM_PATH", "/models/lgbm_v8.onnx")
FEATURE_SCALER_PATH = os.getenv("FEATURE_SCALER_PATH", "/models/feature_scaler_v8.json")
MANIFEST_PATH = os.getenv("MANIFEST_PATH", "/models/manifest_v8.json")

# ── Per-Type Models (v8.1: 6 separate LightGBM models) ─────────────────────
# When enabled, events are routed to a type-specific LGBM model instead of
# Per-type models disabled in v8.2 — global model outperforms on both
# accuracy (F1=0.9492 vs 0.9486) and latency (~10µs vs 10-140µs/event).
# Config retained for potential future use.

PER_TYPE_MODELS_ENABLED = os.getenv("PER_TYPE_MODELS_ENABLED", "false").lower() == "true"
PER_TYPE_MANIFEST_PATH = os.getenv(
    "PER_TYPE_MANIFEST_PATH", "/models/manifest_per_type.json"
)

# Log type → per-type model name mapping
# Types not listed here fall back to the global lgbm_v8.onnx model.
LOG_TYPE_TO_MODEL = {
    "ids": "ids",
    "firewall": "netflow",  # firewall is trained in netflow group
    "netflow": "netflow",
    "syslog": "auth",
    "ad": "auth",
    "dns": "dns",
    "email": "email",
    "windows": "windows",
}

# ── Score Weights (v8.3: LightGBM only) ─────────────────────────────────────

LGBM_WEIGHT = float(os.getenv("LGBM_WEIGHT", "1.00"))

# ── Thresholds (v8) ────────────────────────────────────────────────────────

DEFAULT_SUSPICIOUS_THRESHOLD = float(
    os.getenv("DEFAULT_SUSPICIOUS_THRESHOLD", "0.40")
)
DEFAULT_ANOMALOUS_THRESHOLD = float(
    os.getenv("DEFAULT_ANOMALOUS_THRESHOLD", "0.90")
)

# ── Per-Log-Type Thresholds ─────────────────────────────────────────────────
# Override the global thresholds for specific log types.
# Root cause analysis showed the global 0.40/0.90 is wrong for most types:
#   - IDS/Netflow: 0.40 is optimal (strong LGBM separation)
#   - Email: 0.40 catches too many FPs → raise suspicious to 0.75
#   - SSH/Auth: attacks score 0.10–0.25 → lower suspicious to 0.20
#   - Windows: attacks score 0.02–0.15 → lower suspicious to 0.15
#   - CloudTrail: attacks score 0.08–0.25 → lower suspicious to 0.20
#   - DNS: model inverted → handled by rules, lower to 0.20
#   - Web: similar to email → raise suspicious to 0.60

PER_TYPE_THRESHOLDS = {
    # log_type: (suspicious_threshold, anomalous_threshold)
    "ids":        (float(os.getenv("THRESHOLD_IDS_SUSPICIOUS", "0.40")),
                   float(os.getenv("THRESHOLD_IDS_ANOMALOUS", "0.90"))),
    "firewall":   (float(os.getenv("THRESHOLD_FIREWALL_SUSPICIOUS", "0.40")),
                   float(os.getenv("THRESHOLD_FIREWALL_ANOMALOUS", "0.90"))),
    "netflow":    (float(os.getenv("THRESHOLD_NETFLOW_SUSPICIOUS", "0.40")),
                   float(os.getenv("THRESHOLD_NETFLOW_ANOMALOUS", "0.90"))),
    "email":      (float(os.getenv("THRESHOLD_EMAIL_SUSPICIOUS", "0.75")),
                   float(os.getenv("THRESHOLD_EMAIL_ANOMALOUS", "0.92"))),
    "syslog":     (float(os.getenv("THRESHOLD_SYSLOG_SUSPICIOUS", "0.20")),
                   float(os.getenv("THRESHOLD_SYSLOG_ANOMALOUS", "0.85"))),
    "windows":    (float(os.getenv("THRESHOLD_WINDOWS_SUSPICIOUS", "0.15")),
                   float(os.getenv("THRESHOLD_WINDOWS_ANOMALOUS", "0.80"))),
    "ad":         (float(os.getenv("THRESHOLD_AD_SUSPICIOUS", "0.20")),
                   float(os.getenv("THRESHOLD_AD_ANOMALOUS", "0.85"))),
    "cloudtrail": (float(os.getenv("THRESHOLD_CT_SUSPICIOUS", "0.20")),
                   float(os.getenv("THRESHOLD_CT_ANOMALOUS", "0.85"))),
    "cloud":      (float(os.getenv("THRESHOLD_CT_SUSPICIOUS", "0.20")),
                   float(os.getenv("THRESHOLD_CT_ANOMALOUS", "0.85"))),
    "dns":        (float(os.getenv("THRESHOLD_DNS_SUSPICIOUS", "0.20")),
                   float(os.getenv("THRESHOLD_DNS_ANOMALOUS", "0.85"))),
    "web":        (float(os.getenv("THRESHOLD_WEB_SUSPICIOUS", "0.60")),
                   float(os.getenv("THRESHOLD_WEB_ANOMALOUS", "0.90"))),
}

def get_thresholds(log_type: str) -> tuple:
    """Return (suspicious, anomalous) thresholds for a given log type."""
    return PER_TYPE_THRESHOLDS.get(
        log_type,
        (DEFAULT_SUSPICIOUS_THRESHOLD, DEFAULT_ANOMALOUS_THRESHOLD),
    )

# ── SSH Brute Force Rule ────────────────────────────────────────────────────
# The LightGBM model was trained on SSH attacks that only targeted non-admin
# usernames (invalid_user type).  Admin-targeting brute force (root, admin)
# produces feature vectors the model considers "benign".  This rule-based
# detector catches those cases using deterministic indicators.

SSH_BRUTE_FORCE_ENABLED = os.getenv("SSH_BRUTE_FORCE_ENABLED", "true").lower() == "true"
SSH_BRUTE_FORCE_MIN_FAIL_RATE = float(os.getenv("SSH_BRUTE_FORCE_MIN_FAIL_RATE", "0.7"))
SSH_BRUTE_FORCE_MIN_EVENT_FREQ = float(os.getenv("SSH_BRUTE_FORCE_MIN_EVENT_FREQ", "0.5"))
SSH_BRUTE_FORCE_SCORE_FLOOR = float(os.getenv("SSH_BRUTE_FORCE_SCORE_FLOOR", "0.92"))

# ── Windows Attack Pattern Rule ─────────────────────────────────────────────
# The LightGBM model scores many real Windows attack events (MITRE ATT&CK)
# below the suspicious threshold because the auth-layer features (fail_rate,
# unique_targets, event_frequency) require accumulated entity history that
# may be sparse.  This rule uses deterministic per-event indicators:
#   A) Security log: severity_numeric >= 2 (high-risk EventIDs)
#   B) Sysmon: attack-indicative content (suspicious processes, credential
#      access, persistence, encoded payloads)

WINDOWS_ATTACK_RULE_ENABLED = os.getenv("WINDOWS_ATTACK_RULE_ENABLED", "true").lower() == "true"
WINDOWS_ATTACK_RULE_SCORE_FLOOR = float(os.getenv("WINDOWS_ATTACK_RULE_SCORE_FLOOR", "0.85"))

# ── DNS Exfiltration Rule ───────────────────────────────────────────────────
# The LightGBM model was trained on DGA (short random domains).  DNS exfil
# uses long encoded subdomains for data tunneling — a structurally different
# pattern the model scores as benign.  This rule detects tunneling indicators:
#   - domain_length >= threshold (encoded data produces long names)
#   - subdomain_depth >= threshold (deeply nested subdomains)
#   - bigram_frequency < threshold (encoded data, not natural language)
#   - has_hex_pattern (hexadecimal encoding common in exfil)
# Requires >= 2 indicators to trigger (reduces false positives).

DNS_EXFIL_RULE_ENABLED = os.getenv("DNS_EXFIL_RULE_ENABLED", "true").lower() == "true"
DNS_EXFIL_MIN_DOMAIN_LENGTH = float(os.getenv("DNS_EXFIL_MIN_DOMAIN_LENGTH", "40"))
DNS_EXFIL_MIN_SUBDOMAIN_DEPTH = float(os.getenv("DNS_EXFIL_MIN_SUBDOMAIN_DEPTH", "3"))
DNS_EXFIL_MAX_BIGRAM_FREQ = float(os.getenv("DNS_EXFIL_MAX_BIGRAM_FREQ", "0.20"))
DNS_EXFIL_SCORE_FLOOR = float(os.getenv("DNS_EXFIL_SCORE_FLOOR", "0.88"))

# ── Email Spam/Phishing Rule ────────────────────────────────────────────────
# With per-type email threshold at 0.75, the model alone handles high-
# confidence spam.  This rule catches emails that show multiple phishing/
# spam indicators (high URL count + urgency, ALL CAPS + financial keywords).

EMAIL_SPAM_RULE_ENABLED = os.getenv("EMAIL_SPAM_RULE_ENABLED", "true").lower() == "true"
EMAIL_SPAM_RULE_SCORE_FLOOR = float(os.getenv("EMAIL_SPAM_RULE_SCORE_FLOOR", "0.88"))

# ── Web Attack Pattern Rule ─────────────────────────────────────────────────
# Boosts web requests with clear SQLi, XSS, or directory traversal patterns.
# Works alongside the per-type web threshold (0.60).

WEB_ATTACK_RULE_ENABLED = os.getenv("WEB_ATTACK_RULE_ENABLED", "true").lower() == "true"
WEB_ATTACK_RULE_SCORE_FLOOR = float(os.getenv("WEB_ATTACK_RULE_SCORE_FLOOR", "0.85"))

# ── Lateral Movement Rule ───────────────────────────────────────────────────
# Credential-based lateral movement: successful remote auth to many distinct
# targets.  High threshold (10+ machines) avoids false positives on normal
# admins or shared-service accounts.  Also requires sufficient event volume
# to ensure we're not triggering on sparse entity-tracker data.

LATERAL_MOVEMENT_RULE_ENABLED = os.getenv("LATERAL_MOVEMENT_RULE_ENABLED", "false").lower() == "true"
LATERAL_MOVEMENT_MIN_UNIQUE_TARGETS = float(os.getenv("LATERAL_MOVEMENT_MIN_UNIQUE_TARGETS", "1.04"))
LATERAL_MOVEMENT_SCORE_FLOOR = float(os.getenv("LATERAL_MOVEMENT_SCORE_FLOOR", "0.85"))
LATERAL_MOVEMENT_MIN_EVENT_FREQ = float(os.getenv("LATERAL_MOVEMENT_MIN_EVENT_FREQ", "1.30"))

# ── Message Pattern Rule ────────────────────────────────────────────────────
# Universal fallback: scans raw message text for attack indicators when
# structured fields are absent and the LGBM model scores events low.
# Three severity tiers: critical (0.92), high (0.88), medium (0.55).

MESSAGE_PATTERN_RULE_ENABLED = os.getenv("MESSAGE_PATTERN_RULE_ENABLED", "true").lower() == "true"

# ── Operational ─────────────────────────────────────────────────────────────

BATCH_SIZE = int(os.getenv("BATCH_SIZE", "2000"))
BATCH_TIMEOUT_MS = int(os.getenv("BATCH_TIMEOUT_MS", "500"))
INFERENCE_WORKERS = int(os.getenv(
    "INFERENCE_WORKERS",
    str(min(8, max(2, multiprocessing.cpu_count() // 2))),
))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
HEALTH_PORT = int(os.getenv("TRIAGE_PORT", "8300"))

# ── EWMA Rate Tracking ─────────────────────────────────────────────────────

EWMA_HALF_LIFE_FAST = float(os.getenv("EWMA_HALF_LIFE_FAST", "2.0"))
EWMA_HALF_LIFE_MEDIUM = float(os.getenv("EWMA_HALF_LIFE_MEDIUM", "60.0"))
EWMA_HALF_LIFE_SLOW = float(os.getenv("EWMA_HALF_LIFE_SLOW", "600.0"))
EWMA_CLEANUP_INTERVAL_SEC = float(os.getenv("EWMA_CLEANUP_INTERVAL_SEC", "60.0"))
EWMA_MAX_ENTITIES = int(os.getenv("EWMA_MAX_ENTITIES", "500000"))

# ── Kill-Chain Tracker ──────────────────────────────────────────────────────

KILL_CHAIN_DECAY_SEC = float(os.getenv("KILL_CHAIN_DECAY_SEC", "3600.0"))
KILL_CHAIN_SCORE_GATE = float(os.getenv("KILL_CHAIN_SCORE_GATE", "0.50"))
KILL_CHAIN_BOOST_PER_STAGE = float(os.getenv("KILL_CHAIN_BOOST_PER_STAGE", "0.05"))
KILL_CHAIN_BOOST_MAX = float(os.getenv("KILL_CHAIN_BOOST_MAX", "1.25"))

# ── Cross-Host Correlation ──────────────────────────────────────────────────

CROSS_HOST_WINDOW_SEC = float(os.getenv("CROSS_HOST_WINDOW_SEC", "900.0"))
CROSS_HOST_MIN_SCORE = float(os.getenv("CROSS_HOST_MIN_SCORE", "0.85"))
CROSS_HOST_MIN_HOSTS = float(os.getenv("CROSS_HOST_MIN_HOSTS", "5.0"))
CROSS_HOST_BOOST = float(os.getenv("CROSS_HOST_BOOST", "1.10"))

# ── Connection Tracker (Sharded) ────────────────────────────────────────────

CONN_TRACKER_SHARDS = int(os.getenv("CONN_TRACKER_SHARDS", "16"))
CONN_TIME_WINDOW_SEC = float(os.getenv("CONN_TIME_WINDOW_SEC", "2.0"))
CONN_HOST_WINDOW_SIZE = int(os.getenv("CONN_HOST_WINDOW_SIZE", "100"))
CONN_CLEANUP_INTERVAL_SEC = float(os.getenv("CONN_CLEANUP_INTERVAL_SEC", "10.0"))

# ── IOC Boost ───────────────────────────────────────────────────────────────

IOC_BOOST_BASE = float(os.getenv("IOC_BOOST_BASE", "0.05"))
IOC_BOOST_SCALE = float(os.getenv("IOC_BOOST_SCALE", "0.15"))

# ── SHAP (Async) ────────────────────────────────────────────────────────────

SHAP_ENABLED = os.getenv("SHAP_ENABLED", "true").lower() == "true"
SHAP_QUEUE_SIZE = int(os.getenv("SHAP_QUEUE_SIZE", "1000"))
SHAP_BATCH_SIZE = int(os.getenv("SHAP_BATCH_SIZE", "50"))

# ── Startup / Health ────────────────────────────────────────────────────────

SELFTEST_ENABLED = os.getenv("SELFTEST_ENABLED", "true").lower() == "true"
STARTUP_HEALTH_RETRIES = int(os.getenv("STARTUP_HEALTH_RETRIES", "30"))
STARTUP_HEALTH_DELAY_SEC = float(os.getenv("STARTUP_HEALTH_DELAY_SEC", "2.0"))

# ── Drift Monitoring ────────────────────────────────────────────────────────

DRIFT_ENABLED = os.getenv("DRIFT_ENABLED", "true").lower() == "true"
DRIFT_INTERVAL_BATCHES = int(os.getenv("DRIFT_INTERVAL_BATCHES", "500"))
DRIFT_WINDOW_SIZE = int(os.getenv("DRIFT_WINDOW_SIZE", "5000"))
DRIFT_PSI_BINS = int(os.getenv("DRIFT_PSI_BINS", "10"))
DRIFT_PSI_WARNING = float(os.getenv("DRIFT_PSI_WARNING", "0.1"))
DRIFT_PSI_CRITICAL = float(os.getenv("DRIFT_PSI_CRITICAL", "0.25"))

# ── Prometheus Metrics ──────────────────────────────────────────────────────

METRICS_ENABLED = os.getenv("METRICS_ENABLED", "true").lower() == "true"

# ── Source Type Numeric Mapping ─────────────────────────────────────────────

SOURCE_TYPE_MAP = {
    "syslog": 1, "linux_auth": 1, "sshd": 1, "sudo": 1, "pam": 1,
    "auditd": 1, "docker_logs": 1, "journald": 1,
    "windows_event": 2, "winlogbeat": 2, "wineventlog": 2, "sysmon": 2,
    "firewall": 3, "cef": 3,
    "active_directory": 4, "ldap": 4,
    "dns": 5, "dns_logs": 5,
    "cloudtrail": 6, "aws_cloudtrail": 6,
    "kubernetes": 7, "k8s_audit": 7,
    "nginx": 8, "apache": 8, "web_server": 8,
    "netflow": 9, "ipfix": 9,
    "ids_ips": 10, "zeek": 10, "snort": 10, "suricata": 10,
    "http_json": 1, "file_logs": 1, "unknown": 1,
}

# ── Protocol Numeric Mapping ────────────────────────────────────────────────

PROTOCOL_MAP = {
    "tcp": 6, "udp": 17, "icmp": 1, "igmp": 2,
    "gre": 47, "esp": 50, "ah": 51, "sctp": 132,
}

# ── Severity Text → Numeric ────────────────────────────────────────────────

SEVERITY_MAP = {
    "debug": 0, "info": 0, "notice": 1, "warning": 2, "warn": 2,
    "error": 3, "err": 3, "critical": 4, "alert": 4, "emergency": 4,
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4,
    "low": 1, "medium": 2, "high": 3,
}

# ── Action Type Mapping ────────────────────────────────────────────────────

ACTION_TYPE_MAP = {
    "info": 0,
    "auth_attempt": 1,
    "auth_success": 2,
    "auth_fail": 3,
    "process_create": 4,
    "process_terminate": 5,
    "network_connect": 6,
    "network_deny": 7,
    "policy_change": 8,
    "privilege_use": 9,
    "data_access": 10,
    "config_change": 11,
}

ACTION_NAMES = {v: k for k, v in ACTION_TYPE_MAP.items()}

# ── Event ID Risk Score Mapping ─────────────────────────────────────────────

WINDOWS_EVENT_RISK = {
    4624: 0.1, 4625: 0.7, 4634: 0.05, 4648: 0.6,
    4656: 0.4, 4663: 0.3, 4672: 0.5, 4688: 0.3,
    4689: 0.1, 4697: 0.8, 4698: 0.7, 4720: 0.9,
    4722: 0.7, 4724: 0.6, 4728: 0.8, 4732: 0.8,
    4756: 0.7, 4768: 0.2, 4769: 0.2, 4771: 0.6,
    4776: 0.3, 5140: 0.4, 5145: 0.4, 7045: 0.8,
    1102: 0.9, 4104: 0.6,
}

# ── Security Keyword Patterns ───────────────────────────────────────────────

THREAT_KEYWORDS = (
    "fail", "denied", "error", "attack", "exploit", "malicious",
    "unauthorized", "violation", "brute", "inject", "overflow",
    "escalat", "privilege", "sudo", "root", "admin",
    "backdoor", "payload", "malware", "shellcode", "reverse",
    "c2", "beacon", "exfiltrat", "lateral", "mimikatz",
    "phish", "trojan", "ransomware", "keylog", "credential",
    "dump", "powershell", "encoded", "obfuscat",
)
