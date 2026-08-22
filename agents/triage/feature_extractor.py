"""
CLIF Triage Agent v8 — Feature Extractor (60 features, 7 layers)
===================================================================
Extracts the 60-feature vector from CLIF pipeline events at inference time.

7 feature layers:
  Layer 1 — Shared Core   (9):  All log types
  Layer 2 — Network       (15): Firewall, NetFlow, IDS, DoH, CREMEv2
  Layer 3 — Authentication (8): Syslog, Windows, AD
  Layer 4 — DNS            (8): DGA, DNS exfiltration
  Layer 5 — Web/HTTP       (7): Web server, CSIC
  Layer 6 — Email          (7): Email / phishing
  Layer 7 — Cloud/API      (6): CloudTrail

Design principles:
  - All 60 features are stateless and deterministic per-event
  - Inactive layers are zero-filled (model learned log_type → active layers)
  - No Drain3, no EWMA, no warm-up dependencies
  - Same feature semantics as training (extract_features_v8.py)
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger("clif.triage.features")

# ── Canonical feature order (60 features, v8) ───────────────────────────────

FEATURE_NAMES = [
    # Layer 1: Shared Core (0–8)
    "hour_sin", "hour_cos", "dow_sin", "dow_cos", "is_off_hours",
    "log_type", "severity_numeric", "message_length_log", "message_entropy",
    # Layer 2: Network (9–23)
    "dst_port_bin", "protocol_numeric", "total_bytes_log", "byte_ratio",
    "total_packets_log", "packet_ratio", "flow_duration_log", "avg_pkt_size",
    "pkt_size_variance", "iat_mean", "iat_stddev", "tcp_syn_flag",
    "tcp_rst_flag", "tcp_fin_flag", "retransmit_ratio",
    # Layer 3: Auth (24–31)
    "auth_type_encoded", "status_is_fail", "is_admin", "src_dst_match",
    "is_remote", "fail_rate", "unique_targets", "event_frequency",
    # Layer 4: DNS (32–39)
    "domain_length", "domain_entropy", "subdomain_depth", "digit_ratio",
    "max_consonant_run", "bigram_frequency", "has_hex_pattern", "tld_risk",
    # Layer 5: Web/HTTP (40–46)
    "url_length", "url_entropy", "query_param_count", "has_sql_pattern",
    "has_xss_pattern", "has_traversal", "http_method",
    # Layer 6: Email (47–53)
    "subject_length", "body_length_log", "subject_entropy", "url_count",
    "caps_ratio", "has_urgency", "has_financial",
    # Layer 7: Cloud/API (54–59)
    "event_name_encoded", "is_sensitive_service", "is_read_only",
    "has_error", "identity_type_encoded", "is_root",
]

NUM_FEATURES = 60
assert len(FEATURE_NAMES) == NUM_FEATURES

# Layer boundaries (inclusive start, exclusive end)
LAYER_RANGES = {
    1: (0, 9),
    2: (9, 24),
    3: (24, 32),
    4: (32, 40),
    5: (40, 47),
    6: (47, 54),
    7: (54, 60),
}

# ── Lookup tables (must match training) ──────────────────────────────────────

LOG_TYPE_MAP = {
    "syslog": 0, "windows": 1, "firewall": 2, "ad": 3, "dns": 4,
    "cloud": 5, "web": 6, "netflow": 7, "ids": 8, "email": 9,
}

PROTOCOL_MAP = {"tcp": 6, "udp": 17, "icmp": 1, "arp": 0, "ospf": 89}

AUTH_TYPE_MAP = {
    "kerberos": 0, "ntlm": 1, "negotiate": 2, "password": 3,
    "?": 4, "ms_auth_v1": 5, "wave": 6,
}

TLD_RISK = {
    "com": 0.1, "org": 0.1, "net": 0.1, "edu": 0.05, "gov": 0.05,
    "io": 0.3, "xyz": 0.7, "top": 0.8, "tk": 0.9, "ml": 0.9,
    "ga": 0.9, "cf": 0.9, "gq": 0.9, "pw": 0.8, "cc": 0.6,
    "info": 0.4, "biz": 0.5, "ru": 0.5, "cn": 0.4, "br": 0.3,
}

HTTP_METHOD_MAP = {
    "get": 0, "post": 1, "put": 2, "delete": 3, "head": 4,
    "options": 5, "patch": 6, "trace": 7,
}

SQL_KEYWORDS = re.compile(
    r"(union\s+select|select\s+.*from|drop\s+table|insert\s+into|"
    r"update\s+.*set|delete\s+from|or\s+1\s*=\s*1|and\s+1\s*=\s*1|"
    r"--\s|;\s*drop|'\s*or\s*'|char\(|concat\(|0x[0-9a-f]{4,})",
    re.IGNORECASE,
)

XSS_PATTERNS = re.compile(
    r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|"
    r"document\.cookie|eval\s*\(|<iframe|<img\s+[^>]*on\w+\s*=)",
    re.IGNORECASE,
)

TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/proc/|/var/log|cmd\.exe|/bin/sh)"
)

URGENCY_KEYWORDS = re.compile(
    r"\b(urgent|immediately|verify|expire|suspend|deactivat|"
    r"confirm\s+your|act\s+now|limited\s+time|final\s+warning)\b",
    re.IGNORECASE,
)

FINANCIAL_KEYWORDS = re.compile(
    r"\b(bank|account|transfer|password|credit\s*card|ssn|"
    r"social\s+security|paypal|bitcoin|wire\s+transfer|routing\s+number)\b",
    re.IGNORECASE,
)

CT_EVENT_NAMES = [
    "RunInstances", "DescribeSnapshots", "AssumeRole", "DescribeInstances",
    "GetBucketAcl", "ListBuckets", "GetObject", "PutObject",
    "CreateUser", "AttachUserPolicy", "DeleteUser", "CreateAccessKey",
    "GetCallerIdentity", "ListUsers", "ListRoles", "CreateRole",
    "PutRolePolicy", "DeleteAccessKey", "StopInstances", "TerminateInstances",
    "DescribeSecurityGroups", "AuthorizeSecurityGroupIngress", "CreateSecurityGroup",
    "DescribeSubnets", "DescribeVpcs", "CreateVpc", "DeleteVpc",
    "CreateTrail", "StopLogging", "DeleteTrail", "PutBucketPolicy",
    "GetBucketPolicy", "ListAccessKeys", "GetUserPolicy", "CreateLoginProfile",
    "UpdateLoginProfile", "DeleteLoginProfile", "ConsoleLogin",
    "DescribeRegions", "DescribeAvailabilityZones", "ModifyInstanceAttribute",
    "CreateKeyPair", "DescribeKeyPairs", "ImportKeyPair",
    "GetSecretValue", "CreateSecret", "DescribeDBInstances",
    "CreateDBInstance", "ModifyDBInstance", "DeleteDBInstance",
]

# O(1) lookup instead of O(n) linear search
CT_EVENT_NAME_TO_IDX = {name: float(i) for i, name in enumerate(CT_EVENT_NAMES)}

SENSITIVE_SERVICES = {
    "iam.amazonaws.com", "sts.amazonaws.com", "kms.amazonaws.com",
    "secretsmanager.amazonaws.com", "organizations.amazonaws.com",
    "cloudtrail.amazonaws.com",
}

_ENGLISH_BIGRAMS = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
    "re": 1.85, "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35,
    "ti": 1.34, "es": 1.34, "or": 1.28, "te": 1.27, "of": 1.17,
    "ed": 1.17, "is": 1.13, "it": 1.12, "al": 1.09, "ar": 1.07,
    "st": 1.05, "to": 1.04, "nt": 1.04, "ng": 0.95, "se": 0.93,
    "ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
    "ve": 0.83, "co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.73,
    "ri": 0.73, "ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69,
    "ra": 0.62, "ce": 0.65, "li": 0.62, "ch": 0.60, "ll": 0.58,
    "be": 0.58, "ma": 0.57, "si": 0.55, "om": 0.55, "ur": 0.54,
}
_MAX_BIGRAM_FREQ = max(_ENGLISH_BIGRAMS.values())

_URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
_HEX_RE = re.compile(r"[0-9a-f]{8,}", re.IGNORECASE)

SEVERITY_MAP = {
    "debug": 0, "info": 1, "notice": 1, "warning": 2, "warn": 2,
    "error": 3, "err": 3, "critical": 4, "crit": 4, "alert": 4,
    "emergency": 4, "emerg": 4,
}

# Admin-like usernames (training: SSH severity = admin-account targeting)
_ADMIN_USERNAMES = {"root", "admin", "administrator", "test", "guest"}

# Security-relevant daemons (training: CREMEv2 syslog severity)
_SEC_COMPONENTS = {"sshd", "sudo", "su", "pam", "login", "systemd-logind"}

# Windows EventID risk tiers (training: 0/1/2)
_HIGH_RISK_EIDS = {4625, 4697, 4720, 4728, 4732, 1102, 7045}
_MED_RISK_EIDS = {4624, 4672, 4688, 4768, 4769}

TOPIC_LOG_TYPE_MAP = {
    "raw-logs": "syslog",
    "security-events": "windows",
    "process-events": "windows",
    "network-events": "netflow",
}


# ── Helper functions (match training pipeline exactly) ───────────────────────

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    if n == 0:
        return 0.0
    counts: Dict[str, int] = Counter(text)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _bigram_frequency_score(domain: str) -> float:
    if not domain or len(domain) < 2:
        return 0.0
    parts = domain.lower().split(".")
    name = parts[0] if parts else domain.lower()
    if len(name) < 2:
        return 0.0
    bigrams = [name[i:i + 2] for i in range(len(name) - 1)]
    total = sum(_ENGLISH_BIGRAMS.get(bg, 0.0) for bg in bigrams)
    return total / (len(bigrams) * _MAX_BIGRAM_FREQ) if bigrams else 0.0


def _max_consonant_run(text: str) -> int:
    if not text:
        return 0
    consonants = set("bcdfghjklmnpqrstvwxyz")
    max_run = 0
    current = 0
    for c in text.lower():
        if c in consonants:
            current += 1
            if current > max_run:
                max_run = current
        else:
            current = 0
    return max_run


def _port_bin(port: float) -> int:
    p = max(0, min(65535, int(port)))
    if p <= 1023:
        return 0
    if p <= 49151:
        return 1
    return 2


def _safe_float(val, default: float = 0.0) -> float:
    try:
        v = float(val)
        return v if math.isfinite(v) else default
    except (TypeError, ValueError):
        return default


def _caps_ratio(text: str) -> float:
    if not text:
        return 0.0
    alpha = sum(1 for c in text if c.isalpha())
    if alpha == 0:
        return 0.0
    return sum(1 for c in text if c.isupper()) / alpha


def _count_urls(text: str) -> int:
    if not text:
        return 0
    return len(_URL_RE.findall(text))


def _parse_timestamp(raw) -> datetime:
    if isinstance(raw, datetime):
        return raw
    if not raw:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _map_severity(raw) -> int:
    if isinstance(raw, (int, float)):
        return max(0, min(4, int(raw)))
    return SEVERITY_MAP.get(str(raw).lower().strip(), 1)


def _compute_severity(log_type_str: str, event: Dict[str, Any]) -> float:
    """Compute severity_numeric matching training per-log-type semantics.

    Training uses domain-specific binary indicators (0/1), NOT text log levels:
      syslog:  admin-account targeting (username in admin set) → 0/1
      windows: EventID risk tier → 0/1/2
      cloud:   has error code → 0/1
      web:     URL has suspicious patterns → 0/1
      email:   urgency/financial keywords → 0/1
      ad:      security-relevant component → 0/1
      dns/firewall/netflow/ids: always 0
    """
    if log_type_str == "syslog":
        user = str(event.get("user", event.get("username", ""))).lower()
        return 1.0 if user in _ADMIN_USERNAMES else 0.0

    if log_type_str == "windows":
        eid = event.get("windows_event_id") or event.get("EventID")
        if eid is not None:
            try:
                eid_int = int(eid)
                if eid_int in _HIGH_RISK_EIDS:
                    return 2.0
                if eid_int in _MED_RISK_EIDS:
                    return 1.0
            except (ValueError, TypeError):
                pass
        return 0.0

    if log_type_str == "cloud":
        error = event.get("errorCode", event.get("errorMessage", ""))
        return 1.0 if error else 0.0

    if log_type_str == "web":
        url = str(event.get("url", event.get("request_uri", event.get("path", ""))))
        if SQL_KEYWORDS.search(url) or XSS_PATTERNS.search(url) or TRAVERSAL_PATTERNS.search(url):
            return 1.0
        return 0.0

    if log_type_str == "email":
        subject = str(event.get("subject", ""))
        body = str(event.get("body", event.get("email_body", "")))
        combined = subject + " " + body
        if URGENCY_KEYWORDS.search(combined) or FINANCIAL_KEYWORDS.search(combined):
            return 1.0
        return 0.0

    if log_type_str == "ad":
        comp = str(event.get("Component", event.get("component", ""))).lower().strip()
        return 1.0 if comp in _SEC_COMPONENTS else 0.0

    # dns, firewall, netflow, ids → 0
    return 0.0


SOURCE_TYPE_ALIAS = {
    "windows_event": "windows",
    "cloudtrail": "cloud",
}


def _detect_log_type(event: Dict[str, Any], topic: str) -> str:
    """Detect the log type from event fields and topic."""
    lt = event.get("log_type", "")
    if lt and str(lt).lower() in LOG_TYPE_MAP:
        return str(lt).lower()

    # Trust explicit source_type from the producer
    st = str(event.get("source_type", "")).lower()
    if st in LOG_TYPE_MAP:
        return st
    if st in SOURCE_TYPE_ALIAS:
        return SOURCE_TYPE_ALIAS[st]

    if event.get("eventSource") or event.get("eventName") or event.get("awsRegion"):
        return "cloud"
    if event.get("dns_query_name") or event.get("query_name") or event.get("domain") or event.get("dns_query"):
        return "dns"
    if event.get("subject") or event.get("email_from") or event.get("email_to"):
        return "email"

    url = event.get("url", event.get("request_uri", event.get("path", "")))
    if url and ("http" in str(url).lower() or "/" in str(url)):
        http_method = event.get("http_method", event.get("method", ""))
        if http_method:
            return "web"

    if event.get("signature") or event.get("alert_signature"):
        return "ids"

    eid = event.get("windows_event_id") or event.get("EventID")
    if eid is not None:
        return "windows"
    if event.get("auth_type") or event.get("AuthenticationPackageName"):
        return "ad"

    if topic == "network-events":
        return "netflow"
    if event.get("src_ip") and event.get("dst_ip"):
        if event.get("bytes_sent") or event.get("bytes_received") or event.get("src_bytes"):
            return "firewall"

    if topic in ("raw-logs", "security-events", "process-events"):
        return "syslog"

    return TOPIC_LOG_TYPE_MAP.get(topic, "syslog")


# ── Per-entity aggregate tracker ─────────────────────────────────────────────

class _EntityTracker:
    """In-memory per-entity aggregate statistics for auth features.

    Tracks fail_count, total_events, and unique targets per entity (src_ip or
    user). Computes fail_rate, unique_targets, event_frequency to match
    training's compute_auth_aggregates() output.
    """

    __slots__ = ("_entities", "_max_entities")

    def __init__(self, max_entities: int = 50000):
        self._entities: Dict[str, List] = {}  # key -> [total, fails, targets_set]
        self._max_entities = max_entities

    def update(self, entity_key: str, is_fail: float, target: str):
        """Record one event for entity_key."""
        rec = self._entities.get(entity_key)
        if rec is None:
            if len(self._entities) >= self._max_entities:
                # Evict oldest half to prevent unbounded memory growth
                keys = list(self._entities.keys())
                for k in keys[: len(keys) // 2]:
                    del self._entities[k]
            rec = [0, 0, set()]
            self._entities[entity_key] = rec
        rec[0] += 1
        if is_fail > 0.5:
            rec[1] += 1
        if target:
            rec[2].add(target)

    def get_aggregates(self, entity_key: str):
        """Return (fail_rate, unique_targets, event_frequency)."""
        rec = self._entities.get(entity_key)
        if rec is None or rec[0] == 0:
            return 0.0, 0.0, 0.0
        total, fails, targets = rec
        fail_rate = fails / total
        unique_targets = math.log10(1 + len(targets))
        event_frequency = math.log10(1 + total)
        return fail_rate, unique_targets, event_frequency


# ── Main Feature Extractor ──────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extracts the 60-feature vector from CLIF pipeline events.

    All features are stateless and deterministic per-event.
    Inactive layers are zero-filled (the model learned this pattern).
    """

    def __init__(self):
        self._entity_tracker = _EntityTracker()

    @property
    def feature_names(self) -> List[str]:
        return FEATURE_NAMES

    def extract(
        self,
        event: Dict[str, Any],
        topic: str,
    ) -> Dict[str, Any]:
        """
        Extract 60 features from a single event.

        Returns:
            Dict with 60 feature values + metadata keys prefixed with '_'.
        """
        log_type_str = _detect_log_type(event, topic)
        log_type_num = float(LOG_TYPE_MAP.get(log_type_str, 0))

        # ── Layer 1: Shared Core (9 features) ───────────────────────
        ts = _parse_timestamp(event.get("timestamp"))
        hour = float(ts.hour)
        dow = float(ts.weekday())

        severity_numeric = _compute_severity(log_type_str, event)

        message_body = str(
            event.get("message_body", event.get("message", event.get("description", "")))
        )
        msg_len = len(message_body) if message_body else 0

        features = {
            "hour_sin": math.sin(2.0 * math.pi * hour / 24.0),
            "hour_cos": math.cos(2.0 * math.pi * hour / 24.0),
            "dow_sin": math.sin(2.0 * math.pi * dow / 7.0),
            "dow_cos": math.cos(2.0 * math.pi * dow / 7.0),
            "is_off_hours": 1.0 if (hour < 6 or hour >= 22 or dow >= 5) else 0.0,
            "log_type": log_type_num,
            "severity_numeric": severity_numeric,
            "message_length_log": math.log10(1.0 + msg_len),
            "message_entropy": _shannon_entropy(message_body),
        }

        # ── Layer 2: Network (15 features) ──────────────────────────
        if log_type_str in ("firewall", "netflow", "ids"):
            src_bytes = min(_safe_float(event.get("bytes_sent", event.get("src_bytes", 0))), 1e9)
            dst_bytes = min(_safe_float(event.get("bytes_received", event.get("dst_bytes", event.get("dbytes", 0)))), 1e9)
            src_pkts = _safe_float(event.get("src_packets", event.get("spkts", 0)))
            dst_pkts = _safe_float(event.get("dst_packets", event.get("dpkts", 0)))
            dur_ms = _safe_float(event.get("duration", event.get("dur", event.get("flow_duration", 0))))
            dst_port = _safe_float(event.get("dst_port", event.get("dsport", 0)))
            proto_raw = str(event.get("protocol", event.get("proto", "tcp"))).lower()
            proto_num = float(PROTOCOL_MAP.get(proto_raw, 6))
            total_bytes = src_bytes + dst_bytes
            total_pkts = src_pkts + dst_pkts

            features.update({
                "dst_port_bin": float(_port_bin(dst_port)),
                "protocol_numeric": proto_num,
                "total_bytes_log": math.log10(1.0 + total_bytes),
                "byte_ratio": src_bytes / (total_bytes + 1e-10),
                "total_packets_log": math.log10(1.0 + total_pkts),
                "packet_ratio": src_pkts / (total_pkts + 1e-10),
                "flow_duration_log": math.log10(1.0 + dur_ms),
                "avg_pkt_size": total_bytes / (total_pkts + 1),
                "pkt_size_variance": _safe_float(event.get("pkt_size_variance", 0)),
                "iat_mean": _safe_float(event.get("iat_mean", event.get("sintpkt", 0))),
                "iat_stddev": _safe_float(event.get("iat_stddev", event.get("sjit", 0))),
                "tcp_syn_flag": _safe_float(event.get("tcp_syn_flag", event.get("syn_flag", 0))),
                "tcp_rst_flag": _safe_float(event.get("tcp_rst_flag", event.get("rst_flag", 0))),
                "tcp_fin_flag": _safe_float(event.get("tcp_fin_flag", event.get("fin_flag", 0))),
                "retransmit_ratio": _safe_float(event.get("retransmit_ratio", 0)),
            })
        else:
            for name in FEATURE_NAMES[9:24]:
                features[name] = 0.0

        # ── Layer 3: Authentication (8 features) ────────────────────
        if log_type_str in ("syslog", "windows", "ad"):
            auth_raw = str(event.get("auth_type", event.get("AuthenticationPackageName", "?"))).lower()
            auth_encoded = float(AUTH_TYPE_MAP.get(auth_raw, 4))

            status_raw = event.get("status", event.get("Status", ""))
            is_fail = 1.0 if str(status_raw).lower() in (
                "fail", "failure", "failed", "0xc000006d", "0xc0000064",
                "error", "denied",
            ) else 0.0
            # Fallback: parse failure indicators from message if status field missing
            if is_fail == 0.0 and not status_raw:
                msg_lower = str(event.get("message_body",
                                event.get("message",
                                event.get("description", "")))).lower()
                if any(kw in msg_lower for kw in (
                    "failed password", "authentication failure",
                    "invalid user", "failed login", "break-in attempt",
                    "access denied", "permission denied",
                )):
                    is_fail = 1.0

            is_admin = 0.0
            eid = event.get("windows_event_id") or event.get("EventID")
            if eid is not None:
                try:
                    if int(eid) in (4672, 4720, 4728, 4732, 4756, 7045, 1102):
                        is_admin = 1.0
                except (ValueError, TypeError):
                    pass
            user = str(event.get("user", event.get("username",
                       event.get("windows_target_user", "")))).lower()
            if "admin" in user or "root" in user:
                is_admin = 1.0

            src = event.get("src_ip", event.get("src_computer", event.get("ip_address", event.get("sourceIPAddress", ""))))
            dst = event.get("dst_ip", event.get("dst_computer", event.get("hostname", "")))
            src_dst_match = 1.0 if (src and dst and str(src) == str(dst)) else 0.0

            logon_type = event.get("windows_logon_type", event.get("LogonType"))
            is_remote = 0.0
            if logon_type is not None:
                try:
                    if int(logon_type) in (3, 10):
                        is_remote = 1.0
                except (ValueError, TypeError):
                    pass
            elif src and dst and str(src) != str(dst):
                is_remote = 1.0

            # Aggregate features via entity tracker
            entity_src = str(src) if src else user
            target_dst = str(dst) if dst else ""
            self._entity_tracker.update(entity_src, is_fail, target_dst)
            fail_rate, unique_targets, event_frequency = \
                self._entity_tracker.get_aggregates(entity_src)

            features.update({
                "auth_type_encoded": auth_encoded,
                "status_is_fail": is_fail,
                "is_admin": is_admin,
                "src_dst_match": src_dst_match,
                "is_remote": is_remote,
                "fail_rate": fail_rate,
                "unique_targets": unique_targets,
                "event_frequency": event_frequency,
            })
        else:
            for name in FEATURE_NAMES[24:32]:
                features[name] = 0.0

        # ── Layer 4: DNS (8 features) ───────────────────────────────
        if log_type_str == "dns":
            domain = str(event.get("dns_query_name", event.get("query_name", event.get("domain", event.get("dns_query", "")))))
            if domain:
                parts = domain.split(".")
                tld = parts[-1].lower() if parts else ""
                total_chars = max(len(domain), 1)
                digit_count = sum(1 for c in domain if c.isdigit())
                features.update({
                    "domain_length": float(len(domain)),
                    "domain_entropy": _shannon_entropy(domain),
                    "subdomain_depth": float(domain.count(".")),
                    "digit_ratio": digit_count / total_chars,
                    "max_consonant_run": float(_max_consonant_run(domain)),
                    "bigram_frequency": _bigram_frequency_score(domain),
                    "has_hex_pattern": 1.0 if _HEX_RE.search(domain) else 0.0,
                    "tld_risk": TLD_RISK.get(tld, 0.3),
                })
            else:
                for name in FEATURE_NAMES[32:40]:
                    features[name] = 0.0
        else:
            for name in FEATURE_NAMES[32:40]:
                features[name] = 0.0

        # ── Layer 5: Web/HTTP (7 features) ──────────────────────────
        if log_type_str == "web":
            url = str(event.get("url", event.get("request_uri", event.get("path", ""))))
            method = str(event.get("http_method", event.get("method", "get"))).lower()
            query_params = 0
            if "?" in url:
                query_str = url.split("?", 1)[1]
                query_params = query_str.count("&") + 1 if query_str else 0

            features.update({
                "url_length": float(len(url)),
                "url_entropy": _shannon_entropy(url),
                "query_param_count": float(query_params),
                "has_sql_pattern": 1.0 if SQL_KEYWORDS.search(url) else 0.0,
                "has_xss_pattern": 1.0 if XSS_PATTERNS.search(url) else 0.0,
                "has_traversal": 1.0 if TRAVERSAL_PATTERNS.search(url) else 0.0,
                "http_method": float(HTTP_METHOD_MAP.get(method, 0)),
            })
        else:
            for name in FEATURE_NAMES[40:47]:
                features[name] = 0.0

        # ── Layer 6: Email (7 features) ─────────────────────────────
        if log_type_str == "email":
            subject = str(event.get("subject", ""))
            body = str(event.get("body", event.get("email_body", "")))
            combined_text = subject + " " + body
            features.update({
                "subject_length": float(len(subject)),
                "body_length_log": math.log10(1.0 + len(body)),
                "subject_entropy": _shannon_entropy(subject),
                "url_count": float(_count_urls(combined_text)),
                "caps_ratio": _caps_ratio(subject),
                "has_urgency": 1.0 if URGENCY_KEYWORDS.search(combined_text) else 0.0,
                "has_financial": 1.0 if FINANCIAL_KEYWORDS.search(combined_text) else 0.0,
            })
        else:
            for name in FEATURE_NAMES[47:54]:
                features[name] = 0.0

        # ── Layer 7: Cloud/API (6 features) ─────────────────────────
        if log_type_str == "cloud":
            event_name = str(event.get("eventName", ""))
            event_source = str(event.get("eventSource", ""))
            read_only = event.get("readOnly", "")
            error_code = event.get("errorCode", event.get("errorMessage", ""))
            user_identity = event.get("userIdentity", {})
            identity_type = str(
                user_identity.get("type", "") if isinstance(user_identity, dict)
                else event.get("identity_type", "")
            )

            evt_idx = CT_EVENT_NAME_TO_IDX.get(event_name, float(len(CT_EVENT_NAMES)))

            id_type_map = {
                "Root": 0, "IAMUser": 1, "AssumedRole": 2,
                "FederatedUser": 3, "AWSAccount": 4, "AWSService": 5,
            }
            id_encoded = float(id_type_map.get(identity_type, -1))

            is_ro = 1.0 if event_name.startswith(("Describe", "Get", "List")) else 0.0

            features.update({
                "event_name_encoded": evt_idx,
                "is_sensitive_service": 1.0 if event_source in SENSITIVE_SERVICES else 0.0,
                "is_read_only": is_ro,
                "has_error": 1.0 if error_code else 0.0,
                "identity_type_encoded": id_encoded,
                "is_root": 1.0 if identity_type == "Root" else 0.0,
            })
        else:
            for name in FEATURE_NAMES[54:60]:
                features[name] = 0.0

        # ── Attach metadata (not fed to models) ────────────────────
        hostname = str(event.get("hostname", event.get("host", "unknown")))
        user_val = str(event.get("user", event.get("windows_target_user",
                       event.get("k8s_user", event.get("cloud_user", "")))))
        entity_key = f"{hostname}::{user_val}" if user_val else hostname

        features["_log_type"] = log_type_str
        features["_hostname"] = hostname
        features["_user"] = user_val
        features["_entity_key"] = entity_key
        features["_topic"] = topic
        features["_source_type"] = str(event.get("source_type", event.get("source", log_type_str)))

        # Pass through raw event metadata for rule-based detection
        eid_raw = event.get("windows_event_id") or event.get("EventID")
        features["_event_id"] = str(eid_raw) if eid_raw is not None else ""
        features["_message_body"] = message_body[:1000] if message_body else ""

        return features

    def extract_batch(
        self, events: List[Dict[str, Any]], topic: str,
    ) -> List[Dict[str, Any]]:
        """Extract features from a batch of events."""
        return [self.extract(e, topic) for e in events]

    def to_numpy(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert a feature dict to numpy array in canonical order."""
        return np.array(
            [features[name] for name in FEATURE_NAMES], dtype=np.float32,
        )

    def batch_to_numpy(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        """Convert a list of feature dicts to a 2D numpy array (N, 60)."""
        arr = np.array(
            [[f[name] for name in FEATURE_NAMES] for f in features_list],
            dtype=np.float32,
        )
        return np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)

    def get_stats(self) -> Dict:
        return {"feature_count": NUM_FEATURES}
