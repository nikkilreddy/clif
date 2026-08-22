"""
CLIF Triage Agent v8 — Score Fusion & Routing
================================================
Applies post-model adjustments to the raw ensemble scores:
  1. Kill-chain progression boost  (up to 1.5×)
  2. Cross-host correlation boost  (1.2×)
  3. IOC context-aware boost       (+0.05 to +0.20)
  4. Disagreement escalation       (force to 0.95)

Then routes each scored event to the appropriate topic:
  - adjusted ≥ 0.90  →  ESCALATE (anomaly-alerts + hunter-tasks)
  - adjusted ≥ 0.40  →  MONITOR  (triage-scores, dashboard visible)
  - adjusted < 0.40  →  DISCARD  (triage-scores, audit only)

v8 changes:
  - Vectorized numpy operations (no row-by-row loops)
  - Lower anomalous threshold (0.90 vs 0.95) — confident with better features
  - Kill-chain and cross-host boosts are NEW
  - IOC boost is context-aware (scaled by combined score)
  - Drift monitoring via PSI (Population Stability Index)
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np

import config

logger = logging.getLogger("clif.triage.fusion")

# ── Action codes (from config) ──────────────────────────────────────────────

LABEL_DISCARD = "discard"
LABEL_MONITOR = "monitor"
LABEL_ESCALATE = "escalate"


# ── Baseline Tracker ────────────────────────────────────────────────────────

class BaselineTracker:
    """
    Tracks running mean/std of scores per entity (host or user)
    to compute z-score deviation from baseline.
    Uses Welford's online algorithm — O(1) per update.
    """

    __slots__ = ("_lock", "_entities", "_max_entities")

    def __init__(self, max_entities: int = 200_000):
        self._lock = threading.Lock()
        self._entities: Dict[str, Tuple[int, float, float, float]] = {}
        # key → (count, mean, M2, last_ts)
        self._max_entities = max_entities

    def update_and_get_z(self, entity: str, score: float, timestamp: float) -> float:
        """Update baseline and return z-score deviation."""
        with self._lock:
            if entity in self._entities:
                count, mean, m2, _ = self._entities[entity]
            else:
                if len(self._entities) >= self._max_entities:
                    # Evict oldest entity instead of silently dropping
                    oldest_key = min(self._entities, key=lambda k: self._entities[k][3])
                    del self._entities[oldest_key]
                count, mean, m2 = 0, 0.0, 0.0

            count += 1
            delta = score - mean
            mean += delta / count
            delta2 = score - mean
            m2 += delta * delta2
            self._entities[entity] = (count, mean, m2, timestamp)

            if count < 10:
                return 0.0

            variance = m2 / count
            std = max(variance ** 0.5, 1e-6)
            return (score - mean) / std

    def cleanup(self, now: float, max_age_sec: float = 86400.0) -> int:
        cutoff = now - max_age_sec
        with self._lock:
            stale = [k for k, v in self._entities.items() if v[3] < cutoff]
            for k in stale:
                del self._entities[k]
            return len(stale)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {"tracked_entities": len(self._entities)}


# ── Drift Monitor (PSI) ────────────────────────────────────────────────────

class DriftMonitor:
    """
    Population Stability Index (PSI) for score distribution drift.
    Compares current batch distribution against a reference window.
    """

    def __init__(
        self,
        n_bins: int = 10,
        window_size: int = 5000,
        psi_warning: float = 0.1,
        psi_critical: float = 0.25,
    ):
        self._n_bins = n_bins
        self._window_size = window_size
        self._psi_warning = psi_warning
        self._psi_critical = psi_critical
        self._reference: Optional[np.ndarray] = None
        self._current_window: Deque[float] = deque(maxlen=window_size)
        self._batches_seen = 0
        self._lock = threading.Lock()

    def set_reference(self, scores: np.ndarray) -> None:
        """Set reference distribution from training or initial scores."""
        self._reference = self._compute_histogram(scores)

    def add_batch(self, scores: np.ndarray) -> Optional[Dict[str, Any]]:
        """Add scores and periodically compute PSI."""
        with self._lock:
            self._current_window.extend(scores.tolist())
            self._batches_seen += 1

            if self._batches_seen % config.DRIFT_INTERVAL_BATCHES != 0:
                return None
            if self._reference is None:
                self._reference = self._compute_histogram(
                    np.array(list(self._current_window))
                )
                return None

            current_hist = self._compute_histogram(
                np.array(list(self._current_window))
            )
            psi = self._compute_psi(self._reference, current_hist)

            level = "ok"
            if psi >= self._psi_critical:
                level = "critical"
                logger.warning("DRIFT CRITICAL: PSI=%.4f (threshold=%.4f)", psi, self._psi_critical)
            elif psi >= self._psi_warning:
                level = "warning"
                logger.info("DRIFT WARNING: PSI=%.4f (threshold=%.4f)", psi, self._psi_warning)

            return {
                "psi": float(psi),
                "level": level,
                "batches_seen": self._batches_seen,
                "window_size": len(self._current_window),
            }

    def _compute_histogram(self, scores: np.ndarray) -> np.ndarray:
        bins = np.linspace(0, 1, self._n_bins + 1)
        hist, _ = np.histogram(scores, bins=bins)
        # Add small epsilon to avoid division by zero
        hist = hist.astype(np.float64) + 1e-6
        return hist / hist.sum()

    @staticmethod
    def _compute_psi(reference: np.ndarray, current: np.ndarray) -> float:
        return float(np.sum((current - reference) * np.log(current / reference)))


# ── Message-based attack pattern detector ───────────────────────────────────
# When events arrive without structured fields (e.g., raw syslog over TCP),
# the LGBM model has insufficient signal.  This detector scans message text
# for known attack indicators and returns a score floor + reason.

_MSG_CRITICAL_PATTERNS = [
    ("privilege escalation", "priv_esc"),
    ("account locked after", "account_lockout"),
    ("multiple failed login attempts", "multi_fail_login"),
]

_MSG_HIGH_PATTERNS = [
    ("failed password for", "ssh_fail_pwd"),
    ("invalid user", "ssh_invalid_user"),
    ("authentication failure", "auth_failure"),
    ("break-in attempt", "breakin_attempt"),
    ("firewall deny", "fw_deny"),
    ("access denied", "access_denied"),
    ("permission denied", "perm_denied"),
]

_MSG_MEDIUM_PATTERNS = [
    ("anomalous login", "anomalous_login"),
    ("tls certificate mismatch", "tls_mismatch"),
    ("geo=unexpected", "geo_anomaly"),
    ("/tmp/suspicious", "suspicious_path"),
    ("/dev/shm/.", "hidden_shm_proc"),
    ("reverse shell", "reverse_shell"),
    ("new ssh key added", "ssh_key_added"),
]


def _check_message_attack(msg_lower: str) -> tuple:
    """Check message text for attack patterns.

    Returns (score_floor, reason) or (0.0, "") if no match.
    Three tiers: critical (0.92), high (0.88), medium (0.55).
    """
    for pattern, label in _MSG_CRITICAL_PATTERNS:
        if pattern in msg_lower:
            return 0.92, label
    for pattern, label in _MSG_HIGH_PATTERNS:
        if pattern in msg_lower:
            return 0.88, label
    for pattern, label in _MSG_MEDIUM_PATTERNS:
        if pattern in msg_lower:
            return 0.55, label
    return 0.0, ""


# ── Sysmon attack-content detector ──────────────────────────────────────────

# Sysmon EventIDs that record attack-relevant activity
_SYSMON_PROCESS_CREATE = {"1"}
_SYSMON_NETWORK_CONNECT = {"3"}
_SYSMON_PROCESS_ACCESS = {"10"}
_SYSMON_FILE_CREATE = {"11"}
_SYSMON_REGISTRY = {"12", "13", "14"}
_SYSMON_IMAGE_LOAD = {"7"}
_SYSMON_ALL = _SYSMON_PROCESS_CREATE | _SYSMON_NETWORK_CONNECT | \
    _SYSMON_PROCESS_ACCESS | _SYSMON_FILE_CREATE | _SYSMON_REGISTRY | \
    _SYSMON_IMAGE_LOAD | {"5", "8", "9", "15", "17", "18", "22", "23", "25"}

# Attack indicators: process execution
_SUSPICIOUS_EXECUTABLES = {
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "cmd.exe", "certutil", "certutil.exe",
    "mshta", "mshta.exe", "regsvr32", "regsvr32.exe",
    "rundll32", "rundll32.exe", "wmic", "wmic.exe",
    "cscript", "cscript.exe", "wscript", "wscript.exe",
    "bitsadmin", "bitsadmin.exe", "msbuild", "msbuild.exe",
    "installutil", "installutil.exe",
    "reg.exe", "whoami", "whoami.exe",
    "net.exe", "net1.exe",
    "sc.exe", "schtasks", "schtasks.exe",
    "taskkill.exe", "nltest.exe", "ntdsutil.exe",
}

# Attack indicators: command-line patterns
_SUSPICIOUS_CMD_PATTERNS = [
    "-enc ", "-encodedcommand", "-nop ", "-noprofile",
    "-windowstyle hidden", "-ep bypass", "-executionpolicy bypass",
    "invoke-expression", "invoke-command", "iex(",
    "downloadstring", "downloadfile", "net user ",
    "net group ", "net localgroup ", "mimikatz",
    "sekurlsa", "lsadump", "procdump", "comsvcs.dll",
    "minidump", "whoami", "systeminfo", "ipconfig /all",
    "tasklist /v", "schtasks /create", "at.exe",
    "reg add", "reg save", "reg export",
    "vssadmin", "wevtutil cl", "bcdedit",
    "ntdsutil", "dsquery", "csvde", "ldifde",
    "psexec", "wmiexec", "smbexec", "atexec",
]

# Attack indicators: credential access targets
_CREDENTIAL_TARGETS = [
    "lsass.exe", "lsass", "security account manager",
    "sam", "ntds.dit", "credentials",
]

# Attack indicators: persistence locations
_PERSISTENCE_INDICATORS = [
    "\\run\\", "\\runonce\\", "\\services\\",
    "\\currentversion\\run", "\\startup\\",
    "\\winlogon\\", "\\userinit", "\\shell\\",
    "\\scheduled tasks\\", "\\appinit_dlls",
]

# Attack indicators: suspicious parent→child relationships
_SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "wmiprvse.exe", "svchost.exe", "services.exe",
}


# Sensitive file paths for credential access detection
_SENSITIVE_FILE_PATHS = [
    "login data", "ntds.dit", "\\config\\sam", "\\config\\security",
    ".kdbx", "id_rsa", "web data", "cookies",
    "credential", "password", "\\config\\system",
]

# Known-safe BITS download domains (not attack indicators)
_BITS_SAFE_DOMAINS = [
    "microsoft.com", "windowsupdate.com", "windows.net",
    "google.com", "googleapis.com", "gstatic.com",
    "mozilla.org", "mozilla.com", "apple.com",
]


def _check_sysmon_attack(
    event_id: str, msg: str, msg_entropy: float, msg_len_log: float
) -> tuple:
    """Check if a Sysmon event contains attack indicators.

    Returns (triggered: bool, reason: str).
    """
    eid = event_id.strip()
    if eid not in _SYSMON_ALL:
        return False, ""

    # EventID 1: Process Create — check for suspicious executables/commands
    if eid in _SYSMON_PROCESS_CREATE:
        for exe in _SUSPICIOUS_EXECUTABLES:
            if exe in msg:
                for pat in _SUSPICIOUS_CMD_PATTERNS:
                    if pat in msg:
                        return True, f"sysmon_proc_create(eid=1,exe={exe},pat)"
                if exe not in ("cmd.exe", "powershell", "powershell.exe"):
                    return True, f"sysmon_proc_create(eid=1,exe={exe})"
                if msg_entropy > 4.5 and msg_len_log > 2.5:
                    return True, f"sysmon_encoded_cmd(eid=1,ent={msg_entropy:.1f})"
        # Processes running from temp/appdata directories
        if "\\temp\\" in msg or "\\tmp\\" in msg:
            if "image=" in msg:
                return True, "sysmon_temp_exec(eid=1)"
        if "appdata\\local\\temp" in msg and "image=" in msg:
            return True, "sysmon_appdata_temp_exec(eid=1)"
        # Suspicious parent processes spawning children
        for parent in _SUSPICIOUS_PARENTS:
            if f"parentimage" in msg and parent in msg:
                return True, f"sysmon_parent_spawn(eid=1,parent={parent})"
        return False, ""

    # EventID 8: CreateRemoteThread — almost always injection
    if eid == "8":
        return True, "sysmon_remote_thread(eid=8)"

    # EventID 10: Process Access — credential dumping detection
    if eid in _SYSMON_PROCESS_ACCESS:
        for target in _CREDENTIAL_TARGETS:
            if target in msg:
                return True, f"sysmon_cred_access(eid=10,target={target})"
        return False, ""

    # EventID 3: Network Connection — suspicious outbound connections
    if eid in _SYSMON_NETWORK_CONNECT:
        for exe in _SUSPICIOUS_EXECUTABLES:
            if exe in msg:
                return True, f"sysmon_net_connect(eid=3,exe={exe})"
        # Network from temp directory processes
        if "\\temp\\" in msg or "\\appdata\\" in msg:
            return True, "sysmon_temp_net(eid=3)"
        return False, ""

    # EventID 11: File Create — suspicious file locations
    if eid in _SYSMON_FILE_CREATE:
        for indicator in _PERSISTENCE_INDICATORS:
            if indicator in msg:
                return True, f"sysmon_file_persist(eid=11)"
        if ("\\temp\\" in msg or "\\tmp\\" in msg or "\\appdata\\" in msg):
            if msg_entropy > 4.0:
                return True, f"sysmon_temp_file(eid=11,ent={msg_entropy:.1f})"
        return False, ""

    # EventID 12/13/14: Registry — persistence/security modifications
    if eid in _SYSMON_REGISTRY:
        for indicator in _PERSISTENCE_INDICATORS:
            if indicator in msg:
                return True, f"sysmon_reg_persist(eid={eid})"
        return False, ""

    # EventID 7: Image Loaded — DLL side-loading or suspicious loads
    if eid in _SYSMON_IMAGE_LOAD:
        if "unsigned" in msg or "expired" in msg:
            return True, "sysmon_unsigned_dll(eid=7)"
        if "\\temp\\" in msg or "\\appdata\\" in msg or "\\downloads\\" in msg:
            return True, "sysmon_suspicious_dll(eid=7)"
        # DLL loads by suspicious processes
        for exe in _SUSPICIOUS_EXECUTABLES:
            if exe in msg:
                return True, f"sysmon_dll_load_by(eid=7,exe={exe})"
        return False, ""

    # EventID 17/18: Named Pipe — C2 and lateral movement indicator
    if eid in ("17", "18"):
        return True, f"sysmon_named_pipe(eid={eid})"

    # EventID 19/20/21: WMI Event — persistence mechanism
    if eid in ("19", "20", "21"):
        return True, f"sysmon_wmi_event(eid={eid})"

    # EventID 22: DNS Query from Sysmon — check for suspicious processes
    if eid == "22":
        for exe in _SUSPICIOUS_EXECUTABLES:
            if exe in msg:
                return True, f"sysmon_dns_query(eid=22,exe={exe})"
        return False, ""

    # Other Sysmon events: flag high-entropy content as suspicious
    if msg_entropy > 5.0 and msg_len_log > 2.5:
        return True, f"sysmon_high_entropy(eid={eid},ent={msg_entropy:.1f})"

    # EventID 5: Process Terminated — only suspicious from temp dirs
    if eid == "5":
        if "\\temp\\" in msg or "\\appdata\\local\\temp" in msg:
            return True, "sysmon_temp_proc_exit(eid=5)"

    return False, ""


# ── Score Fusion Engine ─────────────────────────────────────────────────────

class ScoreFusion:
    """
    Applies post-model adjustments and routes scored events.

    Process:
      1. Start with combined score = lgbm score
      2. Apply kill-chain boost (up to 1.5×)
      3. Apply cross-host correlation boost (1.2×)
      4. Apply IOC context-aware boost (+0.05 to +0.20)
      5. Route to appropriate topic/action

    All operations are vectorized over the batch.
    """

    def __init__(self):
        self._host_baseline = BaselineTracker()
        self._user_baseline = BaselineTracker()
        self._drift_monitor: Optional[DriftMonitor] = None


        if config.DRIFT_ENABLED:
            self._drift_monitor = DriftMonitor(
                n_bins=config.DRIFT_PSI_BINS,
                window_size=config.DRIFT_WINDOW_SIZE,
                psi_warning=config.DRIFT_PSI_WARNING,
                psi_critical=config.DRIFT_PSI_CRITICAL,
            )

        self._total_events = 0
        self._total_escalated = 0
        self._total_monitored = 0
        self._total_discarded = 0

    def fuse_batch(
        self,
        features_list: List[Dict[str, Any]],
        model_scores: Dict[str, np.ndarray],
    ) -> List[Dict[str, Any]]:
        """
        Fuse model scores with contextual adjustments for a batch.

        Args:
            features_list: list of N feature dicts (from FeatureExtractor)
            model_scores: dict with "lgbm_scores", "combined"

        Returns:
            list of N result dicts, each with:
                "final_score", "label", "lgbm_score",
                "adjustments" (dict of applied boosts), metadata
        """
        n = len(features_list)
        lgbm = model_scores["lgbm_scores"]
        combined = model_scores["combined"].copy()

        # ── Vectorized boost extraction ─────────────────────────────────
        kc_stages = np.array([f.get("kill_chain_stage", 0.0) for f in features_list])
        xhost_corrs = np.array([f.get("cross_host_correlation", 0.0) for f in features_list])
        has_iocs = np.array([f.get("has_known_ioc", 0.0) for f in features_list])

        # Per-event adjustment log (still needs list for string tracking)
        adjustments_log = [[] for _ in range(n)]

        # ── 1. Kill-chain boost (vectorized) ────────────────────────────
        kc_mask = kc_stages >= 2
        kc_boost = np.where(
            kc_mask,
            np.minimum(1.0 + kc_stages * config.KILL_CHAIN_BOOST_PER_STAGE,
                       config.KILL_CHAIN_BOOST_MAX),
            1.0,
        )
        combined *= kc_boost
        for i in np.where(kc_mask)[0]:
            adjustments_log[i].append(
                f"kc_boost:{kc_boost[i]:.2f}(stage={int(kc_stages[i])})"
            )

        # ── 2. Cross-host correlation boost (vectorized) ────────────────
        xhost_mask = xhost_corrs >= config.CROSS_HOST_MIN_HOSTS
        combined = np.where(xhost_mask, combined * config.CROSS_HOST_BOOST, combined)
        for i in np.where(xhost_mask)[0]:
            adjustments_log[i].append(
                f"xhost_boost:{config.CROSS_HOST_BOOST:.2f}(hosts={xhost_corrs[i]:.0f})"
            )

        # ── 3. IOC context-aware boost (vectorized) ─────────────────────
        ioc_mask = has_iocs > 0.5
        ioc_boost = config.IOC_BOOST_BASE + config.IOC_BOOST_SCALE * combined
        combined = np.where(ioc_mask, combined + ioc_boost, combined)
        for i in np.where(ioc_mask)[0]:
            adjustments_log[i].append(f"ioc_boost:{ioc_boost[i]:.3f}")

        # ── 4. (Disagreement escalation removed in v8.3 — AE removed) ───

        # ── 5. SSH brute force rule-based detection ─────────────────────
        # The LightGBM model was trained exclusively on SSH "invalid_user"
        # attacks (non-admin usernames).  Admin-targeting brute force
        # (root, admin) produces features the model scores as benign.
        # This rule catches those cases using deterministic indicators:
        #   - source_type is syslog (SSH logs)
        #   - fail_rate >= threshold (sustained authentication failures)
        #   - status_is_fail == 1 (current event IS a failure)
        #   - event_frequency >= threshold (enough events to be meaningful)
        #   - lgbm score is low (model missed it)
        if config.SSH_BRUTE_FORCE_ENABLED:
            ssh_floor = config.SSH_BRUTE_FORCE_SCORE_FLOOR
            min_fail = config.SSH_BRUTE_FORCE_MIN_FAIL_RATE
            min_freq = config.SSH_BRUTE_FORCE_MIN_EVENT_FREQ

            for i in range(n):
                feat = features_list[i]
                src_type = feat.get("_source_type", "")
                log_type = feat.get("_log_type", "")
                if src_type != "syslog" and log_type != "syslog":
                    continue
                fail_rate = feat.get("fail_rate", 0.0)
                status_fail = feat.get("status_is_fail", 0.0)
                event_freq = feat.get("event_frequency", 0.0)

                if (
                    fail_rate >= min_fail
                    and status_fail >= 0.5
                    and event_freq >= min_freq
                    and combined[i] < ssh_floor
                ):
                    adjustments_log[i].append(
                        f"ssh_brute_rule(floor={ssh_floor:.2f},"
                        f"fail_rate={fail_rate:.2f},"
                        f"freq={event_freq:.2f})"
                    )
                    combined[i] = ssh_floor

        # ── 6. Windows attack pattern detection ────────────────────────
        # Two sub-detectors:
        #   A) Security log: high-risk EventIDs (4625, 4697, etc.)
        #   B) Sysmon: attack-indicative content in process creation,
        #      credential access, persistence, etc.
        # The ML model was trained on Security log events and scores
        # Sysmon events ~0.  Rule-based detection catches these.
        if config.WINDOWS_ATTACK_RULE_ENABLED:
            win_floor = config.WINDOWS_ATTACK_RULE_SCORE_FLOOR
            for i in range(n):
                feat = features_list[i]
                if feat.get("_log_type", "") != "windows":
                    continue
                if combined[i] >= win_floor:
                    continue

                severity = feat.get("severity_numeric", 0)
                is_admin_val = feat.get("is_admin", 0)
                is_remote_val = feat.get("is_remote", 0)
                is_fail_val = feat.get("status_is_fail", 0)

                triggered = False
                reason = ""

                # (A) Security log EventID-based detection
                if severity >= 2.0:
                    triggered = True
                    reason = f"high_risk_eid(sev={severity:.0f})"
                elif severity >= 1.0 and is_remote_val > 0.5:
                    triggered = True
                    reason = f"remote_med_risk(sev={severity:.0f})"
                elif is_admin_val > 0.5 and is_remote_val > 0.5:
                    triggered = True
                    reason = "remote_admin"
                elif is_fail_val > 0.5 and severity >= 1.0:
                    triggered = True
                    reason = f"auth_fail(sev={severity:.0f})"

                # (B) Sysmon content-based detection
                if not triggered:
                    event_id = feat.get("_event_id", "")
                    msg = feat.get("_message_body", "").lower()
                    msg_entropy = feat.get("message_entropy", 0)
                    msg_len = feat.get("message_length_log", 0)

                    if event_id and msg:
                        triggered, reason = _check_sysmon_attack(
                            event_id, msg, msg_entropy, msg_len
                        )

                # (C) BITS download to suspicious URLs
                if not triggered:
                    event_id = feat.get("_event_id", "")
                    msg = feat.get("_message_body", "").lower()
                    if event_id in ("59", "60", "61"):
                        if "url=" in msg:
                            safe = any(d in msg for d in _BITS_SAFE_DOMAINS)
                            if not safe:
                                triggered = True
                                reason = "bits_suspicious_url"

                # (D) Security audit: sensitive file access / SMB lateral mvmt
                if not triggered:
                    event_id = feat.get("_event_id", "")
                    msg = feat.get("_message_body", "").lower()
                    if event_id == "4663":
                        for sf in _SENSITIVE_FILE_PATHS:
                            if sf in msg:
                                triggered = True
                                reason = f"sensitive_file({sf})"
                                break
                    # SMB share access: admin/IPC shares used in lateral movement
                    elif event_id == "5145":
                        for share in ("admin$", "c$", "ipc$"):
                            if share in msg:
                                triggered = True
                                reason = f"smb_admin_share({share})"
                                break
                    # Explicit credential logon (pass-the-hash/token)
                    elif event_id == "4648":
                        triggered = True
                        reason = "explicit_credential_logon"
                    # AD modification (persistence/privilege escalation)
                    elif event_id == "5136":
                        triggered = True
                        reason = "ad_modification"
                    # Windows Defender threat detection
                    elif event_id in ("1116", "1117"):
                        triggered = True
                        reason = "defender_alert"

                # (E) Sysmon network connect — broader detection
                # Any Sysmon EID 3 event is an observed network connection;
                # even without a known-bad executable, the presence of
                # EID 3 in attack context is noteworthy.
                if not triggered:
                    event_id = feat.get("_event_id", "")
                    msg = feat.get("_message_body", "").lower()
                    if event_id == "3" and "destinationip" in msg:
                        triggered = True
                        reason = "sysmon_network(eid=3)"

                if triggered:
                    adjustments_log[i].append(
                        f"windows_rule({reason},floor={win_floor:.2f})"
                    )
                    combined[i] = win_floor

        # ── 7. DNS exfiltration pattern detection ──────────────────────
        # DNS tunneling/exfil uses long encoded subdomains that differ
        # from the DGA patterns the ML model was trained on.
        if config.DNS_EXFIL_RULE_ENABLED:
            dns_floor = config.DNS_EXFIL_SCORE_FLOOR
            min_dlen = config.DNS_EXFIL_MIN_DOMAIN_LENGTH
            min_depth = config.DNS_EXFIL_MIN_SUBDOMAIN_DEPTH
            max_bigram = config.DNS_EXFIL_MAX_BIGRAM_FREQ

            for i in range(n):
                feat = features_list[i]
                if feat.get("_log_type", "") != "dns":
                    continue
                if combined[i] >= dns_floor:
                    continue

                domain_len = feat.get("domain_length", 0)
                depth = feat.get("subdomain_depth", 0)
                bigram = feat.get("bigram_frequency", 1.0)
                has_hex = feat.get("has_hex_pattern", 0)

                indicators = 0
                if domain_len >= min_dlen:
                    indicators += 1
                if depth >= min_depth:
                    indicators += 1
                if bigram < max_bigram:
                    indicators += 1
                if has_hex > 0.5:
                    indicators += 1

                if indicators >= 2:
                    adjustments_log[i].append(
                        f"dns_exfil_rule(floor={dns_floor:.2f},"
                        f"len={domain_len:.0f},depth={depth:.0f},"
                        f"bigram={bigram:.3f},hex={has_hex:.0f})"
                    )
                    combined[i] = dns_floor

        # ── 8. Email spam/phishing detection ───────────────────────────
        # The LGBM model gives many benign emails scores in the 0.40-0.55
        # range, causing FPs. Combined with per-type threshold (0.75), the
        # FP rate drops. This rule boosts emails that show clear spam/phish
        # indicators beyond what the model catches:
        #   - High URL count (>= 3) + urgency keywords
        #   - Subject ALL CAPS (caps_ratio > 0.70) + financial keywords
        #   - Very high subject entropy (> 4.5) + multiple URLs
        # Requires >= 2 indicators to trigger.
        if config.EMAIL_SPAM_RULE_ENABLED:
            email_floor = config.EMAIL_SPAM_RULE_SCORE_FLOOR

            for i in range(n):
                feat = features_list[i]
                if feat.get("_log_type", "") != "email":
                    continue
                if combined[i] >= email_floor:
                    continue

                url_count = feat.get("url_count", 0)
                caps_ratio = feat.get("caps_ratio", 0)
                has_urgency = feat.get("has_urgency", 0)
                has_financial = feat.get("has_financial", 0)
                subj_entropy = feat.get("subject_entropy", 0)
                subj_length = feat.get("subject_length", 0)

                indicators = 0
                if url_count >= 3:
                    indicators += 1
                if has_urgency > 0.5 and has_financial > 0.5:
                    indicators += 1
                if caps_ratio > 0.70:
                    indicators += 1
                if subj_entropy > 4.5 and url_count >= 2:
                    indicators += 1
                if subj_length > 80 and has_urgency > 0.5:
                    indicators += 1

                if indicators >= 2:
                    adjustments_log[i].append(
                        f"email_spam_rule(floor={email_floor:.2f},"
                        f"urls={url_count:.0f},caps={caps_ratio:.2f},"
                        f"urg={has_urgency:.0f},fin={has_financial:.0f})"
                    )
                    combined[i] = email_floor

        # ── 9. Web attack pattern detection ────────────────────────────
        # Boost web requests that show clear SQLi, XSS, or traversal
        # patterns in the URL. The LGBM model handles some of these but
        # misses many at the 0.60 per-type threshold. This rule catches
        # requests with multiple attack indicators.
        if config.WEB_ATTACK_RULE_ENABLED:
            web_floor = config.WEB_ATTACK_RULE_SCORE_FLOOR

            for i in range(n):
                feat = features_list[i]
                if feat.get("_log_type", "") != "web":
                    continue
                if combined[i] >= web_floor:
                    continue

                has_sql = feat.get("has_sql_pattern", 0)
                has_xss = feat.get("has_xss_pattern", 0)
                has_traversal = feat.get("has_traversal", 0)
                url_length = feat.get("url_length", 0)
                url_entropy = feat.get("url_entropy", 0)
                query_params = feat.get("query_param_count", 0)

                indicators = 0
                if has_sql > 0.5:
                    indicators += 1
                if has_xss > 0.5:
                    indicators += 1
                if has_traversal > 0.5:
                    indicators += 1
                if url_length > 100 and url_entropy > 4.0:
                    indicators += 1
                if query_params >= 5:
                    indicators += 1

                if indicators >= 1:
                    adjustments_log[i].append(
                        f"web_attack_rule(floor={web_floor:.2f},"
                        f"sql={has_sql:.0f},xss={has_xss:.0f},"
                        f"trav={has_traversal:.0f},len={url_length:.0f})"
                    )
                    combined[i] = web_floor

        # ── 10. Lateral movement detection ─────────────────────────────
        # Credential-based lateral movement: successful remote auth from
        # one entity to many distinct targets.  Requires high unique_targets
        # count (10+ machines) to avoid false positives on normal admins
        # who legitimately access multiple servers.
        if config.LATERAL_MOVEMENT_RULE_ENABLED:
            lat_floor = config.LATERAL_MOVEMENT_SCORE_FLOOR
            min_targets = config.LATERAL_MOVEMENT_MIN_UNIQUE_TARGETS
            min_freq = config.LATERAL_MOVEMENT_MIN_EVENT_FREQ

            for i in range(n):
                feat = features_list[i]
                log_type = feat.get("_log_type", "")
                if log_type not in ("ad", "syslog", "windows"):
                    continue
                if combined[i] >= lat_floor:
                    continue

                is_remote_val = feat.get("is_remote", 0)
                is_fail_val = feat.get("status_is_fail", 0)
                src_dst_match = feat.get("src_dst_match", 0)
                unique_targets = feat.get("unique_targets", 0)
                event_freq = feat.get("event_frequency", 0)

                # Successful remote auth to many distinct targets with
                # sufficient event volume (avoids triggering on sparse data)
                if (is_remote_val > 0.5
                        and is_fail_val < 0.5
                        and src_dst_match < 0.5
                        and unique_targets > min_targets
                        and event_freq > min_freq):
                    adjustments_log[i].append(
                        f"lateral_move_rule(floor={lat_floor:.2f},"
                        f"targets={unique_targets:.2f},"
                        f"freq={event_freq:.2f},"
                        f"remote={is_remote_val:.0f})"
                    )
                    combined[i] = lat_floor

        # ── 11. Message-based attack pattern detection ────────────────
        # When events lack structured fields (log_type, auth_type, status),
        # the LGBM model has insufficient signal.  This rule scans the raw
        # message text for known attack indicators (SSH brute force,
        # firewall blocks, privilege escalation, anomalous logins, etc.)
        # and boosts the score when clear patterns are found.
        # Three tiers: critical (0.92), high (0.88), medium (0.55).
        if config.MESSAGE_PATTERN_RULE_ENABLED:
            for i in range(n):
                feat = features_list[i]
                if combined[i] >= 0.90:
                    continue
                msg = feat.get("_message_body", "")
                if not msg:
                    continue
                msg_lower = msg.lower()
                floor, reason = _check_message_attack(msg_lower)
                if floor > 0 and combined[i] < floor:
                    adjustments_log[i].append(
                        f"msg_pattern_rule({reason},floor={floor:.2f})"
                    )
                    combined[i] = floor

        # Clamp to [0, 1]
        combined = np.clip(combined, 0.0, 1.0)

        # ── Update baselines and compute z-scores ───────────────────────
        now = time.monotonic()
        results = []

        for i in range(n):
            feat = features_list[i]
            score = float(combined[i])
            hostname = feat.get("_hostname", "unknown")
            user = feat.get("_user", "")

            # Update baseline trackers
            host_z = self._host_baseline.update_and_get_z(hostname, score, now)
            user_z = self._user_baseline.update_and_get_z(user, score, now) if user else 0.0

            # Route — per-log-type thresholds
            log_type = feat.get("_log_type", "")
            sus_t, anom_t = config.get_thresholds(log_type)

            if score >= anom_t:
                label = LABEL_ESCALATE
                self._total_escalated += 1
            elif score >= sus_t:
                label = LABEL_MONITOR
                self._total_monitored += 1
            else:
                label = LABEL_DISCARD
                self._total_discarded += 1

            self._total_events += 1

            results.append({
                "final_score": score,
                "label": label,
                "lgbm_score": float(lgbm[i]),
                "ae_score": 0.0,
                "host_baseline_z": host_z,
                "user_baseline_z": user_z,
                "adjustments": "; ".join(adjustments_log[i]) if adjustments_log[i] else "none",
                "hostname": hostname,
                "user": user,
                "entity_key": feat.get("_entity_key", ""),
                "source_type": feat.get("_source_type", ""),
                "topic": feat.get("_topic", ""),
                "action_type_name": feat.get("_action_type_name", "info"),
                "template_id": feat.get("_template_id", ""),
                # v8: entity EWMA rates for Hunter consumption
                "entity_event_rate": feat.get("entity_event_rate", 0.0),
                "entity_error_rate": feat.get("entity_error_rate", 0.0),
            })

        # Drift monitoring
        if self._drift_monitor is not None:
            drift_result = self._drift_monitor.add_batch(combined)
            if drift_result and drift_result["level"] != "ok":
                for r in results:
                    r["drift_alert"] = drift_result

        return results

    def get_baseline_z(self, hostname: str, user: str) -> Tuple[float, float]:
        """Get current baseline z-scores for a host and user."""
        host_z = 0.0
        user_z = 0.0
        # We can't query without updating, so return 0 for unknown entities
        return host_z, user_z

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_events": self._total_events,
            "total_escalated": self._total_escalated,
            "total_monitored": self._total_monitored,
            "total_discarded": self._total_discarded,
            "escalation_rate": (
                self._total_escalated / max(self._total_events, 1)
            ),
            "monitoring_rate": (
                self._total_monitored / max(self._total_events, 1)
            ),
            "host_baselines": self._host_baseline.get_stats(),
            "user_baselines": self._user_baseline.get_stats(),
        }

    def cleanup(self) -> None:
        now = time.monotonic()
        h = self._host_baseline.cleanup(now)
        u = self._user_baseline.cleanup(now)
        if h > 0 or u > 0:
            logger.info("Baseline cleanup: removed %d hosts, %d users", h, u)
