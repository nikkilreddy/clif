"""
Cognitive Log Investigation Platform SecureBank — Demo Vulnerable Web Application
==================================================
A realistic banking portal that generates structured JSON logs
and sends them to Vector (TCP NDJSON on port 9514) for the
full Cognitive Log Investigation Platform pipeline to ingest, triage, investigate, and verify.

Every HTTP request, auth event, and suspicious action produces
logs that Vector's mega_transform classifies into security,
network, or raw events — triggering the AI agent pipeline.
"""

import json
import socket
import time
import uuid
import random
import hashlib
import os
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, abort
)

# =============================================================================
# Configuration
# =============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "clif-demo-secret-key-change-me")

VECTOR_HOST = os.environ.get("VECTOR_HOST", "localhost")
VECTOR_PORT = int(os.environ.get("VECTOR_PORT", "9514"))
BANK_HOSTNAME = os.environ.get("BANK_HOSTNAME", "securebank-web01")
BANK_IP = os.environ.get("BANK_IP", "10.0.1.50")  # simulated server IP

# Simulated user database
USERS_DB = {
    "admin": {
        "password": hashlib.sha256("Admin@2026!".encode()).hexdigest(),
        "role": "admin",
        "full_name": "Sarah Chen",
        "email": "s.chen@securebank.com",
    },
    "john.doe": {
        "password": hashlib.sha256("Welcome123".encode()).hexdigest(),
        "role": "user",
        "full_name": "John Doe",
        "email": "j.doe@securebank.com",
    },
    "jane.smith": {
        "password": hashlib.sha256("Password1!".encode()).hexdigest(),
        "role": "user",
        "full_name": "Jane Smith",
        "email": "j.smith@securebank.com",
    },
    "mike.ops": {
        "password": hashlib.sha256("Ops$ecure99".encode()).hexdigest(),
        "role": "operator",
        "full_name": "Mike Operations",
        "email": "m.ops@securebank.com",
    },
}

# Simulated transaction data
TRANSACTIONS = [
    {"id": "TXN-001", "from": "john.doe", "to": "EXT-9981", "amount": 1250.00, "currency": "USD", "status": "completed", "date": "2026-03-15"},
    {"id": "TXN-002", "from": "john.doe", "to": "EXT-4422", "amount": 89.99, "currency": "USD", "status": "completed", "date": "2026-03-14"},
    {"id": "TXN-003", "from": "jane.smith", "to": "EXT-1100", "amount": 5400.00, "currency": "USD", "status": "pending", "date": "2026-03-15"},
    {"id": "TXN-004", "from": "admin", "to": "PAYROLL", "amount": 125000.00, "currency": "USD", "status": "completed", "date": "2026-03-13"},
    {"id": "TXN-005", "from": "mike.ops", "to": "VENDOR-77", "amount": 33200.00, "currency": "USD", "status": "completed", "date": "2026-03-12"},
]

# Simulated customer PII (exfiltration target)
CUSTOMERS = [
    {"id": f"CUST-{i:04d}", "name": f"Customer {i}", "ssn": f"***-**-{random.randint(1000,9999)}", "balance": round(random.uniform(1000, 500000), 2)}
    for i in range(1, 201)
]

# Track failed login attempts per IP
_failed_logins = {}

# Blocked users — set by Cognitive Log Investigation Platform SIEM dashboard (SOAR response)
_blocked_users = {}  # { username: { reason, blocked_at, blocked_by, investigation_id } }

# Blocked IPs — set by Cognitive Log Investigation Platform SIEM dashboard (SOAR response)
_blocked_ips = {}  # { ip: { reason, blocked_at, blocked_by, investigation_id } }


# =============================================================================
# Per-request network telemetry — feeds KDD aggregation features
# =============================================================================

@app.before_request
def _check_blocked():
    """If the logged-in user is blocked, force logout them immediately."""
    user = session.get("user")
    if user and user in _blocked_users:
        block_info = _blocked_users[user]
        session.clear()
        log_security(
            "auth", 4,
            f"Active session terminated: user '{user}' is blocked — {block_info.get('reason', '')}",
            user_id=user, ip=request.remote_addr,
            log_type="syslog", status="blocked", auth_type="soar", username=user,
        )
        flash("Your account has been suspended by the security team.", "danger")
        return redirect(url_for("login"))


@app.before_request
def _check_blocked_ip():
    """Block requests from IPs that have been flagged by SIEM SOAR actions."""
    if request.path.startswith("/api/block-ip") or request.path.startswith("/api/unblock-ip") or request.path.startswith("/api/blocked-ip"):
        return  # Allow SOAR API calls through
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    if client_ip in _blocked_ips:
        block_info = _blocked_ips[client_ip]
        log_security(
            "firewall", 5,
            f"BLOCKED IP: request from {client_ip} denied — {block_info.get('reason', '')}",
            ip=client_ip,
            log_type="syslog", status="blocked", auth_type="soar",
            mitre_tactic="command-and-control",
            mitre_technique="T1071",
        )
        return jsonify({
            "error": "Access Denied",
            "message": f"Your IP address ({client_ip}) has been blocked by the security team.",
            "blocked_at": block_info.get("blocked_at", ""),
        }), 403


@app.before_request
def _start_timer():
    request._start_time = time.monotonic()


@app.after_request
def _emit_network_event(response):
    """Emit a network-events log for every HTTP request.
    This feeds the KDD sliding-window tracker in the triage agent
    (count, srv_count, same_srv_rate, diff_srv_rate, etc.)."""
    try:
        elapsed_ms = int((time.monotonic() - getattr(request, '_start_time', time.monotonic())) * 1000)
        req_bytes = request.content_length or len(request.get_data(as_text=True) or "")
        resp_bytes = response.content_length or len(response.get_data() or b"")
        # Determine severity from status code
        level = "INFO"
        if response.status_code >= 500:
            level = "ERROR"
        elif response.status_code >= 400:
            level = "WARNING"
        send_log({
            "clif_event_type": "network",
            "log_type": "netflow",
            "src_ip": request.remote_addr or "0.0.0.0",
            "dst_ip": BANK_IP,
            "src_port": random.randint(40000, 65000),
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": req_bytes,
            "bytes_received": resp_bytes,
            "direction": "inbound",
            "duration_ms": max(elapsed_ms, 1),
            "level": level,
            "message": f"HTTP {request.method} {request.path} {response.status_code} "
                       f"{req_bytes}B→{resp_bytes}B {elapsed_ms}ms",
        })
    except Exception:
        pass  # never break the response
    return response


# =============================================================================
# Logging to Vector (TCP NDJSON on port 9514)
# =============================================================================

def send_log(log_dict):
    """Send a JSON log line to Vector's tcp_json source via TCP."""
    log_dict.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    log_dict.setdefault("hostname", BANK_HOSTNAME)
    log_dict.setdefault("source", "securebank")
    log_dict.setdefault("request_id", str(uuid.uuid4())[:8])

    line = json.dumps(log_dict, default=str) + "\n"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((VECTOR_HOST, VECTOR_PORT))
        sock.sendall(line.encode("utf-8"))
        sock.close()
    except Exception as e:
        # Silently fail in demo — print for debugging
        print(f"[LOG-SEND-FAIL] {e} | {line[:120]}")


def log_security(category, severity, message, **extra):
    """Emit a security-classified log event.

    Accepts log_type= to set the explicit log type for feature extraction.
    Accepts url= and http_method= for web-layer features.
    """
    event = {
        "clif_event_type": "security",
        "level": ["INFO", "INFO", "WARNING", "ERROR", "CRITICAL"][min(severity, 4)],
        "category": category,
        "severity": severity,
        "description": message,
        "message": message,
        "user_id": extra.get("user_id", session.get("user", "")),
        "ip_address": extra.get("ip", request.remote_addr if request else "0.0.0.0"),
        "mitre_tactic": extra.get("mitre_tactic", ""),
        "mitre_technique": extra.get("mitre_technique", ""),
    }
    # pass through log_type, url, http_method, status, auth_type, username explicitly
    passthrough = ("log_type", "url", "http_method", "status", "auth_type", "username",
                   "user_id", "ip", "mitre_tactic", "mitre_technique")
    for k, v in extra.items():
        if k not in passthrough:
            event[k] = v
    # set the passthrough fields directly on the event
    if "log_type" in extra:
        event["log_type"] = extra["log_type"]
    if "url" in extra:
        event["url"] = extra["url"]
    if "http_method" in extra:
        event["http_method"] = extra["http_method"]
    if "status" in extra:
        event["status"] = extra["status"]
    if "auth_type" in extra:
        event["auth_type"] = extra["auth_type"]
    if "username" in extra:
        event["username"] = extra["username"]
    send_log(event)


def log_network(src_ip, dst_ip, dst_port, protocol="TCP", bytes_sent=0, bytes_received=0, **extra):
    """Emit a network event log. Accepts log_type= for feature extraction."""
    event = {
        "clif_event_type": "network",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(40000, 65000),
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "direction": "inbound",
        "duration_ms": random.randint(1, 500),
        "message": extra.get("message", f"Connection {src_ip} -> {dst_ip}:{dst_port}"),
        "level": "INFO",
    }
    if "log_type" in extra:
        event["log_type"] = extra["log_type"]
    for k, v in extra.items():
        if k not in ("message", "log_type"):
            event[k] = v
    send_log(event)


def log_access(message, level="INFO"):
    """Emit a generic access/raw log."""
    send_log({
        "level": level,
        "message": message,
        "user_id": session.get("user", "anonymous"),
        "ip_address": request.remote_addr if request else "0.0.0.0",
    })


# =============================================================================
# Auth decorator
# =============================================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            log_security(
                "privilege-escalation", 3,
                f"Access denied: user '{session['user']}' attempted to access admin panel — privilege escalation attempt",
                user_id=session["user"],
                ip=request.remote_addr,
                log_type="syslog", status="denied", auth_type="password", username=session["user"],
                mitre_tactic="privilege-escalation",
                mitre_technique="T1548",
            )
            abort(403)
        return f(*args, **kwargs)
    return decorated


# =============================================================================
# Routes
# =============================================================================

@app.route("/")
def index():
    log_access(f"Homepage accessed from {request.remote_addr}")
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        ip = request.remote_addr
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        # Log network event for the connection
        log_network(ip, "10.0.1.50", 443, bytes_sent=len(password) + len(username), bytes_received=256, log_type="netflow")

        # ── Check if user is blocked by SIEM ──
        if username in _blocked_users:
            block_info = _blocked_users[username]
            log_security(
                "auth", 4,
                f"BLOCKED user '{username}' attempted login from ip={ip} — "
                f"account suspended by SIEM. Reason: {block_info.get('reason', 'N/A')}",
                user_id=username, ip=ip,
                log_type="syslog", status="blocked", auth_type="password", username=username,
                mitre_tactic="credential-access",
                mitre_technique="T1110",
            )
            flash("Account suspended. Contact your administrator.", "danger")
            return render_template("login.html", error=True, blocked=True)

        user = USERS_DB.get(username)
        if user and user["password"] == pw_hash:
            # ── Successful login ──
            session["user"] = username
            session["role"] = user["role"]
            session["login_time"] = datetime.now(timezone.utc).isoformat()

            # Check if this IP had many failed attempts before success (suspicious!)
            fails = _failed_logins.get(ip, 0)
            if fails >= 5:
                log_security(
                    "auth", 4,
                    f"Login successful AFTER {fails} failed attempts — possible brute force success. "
                    f"user={username} ip={ip} — authentication failure pattern followed by access",
                    user_id=username, ip=ip,
                    log_type="syslog", status="success", auth_type="password", username=username,
                    mitre_tactic="credential-access",
                    mitre_technique="T1110",
                )
            else:
                log_security(
                    "auth", 1,
                    f"Login successful for user={username} from ip={ip} — session opened",
                    user_id=username, ip=ip,
                    log_type="syslog", status="success", auth_type="password", username=username,
                    mitre_tactic="initial-access",
                    mitre_technique="T1078",
                )
            _failed_logins[ip] = 0
            flash(f"Welcome back, {user['full_name']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            # ── Failed login ──
            _failed_logins[ip] = _failed_logins.get(ip, 0) + 1
            count = _failed_logins[ip]

            if count >= 10:
                log_security(
                    "auth", 4,
                    f"Brute force detected: {count} failed login attempts from ip={ip} "
                    f"for user='{username}' — account locked threshold exceeded — brute force attack",
                    user_id=username, ip=ip,
                    log_type="syslog", status="failure", auth_type="password", username=username,
                    mitre_tactic="credential-access",
                    mitre_technique="T1110",
                )
            elif count >= 5:
                log_security(
                    "auth", 3,
                    f"Multiple authentication failures: {count} failed password attempts from ip={ip} "
                    f"for user='{username}' — possible credential stuffing — login failed",
                    user_id=username, ip=ip,
                    log_type="syslog", status="failure", auth_type="password", username=username,
                    mitre_tactic="credential-access",
                    mitre_technique="T1110",
                )
            else:
                log_security(
                    "auth", 2,
                    f"Authentication failure: invalid user or password for user='{username}' "
                    f"from ip={ip} — failed password — login failed",
                    user_id=username, ip=ip,
                    log_type="syslog", status="failure", auth_type="password", username=username,
                    mitre_tactic="credential-access",
                    mitre_technique="T1078",
                )
            flash("Invalid username or password.", "danger")
            return render_template("login.html", error=True)

    return render_template("login.html")


@app.route("/logout")
def logout():
    user = session.get("user", "unknown")
    log_access(f"User {user} logged out from {request.remote_addr}")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = session["user"]
    log_access(f"Dashboard accessed by user={user}")
    user_txns = [t for t in TRANSACTIONS if t["from"] == user or session.get("role") == "admin"]
    return render_template("dashboard.html", user=USERS_DB[user], transactions=user_txns)


@app.route("/admin")
@admin_required
def admin_panel():
    log_security(
        "auth", 2,
        f"Admin panel accessed by user={session['user']} from ip={request.remote_addr} — "
        f"is_admin_action=true",
        user_id=session["user"],
        ip=request.remote_addr,
    )
    return render_template("admin.html", users=USERS_DB, transactions=TRANSACTIONS)


# =============================================================================
# API Endpoints (attack targets)
# =============================================================================

@app.route("/api/users", methods=["GET"])
@login_required
def api_users():
    """User listing API — exfiltration target."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    # Detect bulk download (exfiltration signal)
    if per_page > 50:
        log_security(
            "exfiltration", 4,
            f"Exfiltration attempt: user={session['user']} requested {per_page} customer records "
            f"in single API call — data leak — unusual transfer — large upload from ip={request.remote_addr}",
            user_id=session["user"],
            ip=request.remote_addr,
            log_type="web", url=f"/api/users?per_page={per_page}", http_method="GET",
            mitre_tactic="exfiltration",
            mitre_technique="T1041",
        )
    else:
        log_access(f"API /api/users accessed by {session['user']} page={page} per_page={per_page}")

    start = (page - 1) * per_page
    end = start + per_page
    return jsonify({
        "users": CUSTOMERS[start:end],
        "total": len(CUSTOMERS),
        "page": page,
        "per_page": per_page,
    })


@app.route("/api/transactions", methods=["GET"])
@login_required
def api_transactions():
    """Transaction API."""
    log_access(f"API /api/transactions accessed by {session['user']}")
    if session.get("role") == "admin":
        return jsonify({"transactions": TRANSACTIONS})
    user_txns = [t for t in TRANSACTIONS if t["from"] == session["user"]]
    return jsonify({"transactions": user_txns})


@app.route("/api/export", methods=["GET"])
@login_required
def api_export():
    """Bulk data export — major exfiltration target."""
    fmt = request.args.get("format", "json")

    # This is always suspicious — bulk export
    log_security(
        "exfiltration", 4,
        f"Bulk data export triggered by user={session['user']} format={fmt} — "
        f"exfiltration of {len(CUSTOMERS)} customer records — data leak — "
        f"unusual transfer — large upload — {len(CUSTOMERS) * 200} bytes from ip={request.remote_addr}",
        user_id=session["user"],
        ip=request.remote_addr,
        log_type="web", url=f"/api/export?format={fmt}", http_method="GET",
        mitre_tactic="exfiltration",
        mitre_technique="T1041",
    )

    # Also emit network event for the large data transfer
    log_network(
        BANK_IP, request.remote_addr, 443,
        bytes_sent=len(CUSTOMERS) * 500,  # PII records are high-value
        bytes_received=64,
        log_type="netflow",
        message=f"Large outbound data transfer: {len(CUSTOMERS) * 500} bytes to {request.remote_addr} — unusual transfer — data leak — exfiltration",
    )

    return jsonify({"customers": CUSTOMERS, "exported_by": session["user"], "count": len(CUSTOMERS)})


@app.route("/api/search", methods=["GET"])
@login_required
def api_search():
    """Search endpoint — SQL injection target."""
    query = request.args.get("q", "")

    # Detect SQL injection patterns
    sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "DROP", "INSERT", "DELETE", "OR 1=1", "' OR '", "1=1"]
    is_sqli = any(p.lower() in query.lower() for p in sqli_patterns)

    if is_sqli:
        log_security(
            "injection", 4,
            f"SQL injection attempt detected: user={session['user']} query=\"{query}\" — "
            f"access denied — malicious input — from ip={request.remote_addr}",
            user_id=session["user"],
            ip=request.remote_addr,
            log_type="web", url=f"/api/search?q={query}", http_method="GET",
            mitre_tactic="initial-access",
            mitre_technique="T1190",
        )
        # Network event with actual payload size — triggers src_bytes feature
        log_network(
            request.remote_addr, BANK_IP, 443,
            bytes_sent=len(query) * 10,
            bytes_received=64,
            log_type="ids",
            message=f"SQLi payload {len(query)}B from {request.remote_addr} — malicious input",
        )
        return jsonify({"error": "Invalid search query"}), 400

    log_access(f"Search query by {session['user']}: q={query}")
    results = [c for c in CUSTOMERS if query.lower() in c["name"].lower()] if query else []
    return jsonify({"results": results[:20], "query": query})


@app.route("/api/profile", methods=["GET", "POST"])
@login_required
def api_profile():
    """Profile update endpoint — XSS attack target."""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        display_name = data.get("display_name", "")
        bio = data.get("bio", "")

        # Detect XSS patterns
        xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "onclick=",
                        "<img", "<iframe", "<svg", "alert(", "document.cookie",
                        "eval(", "<body", "onmouseover=", "onfocus="]
        combined = (display_name + " " + bio).lower()
        is_xss = any(p.lower() in combined for p in xss_patterns)

        if is_xss:
            log_security(
                "injection", 4,
                f"XSS attack detected: user={session['user']} injected script payload in profile update — "
                f"cross-site scripting — malicious input — access denied — from ip={request.remote_addr}",
                user_id=session["user"],
                ip=request.remote_addr,
                log_type="web", url=f"/api/profile", http_method="POST",
                mitre_tactic="initial-access",
                mitre_technique="T1059",
                payload_preview=combined[:100],
            )
            # Network event with payload size
            log_network(
                request.remote_addr, BANK_IP, 443,
                bytes_sent=len(combined) * 5,
                bytes_received=64,
                log_type="ids",
                message=f"XSS payload {len(combined)}B from {request.remote_addr} — malicious script injection",
            )
            return jsonify({"error": "Malicious content detected"}), 400

        log_access(f"Profile updated by {session['user']} — display_name={display_name}")
        return jsonify({"status": "updated", "user": session["user"]})

    return jsonify({"user": session["user"], "role": session.get("role")})


@app.route("/api/documents/<path:filepath>")
@login_required
def api_documents(filepath):
    """Document retrieval — path traversal target."""
    # Detect path traversal patterns
    traversal_patterns = ["..", "%2e%2e", "..%2f", "%2f..", "/etc/passwd",
                          "/etc/shadow", "../../", "....//", "..\\"]
    is_traversal = any(p.lower() in filepath.lower() for p in traversal_patterns)

    if is_traversal:
        log_security(
            "injection", 4,
            f"Path traversal attack detected: user={session['user']} path='{filepath}' — "
            f"directory traversal — unauthorized file access — access denied — from ip={request.remote_addr}",
            user_id=session["user"],
            ip=request.remote_addr,
            log_type="web", url=f"/api/documents/{filepath}", http_method="GET",
            mitre_tactic="discovery",
            mitre_technique="T1083",
        )
        # Network event for traversal
        log_network(
            request.remote_addr, BANK_IP, 443,
            bytes_sent=len(filepath) * 5,
            bytes_received=64,
            log_type="ids",
            message=f"Path traversal {len(filepath)}B from {request.remote_addr} — directory traversal",
        )
        return jsonify({"error": "Access denied — invalid path"}), 403

    # Simulated document listing
    fake_docs = {
        "statements/march-2026.pdf": {"name": "March 2026 Statement", "size": "245 KB"},
        "statements/february-2026.pdf": {"name": "February 2026 Statement", "size": "198 KB"},
        "tax/w2-2025.pdf": {"name": "W-2 Form 2025", "size": "52 KB"},
    }
    doc = fake_docs.get(filepath)
    if doc:
        log_access(f"Document accessed by {session['user']}: {filepath}")
        return jsonify({"document": doc, "path": filepath})
    return jsonify({"error": "Document not found"}), 404


@app.route("/api/transfer", methods=["POST"])
@login_required
def api_transfer():
    """Fund transfer — for demonstrating suspicious transaction patterns."""
    data = request.get_json(silent=True) or {}
    amount = data.get("amount", 0)
    to_account = data.get("to", "unknown")

    if amount > 50000:
        log_security(
            "exfiltration", 4,
            f"Suspicious high-value transfer: user={session['user']} amount=${amount:,.2f} "
            f"to={to_account} — unusual transfer — possible money laundering from ip={request.remote_addr}",
            user_id=session["user"],
            ip=request.remote_addr,
            log_type="web", url="/api/transfer", http_method="POST",
            mitre_tactic="exfiltration",
            mitre_technique="T1041",
        )
        # Large outbound transfer network event
        log_network(
            BANK_IP, request.remote_addr, 443,
            bytes_sent=int(amount * 10),  # financial data volume
            log_type="netflow",
            bytes_received=256,
            message=f"High-value transfer ${amount:,.2f} to {to_account} — unusual transfer — exfiltration",
        )
    else:
        log_access(f"Transfer: user={session['user']} amount=${amount:,.2f} to={to_account}")

    return jsonify({"status": "processed", "transaction_id": f"TXN-{uuid.uuid4().hex[:6].upper()}"})


# =============================================================================
# Error handlers
# =============================================================================

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access Denied — Insufficient Privileges"), 403

@app.errorhandler(404)
def not_found(e):
    log_security(
        "discovery", 2,
        f"404 Not Found: {request.path} from ip={request.remote_addr} — "
        f"possible directory enumeration — port scan",
        ip=request.remote_addr,
        log_type="web", url=request.path, http_method=request.method,
        mitre_tactic="discovery",
        mitre_technique="T1046",
    )
    # Network event with varied ports to trigger diff_srv_rate features
    log_network(
        request.remote_addr, BANK_IP, random.choice([80, 443, 8080, 8443, 3306, 5432, 22, 21]),
        bytes_sent=len(request.path),
        bytes_received=0,
        log_type="ids",
        message=f"Recon probe: {request.path} from {request.remote_addr} — 404 — port scan — discovery",
    )
    return render_template("error.html", code=404, message="Page Not Found"), 404


# =============================================================================
# Health check (for Docker)
# =============================================================================

# =============================================================================
# Live Cognitive Log Investigation Platform Detection Feed (for jury demo — queries ClickHouse directly)
# =============================================================================

_CH_HTTP = os.environ.get("CLICKHOUSE_URL", "http://10.52.166.221:8123")
_CH_USER = os.environ.get("CLICKHOUSE_USER", "clif_admin")
_CH_PASS = os.environ.get("CLICKHOUSE_PASS", "Cl1f_Ch@ngeM3_2026!")
_CH_DB = os.environ.get("CLICKHOUSE_DB", "clif_logs")


def _ch_query(sql):
    """Quick ClickHouse HTTP query for the live feed."""
    import requests as _rq
    try:
        resp = _rq.post(
            f"{_CH_HTTP}/",
            params={"database": _CH_DB, "default_format": "JSON"},
            data=sql.encode(),
            headers={"X-ClickHouse-User": _CH_USER, "X-ClickHouse-Key": _CH_PASS},
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[CH-QUERY-ERROR] {e} | url={_CH_HTTP} | sql={sql[:80]}", flush=True)
        return {"data": []}


@app.route("/live-feed")
def live_feed_page():
    """Live Cognitive Log Investigation Platform detection feed — real-time view for jury demo."""
    return render_template("live_feed.html")


@app.route("/api/live-feed")
def api_live_feed():
    """API endpoint returning latest triage scores for live feed."""
    limit = min(request.args.get("limit", 50, type=int), 200)
    result = _ch_query(
        f"SELECT event_id, timestamp, source_type, hostname, source_ip, user_id, "
        f"adjusted_score, lgbm_score, combined_score, action, "
        f"mitre_tactic, mitre_technique, shap_top_features, model_version "
        f"FROM triage_scores ORDER BY timestamp DESC LIMIT {limit}"
    )
    return jsonify({"events": result.get("data", []), "count": len(result.get("data", []))})


@app.route("/api/live-stats")
def api_live_stats():
    """API endpoint returning pipeline stats for live feed header."""
    stats = _ch_query(
        "SELECT "
        "  countIf(action = 'escalate') AS escalated, "
        "  countIf(action = 'monitor') AS monitored, "
        "  countIf(action = 'discard') AS discarded, "
        "  count() AS total, "
        "  max(adjusted_score) AS max_score, "
        "  avg(adjusted_score) AS avg_score "
        "FROM triage_scores "
        "WHERE timestamp >= now() - INTERVAL 24 HOUR"
    )
    hunters = _ch_query("SELECT count() AS c FROM hunter_investigations WHERE started_at >= now() - INTERVAL 24 HOUR")
    verifiers = _ch_query("SELECT count() AS c FROM verifier_results WHERE started_at >= now() - INTERVAL 24 HOUR")
    row = (stats.get("data") or [{}])[0]
    return jsonify({
        "total": row.get("total", 0),
        "escalated": row.get("escalated", 0),
        "monitored": row.get("monitored", 0),
        "discarded": row.get("discarded", 0),
        "max_score": row.get("max_score", 0),
        "avg_score": row.get("avg_score", 0),
        "hunter_investigations": (hunters.get("data") or [{}])[0].get("c", 0),
        "verifier_results": (verifiers.get("data") or [{}])[0].get("c", 0),
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "securebank", "version": "2.0.0"})


# =============================================================================
# SOAR Response — Block/Unblock users from Cognitive Log Investigation Platform SIEM
# =============================================================================

@app.route("/api/block", methods=["POST"])
def api_block_user():
    """Block a user account — called by Cognitive Log Investigation Platform SIEM dashboard."""
    data = request.get_json(force=True) if request.is_json else {}
    username = data.get("username", "").strip()
    reason = data.get("reason", "Blocked by SIEM investigation")
    investigation_id = data.get("investigation_id", "")
    blocked_by = data.get("blocked_by", "siem-analyst")

    if not username:
        return jsonify({"error": "username required"}), 400

    _blocked_users[username] = {
        "reason": reason,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "blocked_by": blocked_by,
        "investigation_id": investigation_id,
    }

    # Force-logout the user if they have an active session
    # (Flask sessions are client-side, so we can't invalidate server-side,
    #  but the before_request check will catch them on next request)

    log_security(
        "auth", 4,
        f"USER BLOCKED: '{username}' account suspended by SIEM — "
        f"reason: {reason} — investigation: {investigation_id}",
        user_id=username, ip=request.remote_addr,
        log_type="syslog", status="blocked", auth_type="soar",
        username=username,
        mitre_tactic="defense-evasion",
        mitre_technique="T1531",
    )

    return jsonify({
        "status": "blocked",
        "username": username,
        "reason": reason,
        "blocked_at": _blocked_users[username]["blocked_at"],
    })


@app.route("/api/unblock", methods=["POST"])
def api_unblock_user():
    """Unblock a user account."""
    data = request.get_json(force=True) if request.is_json else {}
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"error": "username required"}), 400

    if username not in _blocked_users:
        return jsonify({"status": "not_blocked", "username": username})

    del _blocked_users[username]

    log_security(
        "auth", 2,
        f"USER UNBLOCKED: '{username}' account re-enabled by SIEM analyst",
        user_id=username, ip=request.remote_addr,
        log_type="syslog", status="unblocked", auth_type="soar",
        username=username,
    )

    return jsonify({"status": "unblocked", "username": username})


@app.route("/api/blocked-users")
def api_blocked_users():
    """List all currently blocked users."""
    return jsonify({"blocked": _blocked_users})


# =============================================================================
# SOAR Response — Block/Unblock IPs from Cognitive Log Investigation Platform SIEM
# =============================================================================

@app.route("/api/block-ip", methods=["POST"])
def api_block_ip():
    """Block an IP address — called by Cognitive Log Investigation Platform SIEM dashboard."""
    data = request.get_json(force=True) if request.is_json else {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "Blocked by SIEM investigation")
    investigation_id = data.get("investigation_id", "")
    blocked_by = data.get("blocked_by", "siem-analyst")

    if not ip:
        return jsonify({"error": "ip required"}), 400

    _blocked_ips[ip] = {
        "reason": reason,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "blocked_by": blocked_by,
        "investigation_id": investigation_id,
    }

    log_security(
        "firewall", 5,
        f"IP BLOCKED: {ip} blocked by SIEM — "
        f"reason: {reason} — investigation: {investigation_id}",
        ip=ip,
        log_type="syslog", status="blocked", auth_type="soar",
        mitre_tactic="command-and-control",
        mitre_technique="T1071",
    )

    return jsonify({
        "status": "blocked",
        "ip": ip,
        "reason": reason,
        "blocked_at": _blocked_ips[ip]["blocked_at"],
    })


@app.route("/api/unblock-ip", methods=["POST"])
def api_unblock_ip():
    """Unblock an IP address."""
    data = request.get_json(force=True) if request.is_json else {}
    ip = data.get("ip", "").strip()

    if not ip:
        return jsonify({"error": "ip required"}), 400

    if ip not in _blocked_ips:
        return jsonify({"status": "not_blocked", "ip": ip})

    del _blocked_ips[ip]

    log_security(
        "firewall", 3,
        f"IP UNBLOCKED: {ip} re-enabled by SIEM analyst",
        ip=ip,
        log_type="syslog", status="unblocked", auth_type="soar",
    )

    return jsonify({"status": "unblocked", "ip": ip})


@app.route("/api/blocked-ips")
def api_blocked_ips():
    """List all currently blocked IPs."""
    return jsonify({"blocked": _blocked_ips})


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"[SecureBank] Starting on port {port}")
    print(f"[SecureBank] Vector endpoint: {VECTOR_HOST}:{VECTOR_PORT}")
    app.run(host="0.0.0.0", port=port, debug=True)
