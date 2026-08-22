# Cognitive Log Investigation Platform SecureBank — Live Attack Demo

**A realistic vulnerable banking portal for demonstrating the full Cognitive Log Investigation Platform SIEM pipeline catching a 7-phase cyber attack in real-time.**

---

## Architecture

```
┌──────────────────┐         ┌──────────────────┐
│  SecureBank Web  │──TCP──▶│  Vector (:9514)  │
│   Flask (:5000)  │  NDJSON │  Parse + Route   │
└──────────────────┘         └────────┬─────────┘
       ▲                              │
       │  HTTP                        ▼
┌──────┴──────────┐         ┌──────────────────┐
│ Attack Script   │         │ Redpanda (3-node)│
│  7-Phase Kill   │         │ 4 topics         │
│  Chain          │         └────────┬─────────┘
└─────────────────┘                  │
                                     ▼
                           ┌───────────────────┐
                           │ Cognitive Log Investigation Platform Agents│
                           │  Triage → Hunter  │
                           │  → Verifier       │
                           └────────┬──────────┘
                                    │
                                    ▼
                           ┌───────────────────┐
                           │  SOC Dashboard    │
                           │  (:3001)          │
                           │  + Live Feed      │
                           │  (:5000/live-feed)│
                           └───────────────────┘
```

## Quick Start

### Step 1: Start the local pipeline

Start the local Cognitive Log Investigation Platform pipeline from the project
root:

```bash
./start_demo.sh
```

### Step 2: Launch SecureBank

```bash
# From the project root directory
docker compose -f demo/docker-compose.demo.yml up -d --build

# Verify it's running
curl http://localhost:5000/health
```

### Step 3: Open Two Browser Windows Side-by-Side

| Window | URL | Purpose |
|--------|-----|---------|
| **Left** | `http://localhost:5000` | SecureBank (victim website) |
| **Right** | `http://localhost:3001/live-feed` | Cognitive Log Investigation Platform Live Detection Feed |

Or use the full SOC Dashboard:
| **Right** | `http://localhost:3001` | Cognitive Log Investigation Platform SOC Dashboard |

### Step 4: Run the Attack

```bash
# Interactive mode (pause between phases for narration)
python demo/securebank/attack.py --interactive

# Fast mode (speed run, no delays)
python demo/securebank/attack.py --fast

# Specific phase only
python demo/securebank/attack.py --phase 2

# High-Volume Flood / Stress attack (streams thousands of attack events directly to Vector)
python demo/securebank/load_attack_generator.py --mode direct --count 50000 --workers 8

# High-Volume HTTP attack burst against SecureBank endpoints
python demo/securebank/load_attack_generator.py --mode http --target http://localhost:5001 --burst 500
```

---

## 7 Attack Phases

| Phase | Attack | MITRE Tactic | Technique | What SIMPLESOC Detects |
|-------|--------|-------------|-----------|-------------------|
| **1** | Directory Enumeration | TA0043 Reconnaissance | T1046, T1595 | Rapid 404 bursts, unusual path probing |
| **2** | Credential Stuffing | TA0006 Credential Access | T1110 | Auth failure spike (50+), brute force pattern |
| **3** | Stolen Credential Login | TA0001 Initial Access | T1078 | Login success after N failures (suspicious!) |
| **4** | SQL Injection | TA0001 Initial Access | T1190 | SQLi patterns in URL parameters |
| **5** | XSS (Cross-Site Scripting) | TA0002 Execution | T1059 | Script injection in profile fields |
| **6** | Path Traversal | TA0007 Discovery | T1083 | `../` patterns in document API |
| **7** | Data Exfiltration | TA0010 Exfiltration | T1041 | Bulk downloads, large transfers, structuring |

## Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `Admin@2026!` | Admin |
| `john.doe` | `Welcome123` | User |
| `jane.smith` | `Password1!` | User |
| `mike.ops` | `Ops$ecure99` | Operator |

## API Endpoints (Attack Surfaces)

| Endpoint | Vulnerability | Attack Phase |
|----------|--------------|--------------|
| `POST /login` | Brute force | Phase 2 |
| `GET /admin` | Privilege escalation | Phase 4 |
| `GET /api/search?q=` | SQL injection | Phase 4 |
| `POST /api/profile` | XSS injection | Phase 5 |
| `GET /api/documents/<path>` | Path traversal | Phase 6 |
| `GET /api/users?per_page=200` | Bulk data leak | Phase 7 |
| `GET /api/export` | Full data export | Phase 7 |
| `POST /api/transfer` | Fraudulent transfers | Phase 7 |

## Live Cognitive Log Investigation Platform Detection Feed

The `/live-feed` page shows real-time triage scores from the SIMPLESOC pipeline:
- Auto-refreshes every 3 seconds
- Color-coded by severity (red = escalated, yellow = monitored, green = discarded)
- Shows MITRE ATT&CK tactics and techniques per event
- Displays LightGBM scores, actions, and pipeline stats
- Filter by action type (escalated / monitored / discarded)


---

## Log Format Examples

### Security Event (auth failure → Vector classifies as `security`)
```json
{
  "timestamp": "2026-03-16T10:30:00.000Z",
  "hostname": "securebank-web01",
  "source": "securebank",
  "level": "ERROR",
  "severity": 3,
  "category": "auth",
  "message": "Authentication failure: invalid user or password for user='admin' from ip=192.168.1.105 — failed password — login failed",
  "user_id": "admin",
  "ip_address": "192.168.1.105"
}
```

### Network Event (large data transfer)
```json
{
  "timestamp": "2026-03-16T10:35:00.000Z",
  "hostname": "securebank-web01",
  "src_ip": "10.0.1.50",
  "dst_ip": "192.168.1.105",
  "dst_port": 443,
  "protocol": "TCP",
  "bytes_sent": 40000,
  "bytes_received": 64,
  "message": "Large outbound data transfer: 40000 bytes — unusual transfer"
}
```

### Exfiltration Event (severity 4 → escalated by Triage)
```json
{
  "timestamp": "2026-03-16T10:36:00.000Z",
  "hostname": "securebank-web01",
  "source": "securebank",
  "level": "CRITICAL",
  "severity": 4,
  "message": "Exfiltration attempt: user=admin requested 200 customer records — data leak — unusual transfer — large upload",
  "user_id": "admin",
  "ip_address": "192.168.1.105"
}
```

---

## How Vector Classifies These Logs

The SecureBank logs contain **trigger keywords** that Vector's VRL `mega_transform` matches:

| Keyword in Log Message                  | Vector Classification | Severity |
|-----------------------------------------|----------------------|----------|
| `failed password`, `login failed`       | security / auth      | 3        |
| `brute force`, `account locked`         | security / auth      | 4        |
| `session opened`, `login successful`    | security / auth      | 1        |
| `exfiltration`, `data leak`, `unusual transfer` | security / exfiltration | 4  |
| `privilege escalation`, `access denied` | security / priv-esc  | 3        |
| `port scan`                             | security / network   | 3        |
| Fields `src_ip`, `dst_ip`, `dst_port`   | network event        | 0        |

---

## Troubleshooting

### Logs not appearing in dashboard
```bash
# Check Vector is receiving logs
docker logs clif-vector --tail 20

# Test TCP connection to Vector
python -c "import socket; s=socket.socket(); s.connect(('localhost',9514)); s.send(b'{\"message\":\"test\"}\n'); s.close(); print('OK')"

# Check Redpanda topics for new messages
rpk topic consume security-events --brokers localhost:17092 -n 5
```

### SecureBank not starting
```bash
docker logs clif-securebank --tail 30
curl http://localhost:5000/health
```

### Attack script can't connect
```bash
# If running attack from host against Docker:
python demo/securebank/attack.py --target http://localhost:5000

# If running both in Docker, use container name:
python demo/securebank/attack.py --target http://clif-securebank:5000
```
