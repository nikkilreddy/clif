# Cognitive Log Investigation Platform Demo Walkthrough

Complete guide to running the Cognitive Log Investigation Platform live demo — 7-phase attack simulation.

The local Compose stack is used for the demo. You only need Docker and Python.

---



## Prerequisites

| Software | Why | Install |
|----------|-----|----------|
| **curl** | Run benchmark | Built into macOS/Linux; on Windows use `curl.exe` (not `curl` — PowerShell aliases it) |
| **Python 3.8+** | Run attack script | `python.org` or pre-installed on macOS/Linux |
| **requests** library | Used by attack script | `pip install requests` |

---

## Table of Contents

1. [Infrastructure Overview](#1-infrastructure-overview)
2. [Benchmark — Live Throughput Test](#2-benchmark--live-throughput-test)
3. [Attack Script — 7-Phase Kill Chain](#3-attack-script--7-phase-kill-chain)
4. [Quick Reference](#4-quick-reference)

---

## 1. Infrastructure Overview

### Local Demo Stack

| Node | IP | Role | Containers |
|------|----|------|------------|
| **Stack** | Local Docker Compose | Ingestion, storage, agents, and dashboard | Vector, Redpanda, ClickHouse, Consumer, Triage, Hunter, Verifier, SecureBank, Dashboard |

### Data Flow

```
  Benchmark / Attack Script
         │
         ▼  TCP :9514 (NDJSON)
  ┌──────────────┐      ┌──────────────────┐
  │   Vector     │─────▶│  Redpanda        │
  │  Parse+Route │      │  3-broker cluster│
  └──────────────┘      └────────┬─────────┘
                                 │  4 Kafka topics
                                 ▼
                        ┌──────────────────┐
                        │ Cognitive Log Investigation Platform Agents│
                        │  Triage → Hunter │
                        │  → Verifier      │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐     ┌──────────────────┐
                        │  Consumer (Go)   │────▶│  ClickHouse      │
                        │  Batch Writer    │     │  2-node cluster  │
                        └──────────────────┘     └────────┬─────────┘
                                                          │
                                                          ▼
                                                 ┌──────────────────┐
                                                 │  SOC Dashboard   │
                                                 │  Next.js (:3001) │
                                                 └──────────────────┘
```

---

## 2. Benchmark — Live Throughput Test

A pre-built payload of 2 million realistic log events (528 MB) is stored on the cloud server along with a high-performance Go TCP blaster. A simple HTTP trigger service exposes it — so you can run the entire benchmark remotely from any machine with a single `curl` command. No file downloads, no SSH, no setup required. The logs never leave the cloud; only the live progress and results stream back to your terminal.

### How It Works

1. You run `curl` from any terminal on any machine
2. The local demo sends attack events into the Cognitive Log Investigation Platform pipeline.
3. Progress streams live to your terminal every ~3 seconds
4. Final summary shows total events, duration, EPS, throughput, and errors

### Usage

```bash
# Run full 2M benchmark with live streaming (default 16 workers)
curl "http://35.200.152.225:9515/benchmark?key=clif-bench-2026"

# Custom worker count
curl "http://35.200.152.225:9515/benchmark?key=clif-bench-2026&workers=8"

# Health check (no key required)
curl http://35.200.152.225:9515/health
```

> **Windows PowerShell**: Use `curl.exe` instead of `curl` (PowerShell aliases `curl` to `Invoke-WebRequest`).

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `key` | *(required)* | API key — `clif-bench-2026` |
| `workers` | `16` | Number of parallel TCP connections (1–64) |

### What You'll See

Output streams line-by-line in real-time:

```
Starting benchmark: 2000000 events, 16 workers, target 127.0.0.1:9514
Worker 03: 125,000 events sent (528.0 MB total across all workers)
Worker 07: 125,000 events sent (528.0 MB total across all workers)
...

=== BENCHMARK COMPLETE ===
Total events:  2,000,000
Data sent:     528.0 MB
Duration:      59.2s
Avg EPS:       33,759
Throughput:    8.9 MB/s
Errors:        0
```

### Performance Results

| Workers | Avg EPS | Duration | Notes |
|---------|---------|----------|-------|
| 16 | **33,759** | ~59s | Recommended — best throughput |
| 8 | **32,217** | ~62s | Slightly lower, still excellent |

### Attack Types in Payload (20% of traffic)

| Attack Type | Description |
|-------------|-------------|
| SSH Brute Force | Rapid failed password attempts from attacker IPs |
| Credential Stuffing | Many different usernames from same IP |
| SQL Injection | WAF alerts with SQLi payloads |
| Web Shell | Upload and execution attempts |
| Port Scanning | SYN scans to many ports |
| Privilege Escalation | Unauthorized sudo, setuid abuse |
| DGA DNS | Algorithmically generated domain queries |
| DNS Tunneling | Large TXT queries to suspicious domains |
| Data Exfiltration | Large outbound transfers to external IPs |
| Lateral Movement | Internal host-to-host suspicious activity |
| Malware C2 | Periodic beaconing to C2 servers |
| RCE Attempts | Log4Shell, OS command injection, path traversal |

---

## 3. Attack Script — 7-Phase Kill Chain

**File:** `demo/securebank/attack.py`

A realistic multi-stage cyber attack simulator against the SecureBank demo app. Each phase maps to MITRE ATT&CK tactics and generates logs that SIMPLESOC detects in real-time.

### Prerequisites

```bash
# Verify SIMPLESOC pipeline and SecureBank are running
curl http://35.200.152.225:9515/health
curl http://localhost:5001/health
```

> SecureBank runs locally at `http://localhost:5001` for this demo.

### Usage

```bash
# Full 7-phase attack with natural delays
python demo/securebank/attack.py

# Interactive mode — pauses between phases (best for live demo)
python demo/securebank/attack.py --interactive

# Fast mode — no delays, speed run
python demo/securebank/attack.py --fast

# Run a specific phase only
python demo/securebank/attack.py --phase 2

# Custom target URL (e.g., GCP-hosted SecureBank)
python demo/securebank/attack.py --target http://35.200.152.225:5000/bank
```

### Parameters

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | `http://localhost:5001` | SecureBank URL |
| `--phase` | All (1–7) | Run a specific phase only (1–7) |
| `--fast` | Off | Skip all delays between actions |
| `--interactive` | Off | Pause between phases (press Enter to continue) |

### The 7 Attack Phases

| Phase | Name | MITRE Tactic | Technique | What It Does |
|-------|------|-------------|-----------|--------------|
| **1** | Reconnaissance | TA0043 Discovery | T1046, T1595 | Enumerates 60+ paths (`/admin`, `/.env`, `/api/swagger`, `/actuator`, etc.) |
| **2** | Brute Force | TA0006 Credential Access | T1110 | 50+ credential stuffing attempts against `/login` |
| **3** | Initial Access | TA0001 Initial Access | T1078 | Logs in with stolen credentials (`admin:Admin@2026!`) |
| **4** | SQL Injection | TA0001 Initial Access | T1190 | 30 SQLi payloads against `/api/search` |
| **5** | XSS | TA0002 Execution | T1059 | 30+ XSS payloads in profile display_name and bio fields |
| **6** | Path Traversal | TA0007 Discovery | T1083 | 25 directory traversal payloads against `/api/documents/` |
| **7** | Exfiltration | TA0010 Exfiltration | T1041 | Bulk data download, $250K wire, 15 micro-transfers (structuring), 5 large transfers |

### Attack Surfaces (SecureBank API)

| Endpoint | Vulnerability | Attack Phase |
|----------|--------------|--------------|
| `POST /login` | Brute force / credential stuffing | Phase 2 |
| `GET /admin` | Privilege escalation probe | Phase 4 |
| `GET /api/search?q=` | SQL injection | Phase 4 |
| `POST /api/profile` | XSS injection (display_name + bio) | Phase 5 |
| `GET /api/documents/<path>` | Path traversal (`../../etc/passwd`) | Phase 6 |
| `GET /api/users?per_page=200` | Bulk data leak | Phase 7 |
| `GET /api/export?format=json` | Full data export | Phase 7 |
| `POST /api/transfer` | Fraudulent wire transfers | Phase 7 |

### Demo Credentials (SecureBank)

| Username | Password | Role |
|----------|----------|------|
| `admin` | `Admin@2026!` | Admin |
| `john.doe` | `Welcome123` | User |
| `jane.smith` | `Password1!` | User |
| `mike.ops` | `Ops$ecure99` | Operator |

### What Cognitive Log Investigation Platform Detects

| Phase | SIMPLESOC Detection |
|-------|----------------|
| 1 — Recon | Rapid 404 bursts, unusual path probing |
| 2 — Brute Force | Auth failure spike (50+), brute force pattern, escalation score >0.8 |
| 3 — Initial Access | Login success after N failures (suspicious!) |
| 4 — SQL Injection | SQLi patterns in URL parameters |
| 5 — XSS | Script injection in profile fields |
| 6 — Path Traversal | `../` patterns in document API |
| 7 — Exfiltration | Bulk downloads, large transfers, structuring pattern |

---

## 4. Quick Reference

```bash
# Benchmark — streams 2M events with live progress (~60 seconds)
curl "http://35.200.152.225:9515/benchmark?key=clif-bench-2026"

# Attack demo — interactive mode (pauses between phases)
python demo/securebank/attack.py --interactive

# Attack demo — full speed
python demo/securebank/attack.py

# Attack demo — single phase
python demo/securebank/attack.py --phase 2

# SOC Dashboard — open in browser
# http://35.200.152.225:3001

# Health check
curl http://35.200.152.225:9515/health
```
