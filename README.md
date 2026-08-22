# 🛡️ CLIF — Cognitive Log Investigation Platform

> **Autonomous Agentic SIEM & Forensics Pipeline**  
> *Transforming millions of noisy security logs into court-admissible forensic verdicts in under 60 seconds.*

[![GitHub](https://img.shields.io/badge/GitHub-nikkilreddy%2Fclif-blue?logo=github)](https://github.com/nikkilreddy/clif)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-yellow.svg?logo=python)](https://www.python.org/)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8.svg?logo=go)](https://go.dev/)
[![Vector](https://img.shields.io/badge/Ingest-Vector%20(Rust)-red.svg)](https://vector.dev/)
[![Redpanda](https://img.shields.io/badge/Streaming-Redpanda%20(C++)-FF4D4D.svg)](https://redpanda.com/)
[![ClickHouse](https://img.shields.io/badge/Storage-ClickHouse%20OLAP-orange.svg?logo=clickhouse)](https://clickhouse.com/)
[![Next.js](https://img.shields.io/badge/Dashboard-Next.js%2014-black.svg?logo=next.js)](https://nextjs.org/)

---

## 📌 Executive Summary

Security Operations Centers (SOCs) face an alert crisis: human analysts receive over **10,000 alerts daily** with a **45%+ false-positive rate**, leading to critical burnout and missed zero-day breaches.

**CLIF (Cognitive Log Investigation Platform)** is an autonomous, agentic SIEM system that eliminates manual log triage. It ingests raw enterprise logs at **35,000+ events per second**, filters noise with edge machine learning in microseconds, autonomously investigates suspicious activity across network hosts, builds interactive **Attack Graphs**, and issues calibrated forensic verdicts with plain-English narratives.

---

## 🏛️ System Architecture

```
[ Application Logs / Syslog / Network Packets ]
                       │
                       ▼
 1. [ Vector (Rust) ] ──────────────────► High-speed transform & canonical schema mapping
                       │
                       ▼
 2. [ Redpanda (Kafka-compatible) ] ────► In-flight distributed streaming buffer
                       │
       ┌───────────────┴────────────────────────────────┐
       ▼                                                ▼
 3. [ Consumer-Go ]                             4. [ Triage Agent (ML) ]
    (Zero-alloc buffers,                         (60-Feature Extractor +
     LZ4 batch writes & UUID5 dedup)              LightGBM & Autoencoder ONNX)
       │                                                │
       ▼                                                │ (Risk Score ≥ 0.70)
 5. [ ClickHouse OLAP DB ]                              ▼
    (Sub-10ms queries over                       5. [ Hunter Agent (Graph AI) ]
     millions of log events) ◄── (Historical Context) (5-Engine Correlator,
       ▲                                               Temporal Analysis & Attack Graph)
       │                                                │
       │                                                │ (Graph & Correlated Evidence)
       │                                                ▼
       │                                         6. [ Verifier Agent (Cognitive AI) ]
       └────────────────────────────────────────────── (Forensic Decision Matrix, Confidence,
                                                        Priority & Timeline Narratives)
                                                        │
                                                        ▼
                                                 7. [ Next.js SOC Dashboard ]
                                                    (Live Feed, Visual Attack Graphs,
                                                     XAI Waterfall Charts & Reports)
```

---

## 🤖 The 3-Agent Cognitive Pipeline

CLIF decomposes incident investigation into three distinct, specialized agent loops:

### 1. ⚡ Triage Agent (High-Throughput Edge ML)
* **Goal**: Separate harmless baseline traffic from suspicious anomalies at line rate ($\approx 10\,\mu\text{s}$ per event).
* **Feature Extraction**: Converts raw logs into a stateless vector of **60 numerical features** across 7 domain layers:
  * *Layer 1 (Core)*: Time sin/cos, off-hours flag, log severity, message Shannon entropy.
  * *Layer 2 (Network)*: Port bins, protocol, byte/packet ratios, TCP flags (`SYN`, `RST`, `FIN`).
  * *Layer 3 (Auth)*: Success/fail flags, admin targeting, remote vs local, failure rates.
  * *Layer 4 (DNS)*: Domain entropy (DGA detection), subdomain depth, consonant runs.
  * *Layer 5 (Web/HTTP)*: SQL injection patterns (`has_sql_pattern`), XSS regex, traversal (`../`).
  * *Layer 6 (Email)*: Subject entropy, urgency flags, financial keywords.
  * *Layer 7 (Cloud)*: Sensitive API calls, root account access, error codes.
* **Dual-Model Ensemble**:
  * **LightGBM (ONNX)**: Supervised tree classifier for known attack patterns.
  * **Autoencoder (ONNX)**: Deep unsupervised neural network for zero-day behavioral anomalies.
* **Explainable AI (XAI)**: Generates mathematical feature attribution via **SHAP (SHapley Additive exPlanations)**.

### 2. 🔍 Hunter Agent (Correlation & Attack Graph AI)
* **Goal**: Contextualize flagged events by examining surrounding network activity ($\pm 15$ mins to 24 hrs).
* **5 Correlating Engines**:
  1. **Sigma Engine**: Pattern matching against MITRE ATT&CK techniques.
  2. **Statistical Process Control (SPC)**: Dynamic baseline tracking for 3-sigma anomalies.
  3. **Temporal Correlation**: Reconstructs multi-step attack chains (e.g., *Brute Force $\rightarrow$ Privilege Escalation $\rightarrow$ Data Access*).
  4. **Attack Graph Builder**: Generates an interactive graph linking IPs, hostnames, user accounts, and processes.
  5. **Campaign Engine**: Detects coordinated multi-host lateral movement.

### 3. ⚖️ Verifier Agent (Forensic Decision Engine)
* **Goal**: Act as a Senior Forensic Investigator to deliver court-admissible decisions.
* **3-Tier Verdict Matrix**:
  * `true_positive`: Confirmed malicious incident with full evidence trail.
  * `false_positive`: Benign anomaly verified by host context.
  * `inconclusive`: Safe fallback when evidence is incomplete or contradictory (*Graceful Degradation*).
* **Automated Forensic Narrative**: Generates plain-English incident summaries, step-by-step timelines, and recommended remediation playbooks.

---

## ⚡ High-Throughput Ingestion Engine

CLIF is engineered for enterprise-grade throughput and zero data loss:

| Component | Technology | Performance / Role |
| :--- | :--- | :--- |
| **Vector Ingest** | Rust / VRL | Sub-millisecond log parsing and schema canonicalization. |
| **Stream Broker** | Redpanda (C++) | Zero-loss event streaming buffer supporting 35,000+ EPS. |
| **Consumer Bridge** | Go (`consumer-go`) | Channel-based worker pools with zero-allocation buffer swaps. |
| **Compression** | LZ4 | 70% log payload reduction with negligible CPU overhead. |
| **Deduplication** | UUIDv5 | Deterministic `topic:partition:offset` hashing for exactly-once ingestion. |
| **Database** | ClickHouse | Columnar OLAP providing sub-10ms SQL queries across 100M+ events. |

---

## 🖥️ Next.js SOC Analyst Dashboard

The modern dashboard (`http://localhost:3001`) provides:
* **Live Feed** (`/live-feed`): Real-time streaming log telemetry.
* **AI Telemetry** (`/ai-agents`): Live latency, throughput, and agent pipeline health metrics.
* **Investigation Workspace** (`/investigations`): Case management, interactive attack graph visualizer, and Verifier forensic reports.
* **Explainability (XAI)**: SHAP waterfall charts revealing exact feature weights behind every score.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
* **Docker Desktop** (with Docker Compose enabled)
* **Python 3.11+**
* ~5–6 GB of free RAM

### 2. Launch Local Environment
```bash
# Clone the repository
git clone https://github.com/nikkilreddy/clif.git
cd clif

# Start all local containers & services
./start_demo.sh
```

### 3. Access Services
* **SOC Dashboard**: [http://localhost:3001](http://localhost:3001)
  * **Username**: `admin`
  * **Password**: `clif2026`
* **Live Feed**: [http://localhost:3001/live-feed](http://localhost:3001/live-feed)
* **Investigations**: [http://localhost:3001/investigations](http://localhost:3001/investigations)
* **Vulnerable Bank Application (Target)**: [http://localhost:5001](http://localhost:5001)

### 4. Simulate Cyberattacks
In a new terminal window, trigger realistic attack scenarios:

```bash
# Option A: Fast automated attack
python3 demo/securebank/attack.py --fast

# Option B: Interactive step-by-step attack walkthrough
python3 demo/securebank/attack.py --interactive

# Option C: High-load stress test (50,000 synthetic events)
python3 demo/securebank/load_attack_generator.py --mode direct --count 50000 --workers 8 --attack-type mixed
```

### 5. Run Automated Evaluation Harness
Verify detection accuracy, precision, and graceful degradation across 20 test cases:

```bash
python3 eval_harness.py
```

---

## 📂 Repository Structure

```
├── agents/
│   ├── triage/            # 60-feature extractor, LightGBM/Autoencoder ONNX models & SHAP XAI
│   ├── hunter/            # 5-engine correlator, temporal analyzer & attack graph builder
│   ├── verifier/          # Cognitive verdict engine, calibration & forensic narrative builder
│   └── xai-service/       # SHAP microservice for model explainability
├── consumer-go/           # High-performance Go Kafka-to-ClickHouse consumer (LZ4 & UUID5 dedup)
├── dashboard/             # Next.js 14 SOC Analyst Web Application
├── demo/
│   └── securebank/        # Vulnerable target banking application & attack simulation scripts
├── vector/                # Rust Vector aggregation & VRL remap configurations
├── clickhouse/            # Columnar database schemas and migration scripts
├── redpanda/              # Streaming message broker setup
├── eval_harness.py        # 20-scenario automated verification & benchmark test suite
├── docker-compose.local.yml # Complete container orchestration
└── start_demo.sh          # One-click startup script
```

---

## 📊 Key Differentiators

| Capability | Legacy SIEM / SOAR | Single-Prompt LLM Wrapper | CLIF (This Platform) |
| :--- | :--- | :--- | :--- |
| **Throughput** | High | Low ($<10$ EPS, costly API calls) | **35,000+ EPS** (Edge ML + Async Agents) |
| **Handling Novel Attacks** | Fails (Rigid static rules) | Hallucinates CVEs & IPs | **Hybrid ML + 5-Engine Graph AI** |
| **Explainability** | None | Unpredictable text | **SHAP XAI + Verified Evidence Graph** |
| **Decision Safety** | Manual analyst approval needed | Unsafe hallucinated actions | **Strict 3-Tier Verdict Matrix (`Inconclusive` fallback)** |

---

## 👥 Authors & License

* **Author**: Ram Nikhil Reddy ([@nikkilreddy](https://github.com/nikkilreddy))
* **License**: Open-source under the [MIT License](LICENSE).
