# 🛡️ CLIF (Cognitive Log Investigation Platform)
## Complete Architectural & Functional Specification Guide

---

## 1. Executive Summary

In modern enterprise cybersecurity, **Security Operations Centers (SOCs)** receive upwards of **10,000 to 100,000 alerts every single day**. Over **45% of these alerts are false positives**, causing severe alert fatigue, high operational costs, and catastrophic delays in identifying real cyberattacks.

**CLIF (Cognitive Log Investigation Platform)** is an autonomous, agentic SIEM and cyber forensics platform designed to eliminate manual log triage and investigation. 

### Core Capabilities:
* **High-Throughput Line-Rate Processing:** Ingests, normalizes, and filters enterprise logs at **35,000+ events per second (EPS)**.
* **Edge Machine Learning (Microsecond Scoring):** Extracts 60 statistical/behavioral features per event and evaluates them against dual LightGBM and Deep Neural Autoencoder models in $\approx 10\,\mu\text{s}$.
* **Autonomous Multi-Agent Forensics:** Connects isolated events across multiple hosts and services into an interactive **Attack Graph**.
* **Court-Admissible Forensic Verdicts:** Delivers calibrated verdicts (`True Positive`, `False Positive`, `Inconclusive`) with automated plain-English narratives and recommended remediation actions in under **60 seconds**.

---

## 2. The Problem & Why Existing Solutions Fail

| Traditional Approach | How It Operates | Why It Fails in Modern SOCs |
| :--- | :--- | :--- |
| **Legacy SIEM & SOAR** (Splunk, Sentinel, QRadar) | Rigid, hand-coded `IF-ELSE` rules and static regex playbooks. | **Breaks under novel attack variants.** Attackers easily bypass static rules with slight payload mutations. High rule maintenance burden. |
| **Single-Prompt LLM Wrappers** | Sends raw log text batches directly to an LLM (e.g. OpenAI / Claude) with a prompt. | **Too slow & expensive.** Response latencies of 5–15 seconds per batch cannot handle high EPS. Frequent hallucinations of non-existent CVEs and private IP addresses. |
| **CLIF (This System)** | **Tiered Hybrid Architecture**: Ultra-fast edge ML models handle high throughput; autonomous multi-agent cognitive loops engage only for suspicious incidents. | **Sub-millisecond filtering at 35k+ EPS**, 100% explainability via SHAP, dynamic cross-host graph correlation, and zero hallucinations. |

---

## 3. High-Level Architecture & End-to-End Flow

```
[ Application Servers / Firewalls / Active Directory ]
                          │
                          ▼ (Raw Syslog / JSON / HTTP Logs)
 ┌─────────────────────────────────────────────────────────────┐
 │ 1. INGESTION LAYER (Rust Vector)                            │
 │    • TCP/Syslog listeners                                   │
 │    • Vector Remap Language (VRL) Canonicalization           │
 └────────────────────────┬────────────────────────────────────┘
                          ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 2. STREAM BUFFER (Redpanda Distributed Cluster)             │
 │    • C++ native Kafka-compatible broker                     │
 │    • In-flight buffering guaranteeing zero packet loss      │
 └────────────┬────────────────────────────────────┬───────────┘
              │                                    │
              ▼                                    ▼
 ┌───────────────────────────┐    ┌───────────────────────────┐
 │ 3. CONSUMER-GO            │    │ 4. TRIAGE AGENT (ML)      │
 │    • Zero-alloc buffers   │    │    • 60-Feature Extractor │
 │    • LZ4 Compression      │    │    • LightGBM ONNX (85%)  │
 │    • UUID5 Deduplication  │    │    • Autoencoder (15%)    │
 └────────────┬──────────────┘    │    • SHAP XAI Explainer   │
              │                   └────────────┬──────────────┘
              ▼                                │ (Risk Score ≥ 0.70)
 ┌───────────────────────────┐                 ▼
 │ 5. CLICKHOUSE OLAP DB     │    ┌───────────────────────────┐
 │    • Columnar storage     │    │ 5. HUNTER AGENT           │
 │    • Sub-10ms queries     │◄───┤    • Temporal Correlator  │
 │    • Stores events, graphs│    │    • Sigma Rule Engine    │
 │      and forensic verdicts│    │    • SPC 3-Sigma Anomaly  │
 └────────────▲──────────────┘    │    • Attack Graph Builder │
              │                   └────────────┬──────────────┘
              │                                │ (Evidence & Graph)
              │                                ▼
              │                   ┌───────────────────────────┐
              │                   │ 6. VERIFIER AGENT         │
              └───────────────────┤    • Forensic Matrix      │
                                  │    • TP / FP / Inconclusive│
                                  │    • Plain Narrative Gen  │
                                  └────────────┬──────────────┘
                                               │
                                               ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 7. SOC ANALYST DASHBOARD (Next.js 14)                       │
 │    • Live Firehose Stream (/live-feed)                      │
 │    • AI Latency & Performance Telemetry (/ai-agents)        │
 │    • Visual Attack Graph Visualizer (/investigations)       │
 │    • Forensic Case Reports & Plain-English Explanations     │
 └─────────────────────────────────────────────────────────────┘
```

---

## 4. Deep Dive: The 3-Agent Cognitive Pipeline

CLIF separates fast statistical edge computation from multi-step cognitive reasoning across three specialized agents:

### ⚡ Agent 1: Triage Agent (The Edge Filter)
* **Directory**: `agents/triage/`
* **Purpose**: Inspects **every single incoming event** in real time and filters out benign noise.
* **Mechanism**:
  1. **60-Feature Extraction**: Converts unstructured log strings into a fixed 60-dimensional vector across 7 orthogonal layers:
     * **Layer 1: Shared Core (9 features)**: Time of day ($\sin/\cos$), off-hours indicator, log type ID, severity level, message length, message Shannon entropy.
     * **Layer 2: Network (15 features)**: Destination port bin, protocol number, byte count, byte ratio, packet count, packet ratio, flow duration, TCP flags (`SYN`, `RST`, `FIN`).
     * **Layer 3: Authentication (8 features)**: Login success/fail flag, admin status, remote vs local, historical failure rate, unique target count, event frequency.
     * **Layer 4: DNS (8 features)**: Domain length, domain Shannon entropy (DGA domain detection), subdomain depth, consonant runs, TLD risk score.
     * **Layer 5: Web / HTTP (7 features)**: URL length, query param count, SQL injection regex match (`has_sql_pattern`), XSS pattern match, directory traversal (`../`).
     * **Layer 6: Email (7 features)**: Subject/body length, caps ratio, urgency indicators, financial keywords.
     * **Layer 7: Cloud / API (6 features)**: Sensitive cloud service calls, error flags, identity type, root account usage.
  2. **Dual-Model ONNX Inference**:
     * **LightGBM (ONNX)**: Supervised tree model detecting known attack signatures.
     * **Neural Autoencoder (ONNX)**: Deep unsupervised neural network detecting zero-day behavioral anomalies.
  3. **Score Fusion**: Produces an anomaly score `[0.000 - 1.000]`.
  4. **XAI (Explainable AI)**: Uses `shap_explainer.py` to calculate exact mathematical contributions of each feature to the final score.

---

### 🔍 Agent 2: Hunter Agent (The Correlator & Graph Engine)
* **Directory**: `agents/hunter/`
* **Purpose**: Contextualizes suspicious alerts by gathering surrounding activity across all network hosts.
* **Mechanism**:
  1. **Temporal Querying**: Pulls historical log context ($\pm 15$ minutes to 24 hours) from ClickHouse around the affected host and IP addresses.
  2. **5 Specialized Investigation Engines**:
     * **Sigma Engine**: Scans logs for MITRE ATT&CK technique signatures.
     * **SPC Engine (Statistical Process Control)**: Measures deviation from historical baselines to flag 3-sigma anomalies.
     * **Temporal Chain Engine**: Connects causal sequences (e.g. `Brute Force` $\rightarrow$ `Successful Admin Login` $\rightarrow$ `Database Dump`).
     * **Campaign Engine**: Identifies if multiple hosts are being probed by the same attacker infrastructure.
     * **Attack Graph Engine (`attack_graph.py`)**: Constructs a topological graph node-by-node, linking IPs, hostnames, user accounts, and executed process binaries.

---

### ⚖️ Agent 3: Verifier Agent (The Forensic Decision Engine)
* **Directory**: `agents/verifier/`
* **Purpose**: Acts as a Senior Forensic Investigator to validate evidence and deliver calibrated verdicts.
* **Mechanism**:
  1. **Forensic Decision Matrix**:
     * `true_positive`: Confirmed malicious threat with unambiguous evidence.
     * `false_positive`: Benign operational spike verified by historical baseline.
     * `inconclusive`: Safe fallback when evidence is incomplete or contradictory (*Graceful Degradation*).
  2. **Priority Assignment**: Assigns urgency from `P1 (Critical)` to `P4 (Low)`.
  3. **Narrative & Report Builder (`report_builder.py`)**: Generates an executive summary, chronological attack timeline, and actionable remediation steps in plain English.

---

## 5. High-Speed Data Engineering Stack

| Component | Technology | Implementation Details |
| :--- | :--- | :--- |
| **Vector Ingest** | Rust / VRL | Listens on TCP 1514/9514, parses Syslog RFC 5424 and JSON, and normalizes fields with zero CPU drag. |
| **Redpanda** | C++ (Kafka-compatible) | High-throughput distributed message queue buffering up to 35,000+ EPS with zero message loss. |
| **Consumer-Go** | Go 1.22 | Custom streaming consumer with worker pools, zero-allocation buffers, and LZ4 compression. |
| **UUIDv5 Deduplication** | Go / SHA-1 | Generates deterministic UUIDs from `topic:partition:offset` coordinates to guarantee exactly-once storage. |
| **ClickHouse** | Columnar OLAP DB | Stores raw logs, features, attack graphs, and forensic verdicts with sub-10ms query execution across 100M+ rows. |

---

## 6. How One Security Event Flows Through CLIF

```
1. Attacker sends SQL injection payload (' OR 1=1 --) to SecureBank.
2. SecureBank logs the HTTP event to Vector.
3. Vector extracts timestamp, client IP, URL, and headers, sending JSON to Redpanda.
4. Consumer-Go receives the event, hashes its offset into UUID5, and batch-inserts it into ClickHouse.
5. Triage Agent extracts 60 numerical features:
   - has_sql_pattern = 1.0
   - url_entropy = 4.82
   - is_off_hours = 1.0
6. LightGBM + Autoencoder score the event at 0.94 (Escalate).
7. Hunter Agent searches ClickHouse for related activity from that IP over the past 30 minutes.
8. Hunter builds an Attack Graph: Attacker IP -> Web Server -> Database Server -> Data Table.
9. Verifier Agent checks evidence coherence, issues a True Positive / P1 verdict, and generates a plain-English timeline.
10. The SOC Dashboard displays the live alert, attack graph, and forensic narrative instantly.
```

---

## 7. Running the Platform Locally

### Step 1: Start All Services
```bash
./start_demo.sh
```

### Step 2: Open Dashboard Pages
* **Dashboard Home**: [http://localhost:3001](http://localhost:3001) (User: `admin` / Password: `clif2026`)
* **Live Feed**: [http://localhost:3001/live-feed](http://localhost:3001/live-feed)
* **Investigations & Attack Graphs**: [http://localhost:3001/investigations](http://localhost:3001/investigations)
* **Vulnerable Bank Application**: [http://localhost:5001](http://localhost:5001)

### Step 3: Run Attack Simulation
```bash
# Automated attack run
python3 demo/securebank/attack.py --fast

# Interactive step-by-step attack simulation
python3 demo/securebank/attack.py --interactive
```

### Step 4: Automated Verification Suite
```bash
python3 eval_harness.py
```

---

## 8. Summary of Differentiators

* **Autonomous vs Manual**: Replaces manual alert review with autonomous multi-agent reasoning.
* **Line-Rate Throughput**: 35,000+ EPS handling via Rust, Go, and ONNX runtime.
* **Explainability**: Mathematically transparent decisions powered by SHAP and interactive visual attack graphs.
* **Safe Decision Making**: Built-in `inconclusive` state prevents harmful automated actions when data is uncertain.
