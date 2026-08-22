# Cognitive Log Investigation Platform — Engineering Failure Log

**Deliverable:** 1-Page Failure Log (Hackathon Tie-Breaker)  
**System:** Cognitive Log Investigation Platform  

---

## 1. What We Tried That Failed

### 💥 Failure 1: Monolithic LLM-First Log Triaging
* **What we tried:** Initially, we passed raw log batches directly to large language models (LLMs) to classify threats and write remediation scripts in a single prompt.
* **Why it failed:** 
  1. **Latency Bottleneck:** LLM response times averaged 4.2–12.0 seconds per batch, completely choking under real enterprise log volumes (10,000+ EPS).
  2. **Hallucination of Threat Indicators:** The model frequently hallucinated non-existent CVEs and confused benign internal IP ranges (`10.x.x.x`) with public malicious infrastructure.
* **The Fix:** Shifted to a tiered architecture: ultra-fast edge ONNX models (LightGBM + Autoencoder) handle sub-millisecond triage, and autonomous specialized agent loops only engage for escalated incidents (score ≥ 0.90).

### 💥 Failure 2: Seven Rounds of ML Data Leakage in Early Models (v1–v7)
* **What we tried:** Training initial tabular triage classifiers directly on aggregated benchmark datasets.
* **Why it failed:** During forensic model auditing, we discovered severe data leakage:
  - *Severity Leakage:* The `severity` field in training datasets directly correlated with labels, creating a false 99.9% accuracy that collapsed on real raw syslog streams.
  - *Tautological SSH Fail Features:* Feature extractors created circular dependencies on failure flags.
  - *Train/Test Split Contamination:* Over 55,000 overlapping IP entities crossed train and test splits.
* **The Fix:** Re-engineered feature extraction from scratch in **v8**, separating 60 clean orthogonal features across 7 independent layers with per-type zero-filling and strict out-of-time train/validation splits.

### 💥 Failure 3: Python-Based Kafka Consumer Bottleneck
* **What we tried:** Ingesting Kafka streams and writing to ClickHouse using an `aiokafka` Python consumer service.
* **Why it failed:** Python's Global Interpreter Lock (GIL) and memory allocation overhead capped ingestion throughput at **4,200 EPS**, causing severe consumer lag and packet drops during burst simulations.
* **The Fix:** Re-architected the ingestion consumer in **Go** (`consumer-go`) utilizing channel-based worker pools, zero-allocation buffer swaps, and LZ4 compressed batch writes, achieving **35,586 EPS** with zero consumer lag.

---

## 2. What Our System Still Gets Wrong (Current Limitations)

1. **"Low-and-Slow" Multi-Month APT Campaigns:**
   - *Limitation:* The Hunter agent currently operates within a temporal correlation window of ±15 minutes to 24 hours. Stealthy attackers rotating residential proxies once every 5 days stay below the current baseline anomaly threshold.
2. **Encrypted C2 over Standard HTTPS (Port 443):**
   - *Limitation:* Without TLS deep packet inspection (DPI), command-and-control traffic mimicking standard Google/AWS API calls has packet size and entropy distributions identical to legitimate web traffic.
3. **Internal Stress-Test False Spikes:**
   - *Limitation:* When developers run massive internal load-testing scripts without tagging traffic, the Statistical Process Control (SPC) engine flags sudden 5-sigma volume surges as potential DDoS attacks until the 60-second baseline window adapts.

---

## 3. What We Would Fix With Another Week

1. **Long-Term GraphRAG Memory:**
   - Extend the Hunter entity graph across a 90-day cold window using LanceDB + ClickHouse hybrid storage to uncover long-running Advanced Persistent Threat (APT) campaigns.
2. **Autonomous SOAR Rollback Guardrails:**
   - Add surgical auto-mitigation capabilities (e.g., dynamic firewall ACL injection, AWS IAM role revocation) paired with an automated rollback state machine if operational latency degrades.
3. **Continuous On-Device Local Evals:**
   - Integrate the `eval_harness.py` test suite directly into a CI/CD pre-commit hook that automatically prevents model weight promotion if precision drops below 95% or tool failure recovery fails.
