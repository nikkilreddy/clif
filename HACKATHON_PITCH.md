# Cognitive Log Investigation Platform — Hackathon Presentation & Defense Brief

**Track:** Agents & Automation  
**Format:** Live Demo + Code Walkthrough + 2-Min Pitch  

---

## 1. Hour 02:00 Milestone: Prior-Art Check

| Existing Product | Link | Why We Differ (One Line) |
| :--- | :--- | :--- |
| **Microsoft Sentinel Copilot** | [learn.microsoft.com/en-us/azure/sentinel](https://learn.microsoft.com/en-us/azure/sentinel) | Relies on closed single-prompt LLM chat queries over cloud logs, whereas Cognitive Log Investigation Platform runs an autonomous 3-agent pipeline. |
| **Splunk SOAR** | [splunk.com/en_us/products/splunk-soar](https://www.splunk.com/en_us/products/splunk-soar.html) | Uses rigid, hand-coded if-else playbooks that break under unknown attacks, whereas Cognitive Log Investigation Platform uses an autonomous investigation loop with temporal graph reasoning. |
| **Torq Hyperautomation** | [torq.io](https://torq.io/) | Requires manual workflow node authoring, whereas Cognitive Log Investigation Platform autonomously orchestrates triage, investigation, and verification end-to-end. |

**Our 1-Line Differentiator:**  
> *Cognitive Log Investigation Platform replaces manual playbook authoring with a resilient, self-orchestrating 3-agent pipeline (Triage → Hunter → Verifier) delivering forensic verdicts at high event throughput with zero human intervention.*

---

## 2. Hour 03:00 Milestone: Idea Lock Pitch (1 Paragraph)

> *"Security Operations Centers (SOCs) receive over 10,000 alerts daily with a 45% false-positive rate, overwhelming human analysts and causing critical threats to be missed. Cognitive Log Investigation Platform is an autonomous agentic SIEM platform that ingests raw logs and orchestrates three specialized AI agents: Triage, Hunter, and Verifier. The system turns hours of manual log digging into sub-minute forensic decisions."*

---

## 3. The 2 Declared Constraints (Brief Section 04)

1. **Two Models, Not One:**
   - **Model 1 (Edge / High-Throughput):** 60-feature LightGBM (85%) + Autoencoder (15%) ONNX ensemble scoring 35k+ events/sec.
   - **Model 2 (Cognitive):** Multi-agent investigation and reasoning layer with Triage, Hunter, and Verifier agents.
2. **Handle Being Wrong & Graceful Degradation:**
   - Explicit 3-tier verdict matrix (`true_positive`, `false_positive`, `inconclusive`).
   - If investigation inputs conflict or are incomplete, the system reduces confidence and issues a safe `inconclusive` verdict instead of taking an unsafe automated action.

---

## 4. The 5 Mandatory Pitch Questions (Judges Score Directly on These)

### Q1: What problem, and who exactly has it?
**Answer:** Tier-1 & Tier-2 SOC (Security Operations Center) Analysts and Incident Responders who drown in 10,000+ daily noisy alerts with a 45% false-positive rate, taking hours to manually correlate fragmented logs across servers and networks.

### Q2: What is the non-obvious hard part?
**Answer:** Two interconnected challenges:
1. **Preventing ML Data Leakage:** Engineering a 60-feature extractor across 10 diverse log types that survived 7 rigorous rounds of leakage auditing (eliminating severity leaks, tautological SSH features, and train-test target contamination).
2. **Zero-Loss Streaming Orchestration:** Managing a high-throughput pipeline (Vector → Redpanda → ClickHouse) with UUID5 deterministic deduplication and sub-100ms query times at 35,000+ EPS.

### Q3: What did you build versus what did the API give you?
**Answer:** We built everything from scratch without relying on external prompt wrappers:
- Custom Rust Vector parsing & routing transform (`mega_transform.vrl`).
- Custom Go Kafka-to-ClickHouse consumer with asynchronous batch flush and zero-alloc buffer swap.
- Custom trained LightGBM + Autoencoder ONNX models and 60-feature extraction pipeline.
- Custom 5-engine Hunter investigation layer (Sigma, SPC anomaly, Graph, Temporal, Campaign).
   - A focused Next.js SOC dashboard for the live investigation flow.

### Q4: Why does this break if you remove the AI?
**Answer:** Without the AI pipeline:
1. The system collapses into a passive log bucket.
2. Raw firehose logs cannot be categorized, scored, or prioritized.
3. Cross-host attack kill-chains and dynamic entity anomalies (3-sigma baseline deviations) cannot be detected by static rule sets.
4. Alerts cannot be self-investigated or explained to analysts.

### Q5: What breaks at ten thousand users (or 1,000,000 EPS)?
**Answer:** 
1. **ClickHouse Memory Pressure:** High-concurrency queries across large raw-log volumes would exhaust RAM; production deployments would require partitioning, retention policies, and horizontal scaling.
2. **Kafka Partition Contention:** Partition rebalancing lag during burst ingest spikes (mitigated by increasing partition counts to 32+ and scaling Go consumer worker pools).

---

## 5. Live Demo Script (5-Minute Winning Flow)

1. **Minute 1: Ingestion & Live Firehose (The Scale)**
   - Show `Live Feed` page in the Next.js Dashboard.
   - Show logs streaming through Vector → Redpanda → ClickHouse in real-time.
2. **Minute 2: Multi-Agent Triage & Graph Investigation (The Agents)**
   - Open `/investigations` and select an active incident.
   - Show how the **Triage Agent** scored it (0.94), triggered the **Hunter Agent**, and built the **Attack Graph** linking the compromised workstation to the domain controller.
3. **Minute 3: Forensic Verification (The Decision)**
   - Show the **Verifier Agent** verdict (`true_positive`, `P1`) with its evidence summary and timeline.
4. **Minute 4: Analyst Review**
   - Use the investigation view to review the attack graph, correlated events, and final narrative.
5. **Minute 5: Automated Evaluation Harness (The Unfair Advantage)**
   - Run `python3 eval_harness.py` directly in the terminal to show all 20 test cases passing with 100% precision, 0% alert fatigue, and graceful degradation under tool failures.

---

## 6. Team Code Walkthrough Guide (Every Member Speaks)

* **Speaker 1 (Data Ingestion & Go Consumer):** Explains `vector/vector.yaml` and `consumer-go/main.go` (UUID5 deduplication, batch flush architecture).
* **Speaker 2 (Triage Agent & ML Ensemble):** Explains `agents/triage/feature_extractor.py` (60 features) and `model_ensemble.py` (LightGBM + Autoencoder ONNX score fusion).
* **Speaker 3 (Hunter & Verifier Agents):** Explains `agents/hunter/investigation/` (graph builder, temporal correlation) and `agents/verifier/verdict_engine.py` (decision matrix, calibration).
* **Speaker 4 (Dashboard & Demo):** Shows the live feed, investigation view, attack graph, and final verifier narrative.
