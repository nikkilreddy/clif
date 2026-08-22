# 🎬 CLIF — Hackathon Demo Video Script
## Title: Autonomous 3-Agent SIEM & Cyber Forensics Pipeline
**Target Duration:** 2:30 – 3:00 Minutes  
**Speaker:** Ram Nikhil Reddy ([@nikkilreddy](https://github.com/nikkilreddy))

---

## 🕒 Video Timeline & Screen Walkthrough

| Time | Scene | On-Screen Action | Spoken Focus |
| :--- | :--- | :--- | :--- |
| **00:00 - 00:30** | 1. The Hook & The Problem | Next.js Dashboard Home (`:3001`) | Modern SOC alert fatigue (10k+ alerts/day, 45% false positives) |
| **00:30 - 01:05** | 2. Ingestion & Live Firehose | Split Screen: Dashboard `/live-feed` + Terminal running `attack.py` | Rust Vector + Redpanda + Go Consumer at 35,000+ EPS |
| **01:05 - 01:45** | 3. Triage & Hunter Graph | Dashboard `/investigations` $\rightarrow$ Interactive Attack Graph | 60-feature ML ensemble & Cross-host topological attack graph |
| **01:45 - 02:20** | 4. Verifier Forensic Verdict | Verifier Section (Verdict, Confidence & Narrative) | 3-tier verdict matrix (`True Positive`), XAI & Graceful degradation |
| **02:20 - 02:50** | 5. The Eval Harness & Close | Terminal running `python3 eval_harness.py` | 20 test cases passing live; why this wins the hackathon |

---

## 🎙️ Word-for-Word Script

---

### 📍 Scene 1: The Problem & The Vision (00:00 – 00:30)

🖥️ **What to Show on Screen:**
* Open browser at `http://localhost:3001` (Dashboard Home).
* Show the clean dark-mode SOC interface with live metric counters.

🗣️ **What to Say:**
> *"Every single day, Security Operations Centers receive over 10,000 security alerts. Over 45% of them are false alarms. Human analysts drown in noise, while real cyberattacks take months to detect.*
>
> *Legacy SIEMs rely on rigid IF-ELSE rules that break under novel mutations, while generic LLM wrappers are too slow and hallucinate.
>
> *We built **CLIF (Cognitive Log Investigation Platform)**—an autonomous 3-agent SIEM system that ingests raw logs at line rate, investigates cross-host attack kill chains, and delivers court-admissible forensic verdicts in under 60 seconds."*

---

### 📍 Scene 2: High-Speed Ingestion & Live Attack Simulation (00:30 – 01:05)

🖥️ **What to Show on Screen:**
* Navigate to `http://localhost:3001/live-feed`.
* Open a split terminal alongside the browser and execute:
  ```bash
  python3 demo/securebank/attack.py --fast
  ```

🗣️ **What to Say:**
> *"Here on our **Live Feed**, logs are streaming in real-time. Our pipeline is powered by a high-throughput engine built in **Rust with Vector** and **Redpanda**, using a custom **Go batch consumer** with LZ4 compression and UUID5 deduplication—capable of processing over 35,000 events per second with zero data loss.*
>
> *In our terminal, we launch a real multi-stage attack against our banking target—starting with reconnaissance, brute-forcing admin credentials, and executing SQL injection."*

---

### 📍 Scene 3: Triage ML & Hunter Attack Graph (01:05 – 01:45)

🖥️ **What to Show on Screen:**
* Click on **Investigations** (`http://localhost:3001/investigations`).
* Open the newly generated high-severity investigation.
* Zoom and pan across the **Interactive Attack Graph**.

🗣️ **What to Say:**
> *"Notice what happens under the hood:
>
> *First, our **Triage Agent** extracts 60 numerical features in microseconds and runs an ONNX dual-model ensemble—combining supervised LightGBM with an unsupervised Deep Neural Autoencoder to catch both known attacks and zero-day anomalies.*
>
> *When an event is flagged, it triggers our **Hunter Agent**. Rather than treating alerts in isolation, Hunter queries ClickHouse for surrounding temporal context across the entire network and dynamically constructs this **Attack Graph**—visually connecting the attacker's external IP, the compromised user account, and the target database table."*

---

### 📍 Scene 4: Verifier Agent & Forensic Decision (01:45 – 02:20)

🖥️ **What to Show on Screen:**
* Scroll down to the **Verifier Verdict & Forensic Report** section.
* Hover over the **Confidence Score**, **Priority Badge**, and **Explainable AI (XAI)** metrics.

🗣️ **What to Say:**
> *"Finally, our **Verifier Agent** acts like a Senior Forensic Investigator. It evaluates evidence coherence and produces a calibrated verdict: **True Positive, Priority 1 Critical, with a 94% confidence score**.
>
> *Crucially, if evidence is contradictory or missing, the system gracefully degrades and issues an explicit `Inconclusive` verdict instead of hallucinating dangerous automated actions.*
>
> *It also generates this plain-English forensic narrative and step-by-step timeline, ready for human analysts or courtroom submission."*

---

### 📍 Scene 5: Automated Evaluation Harness & Closing (02:20 – 02:50)

🖥️ **What to Show on Screen:**
* Switch full-screen to terminal and run:
  ```bash
  python3 eval_harness.py
  ```
* Show all 20 test cases passing with green checkmarks.

🗣️ **What to Say:**
> *"To prove reliability, we built an automated evaluation harness testing 20 distinct cyberattack scenarios. As you can see, every test passes with 100% precision, zero alert fatigue, and robust error recovery.*
>
> *CLIF combines sub-millisecond data engineering with cognitive multi-agent reasoning to build something that truly couldn't have existed two years ago. Thank you!"*

---

## 💡 Quick Tips for Recording:
1. **Screen Resolution:** Record in 1080p (1920x1080) for sharp text.
2. **Audio:** Speak clearly with a confident, steady pace.
3. **Pre-check:** Ensure `./start_demo.sh` is running in the background before hitting record so all pages load instantly!
