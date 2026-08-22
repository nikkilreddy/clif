# 🎬 CLIF — Hackathon Demo Video Script & Simulation Walkthrough
## Title: Autonomous 3-Agent SIEM & Cyber Forensics Pipeline
**Target Duration:** 2:30 – 3:00 Minutes  
**Speaker:** Ram Nikhil Reddy ([@nikkilreddy](https://github.com/nikkilreddy))

---

## 🎯 Demo Concept: The Attack & Defense Flow
In this live demonstration:
1. **We act as the Threat Actor / Attacker** launching targeted cyberattacks against **SecureBank** (our realistic banking web application).
2. As the attack unfolds, **SecureBank generates raw security logs** (brute-force failures, SQL injections, privilege escalations, database queries).
3. **CLIF captures and monitors these logs live** through the streaming path:  
   `SecureBank` $\rightarrow$ `Vector (Rust)` $\rightarrow$ `Redpanda (Stream)` $\rightarrow$ `Consumer-Go` $\rightarrow$ `ClickHouse`
4. **The 3 AI Agents (Triage $\rightarrow$ Hunter $\rightarrow$ Verifier)** autonomously catch, reconstruct, and explain the entire attack into visual attack graphs and forensic reports in real time!

---

## 🕒 Video Timeline & Screen Breakdown

| Time | Scene | On-Screen Action | Spoken Focus |
| :--- | :--- | :--- | :--- |
| **00:00 - 00:30** | 1. The Hook & The Problem | Dashboard Home (`http://localhost:3001`) | Modern SOC alert fatigue (10k+ alerts/day, 45% false positives) |
| **00:30 - 01:05** | 2. Target SecureBank & Live Ingestion | Split Screen: SecureBank (`:5001`), Terminal (`attack.py`), and Live Feed (`:3001/live-feed`) | Attacking SecureBank; logs captured live through Vector $\rightarrow$ Redpanda $\rightarrow$ Go Consumer $\rightarrow$ ClickHouse |
| **01:05 - 01:45** | 3. Triage AI & Hunter Attack Graph | Dashboard `/investigations` $\rightarrow$ Zoom into Interactive Attack Graph | 60-feature ML ensemble & cross-host topological attack graph |
| **01:45 - 02:20** | 4. Verifier Forensic Verdict & Narrative | Verifier Section (Verdict, Confidence & Narrative) | 3-tier verdict matrix (`True Positive`), XAI & Graceful degradation |
| **02:20 - 02:50** | 5. Automated Evaluation & Closing | Terminal running `python3 eval_harness.py` | 20 test cases passing live with 100% precision; Why this wins |

---

## 🎙️ Word-for-Word Spoken Script

---

### 📍 Scene 1: The Problem & The Solution (00:00 – 00:30)

🖥️ **What to Show on Screen:**
* Open browser at `http://localhost:3001` (Dashboard Home).
* Show the clean dark-mode SOC interface with active agent statuses and live telemetry counters.

🗣️ **What to Say:**
> *"Every single day, Security Operations Centers receive over 10,000 security alerts. Over 45% of them are false alarms. Human analysts drown in noise, while real cyberattacks take months to detect.*
>
> *Legacy SIEMs rely on rigid IF-ELSE rules that break under novel mutations, while generic LLM wrappers are too slow and hallucinate.*
>
> *We built **CLIF (Cognitive Log Investigation Platform)**—an autonomous 3-agent SIEM system that ingests raw logs at line rate, investigates cross-host attack kill chains, and delivers court-admissible forensic verdicts in under 60 seconds."*

---

### 📍 Scene 2: Attacking SecureBank & High-Speed Ingestion (00:30 – 01:05)

🖥️ **What to Show on Screen:**
* Open **SecureBank** at `http://localhost:5001` (the vulnerable banking target).
* Open the **Live Feed** at `http://localhost:3001/live-feed`.
* Open a split terminal alongside the browser and execute the attack script:
  ```bash
  python3 demo/securebank/attack.py --fast
  ```

🗣️ **What to Say:**
> *"To demonstrate this live, we act as the threat actor targeting our vulnerable banking application, **SecureBank**.*
>
> *As our attack script runs in the terminal—launching reconnaissance, brute-forcing admin credentials, and executing SQL injections—SecureBank continuously emits raw security events.*
>
> *CLIF captures and monitors this telemetry in real-time through our high-speed data flow path: from **Rust-native Vector**, into **Redpanda's distributed stream**, batched via our custom **Go consumer with LZ4 compression and UUID5 deduplication**, and stored directly into **ClickHouse** at over 35,000 events per second with zero data loss."*

---

### 📍 Scene 3: Triage ML & Hunter Attack Graph (01:05 – 01:45)

🖥️ **What to Show on Screen:**
* Navigate to **Investigations** (`http://localhost:3001/investigations`).
* Click and open the newly escalated investigation.
* Zoom in and pan across the **Interactive Attack Graph**.

🗣️ **What to Say:**
> *"Now let's see how our AI pipeline investigates what just happened:*
>
> *First, our **Triage Agent** extracts 60 numerical features per event in microseconds and runs an ONNX dual-model ensemble—combining supervised LightGBM with an unsupervised Deep Neural Autoencoder to catch both known attack patterns and zero-day payload anomalies.*
>
> *When an event is flagged as high-risk, it triggers our **Hunter Agent**. Rather than looking at alerts in isolation, Hunter queries ClickHouse for historical context across the entire network and dynamically constructs this **Attack Graph**—visually mapping how the attacker's external IP compromised the admin account and accessed sensitive customer financial records."*

---

### 📍 Scene 4: Verifier Agent & Forensic Decision (01:45 – 02:20)

🖥️ **What to Show on Screen:**
* Scroll down to the **Verifier Verdict & Forensic Report** section.
* Point out the **Verdict Badge**, **Confidence Score**, **Priority Level**, and **Explainable AI (XAI)** metrics.

🗣️ **What to Say:**
> *"Finally, our **Verifier Agent** acts like a Senior Forensic Investigator. It evaluates evidence coherence across the graph and produces a calibrated verdict: **True Positive, Priority 1 Critical, with a 94% confidence score**.*
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
> *CLIF bridges high-speed data engineering with cognitive multi-agent reasoning to build an autonomous SIEM that truly couldn't have existed two years ago. Thank you!"*

---

## 🛠️ Pre-Recording Checklist:
1. Ensure all local services are up: `./start_demo.sh`
2. Open tabs in browser:
   * Tab 1: `http://localhost:3001` (Dashboard Home)
   * Tab 2: `http://localhost:3001/live-feed` (Live Feed)
   * Tab 3: `http://localhost:3001/investigations` (Investigations)
   * Tab 4: `http://localhost:5001` (SecureBank)
3. Have a terminal ready with: `python3 demo/securebank/attack.py --fast`
4. Have a second terminal ready with: `python3 eval_harness.py`
