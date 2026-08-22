# 🎬 CLIF — Official Hackathon Demo Video Script & Spoken Presentation
**Project:** CLIF (Cognitive Log Investigation Platform)  
**Repository:** [https://github.com/nikkilreddy/clif](https://github.com/nikkilreddy/clif)  
**Speaker:** Ram Nikhil Reddy ([@nikkilreddy](https://github.com/nikkilreddy))  
**Duration:** ~3 Minutes (180 Seconds)  
**Tone:** Confident, Clear, Authoritative, Steady Pace  

---

## 🎯 Demo Concept: The Attack & Defense Flow
1. **We act as the Threat Actor / Attacker** launching targeted attacks against **SecureBank** (our realistic banking web application).
2. As the attack runs, SecureBank emits real-time security events (recon, brute-force auth, SQL injection, database exfiltration).
3. **CLIF captures and streams these logs live via:**  
   `SecureBank` $\rightarrow$ `Vector (Rust)` $\rightarrow$ `Redpanda (Kafka stream)` $\rightarrow$ `Consumer-Go (LZ4 + UUID5)` $\rightarrow$ `ClickHouse`
4. **The 3 AI Agents (Triage $\rightarrow$ Hunter $\rightarrow$ Verifier)** autonomously score, investigate, build visual Attack Graphs, and issue forensic verdicts in real time.

---

## 🕒 Timeline & On-Screen Cues

| Time | Scene | On-Screen Action | Spoken Focus |
| :--- | :--- | :--- | :--- |
| **00:00 - 00:35** | 1. The Problem & Vision | Dashboard Home (`http://localhost:3001`) | Modern SOC alert fatigue (10k+ alerts/day, 45% false positives) |
| **00:35 - 01:10** | 2. Target SecureBank & Ingestion | SecureBank (`:5001`), Terminal (`attack.py`), Live Feed (`:3001/live-feed`) | Attacking SecureBank; logs captured live through Vector $\rightarrow$ Redpanda $\rightarrow$ Go Consumer $\rightarrow$ ClickHouse |
| **01:10 - 01:50** | 3. Triage ML & Hunter Graph | Dashboard `/investigations` $\rightarrow$ Zoom into Interactive Attack Graph | 60-feature ML ensemble & cross-host topological attack graph |
| **01:50 - 02:25** | 4. Verifier Forensic Verdict | Verifier Section (Verdict, Confidence & Narrative) | 3-tier verdict matrix (`True Positive`), XAI & Graceful degradation |
| **02:25 - 03:00** | 5. Automated Evaluation & Close | Terminal running `python3 eval_harness.py` | 20 test cases passing live with 100% precision; Why this wins |

---

## 🎙️ Complete Word-for-Word Spoken Script

---

### 📍 Scene 1: The Problem & The Vision (00:00 – 00:35)

🖥️ **What to Show on Screen:**
* Open browser at `http://localhost:3001` (Dashboard Home).
* Show the dark-mode SOC dashboard with active agent telemetry cards and live metric counters.

🗣️ **What to Speak:**
> *"Good morning judges and mentors.*
>
> *Every single day, enterprise Security Operations Centers receive over 10,000 security alerts. Over 45% of them are false alarms. Human analysts are drowning in alert fatigue, and as a result, real cyber breaches go undetected for months.*
>
> *Traditional SIEMs rely on rigid, hand-written IF-ELSE rules that break the moment an attacker modifies a payload. On the other hand, generic single-prompt LLM wrappers are too slow, expensive, and hallucinate fake CVEs.*
>
> *To solve this, we built **CLIF**—the Cognitive Log Investigation Platform.*
>
> *CLIF is an autonomous, three-agent SIEM system that ingests raw telemetry at line rate, correlates cross-host attack kill chains, and delivers court-admissible forensic verdicts in under sixty seconds."*

---

### 📍 Scene 2: Attacking SecureBank & High-Speed Data Pipeline (00:35 – 01:10)

🖥️ **What to Show on Screen:**
* Show **SecureBank** at `http://localhost:5001` (our vulnerable banking target).
* Show the **Live Feed** at `http://localhost:3001/live-feed`.
* Open a split terminal window alongside the browser and execute:
  ```bash
  python3 demo/securebank/attack.py --fast
  ```

🗣️ **What to Speak:**
> *"To demonstrate this live, we are going to act as the threat actor targeting our vulnerable banking application, **SecureBank**.*
>
> *In our terminal, we launch a real multi-stage attack: port reconnaissance, credential brute-forcing, SQL injection, and database exfiltration.*
>
> *Notice what happens on our Live Feed: SecureBank is continuously emitting raw security events.*
>
> *CLIF captures this firehose instantly through our high-speed ingestion pipeline:*
> *First, a Rust-native Vector engine normalizes the raw logs.*
> *Second, Redpanda buffers the stream with zero packet loss.*
> *Third, our custom Go batch consumer—utilizing zero-allocation buffers, LZ4 compression, and deterministic UUID5 deduplication—flushes records directly into ClickHouse at over 35,000 events per second."*

---

### 📍 Scene 3: The AI Intelligence Tier — Triage & Hunter (01:10 – 01:50)

🖥️ **What to Show on Screen:**
* Navigate to `http://localhost:3001/investigations`.
* Click and open the newly escalated investigation.
* Zoom in and pan across the interactive **Attack Graph**.

🗣️ **What to Speak:**
> *"Now, let's look at the brain of CLIF—our multi-agent AI pipeline.*
>
> *Step One is the **Triage Agent**. For every single event, it extracts 60 numerical features across seven domain layers in just ten microseconds. It runs a dual ONNX ensemble: supervised LightGBM for known attack signatures, and an unsupervised Deep Neural Autoencoder for zero-day behavioral anomalies.*
>
> *When an event exceeds our risk threshold, it escalates to Step Two: the **Hunter Agent**.*
>
> *Rather than looking at alerts in isolation, Hunter queries ClickHouse for surrounding context across the entire network. It uses five correlation engines—including Sigma rules, statistical 3-sigma anomalies, and temporal sequencing—to automatically construct this interactive **Attack Graph**.*
>
> *As you can see on screen, the graph visually links the attacker's external IP, the compromised admin account, and the target database table."*

---

### 📍 Scene 4: Verifier Forensic Verdict & Narrative (01:50 – 02:25)

🖥️ **What to Show on Screen:**
* Scroll down to the Verifier section.
* Highlight the **Verdict Badge** (`True Positive`), **Confidence Score** (`94%`), **Priority Level** (`P1 Critical`), and the **Explainable AI (XAI)** metrics.

🗣️ **What to Speak:**
> *"Step Three is the **Verifier Agent**, which acts like a Senior Forensic Investigator.*
>
> *It evaluates the coherence of the evidence and delivers a calibrated verdict: **True Positive, Priority 1 Critical, with a 94% confidence score**.*
>
> *Crucially, we built CLIF around the principle of **Graceful Degradation**. If logs are missing or contradictory, the system will never hallucinate an unsafe automated action—it safely issues an explicit `Inconclusive` verdict with wide confidence bounds.*
>
> *Furthermore, it generates this plain-English incident timeline and recommended remediation playbook, ready for tier-1 analysts or courtroom submission."*

---

### 📍 Scene 5: Evaluation Harness & Closing (02:25 – 03:00)

🖥️ **What to Show on Screen:**
* Switch full-screen to terminal and run:
  ```bash
  python3 eval_harness.py
  ```
* Show all 20 test cases passing with green checkmarks.

🗣️ **What to Speak:**
> *"Finally, we didn't just build a demo—we built an automated evaluation harness testing 20 distinct cyberattack and failure scenarios.*
>
> *As you can see in the terminal, all twenty test cases pass with 100% precision, zero alert fatigue, and full resilience against simulated tool outages.*
>
> *CLIF proves that by combining line-rate data engineering with cognitive multi-agent reasoning, we can replace hours of manual log digging with sub-minute forensic clarity.*
>
> *Thank you, and I am now ready for your questions!"*

---

## 🛠️ Pre-Recording Checklist:
1. Start local stack: `./start_demo.sh`
2. Open browser tabs:
   * Tab 1: `http://localhost:3001` (Dashboard Home)
   * Tab 2: `http://localhost:3001/live-feed` (Live Feed)
   * Tab 3: `http://localhost:3001/investigations` (Investigations)
   * Tab 4: `http://localhost:5001` (SecureBank)
3. Terminal ready: `python3 demo/securebank/attack.py --fast`
4. Terminal ready: `python3 eval_harness.py`
