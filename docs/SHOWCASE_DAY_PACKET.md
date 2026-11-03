# CyberTrace — BharatCode Showcase Day Packet (Offline Guide)

**Showcase Date:** November 5, 2026 (8:00 PM – 9:00 PM IST)  
**Target Window:** 4-Minute Presentation + 3-Minute Technical Jury Q&A  
**Measured Duration:** **3m 30.1s** (with a **29.9s safety buffer**)  
**Codebase Baseline:** `main` at commit [`1024c6f`](https://github.com/PrathviSahu/CyberTrace/commit/1024c6f) (Strict Build Freeze)  

---

## 1. Operational Pre-Flight Checklist (15 Minutes Before Demo)

### A. Window Arrangement
- **Left 65% of screen:** Google Chrome at `http://localhost:5173/` (Full height, 100% zoom).
- **Right 35% of screen:** Terminal window pre-staged in `/Users/snehasahu/Desktop/CyberTrace`.

### B. Cold Start Verification
If restarting machines or terminal sessions before the presentation:
```bash
# Terminal 1: Backend Daemon
cd "/Users/snehasahu/Desktop/CyberTrace /backend" || exit 1
DATABASE_URL="sqlite+aiosqlite:////Users/snehasahu/Desktop/CyberTrace /backend/cybertrace_showcase.db" .venv/bin/uvicorn app.main:app --port 8000

# Terminal 2: Frontend Dev Server
cd "/Users/snehasahu/Desktop/CyberTrace /frontend" || exit 1
npm run dev
```

### C. Bulletproof Database Reset (Between Rehearsals / Demos)
Run this command from inside the backend directory to reset the database to pristine baseline:
```bash
cd "/Users/snehasahu/Desktop/CyberTrace /backend" || exit 1
DB_PATH="$(pwd)/cybertrace_showcase.db"
rm -f "$DB_PATH"
DATABASE_URL="sqlite+aiosqlite:///$DB_PATH" .venv/bin/alembic upgrade head
curl -s -X POST http://127.0.0.1:8000/api/v1/logs/upload \
  -F "file=@app/data/sample_logs/multi_stage_attack.json" | jq .status
```
**Expected baseline state:**
- `saved_hunts`: 0
- `detection_rule_drafts`: 0
- `active_detection_rules`: 0
- `rule_code_allocators`: `custom_rule` at 0 (next rule will strictly be `CUST-001`)
- `incidents`: 1 (`inc_3026773198`)

---

## 2. Calibrated Spoken Script & Presenter Action Guide (3:30 Total)

### Segment 1: Command Centre & Provenance Transparency (Target: ~44s)
- **Visual Action:** Open `http://localhost:5173/`. Point cursor to the provenance badge in the header. Click on base incident `inc_3026773198`.
- **Spoken Words:**
  > *"Welcome to CyberTrace — an AI-assisted SOC and detection engineering platform built for defensible security operations. We start here in our Command Centre with real-time processing of incoming security telemetry.*  
  > *Notice our data provenance badge: in CyberTrace, provenance is a core trust guarantee. Because our baseline sample log lacks verified cryptographic collector attribution, it is truthfully classified as Unknown Provenance rather than making unverified claims.*  
  > *In our active incidents feed, we immediately spot high-severity incident `inc_3026773198`, involving compromised user `svc_deploy` and attacker IP `198.51.100.44`. Let's see how our analyst hunts for adversary persistence."*

### Segment 2: Threat Hunting & Query AST (Target: ~50s)
- **Visual Action:** Click **Threat Hunting** in sidebar. Select preset `"Service Account Remote Access"`. Click **"Execute Hunt"**. Click **"Inspect"** on first event to show Evidence Drawer. Click `X` to close drawer. Click **"Save Hunt"**, type name `"C2 Beaconing to External Staging Host"`, and click **"Save Threat Hunt"**.
- **Spoken Words:**
  > *"When a security analyst suspects lateral movement, they transition into Threat Hunting to query normalized Common Event Schema telemetry.*  
  > *Instead of fragile raw queries, CyberTrace provides a structured AST filter. We select our preset for Service Account Remote Access targeting `svc_deploy`.*  
  > *We click 'Execute Hunt' — and in just 5 milliseconds, the matching telemetry is returned. Clicking 'Inspect' slides out our evidence drawer showing normalized CES attributes.*  
  > *Closing the drawer, we click 'Save Hunt' to persist this query definition into our catalog as candidate rule C2 Beaconing to External Staging Host."*

### Segment 3: ThreatLab Benchmark Replay (Target: ~44s)
- **Visual Action:** Click **ThreatLab** in sidebar. Click **"SCN-004"** scenario card. Click **"Replay SCN-004"**.
- **Spoken Words:**
  > *"Before any detection rule is activated in live ingestion, how do we evaluate baseline noise and false positive risks? CyberTrace integrates ThreatLab directly into the platform.*  
  > *We select benchmark scenario SCN-004 — a ground-truth benign administrative baseline.*  
  > *We click 'Replay SCN-004'. In under 2 milliseconds, the replay evaluates the baseline, verifying zero false positives in this run. ThreatLab provides empirical ground truth before promoting candidate rules."*

### Segment 4: Four-Eyes Rule Governance Workflow (Target: ~46s)
- **Visual Action:** Click **Detection Rules** in sidebar. Switch to right terminal and execute:  
  `backend/.venv/bin/python backend/demo_lifecycle.py --url http://127.0.0.1:8000`  
  Highlight the `HTTP 403 FORBIDDEN` self-approval rejection in terminal. Switch back to browser, refresh, click **"Active Rules"** tab to show `CUST-001`, then click **"Audit Ledger"** tab to show the SHA-256 state hash.
- **Spoken Words:**
  > *"Now for our core detection engineering breakthrough: four-eyes rule lifecycle governance. In Detection Rules, we promote our saved hunt into a candidate draft.*  
  > *Our four-eyes state machine strictly prevented self-approval by author Alice. Upon independent peer review by Lead Bob, the engine atomically allocated canonical rule code CUST-001.*  
  > *Now CUST-001 is active in CyberTrace's runtime detection engine, and every transition is recorded in our append-only Governance Audit Ledger with SHA-256 state hashing."*

### Segment 5: Incident Workspace & AI Triage (Target: ~26s)
- **Visual Action:** Click **Command Centre** (`/`) to show the newly correlated incident card. Click into the new incident to open the Incident Workspace. Show the Dagre interactive Attack Graph with the `CUST-001` node and AI investigation brief below.
- **Spoken Words:**
  > *"Returning to Command Centre, newly ingested telemetry triggers CUST-001, dynamically correlating into a new high-severity incident.*  
  > *In Incident Workspace, the interactive graph correlates CUST-001 with the compromised deployment account, while the AI assistant synthesizes evidence and proposes containment actions. That is CyberTrace. Thank you."*

---

## 3. Calibrated Technical Judge Q&A Cheat Sheet

| Question | Calibrated Answer |
| :--- | :--- |
| **Deterministic vs. AI?** | *"Our deterministic detection engine produces repeatable, rule-based results. AI is used separately for evidence-grounded investigation and contextual analysis. This separation means an AI-generated explanation does not independently determine whether an alert fires or whether a rule becomes active."* |
| **Real vs. Synthetic Telemetry?** | *"We classify provenance as observed, synthetic benchmark, unknown, or mixed. Generic uploads cannot claim observed status just by including collector metadata; without an authenticated collector session, uploads remain unknown."* |
| **Are benchmarks real attacks?** | *"ThreatLab scenarios are synthetic benchmarks modeled on MITRE ATT&CK patterns. Zero false positives on SCN-004 reflects that specific benchmark run under controlled conditions, not a blanket production guarantee."* |
| **Can AI activate rules?** | *"No. The AI assistant operates strictly in a read-only advisory capacity. Rule activation requires independent human peer approval through our four-eyes state machine."* |
| **How does Four-Eyes work?** | *"A draft is created and validated; a separate reviewer must approve it. The approval is cryptographically bound to the draft revision and AST hash. Demo identities are verified caller-supplied identities rather than enterprise SSO tokens."* |
| **Is the audit ledger immutable?** | *"It is an application-level append-only ledger with SHA-256 state hashing. It provides change integrity within the application, but is not hardware WORM storage."* |
| **Does rule activation block attackers?** | *"No. Activation enables the rule within CyberTrace's internal detection engine. It generates correlated alerts and containment recommendations requiring analyst approval; it does not reconfigure endpoint firewalls."* |
| **Model Outage Resilience?** | *"If external models time out or are unreachable, CyberTrace fails over instantaneously to the internal Deterministic Fallback Engine with sub-second in-memory execution (typically under 5ms)."* |

---

## 4. Offline Contingency Protocols

1. **If the internet drops or AI provider is slow:**
   - Do nothing! CyberTrace automatically detects the timeout/error and triggers the `DeterministicFallbackEngine`.
   - The UI displays `[Deterministic Heuristic Synthesis]` with observed facts, conservative hypotheses, unknowns, and human-authorized actions. Mention this resilience during Q&A.
2. **If a click misses or modal sticks:**
   - Press the browser Refresh button (`Cmd+R` / `F5`).
   - All state is persisted in SQLite; the page restores cleanly.
3. **If you have extra time:**
   - **Do NOT add new topics.** Use the remaining ~30 seconds for a relaxed cadence, pausing after key milestones (`HTTP 403` block, `CUST-001` graph rendering).
