# CyberTrace — Backend Architecture & AI Investigation Engine

CyberTrace is an AI-assisted Security Operations Centre (SOC) incident investigation platform designed for defensive cybersecurity operations. It normalizes heterogeneous security logs into a Common Event Schema (CES), detects threats using deterministic rules, safeguards incident correlation, and empowers SOC analysts with evidence-grounded AI investigations powered by BharatCode.

---

## 1. Environment & BharatCode Configuration

Configure environment variables in `backend/.env` (see safe template at `backend/.env.example`):

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `BHARATCODE_API_KEY` | *(None / Empty)* | Secret API key for BharatCode (`https://bharatcode.ai/account`). Server-side only; never exposed via API or logs. |
| `BHARATCODE_BASE_URL` | `https://bharatcode.ai/api/model/v1` | Official BharatCode API endpoint root. |
| `BHARATCODE_MODEL` | `qwen-3.8-27b` | Primary inference model for security investigations. |
| `BHARATCODE_TIMEOUT_SECONDS` | `30.0` | Client HTTP timeout per request. |
| `BHARATCODE_MAX_TOOL_ROUNDS` | `5` | Maximum number of multi-turn function-calling iterations allowed. |
| `BHARATCODE_MAX_TOTAL_TOOL_CALLS` | `10` | Hard safety cap on cumulative tool executions per investigation. |
| `BHARATCODE_MAX_OUTPUT_TOKENS` | `4096` | Output token budget allocated to the model. |
| `DATABASE_URL` | `sqlite+aiosqlite:///cybertrace.db` | Async SQLAlchemy database connection string. |

> **Security Note:** Never commit `.env` or production API keys to Git. Use synthetic security logs for testing and evaluation.

---

## 2. Investigation Workflow

```
Security Logs (JSON / CSV / Syslog / Zeek / Windows)
        │
        ▼
Log Ingestion Pipeline (Auto-detection & CES Normalization)
        │
        ▼
Deterministic Detection Rules (DET-001 through DET-004)
        │
        ▼
Incident Correlation Engine (Entity & Temporal Safeguards)
        │
        ▼
Incident Evidence Dossier (Events, Detections, Entities)
        │
        ├──▶ [API Key Present & Responsive] ──▶ BharatCode AI Agent (Stateless Tool Loop)
        │                                             │
        │                                             ▼
        │                                    Server-Side Evidence Verifier
        │                                             │
        └──▶ [API Key Missing / HTTP 5xx / Timeout] ──┼─▶ Deterministic Fallback Engine
                                                      │
                                                      ▼
                                       Persistent AI Investigation Record
                                        (Stored in SQLite / Retrieved by API)
```

1. **Ingestion & Normalization:** Ingests raw logs into standardized CES format (`/api/v1/logs/upload`).
2. **Deterministic Rules:** Authority for security detections and severity (e.g. brute force, exfiltration).
3. **Correlation:** Connects related events into incidents with strict hub-node and public-IP safeguards.
4. **Investigation Trigger:** `POST /api/v1/incidents/{incident_id}/investigate` initiates the investigation.
5. **AI Reasoning / Tool Calling:** If configured, the BharatCode agent retrieves telemetry using allow-listed tools.
6. **Evidence Verification:** Server-side verifier inspects all returned event IDs, purging hallucinations.
7. **Deterministic Fallback:** If BharatCode is unconfigured or unavailable, heuristic synthesis ensures uninterrupted SOC utility.

---

## 3. Stateless Responses API & Multi-Turn Loop

CyberTrace integrates with BharatCode's `POST /responses` API adhering to these design rules:
- **`store: false`:** Mandatory on all requests to invoke BharatCode's stateless Responses API processing. This instructs the endpoint not to persist the conversation state or response object remotely, requiring CyberTrace to maintain and replay conversation history on each tool-calling iteration without relying on `previous_response_id`.
  *Data Protection Notice:* `store: false` governs client-managed API session orchestration; it does not independently guarantee zero data retention by external model inference providers or subprocessors. Real production security telemetry requires an appropriate provider privacy and data-handling review before transmission. For evaluations, CyberTrace recommends reproducible synthetic benchmark datasets.
- **No `previous_response_id`:** Conversation state is maintained entirely client-side.
- **Stateless Replay:** On each subsequent tool round, the agent replays the original conversation input, previous `response.output` items, and matching `function_call_output` items with identical `call_id`s.
- **Incomplete Detection:** Responses with `status == "incomplete"` and `reason == "max_output_tokens"` are aborted cleanly without executing partial or truncated tool calls.
- **Bounded Retries:** Automatic exponential backoff on transient HTTP 503 (busy) or HTTP 429 (rate-limited) responses.

---

## 4. Backend Read-Only Investigation Tools

Tools are strictly read-only and scoped to the authorized incident ID:

1. **`get_incident_timeline(incident_id: str)`**
   - Returns chronological, deterministic sequence of events and detections within the incident.
2. **`get_event_details(incident_id: str, event_ids: List[str])`**
   - Returns normalized fields for up to 20 requested event IDs. Rejects IDs outside incident boundaries.
3. **`get_detection_details(incident_id: str, detection_ids: List[str])`**
   - Retrieves rule explanation, severity, and triggering event links for specific detections.
4. **`query_entity_history(incident_id: str, entity_type: str, entity_value: str, limit: int, start_time: Optional[str] = None, end_time: Optional[str] = None)`**
   - Queries telemetry for specific users, hostnames, or IPs within the incident scope, with optional ISO-8601 inclusive temporal bounds (`start_time`, `end_time`). Bounded to max 20 events.

---

## 5. Structured Investigation Schema

The model returns structured output enforced by JSON schema:

```json
{
  "executive_summary": "Concise factual summary of the incident",
  "observed_facts": [
    {
      "statement": "Factual claim verified by telemetry",
      "event_ids": ["evt_001", "evt_002"]
    }
  ],
  "hypotheses": [
    {
      "statement": "Plausible attacker technique or intent",
      "supporting_event_ids": ["evt_001"],
      "contradicting_event_ids": [],
      "confidence": "low | medium | high",
      "caveats": ["Assumptions requiring verification"]
    }
  ],
  "unknowns": [
    {
      "question": "What crucial investigative question remains?",
      "reason": "Why telemetry is missing or inconclusive"
    }
  ],
  "recommended_actions": [
    {
      "action": "Defensive containment or remediation action",
      "rationale": "Evidence-based justification",
      "supporting_event_ids": ["evt_002"],
      "impact": "low | medium | high",
      "requires_human_approval": true
    }
  ],
  "limitations": [
    "Telemetry gaps or analytical constraints"
  ]
}
```

---

## 6. Deterministic Fallback Failover

When BharatCode AI is unconfigured (`BHARATCODE_API_KEY=""`), times out, or encounters errors (HTTP 400, 429, 503, token exhaustion, or malformed schema), CyberTrace automatically routes to `DeterministicFallbackEngine`:
- Derives observed facts from authoritative detection rule explanations.
- Constructs conservative, non-speculative hypotheses based on rule combinations.
- Formulates standard investigative unknowns and telemetry gap inquiries.
- Proposes human-approved containment recommendations.
- Persists record with `status: "fallback"` and `model_id: "deterministic-fallback"`.

---

## 7. Security, Trust & Safety Protections

- **Untrusted Telemetry Defense:** Event logs, usernames, and command lines are treated strictly as passive forensic evidence. The agent system prompt explicitly defends against prompt injection payloads embedded in logs.
- **Zero Hallucination Tolerance:** The `EvidenceVerifier` validates all event citations against database ground truth. Hallucinated or external event references are stripped.
- **Strict Human-in-the-Loop:** All defensive recommendations enforce `requires_human_approval: true`. The AI is never permitted to execute containment actions autonomously.
- **No Secret Exposure:** Secrets and API keys are isolated on the backend and omitted from API responses and database tables.

---

## 8. Asset & Identity Intelligence Engine (Phase 6.1)

CyberTrace extracts an authoritative observed asset and identity inventory directly from ingested security telemetry (`SecurityEventModel`):

- **Zero Fabricated Metadata:** All inventory records, event counts, and first/last seen timestamps originate strictly from genuine ingested events.
- **Canonical Entity Grouping:**
  - **Hostnames (UPPERCASE):** Grouped via `UPPER(TRIM(hostname))` so variants like `srv-app-01` and `SRV-APP-01` resolve to the single canonical entity `SRV-APP-01`.
  - **Identities (LOWERCASE):** Grouped via `LOWER(TRIM(username))` so accounts like `SVC_DEPLOY` and `svc_deploy` collapse into `svc_deploy`.
  - **IP Addresses:** Distinctly extracted across source and destination IP columns. An event featuring an identical IP in both source and destination is counted exactly once via `func.count(distinct id)`.
- **Global Pagination & Deterministic Sorting:** Candidates from hostnames and IPs are unified in a database-level subquery and ordered globally by `last_seen DESC, asset_value ASC, asset_type ASC` before applying `LIMIT` and `OFFSET`.
- **Entity Association Isolation:** Detections and incident entities match strictly against normalized entity names within their authorized entity namespaces (`host`/`hostname`, `ip`/`source_ip`/`destination_ip`, `user`), preventing substring or prefix bleed.
- **Truthful Provenance:** All asset and identity responses return `"provenance": "observed_telemetry"`.

---

## 9. Local Development & Testing Commands

### Run Full Test Suite (94 Passing Tests)
```bash
PYTHONPATH=backend backend/.venv/bin/pytest -c backend/pytest.ini backend/tests/ -v
```

### Run Phase 6.1 Asset & Identity Tests Only
```bash
PYTHONPATH=backend backend/.venv/bin/pytest -c backend/pytest.ini backend/tests/test_assets.py -v
```

### Run Phase 3 AI Engine Tests Only
```bash
PYTHONPATH=backend backend/.venv/bin/pytest -c backend/pytest.ini backend/tests/test_investigation.py -v
```

### Apply Database Migrations
```bash
cd backend
.venv/bin/alembic upgrade head
```

### Start Development Server
```bash
cd backend
.venv/bin/uvicorn app.main:app --reload --port 8000
```
