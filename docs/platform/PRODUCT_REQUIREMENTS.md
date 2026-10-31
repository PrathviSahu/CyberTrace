# CyberTrace — Product Requirements Document (PRD)
## AI-Native Security Operations and Threat Intelligence Platform

---

## 1. Executive Summary & Product Vision

### 1.1 Product Vision
**CyberTrace** is an AI-native Security Operations Centre (SOC) incident investigation and threat intelligence platform designed for defensive cybersecurity teams. It transforms disconnected, heterogeneous security telemetry into correlated, evidence-backed incident investigations, enabling security analysts to rapidly comprehend complex attack sequences, evaluate detection coverage, hunt for related threats, and coordinate human-approved defensive response.

CyberTrace is engineered as a **functional defensive cybersecurity system**, not a generic chatbot or a cosmetic dashboard with simulated numbers. Every alert, correlation, graph node, and AI finding is anchored in verifiable forensic evidence.

### 1.2 Target Personas

| Persona | Primary Needs & Pain Points | Key CyberTrace Capabilities Utilized |
| :--- | :--- | :--- |
| **Tier 1 SOC Analyst** | Overwhelmed by alert fatigue and disjointed logs; needs fast triage, plain-English synthesis, and immediate access to underlying evidence. | Alert Inbox, Incident Workspace, AI Investigation Summaries, Verified Fact Inspection. |
| **Tier 2 Incident Responder** | Needs full attack timeline reconstruction, blast-radius analysis, entity pivoting, and defensive containment options. | Attack Graph Explorer, Entity History, Response Playbook Simulation, Case Management. |
| **Detection Engineer** | Struggles with rule drift, false-positive spikes, and untracked rule coverage; requires Detection-as-Code and reproducible testing. | Detection Engineering (Sigma subset), ThreatLab Replay Studio, MITRE ATT&CK Mapping. |
| **SOC Lead / Manager** | Requires visibility into team workload, mean-time-to-investigate (MTTI), coverage blind spots, and AI model accuracy. | Command Centre, Model Benchmark Evaluation, Audit Logs, Case Assignment Metrics. |
| **Security Administrator** | Demands rigorous access controls, tenant isolation, zero accidental data leakage, and compliance auditability. | Platform Administration, Role-Based Access Control (RBAC), Secrets Isolation, Telemetry Redaction. |

### 1.3 Core Product Principles & Non-Negotiables
1. **Deterministic Rule Sovereignty:** Deterministic detection rules remain the authoritative source of truth for detections, triggering entities, and incident severity. Generative AI models are strictly prohibited from altering rule definitions, elevating incident severity, or overriding engine detections.
2. **Strict Factual Grounding & Zero Hallucination Tolerance:** The platform rejects manufactured claims. Every observed fact in an investigation must cite an existing, verified event ID belonging strictly to that incident. Unsupported claims are aggressively purged or labeled.
3. **Untrusted Telemetry & Prompt Injection Resistance:** All event logs, usernames, process command lines, domains, and HTTP payloads are treated as untrusted external inputs. The system instructs and constrains AI models to treat logs purely as passive forensic evidence, never as executable instructions.
4. **Mandatory Human-in-the-Loop Response:** All recommended containment, remediation, and isolation actions require explicit human analyst sign-off (`requires_human_approval: true`). CyberTrace never performs autonomous destructive containment on production infrastructure.
5. **Transparency in Operational Metrics:** Operational metrics, coverage scores, and benchmark statistics must originate from genuine stored telemetry or explicitly tagged synthetic benchmarks. Artificial or fabricated numbers are strictly banned.

---

## 2. Current Baseline & Phase 3 Audit Remediation

### 2.1 Current Working State (Phase 1 through Phase 3)
- **Phase 1 (Committed `9b9ca75`):** Common Event Schema (CES), multi-format log ingestion pipeline (Generic JSON, CSV, Linux Syslog, Windows Security Event Log, Zeek Connection logs), deterministic rules (`DET-001` through `DET-004`), and reproducible synthetic benchmarks.
- **Phase 2 & 2.1 (Committed `60b1ab4`):** Async SQLite persistence (SQLAlchemy 2.0), Alembic migrations, correlation engine with hub-node and public-IP safeguards, idempotent event upserts, and `POST /api/v1/logs/upload` HTTP ingestion.
- **Phase 3 (Implemented, 63/63 Tests Passing):** BharatCode AI investigation engine integration (`qwen-3.8-27b`), stateless Responses API client with conversation replay, read-only analytical tools, server-side `EvidenceVerifier`, `DeterministicFallbackEngine`, and `ai_investigations` persistence.

### 2.2 Phase 3 Read-Only Audit Findings (To be remediated in Phase 3.1)
The platform expansion builds on the Phase 3 audit findings:
1. **Stateless Multi-Round Replay Testing:** While single-turn and 1-round tool loops are thoroughly tested, an automated integration test executing $\ge 2$ consecutive tool-calling rounds must be formalized to ensure continuous accumulated history integrity across multi-turn exchanges.
2. **Stricter Unsupported Claim Handling:** `EvidenceVerifier` currently strips invalid IDs from hypotheses and recommended actions, leaving statements intact with empty citation lists. Phase 3.1 will enforce that hypotheses or actions left with zero verified citations are omitted or flagged as analytical gaps.
3. **Entity History Time Bounds:** The `query_entity_history` tool currently lacks `start_time` and `end_time` parameters in both its JSON schema and execution logic. These bounds must be added and validated.
4. **Data Retention Precision:** Documentation in `README.md` must accurately clarify that `store: false` ensures stateless client-managed requests without guaranteeing zero retention across third-party inference partners.

---

## 3. Comprehensive Feature Catalogue (12 Core Modules)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               CYBERTRACE UNIFIED PLATFORM                                     │
├─────────────────┬──────────────────────┬────────────────────────┬──────────────────────────────┤
│ 1. Command      │ 2. Detection         │ 3. Threat Hunting      │ 4. Asset & Identity          │
│    Centre       │    Engineering       │    • Safe Query Builder│    • Hardware / Hosts        │
│    • Overview   │    • Detection-as-Code│   • Entity Pivoting   │    • User & Service Accounts │
│    • Alert Inbox│    • Sigma Subset    │    • Saved Searches    │    • Identity Risk Scores    │
│    • Metrics    │    • ATT&CK Matrix   │    • Hunting Sessions  │    • Criticality Tiers       │
├─────────────────┼──────────────────────┼────────────────────────┼──────────────────────────────┤
│ 5. Threat       │ 6. Attack Graph      │ 7. AI Investigation    │ 8. CyberTrace ThreatLab      │
│    Intelligence │    • Interactive BFS │    • Model Router      │    • Scenario Replay Harness │
│    • IOC Feeds  │    • Blast-Radius    │    • Specialist Roles  │    • Confusion Matrix (P/R/F1│
│    • Provenance │    • Edge Taxonomy   │    • Evidence Verifier │    • Missed Detections       │
│    • IP/Domain  │    • Time Travel Nav │    • Fallback Failover │    • Rule Diff Evaluator     │
├─────────────────┼──────────────────────┼────────────────────────┼──────────────────────────────┤
│ 9. SOC Case     │ 10. Defensive        │ 11. Reliability &      │ 12. Interoperability         │
│    Management   │     Simulation       │     Security           │     • CES 2.0 Contracts      │
│    • Notes & SLA│     • Playbooks      │     • RBAC & Auth      │     • OCSF 1.1 Adapters      │
│    • Assignment │     • Approval Gating│     • Background Tasks │     • Sigma Converters       │
│    • Audit Log  │     • Zero Contain   │     • LLM Redaction    │     • REST Webhooks          │
└─────────────────┴──────────────────────┴────────────────────────┴──────────────────────────────┘
```

### Module 1: Command Centre (SOC Overview & Operations)
- **Real-Time Operational Overview:** Displays open incidents categorized by severity (Critical, High, Medium, Low), mean-time-to-triage, active investigation count, and monitored asset health.
- **Alert Ingestion Health:** Visualizes incoming log throughput (events/second, bytes/minute), parser error rates, and file upload audit history.
- **Model Provider Status:** Live connectivity indicator for BharatCode inference endpoints (`qwen-3.8-27b`, `deepseek-v4.1-flash`) with status pills (Healthy, Degraded, Fallback Active).
- **Recent Analyst Activity:** Chronological activity stream of case assignments, rule activations, and playbook approvals.
- **Strict Data Provenance:** All metrics display provenance badges: `[Live Telemetry]` or `[Synthetic Benchmark]`.

### Module 2: Advanced Detection Engineering (Detection-as-Code)
- **Detection-as-Code Repository:** Stores detection rules in structured YAML definitions version-controlled alongside application code.
- **Sigma-Compatible Subset Parser:** Ingests standardized Sigma rules (subset: `selection`, `condition: selection`, `level`, `tags: attack.*`, field equality, and simple boolean logic). Unsupported constructs are flagged explicitly.
- **MITRE ATT&CK Matrix Navigator:** Interactive ATT&CK heat map illustrating active rule coverage across tactics (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact).
- **Rule Lifecycle Management:** Rule versioning, testing against synthetic logs before activation, one-click enable/disable toggles, and audit logging of author and rationale.

### Module 3: Threat Hunting & Query Studio
- **Structured Safe Query Builder:** Multi-condition search builder supporting field filters (`timestamp`, `username`, `hostname`, `source_ip`, `destination_ip`, `action`, `category`, `source_format`) without exposing raw SQL or arbitrary shell injection vectors.
- **Saved Searches & Hunting Sessions:** Analysts can bookmark complex hunt hypotheses, tag findings, and maintain active hunting sessions.
- **Pivoting & Related Event Discovery:** Right-click on any IP, user, or host to find all co-occurring activity across the enterprise within adjustable time windows.
- **Incident Escalation:** One-click conversion of verified hunting search results into a formal correlated incident.
- **Evidence Export:** Export search results in sanitized JSON or CSV formats with SHA-256 provenance hashes.

### Module 4: Asset and Identity Intelligence
- **Entity Asset Catalog:** Centralized directory of monitored assets: Endpoints, Servers, Network Gateways, User Accounts, Service Accounts, and Cloud Resources.
- **Asset Criticality Tiers:** Tier 1 (Domain Controllers, Core Databases, Crown Jewels), Tier 2 (Internal Application Servers), Tier 3 (Developer Workstations), Tier 4 (Guest/Public Endpoints).
- **Identity Context Cards:** Displays user department, privilege level, standard logon hours, observed IP addresses, and recent failed authentication counts.
- **Observed Risk Indicators:** Evidence-backed risk badges (e.g., `Burst Logon Failure`, `Privilege Elevation Observed`, `Anomalous Egress Volume`) strictly derived from stored detections.

### Module 5: Threat Intelligence & IOC Management
- **Indicator of Compromise (IOC) Database:** Stores malicious IPv4/IPv6 addresses, domains, URLs, and file hashes (SHA-256, MD5).
- **Enrichment Engine:** Automatic background correlation of incoming events against stored threat intelligence indicators.
- **Indicator Provenance & Confidence:** Records feed source, source reliability score (A–F), confidence score (0–100), first observed, last observed, and expiration date.
- **Extensible Threat Feeds:** Modular architecture supporting local curated JSON fixtures, MISP, AlienVault OTX, or custom STIX/TAXII feeds (without requiring external API keys for local demo operation).

### Module 6: Attack Graph and Blast-Radius Analysis
- **Interactive Multi-Stage Attack Graph:** Visualizes attack paths connecting entities and events using a directional graph (React Flow).
- **Explicit Edge Taxonomy:**
  - `Observed` (solid edge): Direct telemetry evidence (e.g. Host A connected to IP B).
  - `Correlated` (dashed edge): Engine-grouped relationship (e.g. Shared compromised account within 15-minute window).
  - `Inferred` (dotted edge): Analytical hypothesis (e.g. Potential lateral movement staging).
- **Blast-Radius Assessment:** Calculates and highlights affected adjacent assets, compromised shared identities, and potential exposure of Tier 1 crown-jewel assets.
- **Time-Travel Navigation:** Slider interface allowing analysts to scrub forward and backward in time to watch the attack unfold chronologically.

### Module 7: AI Investigation & Multi-Model Routing
- **Dynamic Model Discovery:** Calls `GET https://bharatcode.ai/api/model/v1/models` on startup to discover authorized models.
- **Multi-Model Support:**
  - `qwen-3.8-27b` (Default): Primary model for general incident synthesis, structured reporting, and tool-based investigation.
  - `deepseek-v4.1-flash` (Advanced): Routed for complex, multi-entity, long-timeline incidents when available.
- **Complexity-Based Routing Policy:** Automatically evaluates incident size, event volume, and detection diversity to select the optimal model, while allowing manual analyst override.
- **Controlled Specialist Workflows:**
  - *Triage Specialist:* Fast initial severity check and scope assessment.
  - *Forensic Investigator:* Multi-round tool loop collecting deep timeline evidence.
  - *Threat Hunter:* Formulates pivot queries for related activity.
  - *Defensive Response Advisor:* Proposes safe, tailored remediation playbooks.
- **Server-Side Evidence Verifier:** Enforces that every cited event ID exists in the incident; purges unverified citations and rejects unsupported claims.
- **Deterministic Fallback Engine:** Guarantees uninterrupted operation with heuristic synthesis when AI models are unavailable or unconfigured.

### Module 8: CyberTrace ThreatLab (Detection Evaluation Studio)
- **Synthetic Attack Scenario Suite:** Pre-packaged benchmark scenarios (Multi-Stage Credential Stuffing & Exfiltration, Ransomware Staging, Privilege Escalation via Sudo, Benign Enterprise Noise).
- **Historical Replay Harness:** Ingests and plays back historical event streams through new or modified detection rules without altering production state.
- **Ground-Truth Evaluation Metrics:** Calculates exact confusion matrix metrics:
  $$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall} = \frac{TP}{TP + FN}, \quad F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
- **False-Positive & Missed-Event Analysis:** Side-by-side comparison of expected ground truth versus actual rule firings to identify detection blind spots.

### Module 9: SOC Case Management
- **Lifecycle Tracking:** Manages case status (`New`, `Under Investigation`, `Pending Approval`, `Contained`, `Resolved`, `Closed - False Positive`).
- **Analyst Assignment & SLA:** Assigns owners, priority ratings (P1–P4), and SLA timers.
- **Investigation Notes & Timeline:** Markdown-supported collaboration log capturing analyst hypotheses, uploaded screenshots, and evidence attachments.
- **Full Action Audit Trail:** Immutable historical record tracking who initiated an investigation, which model executed, and who reviewed playbooks.

### Module 10: Defensive Response Simulation
- **Defensive Playbook Library:** Pre-defined defensive response workflows:
  - `PB-001: Compromised Account Triage & Session Invalidation`
  - `PB-002: Perimeter Egress IP Blocking Simulation`
  - `PB-003: Endpoint Network Isolation Simulation`
  - `PB-004: Lateral Movement Credential Rotation Advisory`
- **Simulated Execution Only:** Playbooks simulate and record what commands/API calls *would* run (e.g. firewall rule additions, Active Directory lockouts). Real destructive changes are disabled.
- **Mandatory Approval Workflow:** All defensive actions generate an approval request requiring explicit analyst confirmation before recording as simulated-complete.

### Module 11: Reliability, Security & Platform Hardening
- **Authentication & RBAC:** Role-based access control supporting 4 tiers: `Viewer`, `Analyst`, `Detection Engineer`, `Admin`.
- **Tenant Isolation:** Multi-tenant database design partitioning telemetry and incidents by `tenant_id`.
- **Stateless API Compliance:** Strict enforcement of BharatCode `store: false`, full conversation replay, and omission of `previous_response_id`.
- **LLM Telemetry Redaction:** PII/credential scrubbing filter stripping passwords, API tokens, and authorization headers before sending telemetry to external inference endpoints.
- **Persistent Background Workers:** Asynchronous job processing for heavy log uploads, ThreatLab replays, and batch correlation.

### Module 12: Interoperability & Open Standards
- **Versioned Common Event Schema (CES 2.0):** Standard JSON contract for all normalized telemetry.
- **OCSF 1.1 Compatibility Adapter:** Bi-directional import and export adapters converting between CyberTrace CES and Open Cybersecurity Schema Framework (OCSF) Security Finding and Network Activity classes.
- **Sigma Rule Export/Import:** Ability to import and export community Sigma rule definitions matching our supported subset.

---

## 4. Acceptance Criteria & Quality Gates

| Milestone | Key Quality Gate | Verification Mechanism |
| :--- | :--- | :--- |
| **Phase 3.1** | Audit Remediation | $\ge 64$ backend tests passing; consecutive tool rounds verified; entity time filters added. |
| **Phase 4** | SOC UI & Workspace | Responsive React/Vite dashboard; 3-panel incident workspace; interactive attack graph rendered. |
| **Phase 5** | ThreatLab & Benchmarks | Replay harness executes; precision/recall/F1 dynamically calculated from benchmark scenarios. |
| **Phase 6** | Intelligence & Hunting | Search builder executes safe queries; asset catalog & IOC enrichment functional. |
| **Phase 7** | Cases & Playbooks | Case creation, note saving, and simulated playbook approval workflows functional. |
| **Phase 8** | Production Polish | Full regression test suite passing; OCSF adapter validated; clean demo deployment ready. |

