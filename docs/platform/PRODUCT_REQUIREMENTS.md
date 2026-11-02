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
| **Tier 2 Incident Responder** | Needs full attack timeline reconstruction, blast-radius analysis, entity pivoting, and defensive containment options. | Attack Graph Explorer (Dagre layout), Entity History, Response Playbook Simulation, Case Management. |
| **Detection Engineer** | Struggles with rule drift, false-positive spikes, and untracked rule coverage; requires Detection-as-Code and reproducible testing. | Detection Engineering (Sigma subset), ThreatLab Replay Studio, MITRE ATT&CK Mapping. |
| **SOC Lead / Manager** | Requires visibility into team workload, operational cadence, coverage blind spots, and AI model accuracy. | Command Centre, Model Benchmark Evaluation, Audit Logs, Case Assignment Metrics. |
| **Security Administrator** | Demands rigorous access controls, tenant isolation, zero accidental data leakage, and compliance auditability. | Platform Administration, Role-Based Access Control (RBAC), Secrets Isolation, Telemetry Redaction. |

### 1.3 Core Product Principles & Non-Negotiables
1. **Deterministic Rule Sovereignty:** Deterministic detection rules remain the authoritative source of truth for detections, triggering entities, and incident severity. Generative AI models are strictly prohibited from altering rule definitions, elevating incident severity, or overriding engine detections.
2. **Strict Factual Grounding & Zero Hallucination Tolerance:** The platform rejects manufactured claims. Every observed fact in an investigation must cite an existing, verified event ID belonging strictly to that incident. Unsupported claims are aggressively purged or labeled.
3. **Untrusted Telemetry & Prompt Injection Resistance:** All event logs, usernames, process command lines, domains, and HTTP payloads are treated as untrusted external inputs. The system instructs and constrains AI models to treat logs purely as passive forensic evidence, never as executable instructions.
4. **Mandatory Human-in-the-Loop Response:** All recommended containment, remediation, and isolation actions require explicit human analyst sign-off (`requires_human_approval: true`). CyberTrace never performs autonomous destructive containment on production infrastructure.
5. **Transparency in Operational Metrics:** Operational metrics, coverage scores, and benchmark statistics must originate from genuine stored telemetry or explicitly tagged synthetic benchmarks. Artificial or fabricated numbers are strictly banned.

---

## 2. Current Baseline & Implementation Status

### 2.1 Completed & Verified Capabilities (Phases 1 through 6.1)
- **Phase 1 (Committed `9b9ca75`):** Common Event Schema (CES 2.0), multi-format log ingestion pipeline (Generic JSON, CSV, Linux Syslog, Windows Security Event Log, Zeek Connection logs), deterministic rules (`DET-001` through `DET-004`), and reproducible synthetic benchmarks.
- **Phase 2 & 2.1 (Committed `60b1ab4`):** Async SQLite persistence (SQLAlchemy 2.0, Alembic migrations), correlation engine with hub-node and public-IP safeguards, idempotent event upserts, and `POST /api/v1/logs/upload` HTTP ingestion.
- **Phase 3 & 3.1 (Committed `5ff350f`):** BharatCode AI investigation engine (`qwen-3.8-27b`), stateless Responses API client with full conversation replay, read-only analytical tools with temporal bounds, server-side `EvidenceVerifier`, `DeterministicFallbackEngine`, and multi-round verification.
- **Phase 4 & 4.1 (Implemented & Verified):** Refined Warm Graphite & Bronze SOC Command Centre interface (`#111315`, `#1D2125`, `#B58A61`, Inter + JetBrains Mono), three-panel Incident Workspace, interactive Attack Graph powered by Dagre hierarchical layout (`@dagrejs/dagre`), and responsive tablet layout preventing clipped tables below 1280px.
- **Phase 5 (Implemented & Verified):** CyberTrace ThreatLab replay studio, synthetic attack scenario suite, dynamic confusion matrix ($TP, FP, FN, TN$), mathematical Precision/Recall/$F_1$-score calculation, and BharatCode multi-model routing.
- **Phase 6.1 (Implemented & Verified, 95/95 Backend Tests Passing):** Live Asset and Identity Intelligence engine. Dynamically aggregates observed endpoints and identities from stored telemetry with canonical case normalization (`UPPER(TRIM(hostname))`, `LOWER(TRIM(username))`), global database pagination, entity namespace isolation, and REST APIs (`GET /api/v1/assets`, `GET /api/v1/identities`).

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
│    • Real Events│    • ATT&CK Matrix   │    • Hunting Sessions  │    • Criticality Tiers       │
├─────────────────┼──────────────────────┼────────────────────────┼──────────────────────────────┤
│ 5. Threat       │ 6. Attack Graph      │ 7. AI Investigation    │ 8. CyberTrace ThreatLab      │
│    Intelligence │    • Dagre Layout    │    • Model Router      │    • Scenario Replay Harness │
│    • IOC Feeds  │    • Blast-Radius    │    • Specialist Roles  │    • Confusion Matrix (P/R/F1│
│    • Provenance │    • Edge Taxonomy   │    • Evidence Verifier │    • Missed Detections       │
│    • IP/Domain  │    • Entity Inspector│    • Fallback Failover │    • Rule Diff Evaluator     │
├─────────────────┼──────────────────────┼────────────────────────┼──────────────────────────────┤
│ 9. SOC Case     │ 10. Defensive        │ 11. Reliability &      │ 12. Interoperability         │
│    Management   │     Simulation       │     Security           │     • CES 2.0 Contracts      │
│    • Notes & SLA│     • Playbooks      │     • RBAC & Auth      │     • OCSF 1.1 Adapters      │
│    • Assignment │     • Approval Gating│     • Background Tasks │     • Sigma Converters       │
│    • Audit Log  │     • Zero Contain   │     • LLM Redaction    │     • REST Webhooks          │
└─────────────────┴──────────────────────┴────────────────────────┴──────────────────────────────┘
```

### Module 1: Command Centre (SOC Overview & Operations)
- **Real-Time Operational Overview:** Displays genuine open incidents categorized by severity (Critical, High, Medium, Low), active alerts count, monitored asset count, and backend system connectivity (`Backend Connected`). Rejects hardcoded or fabricated metrics (e.g., hardcoded triage minutes).
- **Content-Sized Incident Queue:**
  - Adapts height to row count rather than stretching into an empty rectangular container.
  - Desktop ($\ge 1280\text{px}$): 7-column unclipped table (`Incident ID`, `Title`, `Severity`, `Status`, `Entities`, `Last Seen`, `Actions`).
  - Tablet ($< 1280\text{px}$): Compact stacked card layout displaying ID/severity on top, summary underneath, entity/detection metrics, status pill, and fully visible `Investigate` button.
- **Detection Activity Feed:** Positioned alongside the incident queue, displaying live triggering rules, MITRE ATT&CK tactics, and affected entities.
- **Recent Observed Events Timeline:** Displays genuine, persisted security telemetry directly from `security_events`, showing chronological event sequences, IP addresses, categories, and timestamps.
- **Strict Data Provenance:** All metrics and tables display honest provenance tags: `[Live Telemetry]`, `[Observed Telemetry]`, or `[Synthetic Benchmark]`.

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
- **Entity Asset Catalog:** Centralized directory of monitored assets: Endpoints, Servers, Network Gateways, User Accounts, Service Accounts, and Cloud Resources derived directly from ingested telemetry (`/api/v1/assets`).
- **Asset Criticality Tiers:** Tier 1 (Domain Controllers, Core Databases, Crown Jewels), Tier 2 (Internal Application Servers), Tier 3 (Developer Workstations), Tier 4 (Guest/Public Endpoints).
- **Identity Context Directory:** Live catalog of user and service accounts (`/api/v1/identities`) with observed IP addresses, logon activity, and role attributes.
- **Observed Risk Indicators:** Evidence-backed risk badges (e.g., `Burst Logon Failure`, `Privilege Elevation Observed`, `Anomalous Egress Volume`) strictly derived from stored detections.

### Module 5: Threat Intelligence & IOC Management
- **Indicator of Compromise (IOC) Database:** Stores malicious IPv4/IPv6 addresses, domains, URLs, and file hashes (SHA-256, MD5).
- **Enrichment Engine:** Automatic background correlation of incoming events against stored threat intelligence indicators.
- **Indicator Provenance & Confidence:** Records feed source, source reliability score (A–F), confidence score (0–100), first observed, last observed, and expiration date.
- **Extensible Threat Feeds:** Modular architecture supporting local curated JSON fixtures, MISP, AlienVault OTX, or custom STIX/TAXII feeds.

### Module 6: Attack Graph and Blast-Radius Analysis
- **Dagre Automatic Graph Layout:** Hierarchical Directed Acyclic Graph (DAG) powered by `@dagrejs/dagre` and `@xyflow/react` with deterministic node positioning, clear stage-by-stage progression, and zero node overlapping.
- **Dark Custom Nodes:** Styled with Warm Graphite surfaces (`#1D2125`), subtle borders (`#30363C`), and zero white outlines.
- **Interactive Entity Inspector:** Clicking any node or edge opens the Entity Inspector slide-over drawer showing observed forensic attributes and related event citations.
- **Explicit Edge Taxonomy:**
  - `Observed` (solid edge): Direct telemetry evidence (e.g. Host A connected to IP B).
  - `Correlated` (dashed edge): Engine-grouped relationship (e.g. Shared compromised account within 15-minute window).
  - `Inferred` (dotted edge): Analytical hypothesis (e.g. Potential lateral movement staging).
- **Blast-Radius Assessment:** Calculates and highlights affected adjacent assets, compromised shared identities, and potential exposure of Tier 1 crown-jewel assets.

### Module 7: AI Investigation & Multi-Model Routing
- **Dynamic Model Discovery:** Calls `GET https://bharatcode.ai/api/model/v1/models` on startup to discover authorized models.
- **Multi-Model Support:**
  - `qwen-3.8-27b` (Default): Primary model for general incident synthesis, structured reporting, and tool-based investigation.
  - `deepseek-v4.1-flash` (Advanced): Routed for complex, multi-entity, long-timeline incidents when available.
- **Complexity-Based Routing Policy:** Automatically evaluates incident size, event volume, and detection diversity to select the optimal model, while allowing manual analyst override.
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
- **Investigation Notes & Timeline:** Markdown-supported collaboration log capturing analyst hypotheses and evidence attachments.
- **Full Action Audit Trail:** Immutable historical record tracking who initiated an investigation, which model executed, and who reviewed playbooks.

### Module 10: Defensive Response Simulation
- **Defensive Playbook Library:** Pre-defined defensive response workflows (Compromised Account Triage, Perimeter Egress IP Blocking, Endpoint Network Isolation, Lateral Movement Credential Rotation).
- **Simulated Execution Only:** Playbooks simulate and record what commands/API calls *would* run (e.g. firewall rule additions, Active Directory lockouts). Real destructive changes are disabled.
- **Mandatory Approval Workflow:** All defensive actions generate an approval request requiring explicit analyst confirmation before recording as simulated-complete.

### Module 11: Reliability, Security & Platform Hardening
- **Authentication & RBAC:** Role-based access control supporting 4 tiers: `Viewer`, `Analyst`, `Detection Engineer`, `Admin`.
- **Tenant Isolation:** Multi-tenant database design partitioning telemetry and incidents by `tenant_id`.
- **Stateless API Compliance:** Strict enforcement of BharatCode `store: false`, full conversation replay, and omission of `previous_response_id`.
- **LLM Telemetry Redaction:** PII/credential scrubbing filter stripping passwords, API tokens, and authorization headers before sending telemetry to external inference endpoints.

### Module 12: Interoperability & Open Standards
- **Versioned Common Event Schema (CES 2.0):** Standard JSON contract for all normalized telemetry.
- **OCSF 1.1 Compatibility Adapter:** Bi-directional import and export adapters converting between CyberTrace CES and Open Cybersecurity Schema Framework (OCSF) Security Finding and Network Activity classes.
- **Sigma Rule Export/Import:** Ability to import and export community Sigma rule definitions matching our supported subset.

---

## 4. Acceptance Criteria & Quality Gates

| Milestone | Key Quality Gate | Verification Mechanism | Status |
| :--- | :--- | :--- | :--- |
| **Phase 3.1** | Audit Remediation & Multi-Turn AI | $\ge 64$ backend tests passing; consecutive tool rounds verified; entity time filters added. | **Completed & Verified** |
| **Phase 4** | Warm Graphite SOC UI & Workspace | Responsive React/Vite dashboard; 3-panel incident workspace; Dagre attack graph; unclipped tablet layout. | **Completed & Verified** |
| **Phase 5** | ThreatLab & Benchmarks | Replay harness executes; mathematically exact precision/recall/F1 calculated from benchmark scenarios. | **Completed & Verified** |
| **Phase 6.1** | Asset & Identity Intelligence | 95/95 backend tests passing; canonical normalization; `/api/v1/assets` and `/api/v1/identities` live. | **Completed & Verified** |
| **Phase 6.2** | Threat Hunting Studio | Search builder executes safe queries; saved searches functional. | In Progress |
| **Phase 7** | Cases & Playbooks | Case creation, note saving, and simulated playbook approval workflows functional. | Planned |
| **Phase 8** | Production Polish & OCSF | Full regression test suite passing; OCSF adapter validated; clean demo deployment ready. | Planned |
