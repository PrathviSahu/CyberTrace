# CyberTrace — AI-Native SOC Incident Investigation Platform

[![CI Backend](https://img.shields.io/badge/pytest-95%2F95%20passing-10b981?style=for-the-badge&logo=pytest)](https://github.com/PrathviSahu/CyberTrace)
[![Frontend](https://img.shields.io/badge/Vite%20%2B%20React-TypeScript-b58a61?style=for-the-badge&logo=react)](https://github.com/PrathviSahu/CyberTrace)
[![AI Engine](https://img.shields.io/badge/BharatCode-Qwen%203.8%2027B-6366f1?style=for-the-badge)](https://bharatcode.ai)

> **BharatCode Hackathon 2026 Official Submission**  
> **Project:** CyberTrace  
> **AI Model:** `qwen-3.8-27b` via BharatCode Responses API (`https://bharatcode.ai/api/model/v1`)  
> **Mission:** Defensive Security Operations Platform with Evidence-Grounded AI Investigation, Warm Graphite Executive Aesthetic & Interactive Dagre Attack Graphs.

---

## 1. Executive Overview

Modern Security Operations Centres (SOCs) drown in thousands of fragmented alerts, disconnected dashboards, and hallucination-prone generic LLM summaries. **CyberTrace** re-architects security operations from the ground up:

1. **Common Event Schema (CES)**: Ingests and normalizes multi-source logs (Linux Syslog, Windows Event XML/CSV, Zeek Conn, JSON) into a single deterministic schema.
2. **Authoritative Detection Rules**: Evaluates declarative, Sigma-compatible detection logic subsets with strict MITRE ATT&CK mapping (`DET-001` through `DET-004`).
3. **Graph Incident Correlation**: Links detections and telemetry across shared identities, hosts, and internal endpoints while enforcing strict hub-node and public-IP isolation safeguards.
4. **BharatCode AI Investigation Engine**: Multi-turn stateless tool-calling loop using `qwen-3.8-27b` with a hardened server-side `EvidenceVerifier` that rejects ungrounded claims.
5. **Warm Graphite Executive SOC Shell**: High-density analyst cockpit (`#111315` canvas, `#1D2125` surfaces, `#B58A61` restrained bronze accent, Inter typography), content-sized incident queue, recent persisted event timeline, and tablet-optimized responsive row layouts.
6. **Flagship Dagre Attack Graph Workspace**: Interactive investigation canvas using `@xyflow/react` and `@dagrejs/dagre` with dark node surfaces, zero white borders, non-overlapping semantic badges, auto-fit viewports, and an interactive slide-over entity inspector.
7. **ThreatLab Benchmark Suite**: Empirical evaluation measuring detection accuracy and confusion matrices against reproducible benchmark attack scenarios.

---

## 2. Problem Statement

### The Crisis in Modern Security Operations

Security analysts in enterprise SOCs face severe operational friction that impairs threat containment and increases mean time to detect (MTTD) and respond (MTTR):

1. **Alert Fatigue & Telemetry Heterogeneity**:
   - Modern enterprises deploy heterogeneous infrastructure generating diverse log formats: Linux auth syslog, Windows Security Event XML/CSV (EventIDs 4624/4625), Zeek connection logs, and custom application JSON.
   - Disparate schemas force analysts to spend up to 40% of their triage time manually parsing timestamps, normalizing IP addresses, and mapping usernames across different syntaxes.

2. **The "AI Wrapper" Hallucination Trap**:
   - Generic LLM chatbots applied to cybersecurity frequently hallucinate non-existent event IDs, misattribute compromised accounts, and recommend destructive containment actions without evidentiary support.
   - In defensive security, an ungrounded claim is a critical vulnerability. Analysts cannot trust an AI that asserts an IP is malicious without pointing to specific observed log records.

3. **Cognitive Overload & Broken Visualizations**:
   - Standard cybersecurity dashboards rely on generic cyber-terminal templates with saturated neon borders, uncalibrated tables, and tangled node graphs with overlapping labels, crossing edges, and white outlines.
   - When an incident involves multi-stage lateral movement (e.g. credential spray → account takeover → sudo privilege escalation → outbound C2 exfiltration), analysts are left without a clear hierarchical attack progression.

4. **Fabricated Metrics & Lack of Provenance**:
   - Many security products present hardcoded triage timers, synthetic coverage scores, or silent mock fallbacks that misrepresent security posture.
   - Operations teams require strict data provenance that clearly distinguishes between genuine live telemetry (`observed_telemetry`), empirical benchmarks (`demo_benchmark`), and calculated evaluations (`calculated_evaluation`).

### How CyberTrace Solves It

| Operational Challenge | CyberTrace Architectural Solution |
| :--- | :--- |
| **Siloed & Heterogeneous Logs** | **Common Event Schema (CES v1.0)**: Automatic multi-format log parser with UTC normalization, RFC-compliant timestamps, and canonical entity extraction (`UPPER(TRIM(hostname))` and `LOWER(TRIM(username))`). |
| **Alert Fatigue & Noise** | **Deterministic Graph Correlation Engine**: Bounded temporal sliding windows with hub-node protection and public IP isolation safeguards to cluster related detections into unified multi-stage incident dossiers. |
| **AI Hallucinations** | **Stateless BharatCode Tool Loop & Server-Side `EvidenceVerifier`**: Strict multi-turn function calling with 4 read-only investigation tools; 100% of claims must cite database-grounded event IDs or be purged. |
| **Tangled Visual Graph Spaghetti** | **Dagre Hierarchical DAG Attack Graph**: Automatic deterministic graph layout (`@dagrejs/dagre`) that organizes investigations into clear stages (Incident Root → Threat Origin → Identities → Host → Exfil Target) with zero white borders and an interactive node inspector. |
| **Misleading Product Metrics** | **Strict Provenance & Honest Disclosures**: All counts reflect database ground truth. The global header reflects `Backend Connected` rather than simulated sensor feeds, and buffer counts disclose sample limits. |
| **Rigid / Clipped Interfaces** | **Warm Graphite Executive System & Tablet Responsiveness**: Calibrated desktop layout (zero clipping at 1920×1080 and 1440×900) with an automatic stacked-row layout below 1280px (`< xl`) for tablets. |

---

## 3. Implementation Status & Product Matrix

To maintain operational integrity and transparency, CyberTrace explicitly distinguishes between live verified capabilities and specified upcoming milestones:

| Capability / Module | Status | Verification & Engine |
| :--- | :--- | :--- |
| **Common Event Schema (CES)** | **Live** | Ingests Linux, Windows, Zeek, CSV, JSON; UTC normalization; entity extraction. |
| **Deterministic Detection Engine** | **Live** | Evaluates Sigma-compatible rule subset (`DET-001` to `DET-004`) with MITRE ATT&CK tags. |
| **Incident Correlation & Safeguards** | **Live** | Hub-node isolation, shared service account filtering, and 24h span partitioning. |
| **BharatCode AI Investigation Engine** | **Live** | Stateless tool loop (4 tools), hardened `EvidenceVerifier`, deterministic fallback. |
| **Warm Graphite Command Centre UI** | **Live** | Warm graphite system (`#111315`/`#B58A61`), 4-metric horizontal strip, content-sized incident queue, recent event timeline, tablet responsive flow. |
| **Dagre Attack Graph Workspace** | **Live** | Full-breadth console, `@dagrejs/dagre` hierarchical layout, dark surfaces (no white borders), clickable evidence citations, entity inspector. |
| **ThreatLab Benchmark Harness** | **Live** | In-memory scenario replay, $TP/FP/FN/TN$ confusion matrix computation. |
| **Asset & Identity Intelligence** | **Live** | Live inventory derived from telemetry (`/api/v1/assets`, `/api/v1/assets/{type}/{value}`); canonical case grouping; observed IP addresses; user identities. |
| **Threat Hunting Query Studio** | **UI Live / API Phase 6.2** | Structured buffer filter UI and CES explorer; safe parameterized query engine scheduled for Phase 6.2. |
| **Multi-Model Routing & Comparison** | **Blueprint (Phase 5.2)** | Single-model live execution (Qwen 27B); multi-model routing specified in Phase 5.2. |
| **Case Management & Playbooks** | **Blueprint (Phase 7)** | Analyst approval gating specified in Phase 7 roadmap. |

---

## 4. Architecture & Pipeline

```
  Raw Security Logs (Syslog / Windows / Zeek / JSON / CSV)
                            │
                            ▼
      Log Ingestion Pipeline (Multi-Format Auto-Detection)
                            │
                            ▼
          Common Event Schema (CES Normalization)
                            │
                            ▼
      Deterministic Rule Engine (Sigma-Compatible DET-001..004)
                            │
                            ▼
        Incident Correlation Engine (Graph Safeguards)
                            │
                            ▼
              Incident Evidence Dossier (SQLite)
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
  [Online AI Mode]                     [Deterministic Mode]
BharatCode Qwen 27B              Deterministic Fallback Synthesis
Stateless Tool Loop (4 Tools)                   │
        │                                       │
        ▼                                       ▼
Server-Side Evidence Verifier           Persistent Audit Record
(100% Grounding Enforcement)                    │
        │                                       │
        └───────────────────┬───────────────────┘
                            ▼
                 Versioned REST API (/api/v1)
                            │
                            ▼
      React 18 + Vite SOC Command Centre & Workspace
    (Warm Graphite Shell, Dagre Attack Graph, Evidence Log, AI Findings)
```

---

## 5. Key Capabilities

### 🛡️ Flagship Incident Workspace & Dagre Attack Graph
- **Dagre Automatic Hierarchical Layout**: Deterministic DAG layout (`@dagrejs/dagre`) automatically structuring investigations into clean stages: Incident Root → Threat Origin → Compromised Accounts → Host Execution → Exfiltration Target.
- **Dark Node Surfaces (Zero White Outlines)**: Built with custom dark node surfaces (`#1D2125`, `#30363C` borders) eliminating default ReactFlow white borders, white handles, and white outlines.
- **Zero Label Collisions**: Non-overlapping concise badges (`Auth Spray`, `Sudo Bash`, `Egress 62MB`) with relationship descriptions available on hover and selection.
- **Interactive Entity Investigation Inspector**: Clicking any node opens a slide-over panel displaying entity role, confidence, rule explanations, and directly associated persisted events with one-click opening in the Evidence Drawer.
- **Orientation & Grouping Toggles**: Switch between `Left → Right` and `Top ↓ Bottom` views, plus toggle between `Group Rules (4 Nodes)` and `All Firings (6 Nodes)`.
- **AI Ground-Truth Findings & Evidence Dossier**: Chronological evidence log (9 events), verified facts with clickable citations, and human-in-the-loop containment approvals.

### ⚡ Command Centre & Operational Triage
- **Compact Metric Strip**: 4-metric horizontal ribbon with vertical dividers (`divide-x`), prominent values, and explicit provenance disclosures.
- **Content-Sized Incident Queue**: Sizes to its content without empty stretched rectangles; unclipped columns across all resolutions (1920×1080 and 1440×900).
- **Recent Observed Events Timeline**: Ground-truth chronological stream of normalized events loaded from the active database buffer with direct JSON payload inspection.
- **Tablet Responsive Flow (1024×768)**: Transitions below 1280px into stacked incident rows and compact event cards with zero horizontal clipping.

### 🔬 ThreatLab Benchmark & Evaluation Studio
- **Reproducible Scenario Catalog**:
  - `SCN-001`: Multi-Stage Credential Stuffing & Exfiltration ($TP=4, FP=0, FN=0, F_1=1.00$).
  - `SCN-002`: Targeted Sudo Privilege Escalation ($TP=1, FP=0, FN=0, F_1=1.00$).
  - `SCN-003`: Shared-Host Multi-User Isolation (Verifies independent users remain in separate incidents).
  - `SCN-004`: Benign Administrative Baseline (20 normal events, 0 false alarms, $TN=20$).
- **In-Memory Isolation**: ThreatLab evaluations run in an isolated execution harness without mutating or polluting the production SQLite database.
- **Synthetic Benchmark Disclosure**: Reported accuracy figures ($100\%$ precision, $100\%$ recall) evaluate deterministic verification of expected behavioral specifications against the synthetic test datasets, not generalized real-world wild detection accuracy.

---

## 6. Quick Start Guide

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm
- (Optional) BharatCode API Key (`https://bharatcode.ai/account`)

### Latest Code Branch
> **Active Working Branch:** `feature/phase-6.1-asset-identity-intelligence`
> ```bash
> git clone https://github.com/PrathviSahu/CyberTrace.git
> cd CyberTrace
> git checkout feature/phase-6.1-asset-identity-intelligence
> ```

### Backend Setup
```bash
# 1. Setup Python virtual environment
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r backend/requirements.txt

# 2. Configure environment
cp backend/.env.example backend/.env
# Edit backend/.env to insert your BHARATCODE_API_KEY (optional for fallback mode)

# 3. Run database migrations
cd backend && alembic upgrade head && cd ..

# 4. Execute backend test suite (95 passing tests)
PYTHONPATH=backend pytest backend/tests -v

# 5. Start FastAPI development server
cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup
```bash
# 1. Install frontend dependencies
cd frontend
npm install

# 2. Build for production & verify types
npm run build

# 3. Launch Vite development server
npm run dev
# SOC Command Centre runs at http://localhost:5173
```

---

## 7. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service health status and version metadata (`{"status": "healthy"}`). |
| `POST` | `/api/v1/logs/upload` | Ingests multi-source log file, normalizes to CES, and correlates. |
| `GET` | `/api/v1/events` | Paginated list of normalized CES security events. |
| `GET` | `/api/v1/detections` | Detections fired by deterministic rule engine. |
| `GET` | `/api/v1/incidents` | List of correlated security incidents with entity summaries. |
| `GET` | `/api/v1/incidents/{id}` | Complete incident dossier with detections, events, and graph links. |
| `PATCH` | `/api/v1/incidents/{id}/status` | Updates and persists incident triage status (`open`, `in_progress`, `contained`, `resolved`). |
| `GET` | `/api/v1/incidents/{id}/graph` | Generates graph nodes and edges for attack graph visualization. |
| `POST` | `/api/v1/incidents/{id}/investigate` | Triggers BharatCode AI investigation or deterministic fallback. |
| `GET` | `/api/v1/incidents/{id}/investigations` | Retrieves persisted investigation history for an incident. |
| `GET` | `/api/v1/threatlab/scenarios` | Lists reproducible ThreatLab benchmark scenarios. |
| `POST` | `/api/v1/threatlab/replay/{id}` | Runs in-memory scenario replay and computes confusion matrix. |
| `GET` | `/api/v1/assets` | Paginated observed assets (hostnames & IPs) derived from telemetry. |
| `GET` | `/api/v1/assets/{asset_type}/{asset_value}` | Detailed observed profile for a specific hostname or IP. |
| `GET` | `/api/v1/identities` | Paginated observed user identities derived from telemetry. |
| `GET` | `/api/v1/identities/{username}` | Detailed observed profile for a specific user identity. |

---

## 8. Repository Structure

```
CyberTrace/
├── .github/
│   ├── ISSUE_TEMPLATE/bug_report.md  # Standardized issue report template
│   └── PULL_REQUEST_TEMPLATE.md       # Pull request checklist & review template
├── BharatCode.txt                     # Hackathon metadata & AI model configuration
├── CONTRIBUTING.md                    # Collaboration & code contribution guidelines
├── README.md                          # Primary platform documentation
├── backend/                           # Python 3.12 FastAPI backend
│   ├── alembic/                       # Database migrations (Alembic)
│   ├── app/
│   │   ├── core/                      # Configuration and settings
│   │   ├── correlation/               # Graph incident correlation engine & safeguards
│   │   ├── db/                        # SQLAlchemy async SQLite models & repositories
│   │   ├── investigation/             # BharatCode AI agent, verifier, tools, & fallback
│   │   ├── parsers/                   # Multi-source log parsers (Linux, Windows, Zeek)
│   │   ├── rules/                     # Deterministic detection engine (DET-001 to DET-004)
│   │   ├── schemas/                   # Pydantic schemas (CES, Detection, Incident)
│   │   └── threatlab/                 # ThreatLab benchmark engine & scenario catalog
│   └── tests/                         # 95 automated pytest integration & unit tests
├── docs/
│   ├── TEAMMATE_QUICKSTART.md         # Step-by-step local developer onboarding guide
│   └── platform/                      # Platform Architecture & Specification Blueprint
│       ├── PRODUCT_REQUIREMENTS.md
│       ├── PLATFORM_ARCHITECTURE.md
│       ├── DATA_MODEL_AND_API_CONTRACTS.md
│       ├── UI_DESIGN_SYSTEM.md
│       ├── IMPLEMENTATION_ROADMAP.md
│       └── SECURITY_AND_THREAT_MODEL.md
└── frontend/                          # Vite + React 18 + TypeScript SOC Platform
    ├── src/
    │   ├── components/                # Reusable UI components (Badges, Drawer, Palette)
    │   ├── services/                  # API client with hybrid failover & demo benchmark
    │   ├── types/                     # TypeScript interface contracts
    │   └── views/                     # Command Centre, Workspace, ThreatLab, Rules, etc.
    └── tailwind.config.js             # Warm Graphite & Bronze executive design tokens
```

---

## 9. Licence

The project licence has not yet been formally selected. A `LICENSE` file will be added in a dedicated commit once the decision is made. Built for the BharatCode Hackathon 2026.
