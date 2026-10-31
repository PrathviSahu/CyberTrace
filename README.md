# CyberTrace — AI-Native SOC Incident Investigation Platform

[![CI Backend](https://img.shields.io/badge/pytest-74%2F74%20passing-10b981?style=for-the-badge&logo=pytest)](https://github.com/PrathviSahu/CyberTrace)
[![Frontend](https://img.shields.io/badge/Vite%20%2B%20React-TypeScript-06b6d4?style=for-the-badge&logo=react)](https://github.com/PrathviSahu/CyberTrace)
[![AI Engine](https://img.shields.io/badge/BharatCode-Qwen%203.8%2027B-6366f1?style=for-the-badge)](https://bharatcode.ai)

> **BharatCode Hackathon 2026 Official Submission**  
> **Project:** CyberTrace  
> **AI Model:** `qwen-3.8-27b` via BharatCode Responses API (`https://bharatcode.ai/api/model/v1`)  
> **Mission:** Defensive Security Operations Platform with Evidence-Grounded AI Investigation & Interactive Attack Graphs.

---

## 1. Executive Overview

Modern Security Operations Centres (SOCs) drown in thousands of fragmented alerts, disconnected dashboards, and hallucination-prone generic LLM summaries. **CyberTrace** re-architects security operations from the ground up:

1. **Common Event Schema (CES)**: Ingests and normalizes multi-source logs (Linux Syslog, Windows Event XML/CSV, Zeek Conn, JSON) into a single deterministic schema.
2. **Authoritative Detection Rules**: Evaluates declarative, Sigma-compatible detection logic subsets with strict MITRE ATT&CK mapping (`DET-001` through `DET-004`).
3. **Graph Incident Correlation**: Links detections and telemetry across shared identities, hosts, and internal endpoints while enforcing strict hub-node and public-IP isolation safeguards.
4. **BharatCode AI Investigation Engine**: Multi-turn stateless tool-calling loop using `qwen-3.8-27b` with a hardened server-side `EvidenceVerifier` that rejects ungrounded claims.
5. **Dark SOC Command Centre & 3-Panel Workspace**: High-density analyst cockpit with live `@xyflow/react` attack graphs, clickable evidence citations, and human-in-the-loop remediation approvals.
6. **ThreatLab Benchmark Suite**: Empirical evaluation measuring detection accuracy and confusion matrices against reproducible benchmark attack scenarios.

---

## 2. Implementation Status & Product Matrix

To maintain operational integrity and transparency, CyberTrace explicitly distinguishes between live verified capabilities and specified upcoming milestones:

| Capability / Module | Status | Verification & Engine |
| :--- | :--- | :--- |
| **Common Event Schema (CES)** | **Live** | Ingests Linux, Windows, Zeek, CSV, JSON; UTC normalization; entity extraction. |
| **Deterministic Detection Engine** | **Live** | Evaluates Sigma-compatible rule subset (`DET-001` to `DET-004`) with MITRE ATT&CK tags. |
| **Incident Correlation & Safeguards** | **Live** | Hub-node isolation, shared service account filtering, and 24h span partitioning. |
| **BharatCode AI Investigation Engine** | **Live** | Stateless tool loop (4 tools), hardened `EvidenceVerifier`, deterministic fallback. |
| **Dark SOC Command Centre UI** | **Live** | Midnight navy design system, live metrics, triage SLA, log upload dropzone. |
| **3-Panel Incident Workspace** | **Live** | Left dossier timeline, center `@xyflow/react` attack graph, right AI findings panel. |
| **ThreatLab Benchmark Harness** | **Live** | In-memory scenario replay, $TP/FP/FN/TN$ confusion matrix computation. |
| **Threat Hunting Query Studio** | **UI Live / API Phase 6** | Structured query UI and CES explorer; safe backend query engine scheduled for Phase 6. |
| **Asset & Identity Inventory** | **UI Live / API Phase 6** | Tier 1–4 asset tracking; automated directory context scheduled for Phase 6. |
| **Multi-Model Routing & Comparison** | **Blueprint (Phase 5.2)** | Single-model live execution (Qwen 27B); multi-model routing specified in Phase 5.2. |
| **Case Management & Playbooks** | **Blueprint (Phase 7)** | Analyst approval gating specified in Phase 7 roadmap. |

---

## 3. Architecture & Pipeline

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
          Deterministic Rule Engine (DET-001 to DET-004)
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
   (3-Panel Dossier, @xyflow/react Attack Graph, AI Panel)
```

---

## 4. Key Capabilities

### 🛡️ Flagship 3-Panel Incident Workspace
- **Panel 1 (Dossier & Timeline)**: Incident blast radius, correlated identities, and chronological event sequence with clickable `[evt_...]` pills.
- **Panel 2 (Adversary Attack Graph)**: Interactive canvas using `@xyflow/react` querying `/api/v1/incidents/{id}/graph` with animated *Observed* network/auth edges (cyan), *Correlated* entity links (indigo), and *Inferred* threat paths (amber).
- **Panel 3 (AI Findings Panel)**: Verified observed facts, confidence-calibrated hypotheses with caveats, unknowns/telemetry gaps, and **Human-in-the-Loop** remediation actions (`[Approve]` / `[Reject]`).
- **Slide-Over Evidence Drawer**: Deep inspection of raw events, structured fields, and SHA-256 ingestion provenance.

### 🔬 ThreatLab Benchmark & Evaluation Studio
- **Reproducible Scenario Catalog**:
  - `SCN-001`: Multi-Stage Credential Stuffing & Exfiltration ($TP=4, FP=0, FN=0, F_1=1.00$).
  - `SCN-002`: Targeted Sudo Privilege Escalation ($TP=1, FP=0, FN=0, F_1=1.00$).
  - `SCN-003`: Shared-Host Multi-User Isolation (Verifies independent users remain in separate incidents).
  - `SCN-004`: Benign Administrative Baseline (20 normal events, 0 false alarms, $TN=20$).
- **In-Memory Isolation**: ThreatLab evaluations run in an isolated execution harness without mutating or polluting the production SQLite database.
- **Synthetic Benchmark Disclosure**: Reported accuracy figures ($100\%$ precision, $100\%$ recall) evaluate deterministic verification of expected behavioral specifications against the synthetic test datasets, not generalized real-world wild detection accuracy.

---

## 5. Quick Start Guide

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm
- (Optional) BharatCode API Key (`https://bharatcode.ai/account`)

### Latest Code Branch
> **Important for Reviewers & Teammates:** The latest active development containing Phase 4 and Phase 5 is on branch **`feature/phase-4-soc-frontend`**.
> ```bash
> git clone https://github.com/PrathviSahu/CyberTrace.git
> cd CyberTrace
> git checkout feature/phase-4-soc-frontend
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

# 4. Execute backend test suite (74 passing tests)
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

## 6. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service health status and version metadata. |
| `POST` | `/api/v1/logs/upload` | Ingests multi-source log file, normalizes to CES, and correlates. |
| `GET` | `/api/v1/events` | Paginated list of normalized CES security events. |
| `GET` | `/api/v1/detections` | Detections fired by deterministic rule engine. |
| `GET` | `/api/v1/incidents` | List of correlated security incidents with entity summaries. |
| `GET` | `/api/v1/incidents/{id}` | Complete incident dossier with detections, events, and graph links. |
| `GET` | `/api/v1/incidents/{id}/graph` | Generates graph nodes and edges for React Flow visualization. |
| `POST` | `/api/v1/incidents/{id}/investigate` | Triggers BharatCode AI investigation or deterministic fallback. |
| `GET` | `/api/v1/incidents/{id}/investigations` | Retrieves persisted investigation history for an incident. |
| `GET` | `/api/v1/threatlab/scenarios` | Lists reproducible ThreatLab benchmark scenarios. |
| `POST` | `/api/v1/threatlab/replay/{id}` | Runs in-memory scenario replay and computes confusion matrix. |

---

## 7. Repository Structure

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
│   └── tests/                         # 74 automated pytest integration & unit tests
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
    └── tailwind.config.js             # SOC midnight theme & custom design tokens
```

---

## 8. Licence

The project licence has not yet been formally selected. A `LICENSE` file will be added in a dedicated commit once the decision is made. Built for the BharatCode Hackathon 2026.
