# CyberTrace — Platform Architecture Specification
## System Design, Domain Decomposition & Component Topology

---

## 1. Architectural Philosophy: The Modular Monolith

CyberTrace adopts a **Modular Monolith** architecture for its core application tier, intentionally rejecting premature microservice fragmentation while strictly maintaining internal module boundaries, clear domain interfaces, and decoupled database abstractions.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CYBERTRACE PRESENTATION TIER                    │
│    React 18 + TypeScript + Vite + Tailwind CSS + Lucide Icons          │
│         @xyflow/react + @dagrejs/dagre (Hierarchical Attack Graph)      │
│         Warm Graphite & Restrained Bronze Design System                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTPS / REST JSON API (/api/v1)
┌───────────────────────────────────▼────────────────────────────────────┐
│                    CYBERTRACE MODULAR MONOLITH CORE                    │
│                        (FastAPI / Python 3.12)                         │
│                                                                        │
│  ┌───────────────────────┐ ┌───────────────────────┐ ┌──────────────┐  │
│  │ Ingestion & Parsers   │ │ Detection & Sigma     │ │ Correlation  │  │
│  │ • Pipeline / Adapters │ │ • Rules DET-001..004  │ │ • Safeguards │  │
│  │ • OCSF 1.1 Exporters  │ │ • ATT&CK Matrix       │ │ • Hub-Nodes  │  │
│  └───────────┬───────────┘ └───────────┬───────────┘ └───────┬──────┘  │
│              │                         │                     │         │
│  ┌───────────▼─────────────────────────▼─────────────────────▼──────┐  │
│  │ Intelligence & Investigation Tier                                │  │
│  │ • BharatCode Model Router (Qwen 3.8 27B / DeepSeek V4.1 Flash)    │  │
│  │ • Stateless Investigation Agent & Allow-Listed Tools              │  │
│  │ • Server-Side Evidence Verifier & Deterministic Fallback Engine   │  │
│  │ • Dagre Attack Graph Builder, Threat Intel & ThreatLab Engine     │  │
│  │ • Asset & Identity Intelligence Aggregation Layer                 │  │
│  └─────────────────────────────────────┬────────────────────────────┘  │
│                                        │                               │
│  ┌─────────────────────────────────────▼────────────────────────────┐  │
│  │ Operations & Management Tier                                     │  │
│  │ • Case Management • Response Playbooks • Audit Logging • RBAC    │  │
│  └─────────────────────────────────────┬────────────────────────────┘  │
└────────────────────────────────────────┼───────────────────────────────┘
                                         │ SQLAlchemy 2.0 (Async)
┌────────────────────────────────────────▼───────────────────────────────┐
│                      PERSISTENCE & STORAGE TIER                        │
│     Development: SQLite + aiosqlite | Production Target: PostgreSQL 16 │
│              Versioned Schema Migrations Managed via Alembic           │
└────────────────────────────────────────────────────────────────────────┘
```

### Why a Modular Monolith?
1. **Defensive Latency & Simplicity:** Security incident correlation requires rapid entity join queries and transactional guarantees. In-memory service calls avoid network serialization overhead, distributed transactions, and RPC failure modes.
2. **Strict Domain Boundaries:** Each domain (Ingestion, Rules, Correlation, Investigation, ThreatLab, Assets/Identities, Cases) possesses dedicated schemas, repositories, and interfaces. Cross-domain data access must use repository interfaces, never ad-hoc SQL joins.
3. **Seamless Evolutionary Path:** When horizontal scaling becomes necessary for compute-heavy workloads (e.g. massive log ingestion batches or continuous ThreatLab scenario replays), modules can be detached into independent background worker processes using the shared database or a Redis queue without rewriting business logic.

---

## 2. Layered Architecture & Subsystem Decomposition

### Layer 1: Ingestion & Normalization Layer
- **Responsibility:** Ingest raw, heterogeneous log formats, normalize fields into Common Event Schema (CES 2.0), and compute content hashes for audit provenance.
- **Key Modules:**
  - `LogIngestionPipeline`: Dispatches text/files to parser strategies.
  - Parsers: `GenericJsonParser`, `GenericCsvParser`, `LinuxAuthParser`, `WindowsParser`, `ZeekParser`.
  - Adapters: `OcsfAdapter` converting between CES and OCSF Security Finding / Network Activity objects.
- **Contract:** Input: Raw stream or string $\to$ Output: `List[CommonEvent]`.

### Layer 2: Detection & Correlation Engine
- **Responsibility:** Authoritative evaluation of security rules and evidence grouping into correlated incidents.
- **Key Modules:**
  - `DetectionEngine`: Evaluates events against `DetectionRule` classes (`DET-001` brute force, `DET-002` login after failure, `DET-003` privilege escalation, `DET-004` high-volume exfiltration).
  - `SigmaSubsetCompiler`: Compiles YAML Sigma rules into executable Python event predicates.
  - `IncidentCorrelationEngine`: Constructs entity graphs, enforces hub-node protection (rejecting spurious joins on shared web servers or public NAT IPs), enforces temporal thresholds (default 15 minutes), and bounds maximum incident span.
- **Contract:** Input: `List[CommonEvent]` $\to$ Output: `List[DetectionResult]`, `List[CorrelatedIncidentGroup]`.

### Layer 3: Persistence & Data Access Layer
- **Responsibility:** Idempotent, transactionally isolated storage with UTC timestamps and referential integrity.
- **Key Modules:**
  - `EventRepository`: Upserts security events with SHA-256 deduplication.
  - `DetectionRepository`: Persists detections and links to triggering events.
  - `IncidentRepository`: Manages incidents, correlated entities, and dossier evidence.
  - `InvestigationRepository`: Persists AI and fallback investigation records.
  - `AssetRepository` & `IdentityRepository`: Aggregates observed hosts, types, criticality tiers, and identities.
  - `CaseRepository`: Manages SOC cases, analyst notes, and playbook records.
  - `ThreatIntelRepository`: Manages IOC indicators and feed metadata.
- **Storage Target:** Asynchronous SQLite (`aiosqlite`) for local development and self-contained testing (95/95 automated tests passing); PostgreSQL with asyncpg connection pooling for production.

### Layer 4: AI Investigation & Multi-Model Engine
- **Responsibility:** Conduct evidence-backed incident investigations, execute read-only tools, verify citations, and provide deterministic fallbacks.
- **Key Modules:**
  - `BharatCodeModelRouter`: Queries BharatCode `GET /models`, inspects incident complexity, routes to `qwen-3.8-27b` or `deepseek-v4.1-flash`, and handles failovers.
  - `BharatCodeAgent`: Implements stateless Responses API loop with complete conversation history replay and `store: false`.
  - `InvestigationToolExecutor`: Allow-listed, read-only tools scoped strictly to the authorized incident dossier with start/end time bounds.
  - `EvidenceVerifier`: Validates returned event IDs against database ground truth; rejects hallucinated IDs.
  - `DeterministicFallbackEngine`: Rules-based heuristic investigator ensuring platform utility when models are offline.

### Layer 5: ThreatLab & Analytics Layer
- **Responsibility:** Benchmark detection quality, calculate ground-truth accuracy metrics, and explore attack graphs.
- **Key Modules:**
  - `ScenarioReplayHarness`: Feeds benchmark datasets through selected rule configurations.
  - `BenchmarkEvaluator`: Computes true positives, false positives, false negatives, Precision, Recall, and F1 score.
  - `AttackGraphBuilder`: Traverses entity-event relationships and labels edges (`Observed`, `Correlated`, `Inferred`).
  - `BlastRadiusCalculator`: Evaluates affected assets and crown-jewel exposure.

### Layer 6: Operations & Presentation Tier
- **Responsibility:** Case management, response simulations, and dark SOC UI.
- **Key Modules:**
  - `PlaybookSimulationEngine`: Generates defensive response recommendations and tracks approval workflows.
  - `FastAPI Application`: Versioned REST API endpoints under `/api/v1`.
  - `Frontend SPA`: Single-page React application delivering the Warm Graphite & Bronze Command Centre experience with `@xyflow/react` and `@dagrejs/dagre`.

---

## 3. End-to-End Incident Investigation Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as SOC Analyst
    participant UI as CyberTrace Frontend
    participant API as FastAPI Gateway
    participant Ingest as Ingestion & Rules Engine
    participant DB as Relational Database
    participant Router as Model Router
    participant BharatCode as BharatCode API
    participant Tools as Tool Executor
    participant Verifier as Evidence Verifier

    Analyst->>UI: Uploads Security Log File (JSON/CSV)
    UI->>API: POST /api/v1/logs/upload
    API->>Ingest: Ingest, Parse to CES, Run Rules, Correlate
    Ingest->>DB: Upsert Events, Detections, Incidents
    DB-->>API: Incident Dossier Persisted
    API-->>UI: Upload Completed (incidents_count: N)

    Analyst->>UI: Selects Incident & Clicks "Investigate"
    UI->>API: POST /api/v1/incidents/{id}/investigate
    API->>Router: Select Model (Default: qwen-3.8-27b)
    Router->>BharatCode: POST /responses (Input: System + Incident, store: false)
    
    loop Stateless Multi-Turn Tool Loop (Max 5 Rounds)
        BharatCode-->>Router: response.output with function_call(tool_name, args)
        Router->>Tools: execute_tool(tool_name, args)
        Tools->>DB: Query Authorized Incident Dossier Evidence
        DB-->>Tools: Scoped Timeline / Event Telemetry
        Tools-->>Router: Tool Execution Result
        Router->>BharatCode: POST /responses (Accumulated Input + function_call_output, store: false)
    end

    BharatCode-->>Router: Final Structured JSON Response
    Router->>Verifier: Validate Schema & Event Citations
    Verifier->>DB: Verify Event IDs exist in Incident
    Verifier-->>Router: Verified Facts, Hypotheses & Human-Approved Actions
    Router->>DB: Save to ai_investigations (status='completed')
    DB-->>API: Investigation Response
    API-->>UI: Render 3-Panel Workspace (Timeline, Dagre Attack Graph, Findings)
    Analyst->>UI: Clicks Event Citation -> Opens Evidence Drawer
```

---

## 4. Multi-Model Routing & Failover Architecture

BharatCode hosts two inference models accessible via its standard REST API. CyberTrace implements a resilient routing layer:

```mermaid
flowchart TD
    Req["Incident Investigation Request"] --> Disc["Discover Models (GET /models)"]
    Disc --> Check{"DeepSeek V4.1 Flash<br/>Available & Complexity High?"}
    
    Check -- Yes --> DS["Route to deepseek-v4.1-flash"]
    Check -- No / Standard --> QW["Route to qwen-3.8-27b (Default)"]
    
    DS --> CallDS["POST /responses (store: false)"]
    QW --> CallQW["POST /responses (store: false)"]
    
    CallDS -- Success --> Verify["Run EvidenceVerifier"]
    CallQW -- Success --> Verify
    
    CallDS -- "HTTP 503 / 429" --> RetryDS{"Retries <= 2?"}
    RetryDS -- Yes --> BackoffDS["Exponential Backoff"] --> CallDS
    RetryDS -- No --> FailoverQW["Failover to qwen-3.8-27b"] --> CallQW
    
    CallQW -- "HTTP 503 / 429" --> RetryQW{"Retries <= 2?"}
    RetryQW -- Yes --> BackoffQW["Exponential Backoff"] --> CallQW
    RetryQW -- No / Auth Error / Missing Key --> Fallback["DeterministicFallbackEngine"]
    
    Verify -- Schema / Citation OK --> Persist["Persist ai_investigations (status='completed')"]
    Verify -- Malformed / Incomplete --> Fallback
    Fallback --> PersistFB["Persist ai_investigations (status='fallback')"]
```

---

## 5. Frontend Presentation Architecture & Graph Engine

```
┌────────────────────────────────────────────────────────────────────────┐
│                        FRONTEND PRESENTATION ARCHITECTURE              │
├────────────────────────────────┬───────────────────────────────────────┤
│ Framework & Build Tool         │ React 18 + TypeScript + Vite          │
│ Styling & Tokens               │ Tailwind CSS (Warm Graphite Theme)    │
│ Icons                          │ Lucide React                          │
│ Graph Visualization            │ @xyflow/react (React Flow v12)        │
│ Graph Layout Engine            │ @dagrejs/dagre (Deterministic DAG)    │
│ State Management               │ React Hooks + Context + Fetch API     │
│ API Proxy                      │ Vite Dev Proxy (/api -> :8000/api)    │
└────────────────────────────────┴───────────────────────────────────────┘
```

### 5.1 Graph Rendering & Dagre Integration
The attack graph in `IncidentWorkspace.tsx` uses `@dagrejs/dagre` to compute node coordinates hierarchically:
- Each entity is modeled as a node (`user`, `host`, `ip`, `detection`) with fixed dimensions (`width: 220px`, `height: 72px`).
- Edges represent relationships (`observed`, `correlated`, `inferred`).
- Dagre calculates deterministic node placement along an orthogonal grid, avoiding overlapping labels or tangled edge crossings.
- ReactFlow renders custom dark nodes with zero white outlines, subtle graphite borders (`#30363C`), and interactive click listeners that open the Entity Inspector drawer.

### 5.2 Responsive Breakpoint Engine
- **Desktop ($\ge 1280\text{px}$ / `xl`):** Renders the 7-column unclipped incident table alongside the live detection feed.
- **Tablet ($< 1280\text{px}$ / `1024\text{px}`):** Replaces the multi-column table with compact stacked incident cards (`block xl:hidden`) to guarantee zero horizontal clipping and accessible touch targets.
