# CyberTrace — UI Design System & Component Specification
## Premium Dark SOC Command Centre Aesthetic

---

## 1. Visual Theme & Design Language

CyberTrace is engineered with a **professional, dark Security Operations Centre (SOC) command aesthetic**, inspired by industry-leading security platforms (SentinelX, Group-IB, Threatdefence). It rejects generic SaaS dashboard templates, brightly colored cartoon cards, and gratuitous neon glow, delivering instead a high-density, high-legibility interface optimized for prolonged analyst focus.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CYBERTRACE DARK SOC PALETTE                     │
├────────────────────────────────┬───────────────────────────────────────┤
│ Surface Background (Base)      │ Deep Graphite: #080C14                │
│ Surface Panel (Elevated 1)     │ Midnight Navy: #0E1626                │
│ Surface Card / Active (Elev 2) │ Slate Obsidian: #162035               │
│ Subtle Structural Border       │ Muted Indigo Border: rgba(99,102,241,0.18) │
│ Primary Brand Accent           │ Restrained Cyan/Teal: #06B6D4         │
│ Secondary Analytic Accent      │ Deep Indigo: #6366F1                  │
│ Severity Critical / High Alert │ Crimson Red: #EF4444 (bg: #2B1218)    │
│ Severity High / Warning        │ Amber Orange: #F59E0B (bg: #281D0D)   │
│ Severity Medium / Caution      │ Topaz Yellow: #EAB308 (bg: #24210B)   │
│ Severity Low / Informational   │ Sky Blue: #38BDF8 (bg: #0D2338)       │
│ System Health / Normal State   │ Emerald Green: #10B981 (bg: #0C281E)  │
└────────────────────────────────┴───────────────────────────────────────┘
```

---

## 2. Design Tokens

### 2.1 Color Tokens
```css
:root {
  /* Surface Layers */
  --color-bg-base: #080c14;
  --color-bg-surface-1: #0e1626;
  --color-bg-surface-2: #162035;
  --color-bg-surface-hover: #1e2c47;
  --color-bg-surface-active: #253759;

  /* Borders & Dividers */
  --color-border-subtle: rgba(255, 255, 255, 0.07);
  --color-border-focus: rgba(6, 182, 212, 0.6);
  --color-border-accent: rgba(99, 102, 241, 0.35);

  /* Typography */
  --color-text-primary: #f8fafc;
  --color-text-secondary: #94a3b8;
  --color-text-muted: #64748b;
  --color-text-code: #38bdf8;

  /* Accents */
  --color-accent-cyan: #06b6d4;
  --color-accent-indigo: #6366f1;

  /* Severities */
  --color-severity-critical: #ef4444;
  --color-severity-high: #f59e0b;
  --color-severity-medium: #eab308;
  --color-severity-low: #38bdf8;
  --color-status-healthy: #10b981;
}
```

### 2.2 Typography Scale
- **UI Fonts:** `Inter`, `Geist`, or `-apple-system, BlinkMacSystemFont, sans-serif`.
- **Monospace Code/Log Fonts:** `JetBrains Mono`, `Fira Code`, or `ui-monospace`.

| Token | Size | Line Height | Weight | Usage |
| :--- | :---: | :---: | :---: | :--- |
| `text-display` | 24px | 32px | 700 | Primary Workspace Headers, Attack Stage Titles |
| `text-h1` | 20px | 28px | 600 | Modal Headers, Section Titles |
| `text-h2` | 16px | 24px | 600 | Panel Titles, Metric Card Labels |
| `text-body` | 14px | 20px | 400 | General Content, Investigation Findings |
| `text-body-sm`| 13px | 18px | 400 | Table Rows, Sidebar Links, Tooltips |
| `text-caption`| 11px | 16px | 500 | Metadata Badges, Graph Edge Tags, Timestamps |
| `text-mono` | 12px | 18px | 400 | Event IDs (`evt_...`), IP Addresses, SHA-256 Hashes |

### 2.3 Elevation & Structural Shadows
- Cards and panels utilize a refined **1px border** (`var(--color-border-subtle)`) with minimal, crisp drop shadows:
  - `elevation-card`: `0 2px 8px 0 rgba(0, 0, 0, 0.45)`
  - `elevation-modal`: `0 8px 32px 0 rgba(0, 0, 0, 0.75)`
  - `elevation-drawer`: `-4px 0 24px 0 rgba(0, 0, 0, 0.65)`

---

## 3. Application Layout & Shell Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ TOP HEADER: [Logo] CYBERTRACE  [Workspace: Default SOC ▼]  [Search ⌘K]  [Time Range ▼]  [Model: Qwen ▼] [Bell] [User] │
├──────────────┬─────────────────────────────────────────────────────────────────────────────────────────┤
│ LEFT NAV     │ MAIN WORKSPACE VIEWPORT                                                                 │
│              │                                                                                         │
│ COMMAND      │  ┌───────────────────────┐ ┌───────────────────────┐ ┌──────────────────────────────┐   │
│ • Overview   │  │ Open Incidents: 24   │ │ Critical Alerts: 06 │ │ Monitored Assets: 148        │   │
│ • Alerts     │  │ [Live Telemetry]      │ │ [Live Telemetry]     │ │ [Live Telemetry]             │   │
│ • Incidents  │  └───────────────────────┘ └───────────────────────┘ └──────────────────────────────┘   │
│ • Cases      │                                                                                         │
│              │  ┌──────────────────────────────────────────────┐ ┌──────────────────────────────────┐  │
│ INTEL        │  │ Incident Severity Distribution (Donut / Bar) │ │ Ingestion Rate & Health (Chart)  │  │
│ • Hunting    │  └──────────────────────────────────────────────┘ └──────────────────────────────────┘  │
│ • Graph      │                                                                                         │
│ • Threat In  │  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│              │  │ Active Incident Feed / Priority Triage Table                                      │  │
│ ENGIN.       │  │ ID        Title                      Severity  Status   Entities   Last Seen       │  │
│ • Rules      │  │ INC-001   Credential Stuffing Burst  CRITICAL  OPEN     3 hosts    2 mins ago      │  │
│ • ThreatLab  │  └───────────────────────────────────────────────────────────────────────────────────┘  │
│              │                                                                                         │
│ ENVIRON.     │                                                                                         │
│ • Assets     │                                                                                         │
│ • Identities │                                                                                         │
│ • Integrat.  │                                                                                         │
│              │                                                                                         │
│ ADMIN.       │                                                                                         │
│ • Audit Logs │                                                                                         │
│ • Settings   │                                                                                         │
└──────────────┴─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Five-Group Navigation Hierarchy
1. **Command:**
   - `Overview`: Threat metrics, severity distribution, ingestion health, analyst activity.
   - `Alert Inbox`: Stream of raw detections awaiting analyst triage.
   - `Incidents`: Correlated security incidents with correlation keys.
   - `Cases`: Formal investigation cases, SLAs, and assignments.
2. **Intelligence:**
   - `Threat Hunting`: Structured multi-filter search builder.
   - `Attack Graph`: Enterprise-wide entity connection explorer.
   - `Threat Intelligence`: IOC registry, feed provenance, and matching engine.
3. **Engineering:**
   - `Detection Rules`: Detection-as-code repository and Sigma subset editor.
   - `ThreatLab`: Scenario replay harness, precision/recall evaluator.
   - `Model Evaluation`: Benchmark comparisons between Qwen and DeepSeek.
4. **Environment:**
   - `Assets`: Host, server, and gateway inventory with criticality tiers.
   - `Identities`: User and service account profiles with risk scores.
   - `Integrations`: OCSF import/export and log source connector settings.
5. **Administration:**
   - `Audit Logs`: Tamper-evident ledger of all user actions.
   - `Settings`: Tenant configuration, API keys, and LLM redaction policies.

---

## 4. Screen-by-Screen Layout Specifications

### 4.1 Incident Investigation Workspace (Three-Panel Layout)
The flagship investigation interface:

```
┌─────────────────────────┬──────────────────────────────────────────┬────────────────────────────────────────┐
│ PANEL 1: INCIDENT DOSSIER│ PANEL 2: INTERACTIVE ATTACK GRAPH        │ PANEL 3: AI INVESTIGATION REPORT       │
│ (Width: 320px)          │ (Flexible Width: Center)                 │ (Width: 420px)                         │
├─────────────────────────┼──────────────────────────────────────────┼────────────────────────────────────────┤
│ • INC-001               │ • React Flow Visualization Canvas        │ • Model: Qwen 3.8 27B [Switch ▼]       │
│ • Severity: CRITICAL    │ • Nodes:                                 │ • Status: Completed (3 tool calls)     │
│ • Status: Open          │   [User: svc_deploy]                     │ • Execution: 1.42s | ID: req_001       │
│ • Owner: Sarah (Tier 2) │       │ (Observed - Solid)               │                                        │
│                         │       ▼                                  │ ── Observed Facts ───────────────────  │
│ ── Chronological        │   [Host: SRV-APP-01]                     │ • Rapid failed logons followed by      │
│    Timeline ─────────── │       │ (Correlated - Dashed)            │   successful authentication.           │
│ 08:00:00 [Logon Failure]│       ▼                                  │   Citations: [evt_001] [evt_002]       │
│   user: svc_deploy      │   [Detection: DET-004 Exfiltration]      │ • 150 MB outbound data egress to       │
│ 08:02:00 [Logon Success]│       │ (Observed - Solid)               │   external destination 203.0.113.99.   │
│   src: 198.51.100.44    │       ▼                                  │   Citations: [evt_003]                 │
│ 08:05:00 [Network Egress│   [IP: 203.0.113.99]                     │                                        │
│   bytes: 150,000,000    │                                          │ ── Hypotheses ───────────────────────  │
│                         │ [Controls: Zoom, Pan, Blast Radius Toggle│ • Credential compromise followed by    │
│ [Event Filter: All ▼]   │  Edge Filter: Observed / Correlated]     │   immediate data staging & egress.     │
│                         │                                          │   Confidence: HIGH | Caveats: 1        │
│                         │ ── Selected Event Drawer (Bottom Slide) ─│                                        │
│                         │ ID: evt_003 | Action: network_connect    │ ── Recommended Actions ──────────────  │
│                         │ Src: 192.168.1.50 -> Dst: 203.0.113.99   │ • Revoke session tokens for svc_deploy │
│                         │ Bytes: 150 MB | Port: 443 | Proto: tcp   │   [Requires Human Approval]            │
│                         │ [View Raw Sanitized Payload]             │ • Block 203.0.113.99 at firewall       │
│                         │                                          │   [Approve Action] [Reject Action]     │
└─────────────────────────┴──────────────────────────────────────────┴────────────────────────────────────────┘
```

- **Interactive Citation Linking:** Clicking any citation pill (`[evt_001]`) highlights the corresponding event on the Timeline (Panel 1), centers the graph on the associated node (Panel 2), and opens the Evidence Drawer with normalized CES attributes.

### 4.2 CyberTrace ThreatLab (Replay & Benchmark Studio)
- **Top Bar:** Scenario Selector dropdown (`Multi-Stage Account Takeover`, `Ransomware Staging`, `Benign Noise`), Replay Button (`▶ Start Replay Run`), Rule Filter toggle (`All Rules`, `Modified Rules Only`).
- **Main Viewport:**
  - **Confusion Matrix Tile:**
    - True Positives (Green): 8
    - False Positives (Yellow): 0
    - False Negatives (Red): 1
    - Precision: 100.0% | Recall: 88.9% | $F_1$ Score: 94.1%
  - **Replay Timeline:** Chronological step-by-step event replay visualizing which rule fired on which exact event.
  - **Missed Detection Inspector:** Highlights events that matched known attack techniques but were missed by current active rules, with recommended rule improvements.

### 4.3 Threat Hunting Studio
- **Query Filter Builder:** Horizontal condition builder:
  `[+ Add Condition] [Field: user_identity ▼] [Operator: equals ▼] [Value: svc_deploy] [AND] [Field: bytes_out ▼] [Operator: > ▼] [Value: 10000000]`
- **Action Buttons:** `[Execute Hunt ⌘Enter]`, `[Save Query]`, `[Export CSV]`, `[Create Incident from Selection]`.
- **Telemetry Results Grid:** High-density, virtualized table with sortable columns, copyable cell pills, and right-click context menu (`Filter by this value`, `Pivot on Entity`).

---

## 5. Reusable Component Catalog

| Component Name | Description & Props | Visual Styling |
| :--- | :--- | :--- |
| `<SeverityBadge>` | Displays severity level (`critical`, `high`, `medium`, `low`, `info`). | Solid dark background with matching border and high-contrast text. |
| `<EvidenceCitation>` | Clickable event ID pill (`evt_...`). Props: `eventId`, `onClick`. | Cyan/indigo border, monospace font, subtle hover highlight. |
| `<AttackGraphCanvas>` | React Flow canvas displaying nodes and labeled edges. | Dark grid background (`#080c14`), styled node cards, directional arrows. |
| `<DataProvenanceBadge>` | Distinguishes `Live Telemetry` from `Synthetic Benchmark`. | Muted purple border, subtle uppercase label. |
| `<PlaybookApprovalModal>` | Gating dialog requiring rationale before recording simulated containment. | Obsidian card, red/amber accent, explicit confirm button. |
| `<TimelineEntry>` | Chronological event or detection node in incident dossier. | Vertical connector line, icon representing category (auth, network, proc). |
| `<MetricTile>` | Summary KPI card. Props: `title`, `value`, `delta`, `provenance`. | Rounded 8px, 1px subtle border, glowing indicator dot. |

