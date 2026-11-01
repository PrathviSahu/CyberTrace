# CyberTrace — UI Design System & Component Specification
## Refined Warm Graphite & Restrained Bronze SOC Command Centre Aesthetic

---

## 1. Visual Theme & Design Philosophy

CyberTrace is engineered with a **refined, professional Security Operations Centre (SOC) command aesthetic**. It decisively rejects the noisy, oversaturated "cyberpunk" tropes of generic AI-generated dashboards—specifically eliminating bright cyan borders on every card, purple/blue glowing gradients, neon animations, and fluorescent green buttons.

Instead, CyberTrace implements a disciplined, high-density, high-legibility interface built on **Warm Graphite, Cool Slate, and a Restrained Warm Bronze accent**, optimized for 12-hour analyst shifts and prolonged cognitive focus.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CYBERTRACE WARM GRAPHITE & BRONZE PALETTE            │
├────────────────────────────────┬───────────────────────────────────────┤
│ Canvas / App Background        │ Deep Warm Graphite: #111315           │
│ Sidebar Navigation             │ Dark Charcoal Slate: #191C1F          │
│ Main Panel Surface             │ Base Surface: #1D2125                 │
│ Elevated Card / Modal Surface  │ Elevated Surface: #24282C             │
│ Structural Border              │ Crisp Graphite Border: #30363C        │
│ Primary Brand Accent           │ Restrained Warm Bronze: #B58A61       │
│ Navigation Selection Surface   │ Warm Dark Bronze Tint: #2B2722        │
│ Severity Critical / High Alert │ Crimson Red: #E06C68 (bg: #2D1817)    │
│ Severity High / Warning        │ Amber Bronze: #D99A54 (bg: #2B1D12)   │
│ Severity Medium / Caution      │ Topaz Ochre: #C9B86B (bg: #2A2714)    │
│ Severity Low / Informational   │ Sage Teal: #76A58B (bg: #15261D)      │
│ Neutral / System Info          │ Slate Muted: #8A94A0 (bg: #1E2328)    │
└────────────────────────────────┴───────────────────────────────────────┘
```

---

## 2. Design Tokens & Variables

### 2.1 CSS Custom Properties
```css
:root {
  /* Surfaces & Canvas */
  --color-canvas: #111315;
  --color-sidebar: #191c1f;
  --color-surface: #1d2125;
  --color-elevated: #24282c;
  --color-active: #2b2722;
  --color-hover: #22272c;

  /* Borders & Dividers */
  --color-border: #30363c;
  --color-border-subtle: #24292e;
  --color-border-accent: #b58a61;

  /* Typography */
  --color-text-primary: #e9ecef;
  --color-text-secondary: #a0a7ae;
  --color-text-muted: #737d87;
  --color-text-code: #d99a54;

  /* Primary Accent: Restrained Warm Bronze */
  --color-accent-bronze: #b58a61;
  --color-accent-bronze-hover: #c69d75;
  --color-accent-bronze-subtle: rgba(181, 138, 97, 0.12);

  /* Security Severity Spectrum */
  --color-severity-critical: #e06c68;
  --color-severity-critical-bg: #2d1817;
  --color-severity-high: #d99a54;
  --color-severity-high-bg: #2b1d12;
  --color-severity-medium: #c9b86b;
  --color-severity-medium-bg: #2a2714;
  --color-severity-low: #76a58b;
  --color-severity-low-bg: #15261d;
  --color-severity-info: #8a94a0;
  --color-severity-info-bg: #1e2328;
}
```

### 2.2 Typography Scale & Font Pairing Rules

CyberTrace enforces a strict separation between **UI Prose/Labels** and **Technical Telemetry Data**:

1. **Primary Interface Font:** `Inter`, `-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`.
   - Used for: Workspace headers, panel titles, narrative summaries, table headers, buttons, navigation links, and analytical findings.
   - Weights: Regular (`400`), Medium (`500`), Semi-bold (`600`), Bold (`700`).
2. **Monospace Telemetry Font:** `JetBrains Mono`, `ui-monospace, "SF Mono", Menlo, Consolas, monospace`.
   - **Strictly reserved for telemetry values:** Event IDs (`evt_...`), Incident IDs (`INC-...`), Detection IDs (`DET-...`), IPv4/IPv6 addresses, SHA-256 hashes, timestamps, and raw JSON logs.
   - **Never used for:** General UI labels, buttons, or paragraph copy (preventing the "cramped terminal emulator" fatigue).

| Token | Size | Line Height | Weight | Font Family | Usage |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `text-display` | 22px | 28px | 600 | Inter | Primary Workspace Headers, Screen Titles |
| `text-h1` | 18px | 24px | 600 | Inter | Section Headers, Modal Titles |
| `text-h2` | 14px | 20px | 600 | Inter | Panel Headers, Metric Card Labels |
| `text-body` | 13px | 18px | 400 | Inter | General Findings, Investigation Dossier |
| `text-body-sm` | 12px | 16px | 400 | Inter | Table Content, Sidebar Links, Tooltips |
| `text-caption` | 11px | 14px | 500 | Inter | Metadata Tags, Subtext, Form Help Text |
| `text-mono` | 12px | 16px | 400 | JetBrains Mono | Event IDs, IP Addresses, Hashes, Timestamps |
| `text-mono-xs` | 11px | 14px | 400 | JetBrains Mono | Inlined Node Identifiers, Port Numbers |

---

## 3. Layout Architecture & Structural Hierarchy

### 3.1 Global Application Shell
The interface consists of a fixed-width left navigation sidebar (`240px` expanded, `64px` collapsed), a top operational status bar (`48px` height), and a flexible central workspace viewport.

```
┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ TOP BAR: [Logo] CYBERTRACE  [Backend Connected ●]  [Search ⌘K]  [Time Range: 24h]  [Live Telemetry]   │
├──────────────┬────────────────────────────────────────────────────────────────────────────────────────┤
│ LEFT NAV     │ MAIN COMMAND WORKSPACE                                                                 │
│              │                                                                                        │
│ COMMAND      │  ┌───────────────────────┐ ┌──────────────────────┐ ┌───────────────────────────────┐  │
│ • Overview   │  │ Open Incidents: 1     │ │ Critical Alerts: 1   │ │ Monitored Assets: 14          │  │
│ • Alerts     │  │ [Live Telemetry]      │ │ [Live Telemetry]     │ │ [Live Telemetry]              │  │
│ • Incidents  │  └───────────────────────┘ └──────────────────────┘ └───────────────────────────────┘  │
│              │                                                                                        │
│ INTEL        │  ┌─────────────────────────────────────────────────┐ ┌──────────────────────────────┐  │
│ • Hunting    │  │ Active Incident Queue (Content-Sized Height)    │ │ Detection Activity Feed      │  │
│ • Graph      │  │ Desktop (≥1280px): 7-Column Full Table          │ │ Stream of triggering rules,  │  │
│ • Threat In  │  │ Tablet (<1280px): Compact Stacked Row Layout    │ │ MITRE tactics, entities      │  │
│              │  └─────────────────────────────────────────────────┘ └──────────────────────────────┘  │
│ ENGIN.       │                                                                                        │
│ • Rules      │  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│ • ThreatLab  │  │ Recent Observed Events (Persisted Telemetry Timeline)                            │  │
│              │  │ Real chronological log sequence with event IDs, IPs, categories, and timestamps   │  │
│ ENVIRON.     │  └──────────────────────────────────────────────────────────────────────────────────┘  │
│ • Assets     │                                                                                        │
│ • Identities │                                                                                        │
└──────────────┴────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Responsive Breakpoint Architecture

CyberTrace adapts between ultra-wide desktop monitors, standard laptops, and SOC tablet devices:

| Breakpoint | Width | Incident Table Behavior | Recent Events Behavior | Detection Feed |
| :--- | :--- | :--- | :--- | :--- |
| **Desktop Ultra** | $\ge 1920\text{px}$ | 7-column tabular grid, side-by-side with detection feed. | Full multi-column grid view. | Full vertical feed alongside queue. |
| **Desktop Standard** | $1280\text{px} - 1919\text{px}$ | 7-column tabular grid, truncated summary, unclipped actions. | Full multi-column grid view. | Side-by-side with queue. |
| **Tablet / Compact** | $< 1280\text{px}$ (`1024\text{px}`) | **Switches to Stacked Incident Row Layout** (`block xl:hidden`): ID & severity on top, summary underneath, entity/detection metrics, status pill, and fully visible `Investigate` button. | Compact wrapped event cards preventing table overflow. | Stacks cleanly below the incident queue. |

---

## 4. Attack Graph & Layout Engine Specification

CyberTrace utilizes **`@xyflow/react`** combined with **`@dagrejs/dagre`** to render deterministic, professional hierarchical Directed Acyclic Graphs (DAGs) representing multi-stage attack scenarios.

### 4.1 Dagre Layout Specifications
- **Layout Direction:** Left-to-Right (`rankdir: 'LR'`) by default, toggleable to Top-to-Bottom (`rankdir: 'TB'`).
- **Node Separation:** `nodesep: 48px` (horizontal spacing between parallel entity nodes).
- **Rank Separation:** `ranksep: 80px` (vertical/horizontal spacing between sequential attack stages).
- **Edge Routing:** Smooth step or orthogonal bezier curves with directional arrowheads.

### 4.2 Dark Custom Node Styling
All attack graph nodes adhere strictly to the Warm Graphite design tokens:
- **Node Container:** Background `#1D2125`, 1px solid border `#30363C`, border-radius `8px`, crisp drop shadow `0 2px 8px rgba(0, 0, 0, 0.45)`.
- **Zero White Borders:** Default ReactFlow white node borders, blue outlines, and bright handles are completely overridden via CSS (`.react-flow__node { border: none !important; }`).
- **Connection Handles:** Subtle graphite dots (`#737D87`), zero glowing halos.
- **Node Types & Category Indicators:**
  - `user`: Identity icon, User Account badge.
  - `host`: Server/Endpoint icon, Hostname and IP badge.
  - `ip`: Network Globe icon, observed IP address.
  - `detection`: Shield Alert icon, severity-tinted pill (`#E06C68` for Critical, `#D99A54` for High).
- **Interactive Inspector:** Clicking any node or edge opens the **Entity Inspector Slide-Over Drawer**, displaying observed attributes, first/last seen timestamps, and direct links to related events.

### 4.3 Edge Taxonomy & Visual Rules
- **`observed` (Solid Edge):** Direct observed telemetry (e.g., Host A connected to IP B). Stroke: `#737D87`, stroke-width: 1.5px.
- **`correlated` (Dashed Edge):** Engine-correlated relationship (e.g., Shared compromised identity within 15-minute window). Stroke: `#B58A61`, stroke-dasharray: `5 5`.
- **`inferred` (Dotted Edge):** AI or heuristic hypothesis (e.g., Potential lateral movement pathway). Stroke: `#8A94A0`, stroke-dasharray: `2 4`.

---

## 5. Screen-by-Screen Layout Specifications

### 5.1 Command Centre (`/`)
- **Metric Strip (4 Tiles):**
  1. *Open Incidents:* Active correlated incidents count.
  2. *Critical Alerts:* Count of active critical-severity detections.
  3. *Monitored Assets:* Derived distinct assets from ingested telemetry.
  4. *System Status:* Ingestion health & model status (`Backend Connected`).
- **Content-Sized Incident Queue:**
  - Avoids artificial height stretching; dynamically sizes to the number of active incidents.
  - Desktop ($\ge 1280\text{px}$): 7-column table (`ID`, `Title`, `Severity`, `Status`, `Entities`, `Last Seen`, `Actions`).
  - Tablet ($< 1280\text{px}$): Stacked card layout with zero horizontal clipping.
- **Detection Activity Feed:**
  - Displays recent detection firings with MITRE ATT&CK tactic tags, triggering rule ID, and triggering entity.
- **Recent Observed Events Timeline:**
  - Direct display of actual ingested events from database (`security_events`).
  - Provides instant forensic context without having to navigate away from the overview.

### 5.2 Incident Investigation Workspace (`/incidents/:id`)
- **Three-Panel Collaborative Architecture:**
  - **Panel 1 (Incident Dossier, Left 340px):**
    - Metadata overview (Incident ID, Severity, Status dropdown, Correlation Key).
    - Chronological event timeline with collapsible event details.
    - Entities list with observed counts.
  - **Panel 2 (Adversary Attack Graph, Center Flexible):**
    - Dagre-powered hierarchical DAG canvas.
    - Controls: Zoom in/out, Fit View, Re-layout (`LR` / `TB`), Blast Radius toggle.
    - Entity Inspector drawer on node click.
  - **Panel 3 (AI Investigation & Evidence Findings, Right 440px):**
    - Model selector (`qwen-3.8-27b`, `deepseek-v4.1-flash`, or `auto`).
    - Executive summary with execution time and tool call count.
    - Verified Observed Facts with clickable `[evt_...]` citation pills.
    - Hypotheses with confidence levels and analytical caveats.
    - Gated Recommended Actions (`requires_human_approval: true`) with "Approve Action" / "Reject Action" buttons.

### 5.3 Detection Rules Studio (`/rules`)
- **Two-Panel Split Layout:**
  - **Left Panel (Rule Registry):** Filterable rule catalog with severity pills, active toggles, and MITRE technique tags.
  - **Right Panel (Rule Definition & Sigma Subset):** Read-only and editable rule specifications adhering to the supported Sigma-compatible subset.

### 5.4 Asset & Identity Directory (`/assets`, `/identities`)
- **Tabular Entity Overview:**
  - Hostnames, asset types (Server, Workstation, Gateway), criticality tiers (`tier_1` to `tier_4`), and observed IP addresses.
  - Real telemetry provenance tag (`[Observed Telemetry]`).
  - Strict absence of simulated or hardcoded values.

### 5.5 ThreatLab Studio (`/threatlab`)
- **Scenario Replay Harness:**
  - Select benchmark scenarios (`Multi-Stage Credential Stuffing`, `Ransomware Staging`, etc.).
  - Run in-memory replay against detection rules.
  - Mathematical confusion matrix display: True Positives, False Positives, False Negatives, Precision, Recall, and $F_1$-score.

---

## 6. Reusable Component Catalog

| Component Name | Description & Props | Visual Specification |
| :--- | :--- | :--- |
| `<SeverityBadge>` | Displays severity level (`critical`, `high`, `medium`, `low`, `info`). | Solid dark tinted background (`#2D1817`), matching 1px border, high-contrast text (`#E06C68`). |
| `<EvidenceCitation>` | Clickable event ID pill (`evt_...`). Props: `eventId`, `onClick`. | JetBrains Mono font, bronze border `#B58A61`, subtle hover highlight, opens Evidence Drawer. |
| `<AttackGraphCanvas>` | React Flow + Dagre canvas displaying nodes and labeled edges. | Graphite canvas `#111315`, dark node surfaces `#1D2125`, no white outlines, directional arrows. |
| `<DataProvenanceBadge>` | Distinguishes `Live Telemetry`, `Observed Telemetry`, and `Synthetic Benchmark`. | Muted border, uppercase label, strictly honest data provenance indicator. |
| `<HumanApprovalModal>` | Gating dialog requiring rationale before recording simulated containment. | Elevated surface `#24282C`, warm bronze accent, explicit Confirm / Cancel buttons. |
| `<TimelineEntry>` | Chronological event or detection node in incident dossier. | Vertical graphite connector `#30363C`, category icon (auth, network, proc), monospace timestamp. |
| `<MetricTile>` | Summary KPI card. Props: `title`, `value`, `delta`, `provenance`. | Rounded 8px, `#1D2125` surface, `#30363C` border, bronze accent subtext. |
