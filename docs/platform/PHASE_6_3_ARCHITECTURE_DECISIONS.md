# Architecture Decision Record: Phase 6.3 Saved Hunts & Detection Rule Lifecycle

**Date:** 2026-11-02  
**Status:** Approved  
**Branch:** `feature/phase-6.3-saved-hunts-detection-rules`  
**Base Commit:** `71e3a7c`  

---

## 1. Context & Architectural Problem Statement

In Phase 6.2, CyberTrace established a structured threat-hunting query compiler with AST validation, parameterized SQL compilation, provenance tracking, and correlation with detections and incidents. However, an architectural audit of the detection subsystem revealed two fundamental gaps:

1. **Fired Detections vs. Rule Definitions:** The database table `detections` stores alerts that have *already fired*, not the definitions of detection rules. Detection rules (`DET-001` through `DET-004`) were hardcoded Python classes executed in memory during event ingestion.
2. **Absence of Rule Management Lifecycle:** There was no mechanism to persist threat hunting queries, promote successful hunting queries into candidate detection rules, validate rule performance against historical benchmarks (ThreatLab), enforce analyst approval (four-eyes review), or record state transitions in an append-only audit ledger.

Phase 6.3 bridges this gap by creating a decoupled, auditable lifecycle from structured threat hunt to active production detection rule.

---

## 2. Locked Architectural Decisions

### Decision A: Detection Rule Complexity — Start with Single-Event AST Rules
* **Decision:** Phase 6.3 focuses on single-event AST rules that evaluate predicates directly against individual security events (e.g., `bytes_out >= 10000000 AND action == "network_connect" AND severity IN ["high", "critical"]`).
* **Rationale:**
  * Maximizes reusability of the battle-tested Phase 6.2 AST parser (`FilterGroup`, `FilterCondition`, `TimeRangeFilter`).
  * Enables zero-overhead query compilation for historical validation against the existing database.
  * Avoids introducing complex stateful streaming or distributed window buffers prematurely.
* **Future Extension:** Sliding-window threshold aggregation fields (e.g., `aggregation_function`, `threshold_count`, `time_window_seconds`, `group_by_fields`) may be reserved in schemas, but engine execution will not claim threshold capability until Phase 7.

### Decision B: Four-Eyes Approval Workflow — Explicit Demo Attribution Disclaimer
* **Decision:** Promotion of a detection rule draft to production requires explicit approval by a reviewer different from the author (`reviewer_id != created_by`), accompanied by a mandatory justification rationale. Self-approval is strictly disabled by default.
* **Security & Authenticity Disclaimer:**
  * CyberTrace currently operates without an authentication subsystem, user database table, or cryptographic session management.
  * Therefore, analyst identifiers (`created_by`, `reviewer_id`) are caller-supplied metadata for demonstration purposes.
  * The system explicitly acknowledges this limitation in API contracts and documentation: caller-supplied identities do not constitute cryptographic identity verification or enterprise RBAC.
  * Self-approval may only be bypassed if an explicit demo override flag (`allow_demo_self_approval=True`) is provided, which triggers a visible security audit warning in the rule audit ledger.

### Decision C: Dynamic Detection Engine — Shared Rule-Matching Abstraction
* **Decision:** Detection rule logic must not be implemented twice. A unified AST evaluation model ensures identical semantics between:
  1. Historical pre-flight validation (evaluating the AST over historical stored events via SQLAlchemy query compilation).
  2. Live stream evaluation (evaluating the AST over incoming `CommonEvent` instances in memory during ingestion).
* **Hardcoded Rules Preservation:** The four foundational hardcoded rules (`DET-001: Excessive Failed Logins`, `DET-002: Off-Hours Admin Activity`, `DET-003: Large Outbound Data Transfer`, `DET-004: Port Scanning Activity`) remain preserved and active, running concurrently alongside dynamic database-backed rules.

---

## 3. Five-Entity Lifecycle Data Model

```
+-----------------------------------------------------------------------------+
|                                1. SavedHunt                                 |
| - ID (UUID)                    - Version (optimistic concurrency lock)      |
| - Name & Description           - Tags (JSON array)                          |
| - Created By (demo metadata)   - Query AST (validated FilterGroup JSON)     |
| - Last Run At & Run Count      - Archive Status (soft-delete flag)          |
+-----------------------------------------------------------------------------+
                                      |
                                      | [Promotion to Detection Rule]
                                      v
+-----------------------------------------------------------------------------+
|                            2. DetectionRuleDraft                            |
| - ID (UUID)                    - Source Hunt Reference (UUID)               |
| - Source Snapshot (immutable)  - Rule Name, Description, Severity, MITRE    |
| - Created By (demo metadata)   - Version (draft iteration)                  |
| - Lifecycle State: DRAFT -> VALIDATED -> PENDING_APPROVAL                   |
+-----------------------------------------------------------------------------+
                                      |
                                      | [Pre-flight Simulation]
                                      v
+-----------------------------------------------------------------------------+
|                            3. RuleValidationRun                             |
| - ID (UUID)                    - Rule Draft ID & Draft Version              |
| - Target Telemetry Scope       - Total Events Scanned & Matches Found       |
| - Estimated Alert Volume/Day   - Provenance Breakdown (Observed vs Synth)   |
| - Execution Duration (ms)      - Benchmark Performance Scores               |
+-----------------------------------------------------------------------------+
                                      |
                                      | [Four-Eyes Review & Approval]
                                      v
+-----------------------------------------------------------------------------+
|                            4. ActiveDetectionRule                           |
| - ID (UUID)                    - Rule Code (e.g. CUST-001)                  |
| - Source Draft Reference       - Active Version & Compiled AST Matcher      |
| - Severity & MITRE Mapping     - Status: ACTIVE / DISABLED / DEPRECATED     |
| - Match Count & Alert Count    - Created At & Updated At                    |
+-----------------------------------------------------------------------------+
                                      |
                         (Records all transitions)
                                      v
+-----------------------------------------------------------------------------+
|                              5. RuleAuditEntry                              |
| - ID (UUID)                    - Target Entity (Draft or Active Rule ID)    |
| - Transition / Action          - Actor ID (caller-supplied demo metadata)   |
| - Justification / Rationale    - Timestamp (UTC)                            |
| - State Before & After (JSON)  - Demo Override Flag & Security Warning      |
+-----------------------------------------------------------------------------+
```

---

## 4. Phase-by-Phase Implementation Plan

1. **Phase 6.3A: Saved Threat Hunts & Query Persistence (CURRENT SCOPE)**
   * `saved_hunts` table & Alembic migration.
   * `SavedHuntModel` and Pydantic schemas reusing Phase 6.2 AST.
   * CRUD endpoints with optimistic version concurrency locking (HTTP 409 on stale update).
   * Re-execution endpoint updating execution telemetry (`last_run_at`, `run_count`).
   * Duplication endpoint creating independent version 1 clones.
   * Soft-delete/archival semantics.
2. **Phase 6.3B: Detection Rule Drafts & Pre-flight Validation**
   * `detection_rule_drafts` and `rule_validation_runs` tables.
   * Promotion API converting saved hunt AST into draft rule.
   * Pre-flight simulation engine measuring event matches across historical telemetry and ThreatLab benchmarks.
   * Granular provenance telemetry breakdown during validation.
3. **Phase 6.3C: Four-Eyes Approval Workflow & Promotion to Active Detection Rule**
   * `active_detection_rules` and `rule_audit_ledger` tables.
   * Approval workflow requiring distinct reviewer and mandatory justification.
   * In-memory evaluator integrating active custom rules into the live ingestion pipeline alongside hardcoded rules `DET-001` through `DET-004`.

