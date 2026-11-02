# Architecture Decision Record: Phase 6.3C Governance, Activation & Audit Ledger

**Date:** 2026-11-02
**Status:** Implemented & Verified (Stages 1–5 Complete)
**Branch:** `feature/phase-6.3-saved-hunts-detection-rules`
**Base Commit:** [`5878eb9`](https://github.com/PrathviSahu/CyberTrace/commit/5878eb93dd7fcbd72381829aa83cb10db23e084d) (docs: Phase 6.3C ADR) over [`b66164b`](https://github.com/PrathviSahu/CyberTrace/commit/b66164bb0babf8e3a063794465f569aa73344867) (feat: Phase 6.3B implementation)
**Scope:** Phase 6.3C (Analyst Approval, Production Activation, Immutable Audit Ledger, Detection Engine Isolation)

---

## 1. Context & Architectural Problem Statement

Phase 6.3A established persistent, versioned saved threat hunts. Phase 6.3B established detection rule drafts with dual-scope pre-flight validation against historical telemetry and ThreatLab benchmark scenarios.

Phase 6.3C bridges the candidate draft workflow with the live production detection engine. An architectural review identified seven critical risks that must be resolved prior to coding:
1. **Four-Eyes Governance vs. Authenticated RBAC:** Because CyberTrace currently operates without an enterprise authentication subsystem or cryptographic sessions, caller-supplied usernames are demo metadata. The architecture must explicitly classify this as **demonstration-level governance** and disclaim real RBAC.
2. **Rule-Code Allocation Race Hazards:** Using `MAX(rule_code_num) + 1` is vulnerable to duplicate codes and race conditions under concurrent approvals. A database-safe atomic sequence allocator is required.
3. **Audit Lineage Severance:** `ON DELETE SET NULL` on foreign keys risks decoupling active rules from their foundational evidence (drafts and validation runs). Restrictive foreign key constraints (`RESTRICT`) must be enforced.
4. **Transaction Ownership & Atomicity:** If repositories independently call `session.commit()`, audit failure could leave orphaned active rules. A dedicated service layer must own the single transaction boundary.
5. **Detection Engine Isolation & Object Immutability:** Python tuples prevent collection resizing, but do not freeze object state. Active custom rules must be frozen immutable objects, and ingestion must execute against request-scoped snapshots preserving `DET-001` through `DET-004`.
6. **Repository History & Alembic Ancestry:** Git ancestry and migration chains must be formally verified against the repository state before creating migrations.
7. **Comprehensive Concurrency & Regression Verification:** A test matrix must prove transaction rollback, allocation safety, lineage retention, and engine isolation under concurrent conditions.

---

## 2. Core Architecture Decisions

### ADR-1: Demonstration-Level Four-Eyes Approval Governance

* **Governance Classification:** Demonstration-Level Approval Governance (Not Authenticated RBAC).
* **Identity Context:** CyberTrace currently operates without an enterprise authentication subsystem, identity provider, password store, or cryptographic session tokens. Analyst identifiers (`created_by`, `approver_id`, `actor`) are **caller-supplied demo metadata**.
* **Governance Rule:**
  - In normal operation, `approver_id.strip().lower() != draft.created_by.strip().lower()`.
  - Self-approval is blocked by default with `HTTP 403 Forbidden` (`detail="Four-eyes principle violation: Approver matches draft author. Independent peer review is required."`).
* **Server-Side Demo Override:**
  - Demo self-approval is controlled **strictly by a server-side configuration parameter**, never by client request payload parameters:
    ```python
    # backend/app/core/config.py
    ALLOW_DEMO_SELF_APPROVAL: bool = False
    ```
  - The API approval schema (`RuleDraftApprovalRequest`) contains **no client-controlled bypass flag**.
  - When `ALLOW_DEMO_SELF_APPROVAL is True` and self-approval occurs, the system **unconditionally logs a visible security audit warning** in `rule_audit_ledger`:
    `"security_warning": "SECURITY AUDIT WARNING: Four-eyes principle violated. Self-approval permitted under server-side ALLOW_DEMO_SELF_APPROVAL configuration."`
    and sets `demo_override_flag = True`.
* **Mandatory Attribution Disclaimer:**
  Every API response referencing approval governance or actor identity explicitly includes:
  ```json
  {
    "governance_classification": "demonstration_level_approval_gate",
    "author_attribution_note": "Caller-supplied demo identity. Not cryptographically verified or backed by enterprise RBAC."
  }
  ```

---

### ADR-2: Atomic Sequential Rule-Code Allocation

* **Context:** Active detection rules must receive human-readable sequential canonical codes (`CUST-001`, `CUST-002`, `CUST-003`). `SELECT MAX(...) + 1` suffers from race hazards under concurrent approval requests.
* **Decision:**
  1. **Dedicated Database Allocator Table:**
     ```sql
     CREATE TABLE rule_code_allocators (
         sequence_name VARCHAR(64) PRIMARY KEY,
         current_value INTEGER NOT NULL DEFAULT 0,
         updated_at TIMESTAMP WITH TIME ZONE NOT NULL
     );
     ```
  2. **Atomic Increment Mechanism:**
     - Allocation executes inside the atomic approval transaction:
       ```sql
       UPDATE rule_code_allocators
       SET current_value = current_value + 1, updated_at = :now
       WHERE sequence_name = 'custom_rule'
       RETURNING current_value;
       ```
     - **PostgreSQL**: Row-level write lock (`FOR UPDATE`) serializes concurrent transactions. The second transaction blocks until the first commits, reading the next integer without collisions.
     - **SQLite**: The write transaction lock (`BEGIN IMMEDIATE`) serializes access. `SELECT current_value FROM rule_code_allocators WHERE sequence_name = 'custom_rule'` returns the incremented integer.
     - Formatted canonically as: `f"CUST-{next_val:03d}"`.
  3. **Defense-in-Depth Schema Constraint:**
     `active_detection_rules.rule_code` retains a strict `UNIQUE` constraint in the database schema. If an unexpected collision occurs, the transaction rolls back cleanly with `HTTP 409 Conflict`.
  4. **Initial Seeding:** Alembic migration seeds the allocator row `('custom_rule', 0, now)` if not present.

---

### ADR-3: Audit Lineage Preservation & Restrictive Foreign Keys

* **Context:** If `active_detection_rules` used `ON DELETE SET NULL` for `source_draft_id` and `validation_run_id`, accidental or intentional deletion of a draft or validation run would sever the provenance of the production rule.
* **Decision:**
  1. **Enforce `ON DELETE RESTRICT` (or `NO ACTION`):**
     ```sql
     ALTER TABLE active_detection_rules
     ADD CONSTRAINT fk_active_rules_source_draft
     FOREIGN KEY (source_draft_id) REFERENCES detection_rule_drafts(id) ON DELETE RESTRICT;

     ALTER TABLE active_detection_rules
     ADD CONSTRAINT fk_active_rules_validation_run
     FOREIGN KEY (validation_run_id) REFERENCES rule_validation_runs(id) ON DELETE RESTRICT;
     ```
  2. **Soft-Archival Alignment:**
     - Drafts are soft-deleted via `is_archived = True`. Archival does not physically remove rows, preserving foreign key integrity and lineage.
     - Physical `DELETE` operations against an approved draft or its validation runs are rejected by the database engine with an integrity error.
  3. **Independent Snapshot Retention:**
     - `active_detection_rules` stores `source_draft_version: int` and an immutable frozen copy of `query_definition` (the validated AST snapshot). Even if a draft is reopened and edited (advancing to version 2), the active rule retains its original validated definition.

---

### ADR-4: Service-Owned Transaction Atomicity

* **Context:** Approval transitions draft status, allocates rule codes, creates active rules, and writes audit records. If individual repository methods call `session.commit()`, a failure during audit logging leaves orphaned active rules without governance records.
* **Decision:**
  1. **Single Transaction Ownership by `RuleLifecycleService`:**
     - A dedicated service `RuleLifecycleService` (`backend/app/services/rule_lifecycle_service.py`) owns the database transaction boundary:
       ```python
       class RuleLifecycleService:
           def __init__(self, session: AsyncSession):
               self.session = session
               self.draft_repo = RuleDraftRepository(session)
               self.active_rule_repo = ActiveRuleRepository(session)
               self.audit_repo = RuleAuditRepository(session)

           async def approve_rule_draft(self, draft_id: str, payload: RuleDraftApprovalRequest) -> ActiveDetectionRuleModel:
               async with self.session.begin():
                   # 1. Fetch draft, verify status == 'VALIDATED', non-stale validation, version match
                   # 2. Check four-eyes demonstration governance
                   # 3. Conditional draft update: status -> 'APPROVED', version = version + 1
                   # 4. Atomic sequence increment on rule_code_allocators -> next CUST-xxx
                   # 5. Insert ActiveDetectionRuleModel
                   # 6. Insert RuleAuditEntryModel (recording before/after state diffs)
               # All operations commit atomically upon clean context exit
       ```
  2. **Repository Hygiene (`flush` instead of `commit`):**
     - Repositories invoked by `RuleLifecycleService` perform `await self.session.flush()` (making IDs and sequence numbers visible within the transaction) but **never call `await self.session.commit()`**.
  3. **Rollback Guarantee:**
     - If any step fails (e.g., audit validation error, disk error, constraint error), the outer transaction rolls back completely.
     - Zero orphaned audit entries; zero unrecorded rule activations.

---

### ADR-6: Optimistic Concurrency Control, Atomic Conditional Updates & Draft-to-Active Lineage Uniqueness

* **Context & Audit Discovery:**
  During the Stage 2 focused concurrency audit, two critical race hazards were identified and reproduced:
  1. *Concurrent Draft Approval Race:* Simultaneous approval requests against the same validated draft could both pass in-memory checks, emit unconstrained `UPDATE` statements, and result in duplicate active rules (e.g., `CUST-001` and `CUST-002`) and duplicate audit entries.
  2. *Status Toggle Race:* The lifecycle service previously updated ORM attributes directly rather than leveraging `ActiveRuleRepository.update_rule_status_atomic()`, risking lost updates under concurrent status patch operations.

* **Decisions & Remediations (Stage 2.1):**
  1. **Atomic Conditional State Transition on Draft Approval:**
     In `RuleLifecycleService.approve_rule_draft()`, the draft status transition is executed via an atomic conditional SQL `UPDATE` prior to rule code allocation:
     ```python
     stmt = (
         update(DetectionRuleDraftModel)
         .where(
             DetectionRuleDraftModel.id == draft_id,
             DetectionRuleDraftModel.version == payload.draft_version,
             DetectionRuleDraftModel.status == DraftStatus.VALIDATED.value,
             DetectionRuleDraftModel.is_archived.is_(False),
         )
         .values(
             status=DraftStatus.APPROVED.value,
             version=DetectionRuleDraftModel.version + 1,
             updated_at=now,
         )
     )
     res = await self.session.execute(stmt)
     if res.rowcount == 0:
         raise VersionConflictError(f"Draft '{draft_id}' state or version conflict: draft was concurrently approved, modified, or archived.")
     ```
     - **Serialization Guarantee:** The database serializes write access on the draft row. Exactly ONE concurrent transaction matches `version == expected_version AND status == 'VALIDATED'`.
     - **Early Abort & Complete Rollback:** The losing transaction receives `rowcount == 0`, raises `VersionConflictError`, and immediately rolls back within the service transaction without calling `_allocate_next_rule_code()`, without creating an active rule, and without writing an audit record.
  2. **Atomic Conditional State Transition on Active Rule Status Toggles:**
     `RuleLifecycleService.toggle_active_rule_status()` directly invokes `ActiveRuleRepository.update_rule_status_atomic()`, executing:
     ```sql
     UPDATE active_detection_rules
     SET status = :new_status, version = version + 1, updated_at = :now
     WHERE id = :rule_id AND version = :expected_version;
     ```
     If `rowcount == 0`, the service raises `VersionConflictError` and rolls back.
  3. **Architectural Evaluation of Uniqueness on `active_detection_rules.source_draft_id`:**
     - *Analysis:*
       - A draft represents a candidate detection rule that, upon successful validation and peer review, promotes to an active production rule.
       - A database-level `UNIQUE(source_draft_id)` constraint would permanently forbid creating another active rule from that draft ID. In a future rule-tuning workflow (e.g. creating version 2 of an active rule from an updated draft), a global unique constraint on `source_draft_id` would block version promotion unless the existing active rule row were physically mutated (violating ADR-3's immutable snapshot principle) or deleted.
       - In contrast, a composite uniqueness on `(source_draft_id, source_draft_version)` or the row-level atomic conditional `WHERE status = 'VALIDATED'` update on the draft guarantees that a given validated draft state can **never** be approved more than once.
       - Because the atomic conditional update serializes the draft state transition from `VALIDATED` $\to$ `APPROVED`, no concurrent or repeated approval of the draft version can succeed.
       - Furthermore, `active_detection_rules.rule_code` retains a strict database `UNIQUE` constraint, and restrictive foreign keys (`RESTRICT`) protect both `source_draft_id` and `validation_run_id`.
     - *Decision:* Maintain `source_draft_id` as an indexed restrictive foreign key without global uniqueness on draft ID alone. The atomic conditional check `WHERE id = :id AND version = :expected_version AND status = 'VALIDATED' AND is_archived = false` is the primary and sufficient database-enforced serialization gate. Future major-version rule upgrades can optionally incorporate a partial or composite unique index on `(source_draft_id, source_draft_version)` without requiring breaking schema migrations now.

---

* **Context:** Storing rules in a Python `tuple` prevents collection resizing, but does not prevent mutation of rule object properties. Mutating shared engine state during ingestion creates race hazards and leaks memory.
* **Decision:**
  1. **Truly Immutable `DynamicCustomRule` Class:**
     - `DynamicCustomRule` is implemented with frozen immutability (via `@dataclass(frozen=True)` or read-only properties with `__slots__`):
       ```python
       @dataclass(frozen=True)
       class DynamicCustomRule(BaseDetectionRule):
           _rule_code: str
           _rule_name: str
           _severity: EventSeverity
           _filter_group: FilterGroup  # Frozen AST
           _mitre_attack_id: Optional[str]
           _mitre_tactic: Optional[str]
           _source_draft_id: str
           _source_draft_version: int
           _validation_run_id: str
           _active_rule_version: int
       ```
     - Any attempt to modify rule attributes (e.g., `rule.severity = ...`) raises `FrozenInstanceError` / `AttributeError`.
  2. **Request-Scoped Engine Snapshot in `IncidentService`:**
     - In `IncidentService.process_and_correlate_events`:
       1. Query database for active rules (`status == "ACTIVE"`).
       2. Instantiate frozen `DynamicCustomRule` instances ordered deterministically by `rule_code ASC`.
       3. Build isolated `DetectionEngine`:
          `engine = DetectionEngine(custom_rules=frozen_custom_rules)`.
       4. Evaluate events: `detections = engine.evaluate_all(events)`.
       5. Discard `engine` instance after evaluation.
  3. **Preservation of Foundational Deterministic Rules:**
     - `DET-001`, `DET-002`, `DET-003`, `DET-004` execute first in their exact order, followed by active custom rules.
  4. **Mid-Flight Isolation Guarantee:**
     - Ingestion batches execute against their frozen initial snapshot. Disabling or deprecating a rule in the database while an ingestion batch is processing does not alter the in-flight engine.
  5. **Detection Provenance Metadata:**
     - Every alert generated by a custom rule includes:
       `rule_code`, `active_rule_id`, `source_draft_id`, `source_draft_version`, `validation_run_id`, `mitre_attack_id`, `mitre_tactic`, and `matched_event_ids`.

---

### ADR-6: Rule Lifecycle Dual State Machines

```
                      DRAFT STATE MACHINE
  [*]
   |
   v
[DRAFT] <----------- (Query AST Modified / Invalidated) <-----------+
   |                                                                |
   v (Pre-flight Validation)                                        |
[VALIDATED]                                                         |
   |                                                                |
   +---------------------> [REJECTED] ------------------------------+
   |                          (Mandatory justification >= 10 chars)
   v (Four-Eyes Approval)
[APPROVED]
   |
   v [Deploy]
=====================================================================
                   ACTIVE RULE STATE MACHINE
[ACTIVE] <------------------------------------+
   |                                          |
   v (Operator Deactivation)                  | (Operator Reactivation)
[DISABLED] -----------------------------------+
   |
   +---------------------> [DEPRECATED] <-----+ (Operator Deprecation)
                              |
                              v
                       [TERMINAL STATE]
                   (Reactivation Prohibited)
```

- **Draft Rules:**
  - `DRAFT`: Initial editable candidate.
  - `VALIDATED`: Verified by non-stale `RuleValidationRunModel`. Editing query resets to `DRAFT` and flags runs `is_stale = True`.
  - `APPROVED`: Passed four-eyes review; locked to exact draft version and validation run.
  - `REJECTED`: Reviewer rejection with justification ($\ge 10$ chars); resets to `DRAFT` for rework.
  - `ARCHIVED`: Soft-deleted draft.
- **Active Rule Rules:**
  - `ACTIVE`: Actively evaluated in ingestion snapshots.
  - `DISABLED`: Temporarily suspended; excluded from ingestion snapshots. Reactivatable with justification.
  - `DEPRECATED`: Permanently retired; excluded from ingestion snapshots. **Terminal state; reactivation returns `HTTP 409 Conflict`.**
  - **Rule Immutability:** Active rules cannot be edited in place. Updating logic requires creating a new draft, validating, approving, and activating as a new rule.

---

### ADR-7: Verified Git Ancestry & Alembic Migration Chain

* **Git Ancestry Verification:**
  - `71e3a7c`: Phase 6.2 structured threat hunting
  - `a04774d`: Phase 6.3A saved threat hunts
  - `b66164b`: Phase 6.3B detection rule drafts & validation runs
  - `5878eb9` (HEAD): Phase 6.3C architecture decision record commit
  - Direct lineage confirmed: `HEAD (5878eb9)` is a direct descendant of `b66164b`.
* **Alembic Migration History Verification:**
  - Migration sequence:
    1. `8909ef443050` (create_initial_core_tables)
    2. `c25bb15d11b1` (add_ai_investigations_table)
    3. `1da2a69a7cf3` (add_saved_hunts_table)
    4. `1e6fea4c0cc9` (add_detection_rule_drafts_and_validation_runs) — **Current Head**
  - **Phase 6.3C Migration Down-Revision**: Strictly `1e6fea4c0cc9`.

---

## 3. Database Schema Specification

```sql
-- Sequence Allocator for Canonical Rule Codes
CREATE TABLE rule_code_allocators (
    sequence_name VARCHAR(64) PRIMARY KEY,
    current_value INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Active Detection Rules Table
CREATE TABLE active_detection_rules (
    id VARCHAR(64) PRIMARY KEY,
    rule_code VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    severity VARCHAR(32) NOT NULL,
    mitre_attack_id VARCHAR(64),
    mitre_tactic VARCHAR(64),
    source_draft_id VARCHAR(64) NOT NULL REFERENCES detection_rule_drafts(id) ON DELETE RESTRICT,
    source_draft_version INTEGER NOT NULL,
    validation_run_id VARCHAR(64) NOT NULL REFERENCES rule_validation_runs(id) ON DELETE RESTRICT,
    query_definition JSON NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    version INTEGER NOT NULL DEFAULT 1,
    approved_by VARCHAR(128) NOT NULL,
    approved_at TIMESTAMP WITH TIME ZONE NOT NULL,
    activated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    deactivated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX ix_active_detection_rules_rule_code ON active_detection_rules(rule_code);
CREATE INDEX ix_active_detection_rules_status ON active_detection_rules(status);
CREATE INDEX ix_active_detection_rules_source_draft_id ON active_detection_rules(source_draft_id);

-- Append-Only Audit Ledger Table
CREATE TABLE rule_audit_ledger (
    id VARCHAR(64) PRIMARY KEY,
    target_type VARCHAR(32) NOT NULL, -- 'DRAFT' or 'ACTIVE_RULE'
    target_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    justification TEXT NOT NULL,
    state_before JSON NOT NULL,
    state_after JSON NOT NULL,
    demo_override_flag BOOLEAN NOT NULL DEFAULT FALSE,
    security_warning TEXT
);

CREATE INDEX ix_rule_audit_ledger_target ON rule_audit_ledger(target_type, target_id);
CREATE INDEX ix_rule_audit_ledger_action ON rule_audit_ledger(action);
CREATE INDEX ix_rule_audit_ledger_actor ON rule_audit_ledger(actor);
CREATE INDEX ix_rule_audit_ledger_timestamp ON rule_audit_ledger(timestamp DESC);
```

---

## 4. API Endpoints & Status Code Contracts

```
POST   /api/v1/rules/drafts/{id}/approve        -> Demonstration four-eyes approval gate
POST   /api/v1/rules/drafts/{id}/reject         -> Reviewer rejection with justification
GET    /api/v1/rules/active                     -> List active, disabled, and deprecated custom rules
GET    /api/v1/rules/active/{id}                -> Get active rule details, query AST, and trigger metrics
PATCH  /api/v1/rules/active/{id}/status         -> Toggle status (ACTIVE <-> DISABLED -> DEPRECATED)
GET    /api/v1/rules/audit                      -> Query immutable audit ledger
```

| Endpoint | Method | Success | Client Error (400) | Governance Error (403) | Conflict Error (409) | Not Found (404) |
|---|---|---|---|---|---|---|
| `.../drafts/{id}/approve` | `POST` | `200 OK` | Justification < 10 chars | Self-approval without server demo config | Not VALIDATED, stale run, version mismatch, archived draft | Draft not found |
| `.../drafts/{id}/reject` | `POST` | `200 OK` | Justification < 10 chars | N/A | Not VALIDATED, archived draft | Draft not found |
| `.../active` | `GET` | `200 OK` | Invalid query filter | N/A | N/A | N/A |
| `.../active/{id}` | `GET` | `200 OK` | N/A | N/A | N/A | Rule not found |
| `.../active/{id}/status` | `PATCH` | `200 OK` | Invalid status, justification < 10 chars | N/A | Version mismatch, reactivating DEPRECATED rule | Rule not found |
| `.../audit` | `GET` | `200 OK` | Invalid query filter | N/A | N/A | N/A |

---

## 5. Comprehensive 24-Test Verification Matrix

```
+----------------------------------------------------------------------------------------------------+
|                                    Phase 6.3C Comprehensive Test Matrix                             |
+----------------------------------------------------------------------------------------------------+
| 1. Demonstration Four-Eyes Review & Governance (6 tests)                                           |
|    - test_approve_draft_by_distinct_analyst_succeeds                                               |
|    - test_self_approval_blocked_when_demo_override_disabled_returns_403                            |
|    - test_self_approval_allowed_when_server_demo_override_enabled_with_audit_warning               |
|    - test_approval_fails_if_draft_not_validated_returns_409                                        |
|    - test_approval_fails_if_validation_run_stale_or_version_mismatched_returns_409                 |
|    - test_approval_fails_if_justification_under_10_chars_returns_400                                |
|                                                                                                    |
| 2. Rejection & Lifecycle Reset (3 tests)                                                           |
|    - test_reject_draft_resets_status_to_draft_and_records_audit_ledger                             |
|    - test_reject_draft_fails_without_justification_returns_400                                     |
|    - test_reject_draft_fails_if_already_archived_or_not_validated_returns_409                      |
|                                                                                                    |
| 3. Concurrency, Allocator & Transaction Atomicity (5 tests)                                        |
|    - test_atomic_rule_code_sequence_allocator_concurrent_safety                                     |
|    - test_concurrent_approval_exactly_one_winner_one_409_conflict                                  |
|    - test_audit_failure_rolls_back_draft_approval_and_active_rule_creation                         |
|    - test_audit_failure_rolls_back_status_toggle_and_preserves_previous_state                       |
|    - test_draft_edit_or_archival_during_approval_race_results_in_409_conflict                      |
|                                                                                                    |
| 4. Active Rule Lifecycle & Evidence Lineage (5 tests)                                              |
|    - test_active_rule_foreign_key_restrict_prevents_hard_delete_of_draft                           |
|    - test_active_rule_foreign_key_restrict_prevents_hard_delete_of_validation_run                  |
|    - test_soft_archived_draft_preserves_active_rule_and_lineage                                    |
|    - test_active_rule_status_toggle_active_to_disabled_and_reactivate                              |
|    - test_deprecate_active_rule_is_terminal_and_blocks_reactivation_with_409                       |
|                                                                                                    |
| 5. Detection Engine Isolation & Frozen Snapshots (5 tests)                                         |
|    - test_dynamic_custom_rule_attributes_are_frozen_immutable                                      |
|    - test_live_ingestion_creates_request_scoped_engine_without_mutating_shared_state               |
|    - test_in_flight_ingestion_snapshot_unaffected_by_concurrent_rule_deactivation                  |
|    - test_consecutive_ingestions_do_not_accumulate_or_leak_rules                                   |
|    - test_hardcoded_rules_det001_to_det004_order_and_execution_preserved_exactly                 |
+----------------------------------------------------------------------------------------------------+
```

---

## 6. Implementation Touch Points

When authorized, Phase 6.3C implementation will proceed across these specific files:
1. `backend/app/core/config.py`: Add `ALLOW_DEMO_SELF_APPROVAL: bool = False`.
2. `backend/app/db/models.py`: Add `RuleCodeAllocatorModel`, `ActiveDetectionRuleModel`, and `RuleAuditEntryModel`.
3. `backend/alembic/versions/`: Migration chained after `1e6fea4c0cc9`.
4. `backend/app/schemas/`: `active_rule.py` and `rule_audit.py`.
5. `backend/app/db/repositories/`: `active_rule_repo.py` and `rule_audit_repo.py`.
6. `backend/app/services/rule_lifecycle_service.py`: Service managing transaction boundaries for approval, rejection, and status toggles.
7. `backend/app/rules/dynamic_rule.py`: Frozen immutable `DynamicCustomRule(BaseDetectionRule)`.
8. `backend/app/rules/rule_engine.py`: Update `DetectionEngine` to accept immutable custom rules tuple.
9. `backend/app/correlation/service.py`: Update `IncidentService` for request-scoped snapshot construction.
10. `backend/app/main.py`: Register Phase 6.3C API endpoints.
11. `backend/tests/test_rule_lifecycle.py`: 24 comprehensive tests.
