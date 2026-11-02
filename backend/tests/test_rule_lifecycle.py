"""
CyberTrace Phase 6.3C: Detection Rule Governance, Activation & Audit Ledger Tests.
Stage 1: Foundation Models, Schema Constraints, Foreign Key Restrictions & Allocator Behavior.
Stage 2: Lifecycle Services, Transaction Ownership, Four-Eyes Review Gate & Audit Integrity.
"""

import asyncio
from datetime import datetime, timezone
from typing import Tuple
from unittest.mock import patch
from pydantic import ValidationError
import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.db.models import (
    ActiveDetectionRuleModel,
    Base,
    DetectionRuleDraftModel,
    RuleAuditEntryModel,
    RuleCodeAllocatorModel,
    RuleValidationRunModel,
    SavedHuntModel,
)
from app.schemas.active_rule import ActiveRuleStatus, ActiveRuleStatusUpdateRequest
from app.schemas.rule_draft import (
    DraftStatus,
    RuleDraftApprovalRequest,
    RuleDraftRejectionRequest,
)
from app.services.rule_lifecycle_service import (
    ActiveRuleNotFoundError,
    DeprecatedRuleTerminalError,
    DraftArchivedError,
    DraftNotFoundError,
    DraftNotValidatedError,
    DuplicateApprovalError,
    FourEyesViolationError,
    InvalidLifecycleTransitionError,
    RuleLifecycleService,
    StaleValidationError,
    ValidationRationaleError,
    VersionConflictError,
)


@pytest.mark.asyncio
async def test_rule_code_allocator_atomic_increment(db_session: AsyncSession):
    """
    Verify that the rule_code_allocators table supports atomic sequence increments
    and initializes or increments the custom_rule sequence correctly.
    """
    stmt = select(RuleCodeAllocatorModel).where(
        RuleCodeAllocatorModel.sequence_name == "custom_rule"
    )
    res = await db_session.execute(stmt)
    allocator = res.scalar_one_or_none()

    if not allocator:
        allocator = RuleCodeAllocatorModel(
            sequence_name="custom_rule",
            current_value=0,
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(allocator)
        await db_session.commit()

    initial_val = allocator.current_value

    now = datetime.now(timezone.utc)
    update_stmt = (
        update(RuleCodeAllocatorModel)
        .where(RuleCodeAllocatorModel.sequence_name == "custom_rule")
        .values(
            current_value=RuleCodeAllocatorModel.current_value + 1,
            updated_at=now,
        )
    )
    await db_session.execute(update_stmt)
    await db_session.commit()

    res = await db_session.execute(stmt)
    updated_allocator = res.scalar_one()
    assert updated_allocator.current_value == initial_val + 1
    canonical_code = f"CUST-{updated_allocator.current_value:03d}"
    assert canonical_code.startswith("CUST-")


@pytest.mark.asyncio
async def test_active_rule_creation_and_evidence_lineage(db_session: AsyncSession):
    """
    Verify that ActiveDetectionRuleModel correctly links to a source draft and validation run,
    and that restrictive foreign keys preserve evidence lineage.
    """
    hunt = SavedHuntModel(
        id="hunt_stage1_test",
        name="Stage 1 Hunt",
        query_definition={
            "combinator": "AND",
            "conditions": [
                {"field": "action", "operator": "EQUALS", "value": "network_connect"}
            ],
        },
        version=1,
    )
    db_session.add(hunt)

    draft = DetectionRuleDraftModel(
        id="draft_stage1_test",
        name="Stage 1 Draft",
        source_hunt_id=hunt.id,
        source_hunt_version=1,
        query_definition=hunt.query_definition,
        status="VALIDATED",
        version=1,
        created_by="analyst_alice",
    )
    db_session.add(draft)

    val_run = RuleValidationRunModel(
        id="val_stage1_test",
        draft_id=draft.id,
        draft_version=1,
        query_definition_snapshot=draft.query_definition,
        events_scanned=100,
        matches_found=5,
        status="COMPLETED",
    )
    db_session.add(val_run)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    active_rule = ActiveDetectionRuleModel(
        id="rule_stage1_test",
        rule_code="CUST-001",
        name="Active Outbound Egress Detection",
        description="Stage 1 production rule verification",
        severity="high",
        mitre_attack_id="T1041",
        mitre_tactic="exfiltration",
        source_draft_id=draft.id,
        source_draft_version=1,
        validation_run_id=val_run.id,
        query_definition=draft.query_definition,
        status="ACTIVE",
        version=1,
        approved_by="lead_bob",
        approved_at=now,
        activated_at=now,
    )
    db_session.add(active_rule)
    await db_session.commit()

    stmt = select(ActiveDetectionRuleModel).where(ActiveDetectionRuleModel.id == active_rule.id)
    res = await db_session.execute(stmt)
    retrieved_rule = res.scalar_one()

    assert retrieved_rule.rule_code == "CUST-001"
    assert retrieved_rule.source_draft_id == draft.id
    assert retrieved_rule.source_draft_version == 1
    assert retrieved_rule.validation_run_id == val_run.id
    assert retrieved_rule.status == "ACTIVE"
    assert retrieved_rule.source_draft.name == "Stage 1 Draft"
    assert retrieved_rule.validation_run.matches_found == 5

    draft.is_archived = True
    await db_session.commit()

    res = await db_session.execute(stmt)
    assert res.scalar_one().source_draft.is_archived is True


@pytest.mark.asyncio
async def test_active_rule_unique_rule_code_constraint(db_session: AsyncSession):
    """
    Verify that active_detection_rules enforces a unique constraint on rule_code.
    """
    now = datetime.now(timezone.utc)
    rule1 = ActiveDetectionRuleModel(
        id="rule_uniq_1",
        rule_code="CUST-999",
        name="Unique Rule 1",
        severity="medium",
        source_draft_id="draft_stage1_test",
        source_draft_version=1,
        validation_run_id="val_stage1_test",
        query_definition={"combinator": "AND", "conditions": []},
        status="ACTIVE",
        approved_by="lead_bob",
        approved_at=now,
        activated_at=now,
    )
    rule2 = ActiveDetectionRuleModel(
        id="rule_uniq_2",
        rule_code="CUST-999",
        name="Unique Rule 2",
        severity="medium",
        source_draft_id="draft_stage1_test",
        source_draft_version=1,
        validation_run_id="val_stage1_test",
        query_definition={"combinator": "AND", "conditions": []},
        status="ACTIVE",
        approved_by="lead_bob",
        approved_at=now,
        activated_at=now,
    )

    db_session.add(rule1)
    await db_session.commit()

    db_session.add(rule2)
    with pytest.raises(IntegrityError):
        await db_session.commit()

    await db_session.rollback()


@pytest.mark.asyncio
async def test_rule_audit_entry_persistence_and_snapshots(db_session: AsyncSession):
    """
    Verify that RuleAuditEntryModel persists before/after state diffs,
    attribution, justification, and security warnings.
    """
    now = datetime.now(timezone.utc)
    audit_entry = RuleAuditEntryModel(
        id="audit_stage1_test",
        target_type="DRAFT",
        target_id="draft_stage1_test",
        action="APPROVE_DRAFT",
        actor="lead_bob",
        timestamp=now,
        justification="Verified pre-flight telemetry and confirmed zero false positives.",
        state_before={"status": "VALIDATED", "version": 1},
        state_after={"status": "APPROVED", "version": 2, "active_rule_id": "rule_stage1_test"},
        demo_override_flag=False,
        security_warning=None,
    )
    db_session.add(audit_entry)
    await db_session.commit()

    stmt = select(RuleAuditEntryModel).where(RuleAuditEntryModel.id == "audit_stage1_test")
    res = await db_session.execute(stmt)
    persisted = res.scalar_one()

    assert persisted.action == "APPROVE_DRAFT"
    assert persisted.actor == "lead_bob"
    assert persisted.state_before["status"] == "VALIDATED"
    assert persisted.state_after["status"] == "APPROVED"
    assert persisted.justification.startswith("Verified pre-flight")
    assert persisted.demo_override_flag is False


# ==============================================================================
# Stage 2: RuleLifecycleService & Transaction Ownership Tests
# ==============================================================================

async def _seed_draft_for_approval(
    session: AsyncSession,
    draft_id: str,
    created_by: str = "analyst_alice",
    status: str = "VALIDATED",
    val_status: str = "COMPLETED",
    is_stale: bool = False,
    draft_version: int = 1,
    val_version: int = 1,
) -> Tuple[DetectionRuleDraftModel, RuleValidationRunModel]:
    """Helper to seed draft and validation run for lifecycle testing."""
    draft = DetectionRuleDraftModel(
        id=draft_id,
        name=f"Title {draft_id}",
        description="Lifecycle validation test",
        severity="high",
        mitre_attack_id="T1041",
        mitre_tactic="exfiltration",
        query_definition={
            "combinator": "AND",
            "conditions": [
                {"field": "action", "operator": "EQUALS", "value": "network_connect"}
            ],
        },
        status=status,
        version=draft_version,
        created_by=created_by,
        is_archived=False,
    )
    session.add(draft)
    await session.flush()

    val_run = RuleValidationRunModel(
        id=f"val_{draft_id}",
        draft_id=draft.id,
        draft_version=val_version,
        query_definition_snapshot=draft.query_definition,
        events_scanned=100,
        matches_found=3,
        status=val_status,
        is_stale=is_stale,
    )
    session.add(val_run)
    await session.commit()
    return draft, val_run


@pytest.mark.asyncio
async def test_approve_draft_success_with_valid_validation(db_session: AsyncSession):
    """
    Test 1: Successful approval by distinct analyst with valid, non-stale validation.
    Verifies:
    - Active rule created with sequential rule code (CUST-xxx).
    - Draft transitions to APPROVED and version is incremented.
    - Audit entry records state diff and actor.
    - Transaction commits atomically.
    """
    draft, val = await _seed_draft_for_approval(db_session, "draft_appr_ok", created_by="analyst_alice")

    service = RuleLifecycleService(db_session)
    payload = RuleDraftApprovalRequest(
        draft_version=1,
        approver_id="lead_bob",  # Distinct reviewer
        justification="Verified pre-flight metrics on ThreatLab scenarios with zero benign noise.",
        activate_immediately=True,
    )

    active_rule, updated_draft, audit_entry = await service.approve_rule_draft(draft.id, payload)

    assert active_rule.rule_code.startswith("CUST-")
    assert active_rule.status == ActiveRuleStatus.ACTIVE.value
    assert active_rule.source_draft_id == draft.id
    assert active_rule.validation_run_id == val.id
    assert active_rule.approved_by == "lead_bob"

    assert updated_draft.status == DraftStatus.APPROVED.value
    assert updated_draft.version == 2

    assert audit_entry.action == "APPROVE_DRAFT"
    assert audit_entry.actor == "lead_bob"
    assert audit_entry.state_before["status"] == "VALIDATED"
    assert audit_entry.state_after["status"] == "APPROVED"
    assert audit_entry.demo_override_flag is False
    assert audit_entry.security_warning is None


@pytest.mark.asyncio
async def test_approve_draft_fails_for_stale_validation(db_session: AsyncSession):
    """
    Test 2: Approval rejected when validation run is flagged stale (is_stale == True).
    """
    draft, _ = await _seed_draft_for_approval(db_session, "draft_appr_stale", is_stale=True)

    service = RuleLifecycleService(db_session)
    payload = RuleDraftApprovalRequest(
        draft_version=1,
        approver_id="lead_bob",
        justification="Valid justification rationale text.",
    )

    with pytest.raises(StaleValidationError) as exc:
        await service.approve_rule_draft(draft.id, payload)
    assert "stale" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_approve_draft_fails_for_unsuccessful_validation(db_session: AsyncSession):
    """
    Test 3: Approval rejected when validation run status is FAILED.
    """
    draft, _ = await _seed_draft_for_approval(db_session, "draft_appr_failed_val", val_status="FAILED")

    service = RuleLifecycleService(db_session)
    payload = RuleDraftApprovalRequest(
        draft_version=1,
        approver_id="lead_bob",
        justification="Valid justification rationale text.",
    )

    with pytest.raises(DraftNotValidatedError) as exc:
        await service.approve_rule_draft(draft.id, payload)
    assert "did not complete successfully" in str(exc.value)


@pytest.mark.asyncio
async def test_approve_draft_fails_after_draft_version_changes(db_session: AsyncSession):
    """
    Test 4: Approval rejected if draft was modified (version changed from 1 to 2) after validation.
    """
    draft, _ = await _seed_draft_for_approval(
        db_session, "draft_appr_ver_mismatch", draft_version=2, val_version=1
    )

    service = RuleLifecycleService(db_session)
    # Caller passes expected draft version 2, but validation was run against version 1
    payload = RuleDraftApprovalRequest(
        draft_version=2,
        approver_id="lead_bob",
        justification="Valid justification rationale text.",
    )

    with pytest.raises(StaleValidationError) as exc:
        await service.approve_rule_draft(draft.id, payload)
    assert "executed against draft version 1" in str(exc.value)


@pytest.mark.asyncio
async def test_approve_draft_fails_for_self_approval_when_demo_override_disabled(db_session: AsyncSession):
    """
    Test 5: Four-eyes violation: Author attempts to approve own draft when ALLOW_DEMO_SELF_APPROVAL is False.
    Must raise FourEyesViolationError (HTTP 403).
    """
    draft, _ = await _seed_draft_for_approval(db_session, "draft_appr_self_fail", created_by="analyst_alice")

    service = RuleLifecycleService(db_session)
    payload = RuleDraftApprovalRequest(
        draft_version=1,
        approver_id="analyst_alice",  # Self-approval!
        justification="Attempting self approval on my own rule.",
    )

    with patch.object(settings, "ALLOW_DEMO_SELF_APPROVAL", False):
        with pytest.raises(FourEyesViolationError) as exc:
            await service.approve_rule_draft(draft.id, payload)
        assert "four-eyes principle violation" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_approve_draft_allows_self_approval_when_server_override_enabled(db_session: AsyncSession):
    """
    Test 6: Self-approval succeeds when server-side ALLOW_DEMO_SELF_APPROVAL is True,
    and unconditionally records a security warning in the audit ledger.
    """
    draft, _ = await _seed_draft_for_approval(db_session, "draft_appr_self_ok", created_by="analyst_alice")

    service = RuleLifecycleService(db_session)
    payload = RuleDraftApprovalRequest(
        draft_version=1,
        approver_id="analyst_alice",  # Self-approval
        justification="Demo demonstration self approval permitted under server override.",
    )

    with patch.object(settings, "ALLOW_DEMO_SELF_APPROVAL", True):
        active_rule, updated_draft, audit_entry = await service.approve_rule_draft(draft.id, payload)

        assert active_rule.status == ActiveRuleStatus.ACTIVE.value
        assert updated_draft.status == DraftStatus.APPROVED.value
        assert audit_entry.demo_override_flag is True
        assert audit_entry.security_warning is not None
        assert "SECURITY AUDIT WARNING: Four-eyes principle violated" in audit_entry.security_warning


@pytest.mark.asyncio
async def test_reject_draft_success_resets_to_draft(db_session: AsyncSession):
    """
    Test 7: Successful rejection resets draft status back to DRAFT for rework,
    increments version, and records REJECT_DRAFT in audit ledger.
    """
    draft, _ = await _seed_draft_for_approval(db_session, "draft_rej_ok", status="VALIDATED")

    service = RuleLifecycleService(db_session)
    payload = RuleDraftRejectionRequest(
        draft_version=1,
        reviewer_id="lead_reviewer_charlie",
        justification="Filter logic is too broad and triggers high alert volume on historical logs.",
    )

    rejected_draft, audit_entry = await service.reject_rule_draft(draft.id, payload)

    assert rejected_draft.status == DraftStatus.DRAFT.value
    assert rejected_draft.version == 2

    assert audit_entry.action == "REJECT_DRAFT"
    assert audit_entry.actor == "lead_reviewer_charlie"
    assert audit_entry.state_before["status"] == "VALIDATED"
    assert audit_entry.state_after["status"] == "DRAFT"
    assert "too broad" in audit_entry.justification


@pytest.mark.asyncio
async def test_reject_draft_fails_without_justification(db_session: AsyncSession):
    """
    Test 8: Rejection fails if justification is missing or shorter than 10 characters.
    """
    draft, _ = await _seed_draft_for_approval(db_session, "draft_rej_short", status="VALIDATED")
    service = RuleLifecycleService(db_session)

    # 1. Pydantic schema validation rejects string < 10 characters
    with pytest.raises(ValidationError):
        RuleDraftRejectionRequest(
            draft_version=1,
            reviewer_id="lead_charlie",
            justification="short",
        )

    # 2. Service level validation also rejects if stripped rationale is < 10 chars
    payload = RuleDraftRejectionRequest.model_construct(
        draft_version=1,
        reviewer_id="lead_charlie",
        justification="          ",  # 10 whitespace chars
    )
    with pytest.raises(ValidationRationaleError) as exc:
        await service.reject_rule_draft(draft.id, payload)
    assert "at least 10 characters" in str(exc.value)


@pytest.mark.asyncio
async def test_duplicate_approval_fails(db_session: AsyncSession):
    """
    Test 9: Attempting to approve an already approved draft fails with DuplicateApprovalError.
    """
    draft, _ = await _seed_draft_for_approval(db_session, "draft_dup_appr")

    service = RuleLifecycleService(db_session)
    payload = RuleDraftApprovalRequest(
        draft_version=1,
        approver_id="lead_bob",
        justification="Initial valid approval justification.",
    )

    # First approval succeeds
    await service.approve_rule_draft(draft.id, payload)

    # Second approval attempt fails
    payload_retry = RuleDraftApprovalRequest(
        draft_version=2,
        approver_id="lead_charlie",
        justification="Attempting duplicate approval on approved draft.",
    )
    with pytest.raises(DuplicateApprovalError):
        await service.approve_rule_draft(draft.id, payload_retry)


@pytest.mark.asyncio
async def test_toggle_active_rule_status_lifecycle(db_session: AsyncSession):
    """
    Test 10: Toggle active rule status: ACTIVE -> DISABLED -> ACTIVE with justification.
    """
    draft, val = await _seed_draft_for_approval(db_session, "draft_toggle_ok")
    service = RuleLifecycleService(db_session)

    # Approve to create active rule
    active_rule, _, _ = await service.approve_rule_draft(
        draft.id,
        RuleDraftApprovalRequest(
            draft_version=1,
            approver_id="lead_bob",
            justification="Approve for status toggle verification.",
        ),
    )
    assert active_rule.status == ActiveRuleStatus.ACTIVE.value
    assert active_rule.version == 1

    # 1. Disable rule
    disabled_rule, audit1 = await service.toggle_active_rule_status(
        active_rule.id,
        ActiveRuleStatusUpdateRequest(
            version=1,
            status=ActiveRuleStatus.DISABLED,
            justification="Temporarily disabling due to rule maintenance window.",
            actor="operator_dan",
        ),
    )
    assert disabled_rule.status == ActiveRuleStatus.DISABLED.value
    assert disabled_rule.version == 2
    assert disabled_rule.deactivated_at is not None
    assert audit1.action == "DEACTIVATE_RULE"

    # 2. Reactivate rule
    reactivated_rule, audit2 = await service.toggle_active_rule_status(
        active_rule.id,
        ActiveRuleStatusUpdateRequest(
            version=2,
            status=ActiveRuleStatus.ACTIVE,
            justification="Reactivating rule following tuning and index creation.",
            actor="operator_dan",
        ),
    )
    assert reactivated_rule.status == ActiveRuleStatus.ACTIVE.value
    assert reactivated_rule.version == 3
    assert reactivated_rule.deactivated_at is None
    assert audit2.action == "REACTIVATE_RULE"


@pytest.mark.asyncio
async def test_deprecate_active_rule_terminal_blocks_reactivation(db_session: AsyncSession):
    """
    Test 11: Deprecate active rule (terminal state). Reactivation is strictly blocked.
    """
    draft, val = await _seed_draft_for_approval(db_session, "draft_deprecate_ok")
    service = RuleLifecycleService(db_session)

    active_rule, _, _ = await service.approve_rule_draft(
        draft.id,
        RuleDraftApprovalRequest(
            draft_version=1,
            approver_id="lead_bob",
            justification="Approve for deprecation verification.",
        ),
    )

    # Deprecate rule
    deprecated_rule, audit = await service.toggle_active_rule_status(
        active_rule.id,
        ActiveRuleStatusUpdateRequest(
            version=1,
            status=ActiveRuleStatus.DEPRECATED,
            justification="Permanently deprecating rule in favor of CUST-010.",
            actor="operator_dan",
        ),
    )
    assert deprecated_rule.status == ActiveRuleStatus.DEPRECATED.value
    assert audit.action == "DEPRECATE_RULE"

    # Attempt reactivation must raise DeprecatedRuleTerminalError
    with pytest.raises(DeprecatedRuleTerminalError) as exc:
        await service.toggle_active_rule_status(
            active_rule.id,
            ActiveRuleStatusUpdateRequest(
                version=2,
                status=ActiveRuleStatus.ACTIVE,
                justification="Attempting forbidden reactivation of deprecated rule.",
            ),
        )
    assert "permanently deprecated" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_missing_allocator_row_seeds_and_allocates(db_session: AsyncSession):
    """
    Test 12: Missing sequence allocator row explicitly handled: seeds custom_rule row and returns CUST-001.
    """
    # Delete the allocator row if present to test missing row resilience
    await db_session.execute(
        RuleCodeAllocatorModel.__table__.delete().where(
            RuleCodeAllocatorModel.sequence_name == "custom_rule"
        )
    )
    await db_session.commit()

    service = RuleLifecycleService(db_session)
    code = await service._allocate_next_rule_code(db_session)
    await db_session.commit()

    assert code == "CUST-001"

    # Subsequent allocation increments cleanly
    code2 = await service._allocate_next_rule_code(db_session)
    await db_session.commit()
    assert code2 == "CUST-002"


@pytest.mark.asyncio
async def test_atomic_rollback_on_audit_failure(db_session: AsyncSession):
    """
    Test 13: Transaction rollback when audit insertion fails.
    Verifies that if audit persistence throws an exception, no draft status change or
    active rule creation is committed. Draft remains VALIDATED at version 1.
    """
    target_draft_id = "draft_audit_rollback"
    draft, _ = await _seed_draft_for_approval(db_session, target_draft_id)
    service = RuleLifecycleService(db_session)

    payload = RuleDraftApprovalRequest(
        draft_version=1,
        approver_id="lead_bob",
        justification="Valid justification rationale text.",
    )

    # Patch audit repo create_audit_entry to simulate disk/constraint failure
    with patch.object(service.audit_repo, "create_audit_entry", side_effect=RuntimeError("Simulated audit write failure")):
        with pytest.raises(RuntimeError) as exc:
            await service.approve_rule_draft(target_draft_id, payload)
        assert "Simulated audit write failure" in str(exc.value)

    # 1. Draft remains in VALIDATED status, version 1
    stmt = select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == target_draft_id)
    res = await db_session.execute(stmt)
    persisted_draft = res.scalar_one()
    assert persisted_draft.status == DraftStatus.VALIDATED.value
    assert persisted_draft.version == 1

    # 2. No active rule was persisted
    rule_stmt = select(ActiveDetectionRuleModel).where(ActiveDetectionRuleModel.source_draft_id == target_draft_id)
    res_rule = await db_session.execute(rule_stmt)
    assert res_rule.scalar_one_or_none() is None

    # 3. No audit entry was persisted
    audit_stmt = select(RuleAuditEntryModel).where(RuleAuditEntryModel.target_id == target_draft_id)
    res_audit = await db_session.execute(audit_stmt)
    assert res_audit.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_sqlite_allocator_concurrency_across_independent_sessions(tmp_path):
    """
    Test 14: SQLite sequence allocator concurrency across independent sessions.
    Simulates competing concurrent tasks allocating rule codes through separate sessions
    over a file-based SQLite database with NullPool (independent connections),
    verifying monotonic, collision-free codes without duplicates.
    """
    db_file = tmp_path / "concurrent_allocator.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_file}",
        poolclass=NullPool,
        connect_args={"timeout": 30},
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    SessionFactory = async_sessionmaker(engine, expire_on_commit=False)

    # Seed allocator
    async with SessionFactory() as session:
        alloc = RuleCodeAllocatorModel(
            sequence_name="custom_rule",
            current_value=0,
            updated_at=datetime.now(timezone.utc),
        )
        session.add(alloc)
        await session.commit()

    async def allocate_task(task_id: int) -> str:
        async with SessionFactory() as session:
            service = RuleLifecycleService(session)
            async with session.begin():
                return await service._allocate_next_rule_code(session)

    # Run 10 concurrent allocation tasks
    tasks = [allocate_task(i) for i in range(10)]
    allocated_codes = await asyncio.gather(*tasks)

    # All 10 codes must be unique and span CUST-001 to CUST-010
    assert len(allocated_codes) == 10
    assert len(set(allocated_codes)) == 10
    expected_codes = {f"CUST-{i:03d}" for i in range(1, 11)}
    assert set(allocated_codes) == expected_codes

    await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_draft_approval_exactly_one_winner(tmp_path):
    """
    Test 15 (Stage 2.1 Concurrency Remediation):
    Two independent database sessions attempt to approve the same VALIDATED draft simultaneously.
    Verifies:
    - Database-level atomic conditional update serializes the state change.
    - Exactly ONE session succeeds, creating active rule CUST-001 and audit entry.
    - The competing session fails with VersionConflictError.
    - The losing transaction rolls back completely (no phantom active rule, no duplicate audit entry).
    - Allocator sequence increments exactly once.
    """
    db_file = tmp_path / "concurrent_draft_approval.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_file}",
        poolclass=NullPool,
        connect_args={"timeout": 30},
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    SessionFactory = async_sessionmaker(engine, expire_on_commit=False)

    target_draft_id = "draft_concurrent_approval"
    async with SessionFactory() as session:
        alloc = RuleCodeAllocatorModel(
            sequence_name="custom_rule",
            current_value=0,
            updated_at=datetime.now(timezone.utc),
        )
        hunt = SavedHuntModel(
            id="hunt_concurrent",
            name="Concurrent Hunt",
            query_definition={"combinator": "AND", "conditions": []},
            version=1,
        )
        draft = DetectionRuleDraftModel(
            id=target_draft_id,
            name="Concurrent Race Rule",
            description="Race condition testing draft",
            severity="high",
            source_hunt_id=hunt.id,
            source_hunt_version=1,
            query_definition={"combinator": "AND", "conditions": []},
            status=DraftStatus.VALIDATED.value,
            version=1,
            created_by="analyst_alice",
            is_archived=False,
        )
        val_run = RuleValidationRunModel(
            id=f"val_{target_draft_id}",
            draft_id=target_draft_id,
            draft_version=1,
            query_definition_snapshot={},
            events_scanned=50,
            matches_found=2,
            status="COMPLETED",
            is_stale=False,
        )
        session.add_all([alloc, hunt, draft, val_run])
        await session.commit()

    async def approve_worker(approver_name: str):
        async with SessionFactory() as session:
            service = RuleLifecycleService(session)
            payload = RuleDraftApprovalRequest(
                draft_version=1,
                approver_id=approver_name,
                justification=f"Approval by {approver_name} with valid peer review rationale.",
                activate_immediately=True,
            )
            return await service.approve_rule_draft(target_draft_id, payload)

    # Launch two simultaneous approvals on independent sessions
    results = await asyncio.gather(
        approve_worker("lead_bob"),
        approve_worker("lead_charlie"),
        return_exceptions=True,
    )

    successes = [r for r in results if not isinstance(r, Exception)]
    errors = [r for r in results if isinstance(r, Exception)]

    # Exactly one winner, exactly one VersionConflictError
    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {results}"
    assert len(errors) == 1, f"Expected exactly 1 error, got {len(errors)}: {results}"
    assert isinstance(errors[0], VersionConflictError)
    assert "version conflict" in str(errors[0]).lower()

    # Winning session checks
    winner_active_rule, winner_draft, winner_audit = successes[0]
    assert winner_active_rule.rule_code == "CUST-001"
    assert winner_draft.status == DraftStatus.APPROVED.value
    assert winner_draft.version == 2
    assert winner_audit.action == "APPROVE_DRAFT"

    # Database state verification
    async with SessionFactory() as session:
        rules = list((await session.execute(select(ActiveDetectionRuleModel))).scalars().all())
        audits = list((await session.execute(select(RuleAuditEntryModel))).scalars().all())
        persisted_draft = (
            await session.execute(
                select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == target_draft_id)
            )
        ).scalar_one()
        persisted_alloc = (
            await session.execute(
                select(RuleCodeAllocatorModel).where(RuleCodeAllocatorModel.sequence_name == "custom_rule")
            )
        ).scalar_one()

        # Database must hold exactly 1 active rule and 1 audit record
        assert len(rules) == 1
        assert rules[0].rule_code == "CUST-001"
        assert len(audits) == 1
        assert audits[0].action == "APPROVE_DRAFT"
        assert persisted_draft.status == DraftStatus.APPROVED.value
        assert persisted_draft.version == 2
        assert persisted_alloc.current_value == 1

    await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_active_rule_status_toggle_optimistic_lock(tmp_path):
    """
    Test 16 (Stage 2.1 Concurrency Remediation):
    Two independent database sessions attempt to toggle the status of the same active rule
    using the same expected version.
    Verifies:
    - ActiveRuleRepository.update_rule_status_atomic enforces optimistic concurrency at the SQL level.
    - Exactly ONE session succeeds in toggling status from ACTIVE to DISABLED.
    - The competing session receives VersionConflictError.
    - Exactly ONE audit entry is persisted.
    """
    db_file = tmp_path / "concurrent_status_toggle.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_file}",
        poolclass=NullPool,
        connect_args={"timeout": 30},
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    SessionFactory = async_sessionmaker(engine, expire_on_commit=False)

    target_rule_id = "rule_concurrent_toggle"
    now = datetime.now(timezone.utc)
    async with SessionFactory() as session:
        draft = DetectionRuleDraftModel(
            id="draft_toggle_source",
            name="Source Draft for Toggle",
            query_definition={"combinator": "AND", "conditions": []},
            status=DraftStatus.APPROVED.value,
            version=2,
            created_by="analyst_alice",
        )
        val = RuleValidationRunModel(
            id="val_toggle_source",
            draft_id="draft_toggle_source",
            draft_version=1,
            query_definition_snapshot={},
            events_scanned=10,
            matches_found=1,
            status="COMPLETED",
        )
        active_rule = ActiveDetectionRuleModel(
            id=target_rule_id,
            rule_code="CUST-005",
            name="Active Rule for Toggle Test",
            severity="medium",
            source_draft_id=draft.id,
            source_draft_version=1,
            validation_run_id=val.id,
            query_definition={},
            status=ActiveRuleStatus.ACTIVE.value,
            version=1,
            approved_by="lead_bob",
            approved_at=now,
            activated_at=now,
        )
        session.add_all([draft, val, active_rule])
        await session.commit()

    async def toggle_worker(actor_name: str):
        async with SessionFactory() as session:
            service = RuleLifecycleService(session)
            payload = ActiveRuleStatusUpdateRequest(
                version=1,  # Both sessions submit expected version 1
                status=ActiveRuleStatus.DISABLED,
                justification=f"Disabling rule by {actor_name} for system maintenance.",
                actor=actor_name,
            )
            return await service.toggle_active_rule_status(target_rule_id, payload)

    # Launch two simultaneous status toggles on independent sessions
    results = await asyncio.gather(
        toggle_worker("operator_dan"),
        toggle_worker("operator_eve"),
        return_exceptions=True,
    )

    successes = [r for r in results if not isinstance(r, Exception)]
    errors = [r for r in results if isinstance(r, Exception)]

    # Exactly one winner, exactly one VersionConflictError
    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {results}"
    assert len(errors) == 1, f"Expected exactly 1 error, got {len(errors)}: {results}"
    assert isinstance(errors[0], VersionConflictError)

    winner_rule, winner_audit = successes[0]
    assert winner_rule.status == ActiveRuleStatus.DISABLED.value
    assert winner_rule.version == 2
    assert winner_audit.action == "DEACTIVATE_RULE"

    # Database state verification
    async with SessionFactory() as session:
        persisted_rule = (
            await session.execute(
                select(ActiveDetectionRuleModel).where(ActiveDetectionRuleModel.id == target_rule_id)
            )
        ).scalar_one()
        audits = list((await session.execute(select(RuleAuditEntryModel))).scalars().all())

        assert persisted_rule.status == ActiveRuleStatus.DISABLED.value
        assert persisted_rule.version == 2
        assert len(audits) == 1
        assert audits[0].action == "DEACTIVATE_RULE"

    await engine.dispose()
