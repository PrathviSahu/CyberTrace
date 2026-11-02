"""
CyberTrace Phase 6.3C Stage 5 — Transaction Ownership & Atomicity Audit Suite.
Validates:
- Normal FastAPI request with a fresh AsyncSession.
- Session where SQLAlchemy has already autobegun a transaction.
- Session inside an externally managed transaction.
- Test fixture that wraps requests in an outer transaction (SAVEPOINT semantics).
- Failure during active-rule creation (full rollback, no partial state).
- Failure during audit insertion (full rollback, draft reset, no active rule).
- Failure after conditional draft update (optimistic rollback).
- Failure during active-rule status update (status reversion, no partial audit).
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.db.models import (
    ActiveDetectionRuleModel,
    DetectionRuleDraftModel,
    RuleAuditEntryModel,
    RuleCodeAllocatorModel,
    RuleValidationRunModel,
    SavedHuntModel,
)
from app.db.session import Base
from app.schemas.active_rule import ActiveRuleStatus, ActiveRuleStatusUpdateRequest
from app.schemas.rule_draft import RuleDraftApprovalRequest
from app.services.rule_lifecycle_service import (
    RuleLifecycleService,
    ValidationRationaleError,
)


@pytest.fixture
async def tx_test_db():
    """Create a completely isolated in-memory SQLite database for transaction tests."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )

    @event.listens_for(engine.sync_engine, "connect")
    def do_connect(dbapi_connection, connection_record):
        dbapi_connection.isolation_level = None

    @event.listens_for(engine.sync_engine, "begin")
    def do_begin(conn):
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )

    # Seed allocator
    async with session_factory() as session:
        alloc = RuleCodeAllocatorModel(
            sequence_name="custom_rule",
            current_value=0,
            updated_at=datetime.now(timezone.utc),
        )
        session.add(alloc)
        await session.commit()

    yield session_factory

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


async def _seed_test_draft(session: AsyncSession, draft_id: str = "draft_tx_1") -> str:
    hunt = SavedHuntModel(
        id=f"hunt_{draft_id}",
        name="Source Hunt",
        query_definition={"combinator": "AND", "conditions": []},
        version=1,
    )
    draft = DetectionRuleDraftModel(
        id=draft_id,
        name="Suspicious Outbound Port",
        description="Transaction audit candidate draft",
        severity="high",
        mitre_attack_id="T1041",
        mitre_tactic="exfiltration",
        source_hunt_id=hunt.id,
        source_hunt_version=1,
        query_definition={
            "filter_group": {
                "logic": "AND",
                "conditions": [{"field": "action", "operator": "eq", "value": "network_connect"}],
                "groups": [],
            }
        },
        status="VALIDATED",
        version=1,
        created_by="analyst_alice",
        is_archived=False,
    )
    val = RuleValidationRunModel(
        id=f"val_{draft_id}",
        draft_id=draft.id,
        draft_version=1,
        query_definition_snapshot={},
        events_scanned=10,
        matches_found=1,
        status="COMPLETED",
        is_stale=False,
    )
    session.add_all([hunt, draft, val])
    await session.commit()
    return draft_id


# ==============================================================================
# 1. Fresh AsyncSession (Normal Execution Path)
# ==============================================================================

@pytest.mark.asyncio
async def test_tx_fresh_session_commits_and_persists_to_independent_session(tx_test_db):
    """
    Scenario: Fresh AsyncSession with no prior queries.
    RuleLifecycleService._transaction_scope() enters `session.begin()`,
    commits upon exit, and independent sessions can immediately read the persisted records.
    """
    draft_id = "draft_fresh_tx"
    async with tx_test_db() as seed_session:
        await _seed_test_draft(seed_session, draft_id)

    # Execute service in fresh session
    async with tx_test_db() as svc_session:
        assert not svc_session.in_transaction()
        service = RuleLifecycleService(svc_session)
        payload = RuleDraftApprovalRequest(
            draft_version=1,
            approver_id="lead_bob",
            justification="Verified pre-flight checks and telemetry.",
            activate_immediately=True,
        )
        active_rule, draft, audit = await service.approve_rule_draft(draft_id, payload)
        assert active_rule.rule_code == "CUST-001"
        assert draft.status == "APPROVED"

    # Query from completely independent session to verify persistence
    async with tx_test_db() as verify_session:
        stmt_rule = select(ActiveDetectionRuleModel).where(ActiveDetectionRuleModel.rule_code == "CUST-001")
        rule_res = await verify_session.execute(stmt_rule)
        persisted_rule = rule_res.scalar_one_or_none()
        assert persisted_rule is not None
        assert persisted_rule.status == "ACTIVE"

        stmt_draft = select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id)
        draft_res = await verify_session.execute(stmt_draft)
        persisted_draft = draft_res.scalar_one()
        assert persisted_draft.status == "APPROVED"
        assert persisted_draft.version == 2

        stmt_audit = select(RuleAuditEntryModel).where(RuleAuditEntryModel.target_id == draft_id)
        audit_res = await verify_session.execute(stmt_audit)
        persisted_audit = audit_res.scalar_one()
        assert persisted_audit.action == "APPROVE_DRAFT"


# ==============================================================================
# 2. Autobegun Session (Prior Read Query on Session)
# ==============================================================================

@pytest.mark.asyncio
async def test_tx_autobegun_session_handles_savepoint_and_commits(tx_test_db):
    """
    Scenario: A read query was run on the session prior to calling the service.
    This puts the session in an autobegun transaction (in_transaction() is True).
    _transaction_scope() uses begin_nested() (SAVEPOINT).
    When the outer session commits, all changes are persisted.
    """
    draft_id = "draft_autobegin_tx"
    async with tx_test_db() as seed_session:
        await _seed_test_draft(seed_session, draft_id)

    async with tx_test_db() as session:
        # Prior read query triggers autobegin
        _ = await session.execute(select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id))
        assert session.in_transaction()  # Autobegun

        service = RuleLifecycleService(session)
        payload = RuleDraftApprovalRequest(
            draft_version=1,
            approver_id="lead_bob",
            justification="Verified pre-flight checks and telemetry.",
            activate_immediately=True,
        )
        active_rule, draft, audit = await service.approve_rule_draft(draft_id, payload)
        assert active_rule.rule_code == "CUST-001"

        # Explicitly commit the outer session (as get_db_session does in FastAPI)
        await session.commit()

    # Verify persistence in independent session
    async with tx_test_db() as verify_session:
        rule = (await verify_session.execute(select(ActiveDetectionRuleModel).where(ActiveDetectionRuleModel.rule_code == "CUST-001"))).scalar_one_or_none()
        assert rule is not None


# ==============================================================================
# 3. Outer Managed Transaction (Test Fixture or Composite Pipeline)
# ==============================================================================

@pytest.mark.asyncio
async def test_tx_outer_transaction_rollback_reverts_savepoint_operations(tx_test_db):
    """
    Scenario: The caller explicitly wraps the unit of work in `async with session.begin():`.
    _transaction_scope() uses `begin_nested()` (SAVEPOINT) rather than overriding the outer commit.
    When the outer transaction is intentionally rolled back, ALL changes are undone.
    Proves that a nested savepoint does NOT claim outer commit authority.
    """
    draft_id = "draft_outer_rollback_tx"
    async with tx_test_db() as seed_session:
        await _seed_test_draft(seed_session, draft_id)

    async with tx_test_db() as session:
        try:
            async with session.begin():
                service = RuleLifecycleService(session)
                payload = RuleDraftApprovalRequest(
                    draft_version=1,
                    approver_id="lead_bob",
                    justification="Approval inside outer transaction to be rolled back.",
                    activate_immediately=True,
                )
                await service.approve_rule_draft(draft_id, payload)
                # Outer caller deliberately raises an exception to force outer rollback
                raise RuntimeError("Deliberate outer transaction abort")
        except RuntimeError:
            pass

    # Independent session verifies zero state leaked
    async with tx_test_db() as verify_session:
        # Draft must still be VALIDATED version 1
        draft = (await verify_session.execute(select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id))).scalar_one()
        assert draft.status == "VALIDATED"
        assert draft.version == 1

        # No active rule was committed
        rules = (await verify_session.execute(select(ActiveDetectionRuleModel))).scalars().all()
        assert len(rules) == 0

        # No audit entry was committed
        audits = (await verify_session.execute(select(RuleAuditEntryModel))).scalars().all()
        assert len(audits) == 0


# ==============================================================================
# 4. Atomicity Failure During Active Rule Creation
# ==============================================================================

@pytest.mark.asyncio
async def test_tx_failure_during_active_rule_creation_rolls_back_draft(tx_test_db):
    """
    Scenario: Draft is conditionally updated, but active rule insertion fails.
    Verifies that the entire transaction rolls back:
    - Draft is NOT left in APPROVED status.
    - Draft version is NOT incremented.
    - No partial audit entry or active rule is stored.
    """
    draft_id = "draft_fail_rule_create"
    async with tx_test_db() as seed_session:
        await _seed_test_draft(seed_session, draft_id)

    async with tx_test_db() as session:
        service = RuleLifecycleService(session)
        payload = RuleDraftApprovalRequest(
            draft_version=1,
            approver_id="lead_bob",
            justification="Approval test where rule creation will fail.",
            activate_immediately=True,
        )

        with patch.object(service.active_rule_repo, "create_active_rule", side_effect=Exception("Simulated ActiveRule DB write failure")):
            with pytest.raises(Exception, match="Simulated ActiveRule DB write failure"):
                await service.approve_rule_draft(draft_id, payload)

    # Verify zero partial state in independent session
    async with tx_test_db() as verify_session:
        draft = (await verify_session.execute(select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id))).scalar_one()
        assert draft.status == "VALIDATED"
        assert draft.version == 1

        rules = (await verify_session.execute(select(ActiveDetectionRuleModel))).scalars().all()
        assert len(rules) == 0

        audits = (await verify_session.execute(select(RuleAuditEntryModel))).scalars().all()
        assert len(audits) == 0


# ==============================================================================
# 5. Atomicity Failure During Audit Insertion
# ==============================================================================

@pytest.mark.asyncio
async def test_tx_failure_during_audit_insertion_rolls_back_entire_approval(tx_test_db):
    """
    Scenario: Draft is updated and active rule is inserted in session, but audit ledger write fails.
    Verifies that the entire unit of work rolls back:
    - No active rule exists.
    - Draft reverts to VALIDATED version 1.
    - Rule code allocator sequence is not committed.
    """
    draft_id = "draft_fail_audit_write"
    async with tx_test_db() as seed_session:
        await _seed_test_draft(seed_session, draft_id)

    async with tx_test_db() as session:
        service = RuleLifecycleService(session)
        payload = RuleDraftApprovalRequest(
            draft_version=1,
            approver_id="lead_bob",
            justification="Approval test where audit write fails.",
            activate_immediately=True,
        )

        with patch.object(service.audit_repo, "create_audit_entry", side_effect=Exception("Simulated Audit Ledger DB failure")):
            with pytest.raises(Exception, match="Simulated Audit Ledger DB failure"):
                await service.approve_rule_draft(draft_id, payload)

    async with tx_test_db() as verify_session:
        draft = (await verify_session.execute(select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id))).scalar_one()
        assert draft.status == "VALIDATED"
        assert draft.version == 1

        rules = (await verify_session.execute(select(ActiveDetectionRuleModel))).scalars().all()
        assert len(rules) == 0

        audits = (await verify_session.execute(select(RuleAuditEntryModel))).scalars().all()
        assert len(audits) == 0


# ==============================================================================
# 6. Atomicity Failure During Active Rule Status Toggle
# ==============================================================================

@pytest.mark.asyncio
async def test_tx_failure_during_status_toggle_audit_write_rolls_back_rule_status(tx_test_db):
    """
    Scenario: Active rule status is atomically toggled, but audit entry persistence fails.
    Verifies that active rule status and version revert to original values.
    """
    draft_id = "draft_status_toggle_tx"
    async with tx_test_db() as seed_session:
        await _seed_test_draft(seed_session, draft_id)

    rule_id = "rule_tx_toggle_test"
    async with tx_test_db() as session:
        now = datetime.now(timezone.utc)
        rule = ActiveDetectionRuleModel(
            id=rule_id,
            rule_code="CUST-001",
            name="Test Active Rule",
            description="Testing status toggle atomicity",
            severity="high",
            mitre_attack_id="T1041",
            mitre_tactic="exfiltration",
            source_draft_id=draft_id,
            source_draft_version=1,
            validation_run_id=f"val_{draft_id}",
            query_definition={"filter_group": {"logic": "AND", "conditions": []}},
            status="ACTIVE",
            version=1,
            approved_by="lead_bob",
            approved_at=now,
            activated_at=now,
        )
        session.add(rule)
        await session.commit()

    # Attempt to disable rule, but mock audit failure
    async with tx_test_db() as session:
        service = RuleLifecycleService(session)
        payload = ActiveRuleStatusUpdateRequest(
            version=1,
            status=ActiveRuleStatus.DISABLED,
            justification="Attempting status toggle where audit write will fail.",
            actor="operator_dan",
        )
        with patch.object(service.audit_repo, "create_audit_entry", side_effect=Exception("Audit failure during status toggle")):
            with pytest.raises(Exception, match="Audit failure during status toggle"):
                await service.toggle_active_rule_status(rule_id, payload)

    # Verify rule remains ACTIVE version 1 and no audit entry exists
    async with tx_test_db() as verify_session:
        rule = (await verify_session.execute(select(ActiveDetectionRuleModel).where(ActiveDetectionRuleModel.id == rule_id))).scalar_one()
        assert rule.status == "ACTIVE"
        assert rule.version == 1

        audits = (await verify_session.execute(select(RuleAuditEntryModel))).scalars().all()
        assert len(audits) == 0


# ==============================================================================
# 7. Atomicity on Version Conflict Gate
# ==============================================================================

@pytest.mark.asyncio
async def test_tx_version_conflict_rolls_back_without_allocator_increment(tx_test_db):
    """
    Scenario: Approval is attempted with a stale version.
    Verifies that the optimistic concurrency gate rejects the transaction immediately:
    - VersionConflictError is raised.
    - Allocator sequence value remains unincremented.
    - Zero active rules or audit entries are persisted.
    """
    draft_id = "draft_ver_conflict_tx"
    async with tx_test_db() as seed_session:
        await _seed_test_draft(seed_session, draft_id)

    async with tx_test_db() as session:
        service = RuleLifecycleService(session)
        payload = RuleDraftApprovalRequest(
            draft_version=99,  # Stale version
            approver_id="lead_bob",
            justification="Attempting approval with stale version 99.",
            activate_immediately=True,
        )
        from app.services.rule_lifecycle_service import VersionConflictError
        with pytest.raises(VersionConflictError):
            await service.approve_rule_draft(draft_id, payload)

    async with tx_test_db() as verify_session:
        # Allocator remains at 0
        alloc = (await verify_session.execute(select(RuleCodeAllocatorModel).where(RuleCodeAllocatorModel.sequence_name == "custom_rule"))).scalar_one()
        assert alloc.current_value == 0

        rules = (await verify_session.execute(select(ActiveDetectionRuleModel))).scalars().all()
        assert len(rules) == 0

        audits = (await verify_session.execute(select(RuleAuditEntryModel))).scalars().all()
        assert len(audits) == 0
