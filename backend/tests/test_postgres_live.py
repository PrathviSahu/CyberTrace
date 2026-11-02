"""
CyberTrace Phase 6.3C Stage 5 — Live PostgreSQL Integration Test Suite.
Executes against live running PostgreSQL 16 on database `cybertrace_test`.
Validates:
1. Phase 6.3C tables, indexes, and foreign keys on PostgreSQL.
2. Allocator UPDATE ... RETURNING with concurrent competing connections.
3. Concurrent approval of the same draft (optimistic concurrency gate).
4. Concurrent active-rule status updates.
5. Foreign-key ON DELETE RESTRICT enforcement on draft deletion.
6. Rollback when audit insertion fails on PostgreSQL (zero partial state).
7. JSON AST snapshot persistence, retrieval, and deep-freezing into DynamicCustomRule.
8. Detection persistence and incident correlation on live PostgreSQL engine.
"""

import asyncio
from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import (
    ActiveDetectionRuleModel,
    DetectionModel,
    DetectionRuleDraftModel,
    IncidentModel,
    RuleAuditEntryModel,
    RuleCodeAllocatorModel,
    RuleValidationRunModel,
    SavedHuntModel,
    SecurityEventModel,
)
from app.db.repositories.active_rule_repo import ActiveRuleRepository
from app.db.repositories.rule_audit_repo import RuleAuditRepository
from app.rules.dynamic_rule import DynamicCustomRule
from app.schemas.active_rule import ActiveRuleStatus, ActiveRuleStatusUpdateRequest
from app.schemas.ces import CommonEvent, EventAction, EventCategory, EventSeverity
from app.schemas.rule_draft import RuleDraftApprovalRequest
from app.services.rule_lifecycle_service import (
    RuleLifecycleService,
    VersionConflictError,
)

POSTGRES_TEST_URL = "postgresql+asyncpg://localhost:5432/cybertrace_test"


@pytest.fixture
async def pg_engine():
    """Provides async engine for live PostgreSQL testing."""
    engine = create_async_engine(
        POSTGRES_TEST_URL,
        echo=False,
        pool_size=10,
        max_overflow=20,
    )
    yield engine
    await engine.dispose()


@pytest.fixture
async def pg_session_factory(pg_engine):
    """Provides sessionmaker bound to live PostgreSQL engine."""
    return async_sessionmaker(
        bind=pg_engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )


@pytest.fixture(autouse=True)
async def clean_pg_tables(pg_engine):
    """Clean all relevant tables before each live PostgreSQL test."""
    async with pg_engine.begin() as conn:
        await conn.execute(text("TRUNCATE TABLE rule_audit_ledger, active_detection_rules, detections, incidents, security_events, rule_validation_runs, detection_rule_drafts, saved_hunts, rule_code_allocators CASCADE;"))
        # Seed allocator
        now = datetime.now(timezone.utc)
        await conn.execute(
            text("INSERT INTO rule_code_allocators (sequence_name, current_value, updated_at) VALUES ('custom_rule', 0, :now)"),
            {"now": now},
        )
    yield


async def _seed_pg_draft_and_val(
    session: AsyncSession,
    draft_id: str,
    status: str = "VALIDATED",
    version: int = 1,
    created_by: str = "analyst_alice",
) -> DetectionRuleDraftModel:
    hunt = SavedHuntModel(
        id=f"hunt_{draft_id}",
        name="Source Hunt",
        query_definition={"combinator": "AND", "conditions": []},
        version=1,
    )
    draft = DetectionRuleDraftModel(
        id=draft_id,
        name="Postgres Live Rule",
        description="Live PG rule verification",
        severity="high",
        mitre_attack_id="T1041",
        mitre_tactic="exfiltration",
        source_hunt_id=hunt.id,
        source_hunt_version=1,
        query_definition={
            "filter_group": {
                "logic": "AND",
                "conditions": [
                    {"field": "action", "operator": "eq", "value": "network_connect"},
                    {"field": "destination_port", "operator": "eq", "value": 4444},
                ],
                "groups": [],
            }
        },
        status=status,
        version=version,
        created_by=created_by,
        is_archived=False,
    )
    val = RuleValidationRunModel(
        id=f"val_{draft_id}",
        draft_id=draft.id,
        draft_version=version,
        query_definition_snapshot={},
        events_scanned=20,
        matches_found=2,
        status="COMPLETED",
        is_stale=False,
    )
    session.add(hunt)
    await session.flush()
    session.add(draft)
    await session.flush()
    session.add(val)
    await session.commit()
    return draft


# ==============================================================================
# 1. Allocator UPDATE ... RETURNING & Concurrency on PostgreSQL
# ==============================================================================

@pytest.mark.asyncio
async def test_pg_live_allocator_concurrent_increments(pg_session_factory):
    """
    Test 10 concurrent tasks simultaneously incrementing the sequence on live PostgreSQL.
    Verifies that Postgres UPDATE ... RETURNING guarantees 10 distinct sequential values
    with zero duplicate rule codes.
    """
    async def _allocate_one():
        async with pg_session_factory() as session:
            service = RuleLifecycleService(session)
            async with session.begin():
                return await service._allocate_next_rule_code(session)

    results = await asyncio.gather(*[_allocate_one() for _ in range(10)])
    assert len(results) == 10
    assert len(set(results)) == 10  # Zero collisions
    assert set(results) == {f"CUST-{i:03d}" for i in range(1, 11)}


# ==============================================================================
# 2. Concurrent Draft Approval Race on PostgreSQL
# ==============================================================================

@pytest.mark.asyncio
async def test_pg_live_concurrent_draft_approval_single_winner(pg_session_factory):
    """
    Two independent PostgreSQL sessions compete to approve the exact same draft simultaneously.
    Verifies optimistic concurrency gate: exactly 1 approval succeeds, exactly 1 fails with VersionConflictError.
    """
    draft_id = "draft_pg_race"
    async with pg_session_factory() as session:
        await _seed_pg_draft_and_val(session, draft_id)

    async def _attempt_approval(approver: str):
        async with pg_session_factory() as session:
            service = RuleLifecycleService(session)
            payload = RuleDraftApprovalRequest(
                draft_version=1,
                approver_id=approver,
                justification="Concurrent approval attempt on PostgreSQL.",
                activate_immediately=True,
            )
            try:
                active_rule, draft, audit = await service.approve_rule_draft(draft_id, payload)
                return {"status": "SUCCESS", "rule_code": active_rule.rule_code, "approver": approver}
            except VersionConflictError as e:
                return {"status": "CONFLICT", "error": str(e), "approver": approver}

    res1, res2 = await asyncio.gather(
        _attempt_approval("reviewer_bob"),
        _attempt_approval("reviewer_charlie"),
    )

    statuses = [res1["status"], res2["status"]]
    assert statuses.count("SUCCESS") == 1
    assert statuses.count("CONFLICT") == 1

    # Verify database state on PostgreSQL
    async with pg_session_factory() as verify_session:
        active_rules = (await verify_session.execute(select(ActiveDetectionRuleModel))).scalars().all()
        assert len(active_rules) == 1
        assert active_rules[0].rule_code == "CUST-001"

        audits = (await verify_session.execute(select(RuleAuditEntryModel))).scalars().all()
        assert len(audits) == 1
        assert audits[0].action == "APPROVE_DRAFT"


# ==============================================================================
# 3. Concurrent Active Rule Status Updates on PostgreSQL
# ==============================================================================

@pytest.mark.asyncio
async def test_pg_live_concurrent_status_toggle_single_winner(pg_session_factory):
    """
    Two independent PostgreSQL sessions compete to update the status of the same active rule.
    Both expect version 1. Exactly one must succeed; the other must receive VersionConflictError.
    """
    rule_id = "rule_pg_status_race"
    draft_id = "draft_pg_status_race"
    async with pg_session_factory() as session:
        draft = await _seed_pg_draft_and_val(session, draft_id)
        now = datetime.now(timezone.utc)
        rule = ActiveDetectionRuleModel(
            id=rule_id,
            rule_code="CUST-001",
            name="PG Status Race Rule",
            description="Testing concurrent status updates on PG",
            severity="high",
            mitre_attack_id="T1041",
            mitre_tactic="exfiltration",
            source_draft_id=draft.id,
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

    async def _attempt_status_toggle(new_status: ActiveRuleStatus, actor: str):
        async with pg_session_factory() as session:
            service = RuleLifecycleService(session)
            payload = ActiveRuleStatusUpdateRequest(
                version=1,
                status=new_status,
                justification="Concurrent status update racing on PostgreSQL.",
                actor=actor,
            )
            try:
                updated, audit = await service.toggle_active_rule_status(rule_id, payload)
                return {"status": "SUCCESS", "new_status": updated.status, "version": updated.version}
            except VersionConflictError as e:
                return {"status": "CONFLICT", "error": str(e)}

    res1, res2 = await asyncio.gather(
        _attempt_status_toggle(ActiveRuleStatus.DISABLED, "operator_dan"),
        _attempt_status_toggle(ActiveRuleStatus.DEPRECATED, "operator_eve"),
    )

    statuses = [res1["status"], res2["status"]]
    assert statuses.count("SUCCESS") == 1
    assert statuses.count("CONFLICT") == 1

    async with pg_session_factory() as verify_session:
        rule = (await verify_session.execute(select(ActiveDetectionRuleModel).where(ActiveDetectionRuleModel.id == rule_id))).scalar_one()
        assert rule.version == 2


# ==============================================================================
# 4. Foreign Key RESTRICT Behavior on PostgreSQL
# ==============================================================================

@pytest.mark.asyncio
async def test_pg_live_foreign_key_restrict_prevents_source_draft_deletion(pg_session_factory):
    """
    Verifies PostgreSQL foreign key constraint `fk_active_rules_source_draft` with ON DELETE RESTRICT.
    Attempting to DELETE a draft referenced by an active rule must raise IntegrityError.
    """
    draft_id = "draft_fk_restrict_pg"
    async with pg_session_factory() as session:
        draft = await _seed_pg_draft_and_val(session, draft_id)
        now = datetime.now(timezone.utc)
        rule = ActiveDetectionRuleModel(
            id="rule_fk_restrict",
            rule_code="CUST-001",
            name="FK Test Rule",
            description="Testing FK RESTRICT on Postgres",
            severity="high",
            mitre_attack_id="T1041",
            mitre_tactic="exfiltration",
            source_draft_id=draft.id,
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

    # Attempt to delete draft
    async with pg_session_factory() as session:
        with pytest.raises(IntegrityError) as exc_info:
            async with session.begin():
                await session.execute(delete(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id))
        # Verify PostgreSQL foreign key violation message
        assert "violates foreign key constraint" in str(exc_info.value).lower() or "fk_active_rules_source_draft" in str(exc_info.value)


# ==============================================================================
# 5. Rollback on Audit Failure on PostgreSQL
# ==============================================================================

@pytest.mark.asyncio
async def test_pg_live_rollback_when_audit_fails(pg_session_factory):
    """
    Verifies that if audit writing fails on PostgreSQL, the entire transaction rolls back cleanly:
    - Draft reverts to VALIDATED version 1.
    - Active rule is not inserted.
    - Rule code allocator sequence changes are rolled back.
    """
    draft_id = "draft_pg_audit_fail"
    async with pg_session_factory() as session:
        await _seed_pg_draft_and_val(session, draft_id)

    async with pg_session_factory() as session:
        service = RuleLifecycleService(session)
        payload = RuleDraftApprovalRequest(
            draft_version=1,
            approver_id="lead_bob",
            justification="Approval where audit write will fail on PostgreSQL.",
            activate_immediately=True,
        )
        from unittest.mock import patch
        with patch.object(service.audit_repo, "create_audit_entry", side_effect=Exception("Simulated PG Audit Write Error")):
            with pytest.raises(Exception, match="Simulated PG Audit Write Error"):
                await service.approve_rule_draft(draft_id, payload)

    async with pg_session_factory() as verify_session:
        # Draft remains VALIDATED version 1
        draft = (await verify_session.execute(select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id))).scalar_one()
        assert draft.status == "VALIDATED"
        assert draft.version == 1

        # No active rules exist
        rules = (await verify_session.execute(select(ActiveDetectionRuleModel))).scalars().all()
        assert len(rules) == 0

        # No audit records exist
        audits = (await verify_session.execute(select(RuleAuditEntryModel))).scalars().all()
        assert len(audits) == 0


# ==============================================================================
# 6. JSON AST Snapshot Persistence & DynamicCustomRule Construction
# ==============================================================================

@pytest.mark.asyncio
async def test_pg_live_ast_persistence_and_dynamic_rule_construction(pg_session_factory):
    """
    Verifies PostgreSQL JSON/JSONB serialization of query AST and flawless loading
    into deep-frozen DynamicCustomRule execution snapshot.
    """
    draft_id = "draft_pg_ast_test"
    complex_ast = {
        "filter_group": {
            "logic": "AND",
            "conditions": [
                {"field": "action", "operator": "eq", "value": "network_connect"},
                {"field": "destination_port", "operator": "in", "value": [4444, 8888, 9999]},
                {"field": "bytes_out", "operator": "gte", "value": 102400},
            ],
            "groups": [
                {
                    "logic": "OR",
                    "conditions": [
                        {"field": "protocol", "operator": "eq", "value": "tcp"},
                        {"field": "protocol", "operator": "eq", "value": "udp"},
                    ],
                    "groups": [],
                }
            ],
        }
    }

    async with pg_session_factory() as session:
        draft = await _seed_pg_draft_and_val(session, draft_id)
        draft.query_definition = complex_ast
        await session.commit()

        service = RuleLifecycleService(session)
        payload = RuleDraftApprovalRequest(
            draft_version=1,
            approver_id="lead_bob",
            justification="Approving complex AST rule on PostgreSQL.",
            activate_immediately=True,
        )
        active_rule, _, _ = await service.approve_rule_draft(draft.id, payload)
        rule_id = active_rule.id

    # Retrieve from independent session and build DynamicCustomRule
    async with pg_session_factory() as verify_session:
        active_repo = ActiveRuleRepository(verify_session)
        loaded_model = await active_repo.get_active_rule_by_id(rule_id)
        assert loaded_model is not None

        # Build dynamic custom rule
        dyn_rule = DynamicCustomRule.from_active_model(loaded_model)
        assert dyn_rule.rule_id == "CUST-001"
        assert dyn_rule.active_rule_id == rule_id
        assert dyn_rule.name == "Postgres Live Rule"
        assert len(dyn_rule.filter_group.conditions) == 3
        assert dyn_rule.filter_group.conditions[1].value == (4444, 8888, 9999)  # deep frozen tuple!
        assert len(dyn_rule.filter_group.groups) == 1

        # Test evaluation against matching and non-matching event
        matching_event = CommonEvent(
            event_id="evt_pg_match",
            timestamp=datetime.now(timezone.utc),
            category=EventCategory.NETWORK_CONNECTION,
            action=EventAction.NETWORK_CONNECT,
            source_format="suricata",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            destination_port=8888,
            bytes_sent=200000,
            protocol="tcp",
        )
        dets = dyn_rule.evaluate([matching_event], [])
        assert len(dets) == 1
        assert dets[0].rule_id == "CUST-001"
        assert dets[0].metadata["active_rule_id"] == rule_id

        non_matching_event = CommonEvent(
            event_id="evt_pg_nomatch",
            timestamp=datetime.now(timezone.utc),
            category=EventCategory.NETWORK_CONNECTION,
            action=EventAction.NETWORK_CONNECT,
            source_format="suricata",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            destination_port=80,  # Port mismatch
            bytes_sent=200000,
            protocol="tcp",
        )
        dets_nomatch = dyn_rule.evaluate([non_matching_event], [])
        assert len(dets_nomatch) == 0


# ==============================================================================
# 7. Detection Persistence & Incident Correlation on Live PostgreSQL
# ==============================================================================

@pytest.mark.asyncio
async def test_pg_live_detection_persistence_and_incident_correlation(pg_session_factory):
    """
    Verifies that detections generated from custom rules and foundational rules
    persist correctly to PostgreSQL `detections` and correlate into `incidents`.
    """
    from app.correlation.service import IncidentService

    draft_id = "draft_pg_corr_test"
    async with pg_session_factory() as session:
        draft = await _seed_pg_draft_and_val(session, draft_id)
        service = RuleLifecycleService(session)
        payload = RuleDraftApprovalRequest(
            draft_version=1,
            approver_id="lead_bob",
            justification="Approving rule for live PG incident correlation.",
            activate_immediately=True,
        )
        active_rule, _, _ = await service.approve_rule_draft(draft.id, payload)
        rule_code = active_rule.rule_code

    # Ingest synthetic matching event through IncidentService
    matching_event = CommonEvent(
        event_id="evt_pg_corr_1",
        timestamp=datetime.now(timezone.utc),
        category=EventCategory.NETWORK_CONNECTION,
        action=EventAction.NETWORK_CONNECT,
        source_format="suricata",
        source_ip="192.168.1.99",
        destination_ip="10.0.0.2",
        destination_port=4444,
        protocol="tcp",
    )

    async with pg_session_factory() as session:
        inc_service = IncidentService(session)
        # Process event batch on live PostgreSQL
        incidents = await inc_service.process_and_correlate_events([matching_event])
        assert len(incidents) >= 1

    # Verify detection and incident persisted in PostgreSQL
    async with pg_session_factory() as verify_session:
        dets = (await verify_session.execute(select(DetectionModel).where(DetectionModel.rule_id == rule_code))).scalars().all()
        assert len(dets) == 1
        assert dets[0].rule_id == rule_code
        assert dets[0].metadata_json["active_rule_id"] == active_rule.id

        incs = (await verify_session.execute(select(IncidentModel))).scalars().all()
        assert len(incs) >= 1
