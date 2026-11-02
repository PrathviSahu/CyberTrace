"""
Comprehensive Test Suite for CyberTrace Phase 6.3B:
Detection Rule Drafts, Promotion, Pre-flight Simulation, Stale Validation Protection,
and Exact SQL / In-Memory AST Evaluator Semantic Parity.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import DetectionRuleDraftModel, RuleValidationRunModel, SecurityEventModel
from app.db.repositories.hunting_repo import HuntingRepository
from app.db.repositories.rule_draft_repo import (
    ArchivedRuleError,
    RuleDraftRepository,
    VersionConflictError,
)
from app.db.repositories.saved_hunt_repo import SavedHuntRepository
from app.db.session import get_db_session
from app.main import app
from app.rules.ast_evaluator import evaluate_filter_group
from app.schemas.ces import CommonEvent, EventAction, EventCategory, EventSeverity
from app.schemas.hunting import (
    FilterCondition,
    FilterField,
    FilterGroup,
    FilterOperator,
)
from app.schemas.saved_hunt import (
    SavedHuntCreate,
    SavedHuntQueryDefinition,
)
from app.schemas.rule_draft import (
    DetectionRuleDraftCreate,
    DetectionRuleDraftUpdate,
    DraftStatus,
    RuleSeverity,
    RuleValidationRunRequest,
    ValidationScope,
)


async def seed_event(
    session: AsyncSession,
    event_id: str,
    timestamp: datetime,
    username: Optional[str] = None,
    action: str = "network_connect",
    category: str = "network_connection",
    severity: str = "medium",
    source_ip: str = "10.0.0.1",
    destination_ip: str = "192.168.1.1",
    bytes_out: int = 1000,
    bytes_in: int = 500,
    source_port: int = 50000,
    destination_port: int = 443,
    hostname: Optional[str] = "WS-01",
    protocol: str = "TCP",
    process_name: Optional[str] = "/usr/bin/curl",
    source_file_hash: Optional[str] = "hash123",
    source_attribution: Optional[str] = "corporate_edr_sensor",
) -> SecurityEventModel:
    payload = {"id": event_id, "test": True}
    if source_attribution:
        payload["source_attribution"] = source_attribution

    ev = SecurityEventModel(
        id=event_id,
        timestamp=timestamp,
        source_type="syslog",
        category=category,
        action=action,
        severity=severity,
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        hostname=hostname,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        bytes_out=bytes_out,
        bytes_in=bytes_in,
        process_name=process_name,
        source_file_hash=source_file_hash,
        raw_payload=payload,
    )
    session.add(ev)
    await session.commit()
    return ev


# ---------------------------------------------------------------------------
# Section 1: Draft Creation & Saved Hunt Promotion Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_draft_from_scratch(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)
    draft = await repo.create_draft(
        DetectionRuleDraftCreate(
            name="Suspicious Curl Outbound",
            description="Detects anomalous curl invocations to external networks",
            severity=RuleSeverity.HIGH,
            mitre_attack_id="T1041",
            mitre_tactic="exfiltration",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[
                        FilterCondition(field=FilterField.PROCESS_NAME, operator=FilterOperator.CONTAINS, value="curl"),
                        FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.GT, value=50000),
                    ]
                )
            ),
        )
    )
    assert draft.id.startswith("draft_")
    assert draft.name == "Suspicious Curl Outbound"
    assert draft.severity == "high"
    assert draft.status == "DRAFT"
    assert draft.version == 1
    assert draft.is_archived is False
    assert draft.source_hunt_id is None
    assert draft.source_hunt_version is None


@pytest.mark.asyncio
async def test_create_draft_promoted_from_saved_hunt(db_session: AsyncSession):
    hunt_repo = SavedHuntRepository(db_session)
    hunt = await hunt_repo.create_saved_hunt(
        SavedHuntCreate(
            name="Base Threat Hunt",
            description="Exploratory hunt for admin logins",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[
                        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="admin")
                    ]
                )
            ),
        )
    )
    assert hunt.version == 1

    draft_repo = RuleDraftRepository(db_session)
    draft = await draft_repo.create_draft(
        DetectionRuleDraftCreate(
            name="Admin Login Rule Draft",
            description="Promoted from hunt: admin login activity",
            severity=RuleSeverity.MEDIUM,
            source_hunt_id=hunt.id,
        )
    )
    assert draft.source_hunt_id == hunt.id
    assert draft.source_hunt_version == 1
    assert draft.query_definition == hunt.query_definition
    assert draft.status == "DRAFT"
    assert draft.version == 1


@pytest.mark.asyncio
async def test_promote_from_archived_hunt_fails_with_409(db_session: AsyncSession):
    hunt_repo = SavedHuntRepository(db_session)
    hunt = await hunt_repo.create_saved_hunt(
        SavedHuntCreate(
            name="Archived Hunt Pattern",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="logon")]
                )
            ),
        )
    )
    await hunt_repo.archive_saved_hunt(hunt.id)

    draft_repo = RuleDraftRepository(db_session)
    with pytest.raises(ArchivedRuleError, match="Cannot promote archived threat hunt"):
        await draft_repo.create_draft(
            DetectionRuleDraftCreate(
                name="Illegal Promotion",
                source_hunt_id=hunt.id,
            )
        )


@pytest.mark.asyncio
async def test_promote_from_nonexistent_hunt_fails_with_404(db_session: AsyncSession):
    draft_repo = RuleDraftRepository(db_session)
    with pytest.raises(ValueError, match="Source saved threat hunt 'nonexistent' was not found"):
        await draft_repo.create_draft(
            DetectionRuleDraftCreate(
                name="Ghost Promotion",
                source_hunt_id="nonexistent",
            )
        )


# ---------------------------------------------------------------------------
# Section 2: Optimistic Concurrency & Lifecycle Invalidation Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_draft_concurrent_updates_same_version_exactly_one_succeeds(db_session: AsyncSession, async_test_engine):
    factory = async_sessionmaker(bind=async_test_engine, expire_on_commit=False, class_=AsyncSession)

    # 1. Seed draft in session 0
    async with factory() as s0:
        repo0 = RuleDraftRepository(s0)
        draft = await repo0.create_draft(
            DetectionRuleDraftCreate(
                name="Race Draft",
                query_definition=SavedHuntQueryDefinition(
                    filter_group=FilterGroup(
                        logic="AND",
                        conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="test")]
                    )
                ),
            )
        )
        draft_id = draft.id
        assert draft.version == 1

    # 2. Worker attempting update with version 1
    async def update_worker(worker_id: int):
        async with factory() as session:
            repo = RuleDraftRepository(session)
            return await repo.update_draft(
                draft_id,
                DetectionRuleDraftUpdate(version=1, name=f"Updated by Worker {worker_id}")
            )

    results = await asyncio.gather(
        update_worker(1),
        update_worker(2),
        return_exceptions=True
    )
    successes = [r for r in results if not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, Exception)]

    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], VersionConflictError)

    async with factory() as s_check:
        repo_check = RuleDraftRepository(s_check)
        final_draft = await repo_check.get_draft(draft_id)
        assert final_draft.version == 2


@pytest.mark.asyncio
async def test_draft_update_query_resets_validated_status_to_draft(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)
    draft = await repo.create_draft(
        DetectionRuleDraftCreate(
            name="Validation Invalidation Test",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="test")]
                )
            ),
        )
    )

    # Validate draft -> transitions to VALIDATED
    report = await repo.validate_draft(draft.id)
    assert report.draft_status_updated is True
    check_draft = await repo.get_draft(draft.id)
    assert check_draft.status == "VALIDATED"

    # Updating ONLY description preserves VALIDATED status
    updated1 = await repo.update_draft(
        draft.id,
        DetectionRuleDraftUpdate(version=1, description="Non-AST update")
    )
    assert updated1.version == 2
    assert updated1.status == "VALIDATED"

    # Updating query_definition MUST reset status to DRAFT
    updated2 = await repo.update_draft(
        draft.id,
        DetectionRuleDraftUpdate(
            version=2,
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="mutated")]
                )
            )
        )
    )
    assert updated2.version == 3
    assert updated2.status == "DRAFT"


@pytest.mark.asyncio
async def test_archived_draft_cannot_be_updated_or_validated(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)
    draft = await repo.create_draft(
        DetectionRuleDraftCreate(
            name="To Archive",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="test")]
                )
            ),
        )
    )
    await repo.archive_draft(draft.id)

    # Attempt update
    with pytest.raises(ArchivedRuleError, match="cannot be modified"):
        await repo.update_draft(draft.id, DetectionRuleDraftUpdate(version=1, name="Illegal Edit"))

    # Attempt validation
    with pytest.raises(ArchivedRuleError, match="cannot be validated"):
        await repo.validate_draft(draft.id)


# ---------------------------------------------------------------------------
# Section 3: Stale Validation Protection Under Concurrent Mutation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stale_validation_after_concurrent_edit_leaves_draft_in_draft_state(
    db_session: AsyncSession, async_test_engine, monkeypatch
):
    factory = async_sessionmaker(bind=async_test_engine, expire_on_commit=False, class_=AsyncSession)
    now = datetime.now(timezone.utc)

    # 1. Seed events
    async with factory() as s_seed:
        await seed_event(s_seed, "evt_stale_1", now, username="alice", action="logon_success")

    # 2. Seed draft (version 1)
    async with factory() as s0:
        repo0 = RuleDraftRepository(s0)
        draft = await repo0.create_draft(
            DetectionRuleDraftCreate(
                name="Stale Validation Target",
                query_definition=SavedHuntQueryDefinition(
                    filter_group=FilterGroup(
                        logic="AND",
                        conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="alice")]
                    )
                ),
            )
        )
        draft_id = draft.id
        assert draft.version == 1
        assert draft.status == "DRAFT"

    # 3. Intercept HuntingRepository._compile_group during validation
    # to simulate another analyst concurrently editing the draft to version 2
    orig_compile = HuntingRepository._compile_group

    def intercept_and_concurrent_edit(self, group):
        # Concurrently edit draft to version 2 in separate session
        loop = asyncio.get_event_loop()
        async def do_concurrent_edit():
            async with factory() as s_concurrent:
                repo_c = RuleDraftRepository(s_concurrent)
                await repo_c.update_draft(
                    draft_id,
                    DetectionRuleDraftUpdate(version=1, name="Concurrently Mutated to v2")
                )
        loop.create_task(do_concurrent_edit())
        return orig_compile(self, group)

    monkeypatch.setattr(HuntingRepository, "_compile_group", intercept_and_concurrent_edit)

    # Allow the concurrent task a moment to finish
    await asyncio.sleep(0.05)

    # 4. Run validation on draft
    async with factory() as s_val:
        repo_val = RuleDraftRepository(s_val)
        report = await repo_val.validate_draft(draft_id)

    # 5. Verify stale protection:
    # - Validation record is preserved as evidence
    assert report.validation_id.startswith("val_")
    # - Draft was NOT marked VALIDATED because version changed
    assert report.is_stale is True
    assert report.draft_status_updated is False

    # Check database: draft remains in DRAFT with version 2
    async with factory() as s_check:
        repo_check = RuleDraftRepository(s_check)
        current = await repo_check.get_draft(draft_id)
        assert current.version == 2
        assert current.status == "DRAFT"
        assert current.name == "Concurrently Mutated to v2"


# ---------------------------------------------------------------------------
# Section 4: SQL vs. In-Memory AST Evaluator Exact Parity Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sql_and_in_memory_evaluator_parity_all_operators(db_session: AsyncSession):
    """
    Exhaustively tests every allowlisted operator across both SQL compilation
    and in-memory evaluation over the exact same event corpus to prove 100% semantic parity.
    """
    now = datetime.now(timezone.utc)
    hunting_repo = HuntingRepository(db_session)

    # Seed 6 diverse events
    events_data = [
        ("evt_p_1", now, "alice", "logon_success", "authentication", "low", "10.0.0.1", "192.168.1.1", 1000, 200, 50000, 443, "WS-01", "TCP", "/bin/bash"),
        ("evt_p_2", now + timedelta(minutes=1), "bob", "logon_failure", "authentication", "medium", "10.0.0.2", "192.168.1.1", 0, 0, 50001, 22, "SRV-01", "TCP", None),
        ("evt_p_3", now + timedelta(minutes=2), "svc_deploy", "network_connect", "network_connection", "high", "10.0.0.3", "198.51.100.44", 150000000, 500, 50002, 443, "SRV-APP", "TCP", "curl"),
        ("evt_p_4", now + timedelta(minutes=3), None, "blocked", "system_log", "informational", "10.0.0.4", "192.168.1.5", 50, 50, 50003, 80, "WS-02", "TCP", "python3"),
        ("evt_p_5", now + timedelta(minutes=4), "CAROL", "elevation_attempt", "privilege_change", "critical", "10.0.0.5", "192.168.1.1", 200, 100, 50004, 8080, "WS-03", "TCP", "sudo"),
        ("evt_p_6", now + timedelta(minutes=5), "admin%test_user", "process_start", "process_execution", "low", "10.0.0.6", "192.168.1.1", 300, 300, 50005, 53, "WS-04", "UDP", "special_proc"),
    ]

    db_models: List[SecurityEventModel] = []
    ces_events: List[CommonEvent] = []

    for item in events_data:
        m = await seed_event(
            db_session,
            event_id=item[0],
            timestamp=item[1],
            username=item[2],
            action=item[3],
            category=item[4],
            severity=item[5],
            source_ip=item[6],
            destination_ip=item[7],
            bytes_out=item[8],
            bytes_in=item[9],
            source_port=item[10],
            destination_port=item[11],
            hostname=item[12],
            protocol=item[13],
            process_name=item[14],
        )
        db_models.append(m)

        ces = CommonEvent(
            event_id=item[0],
            timestamp=item[1],
            source_format="syslog",
            user_identity=item[2],
            action=EventAction(item[3]),
            category=EventCategory(item[4]),
            severity=EventSeverity(item[5]),
            source_ip=item[6],
            destination_ip=item[7],
            bytes_sent=item[8],
            bytes_received=item[9],
            source_port=item[10],
            destination_port=item[11],
            hostname=item[12],
            protocol=item[13],
            process_name=item[14],
        )
        ces_events.append(ces)

    async def verify_parity(filter_group: FilterGroup, test_label: str):
        # 1. SQL evaluation
        clause = hunting_repo._compile_group(filter_group)
        sql_stmt = select(SecurityEventModel.id).where(clause)
        sql_ids = set((await db_session.execute(sql_stmt)).scalars().all())

        # 2. In-memory evaluation over CommonEvents
        in_memory_ids = {e.event_id for e in ces_events if evaluate_filter_group(e, filter_group)}

        assert sql_ids == in_memory_ids, (
            f"Parity failure for '{test_label}': SQL={sql_ids} vs In-Memory={in_memory_ids}"
        )

    # Test 1: EQ
    await verify_parity(
        FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="alice")]),
        "EQ username"
    )

    # Test 2: NEQ on nullable column (checks that evt_p_4 with NULL username is included)
    await verify_parity(
        FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.NEQ, value="alice")]),
        "NEQ username with null handling"
    )

    # Test 3: Case-insensitive CONTAINS (searching 'deploy' matches 'svc_deploy')
    await verify_parity(
        FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.CONTAINS, value="deploy")]),
        "CONTAINS case-insensitive"
    )

    # Test 4: Case-insensitive STARTS_WITH (searching 'carol' matches 'CAROL')
    await verify_parity(
        FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.STARTS_WITH, value="carol")]),
        "STARTS_WITH case-insensitive"
    )

    # Test 5: IN list operator
    await verify_parity(
        FilterGroup(conditions=[FilterCondition(field=FilterField.SEVERITY, operator=FilterOperator.IN, value=["high", "critical"])]),
        "IN operator"
    )

    # Test 6: GT numeric operator
    await verify_parity(
        FilterGroup(conditions=[FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.GT, value=1000000)]),
        "GT bytes_out"
    )

    # Test 7: GTE and LTE range
    await verify_parity(
        FilterGroup(
            logic="AND",
            conditions=[
                FilterCondition(field=FilterField.DESTINATION_PORT, operator=FilterOperator.GTE, value=80),
                FilterCondition(field=FilterField.DESTINATION_PORT, operator=FilterOperator.LTE, value=443),
            ]
        ),
        "GTE & LTE port range"
    )

    # Test 8: Nested OR inside AND
    await verify_parity(
        FilterGroup(
            logic="AND",
            conditions=[
                FilterCondition(field=FilterField.PROTOCOL, operator=FilterOperator.EQ, value="TCP"),
            ],
            groups=[
                FilterGroup(
                    logic="OR",
                    conditions=[
                        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="alice"),
                        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="bob"),
                    ]
                )
            ]
        ),
        "Nested AND/OR groups"
    )

    # Test 9: Special wildcard character escaping ('%' in value)
    await verify_parity(
        FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.CONTAINS, value="%test")]),
        "Wildcard % escaping"
    )


# ---------------------------------------------------------------------------
# Section 5: Historical Telemetry Transparent Metrics Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_historical_metrics_transparent_calculations(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)
    t0 = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(days=2)  # exactly 2 days

    await seed_event(db_session, "evt_hist_1", t0, action="network_connect", bytes_out=20000)
    await seed_event(db_session, "evt_hist_2", t1, action="network_connect", bytes_out=50000)

    draft = await repo.create_draft(
        DetectionRuleDraftCreate(
            name="Two-Day Historical Test",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.GTE, value=20000)]
                )
            ),
        )
    )

    report = await repo.validate_draft(
        draft.id,
        RuleValidationRunRequest(target_scope=ValidationScope.HISTORICAL_TELEMETRY)
    )

    hm = report.historical_metrics
    assert hm is not None
    assert hm.events_scanned >= 2
    assert hm.matches_found == 2
    assert hm.observation_duration_days == 2.0
    # 2 matches over 2 days = 1.0 alerts/day
    assert hm.estimated_daily_alert_volume == 1.0
    assert "2 matches / 2.00 observation days = 1.00 alerts/day" in hm.daily_volume_formula
    assert hm.insufficient_history_warning is False
    assert len(hm.sample_matched_event_ids) == 2


@pytest.mark.asyncio
async def test_historical_metrics_zero_duration_telemetry(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)
    t0 = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Two events at identical timestamp
    await seed_event(db_session, "evt_same_1", t0, action="logon_failure")
    await seed_event(db_session, "evt_same_2", t0, action="logon_failure")

    draft = await repo.create_draft(
        DetectionRuleDraftCreate(
            name="Zero Duration Draft",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="logon_failure")]
                )
            ),
        )
    )

    report = await repo.validate_draft(
        draft.id,
        RuleValidationRunRequest(target_scope=ValidationScope.HISTORICAL_TELEMETRY)
    )
    hm = report.historical_metrics
    assert hm is not None
    assert hm.insufficient_history_warning is True
    assert hm.observation_duration_days == 0.0
    assert hm.estimated_daily_alert_volume >= 2.0


# ---------------------------------------------------------------------------
# Section 6: ThreatLab Benchmark & Benign Baseline Warning Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_threatlab_benign_baseline_warning(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)

    # Rule that matches logon_success (which occurs in benign scenario SCN-004!)
    draft = await repo.create_draft(
        DetectionRuleDraftCreate(
            name="Overly Broad Logon Rule",
            description="Matches routine logon success",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="logon_success")]
                )
            ),
        )
    )

    report = await repo.validate_draft(
        draft.id,
        RuleValidationRunRequest(target_scope=ValidationScope.THREATLAB_BENCHMARKS)
    )

    tm = report.threatlab_metrics
    assert tm is not None
    assert tm.has_benign_baseline_warning is True
    assert tm.benign_baseline_matches > 0

    # Locate SCN-004 result
    scn4_res = next(r for r in tm.scenario_results if r.scenario_id == "SCN-004")
    assert scn4_res.classification == "benign_baseline_warning"
    assert scn4_res.is_benign_baseline_warning is True
    assert scn4_res.matches_found > 0


@pytest.mark.asyncio
async def test_threatlab_clean_rule_zero_benign_warnings(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)

    # Rule targeting high outbound egress (>100MB), which only occurs in attack scenario SCN-001
    draft = await repo.create_draft(
        DetectionRuleDraftCreate(
            name="Massive Exfiltration Rule",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.GT, value=100000000)]
                )
            ),
        )
    )

    report = await repo.validate_draft(
        draft.id,
        RuleValidationRunRequest(target_scope=ValidationScope.THREATLAB_BENCHMARKS)
    )

    tm = report.threatlab_metrics
    assert tm is not None
    assert tm.has_benign_baseline_warning is False
    assert tm.benign_baseline_matches == 0

    scn4_res = next(r for r in tm.scenario_results if r.scenario_id == "SCN-004")
    assert scn4_res.classification == "true_negative"
    assert scn4_res.is_benign_baseline_warning is False


# ---------------------------------------------------------------------------
# Section 7: REST API Endpoints & Error Status Mappings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_draft_full_lifecycle(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Create draft from scratch
            create_resp = await client.post(
                "/api/v1/rules/drafts",
                json={
                    "name": "API Full Lifecycle Rule",
                    "severity": "high",
                    "mitre_attack_id": "T1041",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [
                                {"field": "action", "operator": "eq", "value": "network_connect"}
                            ]
                        }
                    }
                }
            )
            assert create_resp.status_code == 201
            draft_data = create_resp.json()
            draft_id = draft_data["id"]
            assert draft_data["status"] == "DRAFT"
            assert draft_data["version"] == 1

            # 2. Run pre-flight validation
            val_resp = await client.post(f"/api/v1/rules/drafts/{draft_id}/validate", json={"target_scope": "all"})
            assert val_resp.status_code == 200
            val_data = val_resp.json()
            assert val_data["status"] == "COMPLETED"
            assert val_data["draft_status_updated"] is True

            # 3. Retrieve draft: status should now be VALIDATED
            get_resp = await client.get(f"/api/v1/rules/drafts/{draft_id}")
            assert get_resp.status_code == 200
            get_data = get_resp.json()
            assert get_data["status"] == "VALIDATED"
            assert get_data["latest_validation"] is not None

            # 4. Update query AST: status should automatically reset to DRAFT
            update_resp = await client.put(
                f"/api/v1/rules/drafts/{draft_id}",
                json={
                    "version": 1,
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [
                                {"field": "action", "operator": "eq", "value": "network_listen"}
                            ]
                        }
                    }
                }
            )
            assert update_resp.status_code == 200
            updated_data = update_resp.json()
            assert updated_data["version"] == 2
            assert updated_data["status"] == "DRAFT"

            # 5. Stale update with version 1 -> returns 409 Conflict
            stale_resp = await client.put(
                f"/api/v1/rules/drafts/{draft_id}",
                json={"version": 1, "name": "Stale Update"}
            )
            assert stale_resp.status_code == 409

            # 6. Archive draft
            del_resp = await client.delete(f"/api/v1/rules/drafts/{draft_id}")
            assert del_resp.status_code == 200
            assert del_resp.json()["is_archived"] is True
            assert del_resp.json()["status"] == "ARCHIVED"

            # 7. Attempt validation on archived draft -> returns 409 Conflict
            archived_val_resp = await client.post(f"/api/v1/rules/drafts/{draft_id}/validate")
            assert archived_val_resp.status_code == 409
            assert "cannot be validated" in archived_val_resp.json()["detail"]

            # 8. List validation history
            history_resp = await client.get(f"/api/v1/rules/drafts/{draft_id}/validations")
            assert history_resp.status_code == 200
            assert history_resp.json()["total"] >= 1
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_list_drafts_filters_and_pagination(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)
    for i in range(5):
        sev = RuleSeverity.CRITICAL if i % 2 == 0 else RuleSeverity.LOW
        await repo.create_draft(
            DetectionRuleDraftCreate(
                name=f"List Test Draft {i}",
                severity=sev,
                query_definition=SavedHuntQueryDefinition(
                    filter_group=FilterGroup(
                        logic="AND",
                        conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="test")]
                    )
                ),
            )
        )

    # Filter by severity
    critical_items, crit_total = await repo.list_drafts(severity="critical")
    assert crit_total == 3
    assert all(d.severity == "critical" for d in critical_items)

    # Exclude archived
    to_archive = critical_items[0]
    await repo.archive_draft(to_archive.id)

    active_items, active_total = await repo.list_drafts(severity="critical", include_archived=False)
    assert active_total == 2
    assert to_archive.id not in [d.id for d in active_items]

    # Include archived
    all_items, all_total = await repo.list_drafts(severity="critical", include_archived=True)
    assert all_total == 3


@pytest.mark.asyncio
async def test_draft_immutable_snapshot_of_source_hunt_version_and_independence(db_session: AsyncSession):
    hunt_repo = SavedHuntRepository(db_session)
    hunt = await hunt_repo.create_saved_hunt(
        SavedHuntCreate(
            name="Source Hunt Original",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="admin")]
                )
            ),
        )
    )
    assert hunt.version == 1

    draft_repo = RuleDraftRepository(db_session)
    draft = await draft_repo.create_draft(
        DetectionRuleDraftCreate(
            name="Promoted Draft Independent",
            source_hunt_id=hunt.id,
        )
    )
    assert draft.source_hunt_version == 1

    # Mutate source hunt to version 2 with a different query
    from app.schemas.saved_hunt import SavedHuntUpdate
    mutated_hunt = await hunt_repo.update_saved_hunt(
        hunt.id,
        SavedHuntUpdate(
            version=1,
            name="Mutated Source Hunt",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="root")]
                )
            ),
        )
    )
    assert mutated_hunt.version == 2

    # Check draft: its source_hunt_version remains 1, and its query definition is unchanged
    draft_check = await draft_repo.get_draft(draft.id)
    assert draft_check.source_hunt_version == 1
    assert draft_check.query_definition["filter_group"]["conditions"][0]["value"] == "admin"


@pytest.mark.asyncio
async def test_draft_ast_validation_rejects_empty_or_invalid_group(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)
    # Missing both source_hunt_id and query_definition
    with pytest.raises(ValueError, match="Either 'source_hunt_id'"):
        DetectionRuleDraftCreate(name="Missing Everything")

    # Empty filter group
    with pytest.raises(ValueError, match="must contain a valid filter_group"):
        await repo.create_draft(
            DetectionRuleDraftCreate(
                name="Empty AST Draft",
                query_definition=SavedHuntQueryDefinition(filter_group=None),
            )
        )


@pytest.mark.asyncio
async def test_repeated_archive_draft_is_idempotent(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)
    draft = await repo.create_draft(
        DetectionRuleDraftCreate(
            name="Idempotent Archive Draft",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="test")]
                )
            ),
        )
    )
    # First archive
    archived1 = await repo.archive_draft(draft.id)
    assert archived1.is_archived is True
    t_first = archived1.updated_at

    # Second archive
    archived2 = await repo.archive_draft(draft.id)
    assert archived2.is_archived is True
    assert archived2.updated_at == t_first


@pytest.mark.asyncio
async def test_validation_history_is_immutable_and_ordered(db_session: AsyncSession):
    repo = RuleDraftRepository(db_session)
    draft = await repo.create_draft(
        DetectionRuleDraftCreate(
            name="Multi-Validation History Draft",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="test")]
                )
            ),
        )
    )

    # Validate once
    rep1 = await repo.validate_draft(draft.id)
    # Validate twice
    rep2 = await repo.validate_draft(draft.id)

    runs, total = await repo.list_validations(draft.id)
    assert total == 2
    assert len(runs) == 2
    assert runs[0].id == rep2.validation_id
    assert runs[1].id == rep1.validation_id
    # Both runs preserved with their own timestamps
    assert runs[0].run_at >= runs[1].run_at


@pytest.mark.asyncio
async def test_author_attribution_security_disclaimer_on_drafts(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/rules/drafts",
                json={
                    "name": "Attribution Check Draft",
                    "created_by": "unverified_demo_user",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [{"field": "action", "operator": "eq", "value": "test"}]
                        }
                    }
                }
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["created_by"] == "unverified_demo_user"
            assert "author_attribution_note" in data
            assert "Caller-supplied demo identity" in data["author_attribution_note"]
    finally:
        app.dependency_overrides.clear()

