"""
CyberTrace Phase 6.3C Stage 3 Tests: Dynamic Custom Rule Engine Integration & Frozen Snapshot Isolation.
Verifies:
- Complete immutability of DynamicCustomRule, FrozenFilterGroup, and FrozenFilterCondition.
- Request-scoped DetectionEngine snapshot isolation across concurrent ingestion batches.
- In-flight snapshot immutability during concurrent database status toggles.
- Preservation of foundational rules DET-001 through DET-004 in exact historical order and behavior.
- Robust handling of corrupted/invalid AST query definitions without crash or broad matching.
- Complete detection persistence and integration with IncidentCorrelationEngine.
- Single-query snapshot loading (no N+1 per-event queries).
"""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import List
from unittest.mock import patch
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.service import IncidentService
from app.db.models import (
    ActiveDetectionRuleModel,
    DetectionEventModel,
    DetectionModel,
    DetectionRuleDraftModel,
    IncidentDetectionModel,
    IncidentModel,
    RuleValidationRunModel,
)
from app.rules.base import DetectionResult
from app.rules.dynamic_rule import (
    DynamicCustomRule,
    FrozenFilterCondition,
    FrozenFilterGroup,
)
from app.rules.rule_engine import (
    DetectionEngine,
    RuleDET001_BruteForce,
    RuleDET002_CompromiseAfterBurst,
    RuleDET003_PrivilegeEscalation,
    RuleDET004_AnomalousOutbound,
)
from app.schemas.active_rule import ActiveRuleStatus
from app.schemas.ces import CommonEvent, EventAction, EventCategory, EventSeverity
from app.schemas.hunting import FilterField, FilterOperator


def _create_event(
    event_id: str,
    action: str = "network_connect",
    category: str = "network",
    user_identity: str = None,
    source_ip: str = "192.168.1.100",
    destination_ip: str = "10.0.0.5",
    destination_port: int = 4444,
    bytes_sent: int = 100,
    ts: datetime = None,
) -> CommonEvent:
    now = ts or datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc)
    return CommonEvent(
        event_id=event_id,
        timestamp=now,
        category=EventCategory.NETWORK_CONNECTION if category == "network" else EventCategory.AUTHENTICATION,
        action=EventAction.NETWORK_CONNECT if action == "network_connect" else EventAction.LOGON_FAILURE,
        user_identity=user_identity,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        bytes_sent=bytes_sent,
        source_format="syslog",
        raw_payload={"test": True},
    )


async def _seed_active_rule(
    session: AsyncSession,
    rule_code: str = "CUST-001",
    name: str = "Suspicious Outbound Port 4444",
    status: str = "ACTIVE",
    severity: str = "high",
    query_definition: dict = None,
    source_draft_id: str = "draft_cust_1",
) -> ActiveDetectionRuleModel:
    now = datetime.now(timezone.utc)
    # Seed draft and val_run first to satisfy RESTRICT foreign keys
    draft = DetectionRuleDraftModel(
        id=source_draft_id,
        name=name,
        query_definition={},
        status="APPROVED",
        version=2,
        created_by="analyst_alice",
    )
    val = RuleValidationRunModel(
        id=f"val_{source_draft_id}",
        draft_id=source_draft_id,
        draft_version=1,
        query_definition_snapshot={},
        events_scanned=10,
        matches_found=1,
        status="COMPLETED",
    )
    session.add(draft)
    session.add(val)
    await session.flush()

    default_query_def = {
        "filter_group": {
            "logic": "AND",
            "conditions": [
                {"field": "action", "operator": "eq", "value": "network_connect"},
                {"field": "destination_port", "operator": "eq", "value": 4444},
            ],
            "groups": [],
        }
    }

    rule = ActiveDetectionRuleModel(
        id=f"rule_{rule_code.lower().replace('-', '_')}",
        rule_code=rule_code,
        name=name,
        description="Testing dynamic custom rule adapter",
        severity=severity,
        mitre_attack_id="T1041",
        mitre_tactic="exfiltration",
        source_draft_id=draft.id,
        source_draft_version=1,
        validation_run_id=val.id,
        query_definition=query_definition or default_query_def,
        status=status,
        version=1,
        approved_by="lead_bob",
        approved_at=now,
        activated_at=now,
    )
    session.add(rule)
    await session.commit()
    return rule


# ==============================================================================
# Category 1: Immutable Rule Objects & AST Deep-Freezing
# ==============================================================================

def test_dynamic_custom_rule_top_level_mutation_rejected():
    """Verify that DynamicCustomRule is a frozen dataclass rejecting all attribute assignments."""
    fg = FrozenFilterGroup(
        logic="AND",
        conditions=(
            FrozenFilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="network_connect"),
        ),
    )
    rule = DynamicCustomRule(
        active_rule_id="rule_001",
        rule_code="CUST-001",
        name="Outbound Egress",
        severity=EventSeverity.HIGH,
        filter_group=fg,
    )

    with pytest.raises(FrozenInstanceError):
        rule.rule_code = "CUST-999"

    with pytest.raises(FrozenInstanceError):
        rule.name = "Tampered Rule Name"

    with pytest.raises(FrozenInstanceError):
        rule.severity = EventSeverity.LOW


def test_dynamic_custom_rule_nested_ast_mutation_rejected():
    """Verify that nested AST structures, conditions, tuples, and MappingProxyTypes reject mutation."""
    cond = FrozenFilterCondition(
        field=FilterField.USERNAME,
        operator=FilterOperator.IN,
        value=("admin", "root", "operator"),
    )
    fg = FrozenFilterGroup(
        logic="AND",
        conditions=(cond,),
    )
    rule = DynamicCustomRule(
        active_rule_id="rule_001",
        rule_code="CUST-001",
        name="Admin Logins",
        severity=EventSeverity.HIGH,
        filter_group=fg,
        query_definition_snapshot=MappingProxyType({"filter_group": {"logic": "AND"}}),
    )

    # 1. FilterGroup mutation rejected
    with pytest.raises(FrozenInstanceError):
        rule.filter_group.logic = "OR"

    with pytest.raises(FrozenInstanceError):
        rule.filter_group.conditions = ()

    # 2. FilterCondition mutation rejected
    with pytest.raises(FrozenInstanceError):
        rule.filter_group.conditions[0].operator = FilterOperator.NEQ

    # 3. Value tuple mutation rejected
    with pytest.raises(AttributeError):
        rule.filter_group.conditions[0].value.append("guest")

    # 4. Snapshot MappingProxyType mutation rejected
    with pytest.raises(TypeError):
        rule.query_definition_snapshot["tampered"] = True


def test_original_source_ast_changes_do_not_mutate_already_created_rule():
    """Verify that modifying the source dictionary after construction does not alter the rule."""
    source_dict = {
        "filter_group": {
            "logic": "AND",
            "conditions": [
                {"field": "action", "operator": "eq", "value": "network_connect"},
                {"field": "destination_port", "operator": "eq", "value": 4444},
            ],
            "groups": [],
        }
    }
    model = ActiveDetectionRuleModel(
        id="rule_orig_test",
        rule_code="CUST-001",
        name="Original Rule",
        severity="high",
        source_draft_id="d1",
        source_draft_version=1,
        validation_run_id="v1",
        query_definition=source_dict,
        status="ACTIVE",
        approved_by="bob",
        approved_at=datetime.now(timezone.utc),
        activated_at=datetime.now(timezone.utc),
    )

    rule = DynamicCustomRule.from_active_model(model)
    assert rule.filter_group.conditions[1].value == 4444

    # Mutate source dictionary
    source_dict["filter_group"]["conditions"][1]["value"] = 9999
    source_dict["filter_group"]["logic"] = "OR"

    # Rule remains completely unmutated
    assert rule.filter_group.logic == "AND"
    assert rule.filter_group.conditions[1].value == 4444


def test_independent_custom_rules_do_not_share_mutable_structures():
    """Verify that multiple instances created from models have isolated memory structures."""
    source_dict = {
        "filter_group": {
            "logic": "AND",
            "conditions": [{"field": "action", "operator": "eq", "value": "network_connect"}],
            "groups": [],
        }
    }
    model1 = ActiveDetectionRuleModel(
        id="r1", rule_code="CUST-001", name="R1", severity="high", source_draft_id="d1",
        source_draft_version=1, validation_run_id="v1", query_definition=deepcopy(source_dict),
        status="ACTIVE", approved_by="bob", approved_at=datetime.now(timezone.utc), activated_at=datetime.now(timezone.utc),
    )
    model2 = ActiveDetectionRuleModel(
        id="r2", rule_code="CUST-002", name="R2", severity="medium", source_draft_id="d2",
        source_draft_version=1, validation_run_id="v2", query_definition=deepcopy(source_dict),
        status="ACTIVE", approved_by="bob", approved_at=datetime.now(timezone.utc), activated_at=datetime.now(timezone.utc),
    )

    r1 = DynamicCustomRule.from_active_model(model1)
    r2 = DynamicCustomRule.from_active_model(model2)

    assert r1.rule_code != r2.rule_code
    assert r1.filter_group is not r2.filter_group


# ==============================================================================
# Category 2: Detection Behavior & Evidence Persistence
# ==============================================================================

@pytest.mark.asyncio
async def test_active_custom_rule_matches_appropriate_event(db_session: AsyncSession):
    """Verify that an active custom rule matches an appropriate event and produces a DetectionResult."""
    await _seed_active_rule(db_session, rule_code="CUST-001")

    service = IncidentService(db_session)
    matching_event = _create_event("evt_match_1", action="network_connect", destination_port=4444)
    non_matching_event = _create_event("evt_nomatch_1", action="network_connect", destination_port=80)

    engine = await service.get_or_create_detection_engine()
    detections = engine.evaluate_all([matching_event, non_matching_event])

    custom_dets = [d for d in detections if d.rule_id == "CUST-001"]
    assert len(custom_dets) == 1
    det = custom_dets[0]
    assert det.rule_id == "CUST-001"
    assert det.rule_name == "Suspicious Outbound Port 4444"
    assert det.severity == EventSeverity.HIGH
    assert det.triggering_event_ids == ["evt_match_1"]
    assert "4444" in det.summary


@pytest.mark.asyncio
async def test_active_custom_rule_nonmatching_event_does_not_trigger(db_session: AsyncSession):
    """Verify that events not satisfying the AST do not trigger detections."""
    await _seed_active_rule(db_session, rule_code="CUST-001")

    service = IncidentService(db_session)
    non_matching_events = [
        _create_event("evt_nomatch_1", action="network_connect", destination_port=22),
        _create_event("evt_nomatch_2", action="logon_failure", destination_port=4444),
    ]

    engine = await service.get_or_create_detection_engine()
    detections = engine.evaluate_all(non_matching_events)

    custom_dets = [d for d in detections if d.rule_id == "CUST-001"]
    assert len(custom_dets) == 0


@pytest.mark.asyncio
async def test_custom_rule_preserves_severity_and_mitre_metadata(db_session: AsyncSession):
    """Verify that severity and MITRE ATT&CK metadata are preserved in the DetectionResult."""
    await _seed_active_rule(db_session, rule_code="CUST-001", severity="critical")

    service = IncidentService(db_session)
    ev = _create_event("evt_meta_1", action="network_connect", destination_port=4444)

    engine = await service.get_or_create_detection_engine()
    detections = engine.evaluate_all([ev])

    custom_dets = [d for d in detections if d.rule_id == "CUST-001"]
    assert len(custom_dets) == 1
    det = custom_dets[0]
    assert det.severity == EventSeverity.CRITICAL
    assert det.metadata["mitre_attack_id"] == "T1041"
    assert det.metadata["mitre_tactic"] == "exfiltration"
    assert det.metadata["rule_code"] == "CUST-001"
    assert det.metadata["source_draft_version"] == 1


@pytest.mark.asyncio
async def test_custom_detection_evidence_persisted_correctly(db_session: AsyncSession):
    """Verify that process_and_correlate_events persists DetectionModel and DetectionEventModel linkages."""
    await _seed_active_rule(db_session, rule_code="CUST-001")

    service = IncidentService(db_session)
    ev = _create_event("evt_persist_1", action="network_connect", destination_port=4444, user_identity="analyst_user")

    await service.process_and_correlate_events([ev])

    # Verify detection persistence in database
    det_stmt = select(DetectionModel).where(DetectionModel.rule_id == "CUST-001")
    det_res = await db_session.execute(det_stmt)
    det_row = det_res.scalar_one()

    assert det_row.rule_id == "CUST-001"
    assert det_row.rule_name == "Suspicious Outbound Port 4444"
    assert det_row.severity == "high"

    # Verify many-to-many event linkage
    link_stmt = select(DetectionEventModel).where(DetectionEventModel.detection_id == det_row.id)
    links = list((await db_session.execute(link_stmt)).scalars().all())
    assert len(links) == 1
    assert links[0].event_id == "evt_persist_1"


@pytest.mark.asyncio
async def test_multiple_active_rules_execute_in_deterministic_order(db_session: AsyncSession):
    """Verify that multiple custom rules execute deterministically sorted by rule_code after foundational rules."""
    await _seed_active_rule(db_session, rule_code="CUST-003", name="Rule 3", source_draft_id="d3")
    await _seed_active_rule(db_session, rule_code="CUST-001", name="Rule 1", source_draft_id="d1")
    await _seed_active_rule(db_session, rule_code="CUST-002", name="Rule 2", source_draft_id="d2")

    service = IncidentService(db_session)
    engine = await service.get_or_create_detection_engine()

    rule_ids = [r.rule_id for r in engine.rules]
    # Foundational rules are always first, followed by custom rules sorted ascending
    assert rule_ids == ["DET-001", "DET-002", "DET-003", "DET-004", "CUST-001", "CUST-002", "CUST-003"]


@pytest.mark.asyncio
async def test_disabled_rules_are_excluded_from_detection_snapshot(db_session: AsyncSession):
    """Verify that active rules with status DISABLED are excluded from the execution snapshot."""
    await _seed_active_rule(db_session, rule_code="CUST-001", status="DISABLED")

    service = IncidentService(db_session)
    engine = await service.get_or_create_detection_engine()

    rule_ids = [r.rule_id for r in engine.rules]
    assert "CUST-001" not in rule_ids
    assert len(rule_ids) == 4  # Only foundational rules


@pytest.mark.asyncio
async def test_deprecated_rules_are_excluded_from_detection_snapshot(db_session: AsyncSession):
    """Verify that active rules with status DEPRECATED are excluded from the execution snapshot."""
    await _seed_active_rule(db_session, rule_code="CUST-001", status="DEPRECATED")

    service = IncidentService(db_session)
    engine = await service.get_or_create_detection_engine()

    rule_ids = [r.rule_id for r in engine.rules]
    assert "CUST-001" not in rule_ids
    assert len(rule_ids) == 4


# ==============================================================================
# Category 3: Snapshot Isolation & In-Flight Semantics
# ==============================================================================

@pytest.mark.asyncio
async def test_two_concurrent_ingestion_batches_receive_independent_snapshots(db_session: AsyncSession):
    """Verify that independent IncidentService instances construct separate, immutable DetectionEngine snapshots."""
    await _seed_active_rule(db_session, rule_code="CUST-001")

    service_a = IncidentService(db_session)
    service_b = IncidentService(db_session)

    engine_a = await service_a.get_or_create_detection_engine()
    engine_b = await service_b.get_or_create_detection_engine()

    # Distinct engine instances and distinct rule objects
    assert engine_a is not engine_b
    assert [r.rule_id for r in engine_a.rules] == [r.rule_id for r in engine_b.rules]
    assert [type(r) for r in engine_a.rules] == [type(r) for r in engine_b.rules]
    assert engine_a.rules[0] is not engine_b.rules[0]
    assert isinstance(engine_a.rules, tuple)
    assert isinstance(engine_b.rules, tuple)


@pytest.mark.asyncio
async def test_in_flight_batch_snapshot_unaffected_by_concurrent_rule_deactivation(db_session: AsyncSession):
    """
    Verify operational in-flight snapshot semantics:
    An in-flight batch that acquired its snapshot continues using it.
    Subsequent batches see the updated disabled state.
    """
    rule_model = await _seed_active_rule(db_session, rule_code="CUST-001", status="ACTIVE")

    # Batch 1 starts and acquires snapshot containing CUST-001
    service_batch_1 = IncidentService(db_session)
    engine_batch_1 = await service_batch_1.get_or_create_detection_engine()
    assert "CUST-001" in [r.rule_id for r in engine_batch_1.rules]

    # Database rule is deactivated during batch 1's run
    rule_model.status = "DISABLED"
    await db_session.commit()

    # Batch 1 finishes execution using its original frozen snapshot: CUST-001 triggers
    ev = _create_event("evt_inflight_1", action="network_connect", destination_port=4444)
    dets_batch_1 = engine_batch_1.evaluate_all([ev])
    assert any(d.rule_id == "CUST-001" for d in dets_batch_1)

    # Batch 2 starts AFTER deactivation: CUST-001 is excluded from its snapshot
    service_batch_2 = IncidentService(db_session)
    engine_batch_2 = await service_batch_2.get_or_create_detection_engine()
    assert "CUST-001" not in [r.rule_id for r in engine_batch_2.rules]
    dets_batch_2 = engine_batch_2.evaluate_all([ev])
    assert not any(d.rule_id == "CUST-001" for d in dets_batch_2)


def test_foundational_rules_det001_through_det004_remain_first_and_unaltered():
    """Verify that foundational rules DET-001 to DET-004 remain first in the engine and preserve behavior."""
    custom = DynamicCustomRule(
        active_rule_id="r1",
        rule_code="CUST-001",
        name="Custom 1",
        severity=EventSeverity.LOW,
        filter_group=FrozenFilterGroup(logic="AND", conditions=(
            FrozenFilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="test"),
        )),
    )
    engine = DetectionEngine(custom_rules=[custom])

    assert len(engine.rules) == 5
    assert isinstance(engine.rules[0], RuleDET001_BruteForce)
    assert isinstance(engine.rules[1], RuleDET002_CompromiseAfterBurst)
    assert isinstance(engine.rules[2], RuleDET003_PrivilegeEscalation)
    assert isinstance(engine.rules[3], RuleDET004_AnomalousOutbound)
    assert engine.rules[4] is custom


@pytest.mark.asyncio
async def test_ingestion_with_zero_custom_rules_produces_unchanged_foundational_results(db_session: AsyncSession):
    """Verify that ingestion with zero active custom rules yields identical foundational detection behavior."""
    service = IncidentService(db_session)
    now = datetime(2026, 11, 2, 8, 0, 0, tzinfo=timezone.utc)

    # Ingest 5 failed logons for user 'jdoe' to trigger DET-001
    burst_events = [
        CommonEvent(
            event_id=f"evt_burst_{i}",
            timestamp=now + timedelta(seconds=i * 10),
            category=EventCategory.AUTHENTICATION,
            action=EventAction.LOGON_FAILURE,
            user_identity="jdoe",
            source_ip="192.168.1.50",
            source_format="syslog",
            raw_payload={},
        )
        for i in range(5)
    ]

    incidents = await service.process_and_correlate_events(burst_events)
    # DET-001 fires for user:jdoe and ip:192.168.1.50, and both correlate into 1 incident
    assert len(service.latest_detections) == 2
    assert all(d.rule_id == "DET-001" for d in service.latest_detections)
    assert len(incidents) == 1


# ==============================================================================
# Category 4: Robustness, Error Handling & Correlation Integration
# ==============================================================================

@pytest.mark.asyncio
async def test_corrupted_ast_rule_skipped_safely_without_crashing_or_matching(db_session: AsyncSession):
    """Verify that a corrupted AST does not crash engine initialization or execute as a broad match."""
    corrupted_query_def = {
        "filter_group": {
            "logic": "INVALID_LOGIC",
            "conditions": [{"field": "unknown_field", "operator": "eq", "value": "val"}],
            "groups": [],
        }
    }
    await _seed_active_rule(
        db_session,
        rule_code="CUST-CORRUPT",
        query_definition=corrupted_query_def,
        source_draft_id="d_corrupt",
    )

    service = IncidentService(db_session)
    # Building the engine should skip the corrupted rule without throwing
    engine = await service.get_or_create_detection_engine()

    rule_ids = [r.rule_id for r in engine.rules]
    assert "CUST-CORRUPT" not in rule_ids
    assert len(rule_ids) == 4  # Foundational rules preserved


@pytest.mark.asyncio
async def test_corrupted_custom_rule_does_not_suppress_foundational_detections(db_session: AsyncSession):
    """Verify that a corrupted custom rule does not suppress foundational detections from running."""
    corrupted_query_def = {
        "filter_group": {
            "logic": "AND",
            "conditions": [],  # Empty conditions violate FilterGroup constraints
            "groups": [],
        }
    }
    await _seed_active_rule(
        db_session,
        rule_code="CUST-EMPTY",
        query_definition=corrupted_query_def,
        source_draft_id="d_empty",
    )

    service = IncidentService(db_session)
    now = datetime(2026, 11, 2, 8, 0, 0, tzinfo=timezone.utc)
    burst_events = [
        CommonEvent(
            event_id=f"evt_burst_robust_{i}",
            timestamp=now + timedelta(seconds=i * 10),
            category=EventCategory.AUTHENTICATION,
            action=EventAction.LOGON_FAILURE,
            user_identity="jdoe_robust",
            source_ip="192.168.1.51",
            source_format="syslog",
            raw_payload={},
        )
        for i in range(5)
    ]

    incidents = await service.process_and_correlate_events(burst_events)
    # Foundational DET-001 fires despite corrupted custom rule
    assert any(d.rule_id == "DET-001" for d in service.latest_detections)
    assert not any(d.rule_id == "CUST-EMPTY" for d in service.latest_detections)


@pytest.mark.asyncio
async def test_custom_detection_participates_in_incident_correlation(db_session: AsyncSession):
    """Verify that custom rule detections participate in incident correlation."""
    await _seed_active_rule(
        db_session,
        rule_code="CUST-001",
        name="Lateral Network Egress",
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
    )

    service = IncidentService(db_session)
    now = datetime(2026, 11, 2, 10, 0, 0, tzinfo=timezone.utc)

    # Matching event by user 'bad_actor'
    ev = CommonEvent(
        event_id="evt_corr_custom",
        timestamp=now,
        category=EventCategory.NETWORK_CONNECTION,
        action=EventAction.NETWORK_CONNECT,
        user_identity="bad_actor",
        source_ip="192.168.1.99",
        destination_ip="10.0.0.99",
        destination_port=4444,
        source_format="syslog",
        raw_payload={},
    )

    incidents = await service.process_and_correlate_events([ev])
    assert len(incidents) == 1
    inc = incidents[0]

    # Verify incident contains the custom detection
    inc_det_stmt = select(IncidentDetectionModel).where(IncidentDetectionModel.incident_id == inc.id)
    inc_dets = list((await db_session.execute(inc_det_stmt)).scalars().all())
    assert len(inc_dets) == 1


@pytest.mark.asyncio
async def test_rule_snapshots_loaded_once_per_batch_no_n_plus_1(db_session: AsyncSession):
    """Verify that active rules are loaded exactly once per ingestion batch, not per event."""
    await _seed_active_rule(db_session, rule_code="CUST-001")

    service = IncidentService(db_session)
    events = [
        _create_event(f"evt_batch_n1_{i}", destination_port=4444 if i % 2 == 0 else 80)
        for i in range(20)
    ]

    with patch.object(
        service.active_rule_repo,
        "get_all_active_for_detection",
        wraps=service.active_rule_repo.get_all_active_for_detection,
    ) as mock_get_active:
        await service.process_and_correlate_events(events)
        # Must be called exactly ONCE for the entire batch of 20 events
        assert mock_get_active.call_count == 1


@pytest.mark.asyncio
async def test_multiple_events_matching_same_custom_rule(db_session: AsyncSession):
    """Verify that multiple events matching the same custom rule all generate linked detections."""
    await _seed_active_rule(db_session, rule_code="CUST-001")
    service = IncidentService(db_session)

    events = [
        _create_event(f"evt_multi_match_{i}", destination_port=4444, user_identity=f"user_{i}")
        for i in range(4)
    ]
    incidents = await service.process_and_correlate_events(events)
    assert len(service.latest_detections) == 4
    assert all(d.rule_id == "CUST-001" for d in service.latest_detections)
    assert len(incidents) >= 1


@pytest.mark.asyncio
async def test_multiple_rules_matching_same_event(db_session: AsyncSession):
    """Verify that when multiple active custom rules match the same event, both detections are generated."""
    # Rule 1: Matches destination_port == 4444
    await _seed_active_rule(db_session, rule_code="CUST-001", source_draft_id="draft_c2_1")

    # Rule 2: Matches action == "network_connect"
    await _seed_active_rule(
        db_session,
        rule_code="CUST-002",
        source_draft_id="draft_c2_2",
        query_definition={
            "filter_group": {
                "logic": "AND",
                "conditions": [
                    {"field": "action", "operator": "eq", "value": "network_connect"}
                ],
                "groups": [],
            }
        },
    )

    service = IncidentService(db_session)
    ev = _create_event("evt_dual_match_1", destination_port=4444)

    incidents = await service.process_and_correlate_events([ev])
    matched_rule_codes = {d.rule_id for d in service.latest_detections}
    assert "CUST-001" in matched_rule_codes
    assert "CUST-002" in matched_rule_codes
    assert len(incidents) >= 1


@pytest.mark.asyncio
async def test_replayed_identical_telemetry_idempotency(db_session: AsyncSession):
    """Verify that replaying identical telemetry preserves idempotency without duplicate corruption."""
    await _seed_active_rule(db_session, rule_code="CUST-001")
    service = IncidentService(db_session)

    events = [
        _create_event("evt_replay_1", destination_port=4444),
        _create_event("evt_replay_2", destination_port=4444),
    ]

    # First run
    incs_run1 = await service.process_and_correlate_events(events, source_file_hash="hash_replay_test")
    assert len(service.latest_detections) == 2

    # Second run (replayed identical telemetry)
    service2 = IncidentService(db_session)
    incs_run2 = await service2.process_and_correlate_events(events, source_file_hash="hash_replay_test")
    # Events are deduplicated or updated via upsert_events; system executes deterministically
    assert len(service2.latest_detections) == 2
