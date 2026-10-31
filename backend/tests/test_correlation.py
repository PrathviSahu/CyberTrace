"""
Unit and integration tests for CyberTrace Incident Correlation Engine and Safeguards.
Verifies deterministic clustering, public IP safeguards, temporal boundaries, and evidence integrity.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.correlation.engine import IncidentCorrelationEngine
from app.correlation.models import CorrelationConfig, CorrelationStrength
from app.correlation.safeguards import evaluate_detection_pair, is_disallowed_merge_entity
from app.correlation.service import IncidentService
from app.parsers.json_parser import GenericJsonParser
from app.rules.base import DetectionResult
from app.schemas.ces import CommonEvent, EventAction, EventCategory, EventSeverity


SAMPLE_DIR = Path(__file__).resolve().parent.parent / "app" / "data" / "sample_logs"


def create_mock_event(event_id: str, ts: datetime, user: str = None, host: str = None, src_ip: str = None, dst_ip: str = None, bytes_sent: int = 0) -> CommonEvent:
    return CommonEvent(
        event_id=event_id,
        timestamp=ts,
        category=EventCategory.AUTHENTICATION if user else EventCategory.NETWORK_CONNECTION,
        action=EventAction.LOGON_FAILURE if user else EventAction.NETWORK_CONNECT,
        user_identity=user,
        hostname=host,
        source_ip=src_ip,
        destination_ip=dst_ip,
        bytes_sent=bytes_sent,
        source_format="test",
    )


def test_related_detections_same_user():
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    ev1 = create_mock_event("evt_1", now, user="svc_deploy", src_ip="198.51.100.44")
    ev2 = create_mock_event("evt_2", now + timedelta(minutes=5), user="svc_deploy", src_ip="198.51.100.44")

    d1 = DetectionResult(
        detection_id="det_1",
        rule_id="DET-001",
        rule_name="Brute Force",
        severity=EventSeverity.MEDIUM,
        summary="Burst on svc_deploy",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_1"],
    )
    d2 = DetectionResult(
        detection_id="det_2",
        rule_id="DET-002",
        rule_name="Logon After Burst",
        severity=EventSeverity.HIGH,
        summary="Compromise of svc_deploy",
        detection_timestamp=now + timedelta(minutes=5),
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_2"],
    )

    engine = IncidentCorrelationEngine()
    incidents = engine.correlate([d1, d2], [ev1, ev2])

    assert len(incidents) == 1
    inc = incidents[0]
    assert set(inc.detection_ids) == {"det_1", "det_2"}
    assert inc.severity == EventSeverity.HIGH
    assert any(e.entity_value == "svc_deploy" for e in inc.entities)


def test_related_privilege_and_host_activity():
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    ev_priv = create_mock_event("evt_priv", now, user="svc_deploy", host="SRV-APP-01")
    ev_exfil = create_mock_event("evt_exfil", now + timedelta(minutes=10), host="SRV-APP-01", src_ip="192.168.1.105", dst_ip="203.0.113.88", bytes_sent=60000000)

    d_priv = DetectionResult(
        detection_id="det_priv",
        rule_id="DET-003",
        rule_name="Privilege Escalation",
        severity=EventSeverity.HIGH,
        summary="Sudo bash on SRV-APP-01",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_priv"],
    )
    d_exfil = DetectionResult(
        detection_id="det_exfil",
        rule_id="DET-004",
        rule_name="Exfiltration",
        severity=EventSeverity.HIGH,
        summary="Outbound egress from SRV-APP-01",
        detection_timestamp=now + timedelta(minutes=10),
        entity_key="ip:203.0.113.88",
        triggering_event_ids=["evt_exfil"],
    )

    engine = IncidentCorrelationEngine()
    incidents = engine.correlate([d_priv, d_exfil], [ev_priv, ev_exfil])

    assert len(incidents) == 1
    assert incidents[0].severity == EventSeverity.CRITICAL


def test_unrelated_events_with_different_entities_stay_separate():
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    ev_alice = create_mock_event("evt_a", now, user="alice", host="WKSTN-ALICE")
    ev_bob = create_mock_event("evt_b", now, user="bob", host="WKSTN-BOB")

    d_alice = DetectionResult(
        detection_id="det_alice",
        rule_id="DET-001",
        rule_name="Brute Force",
        severity=EventSeverity.MEDIUM,
        summary="Failed logins on alice",
        detection_timestamp=now,
        entity_key="user:alice",
        triggering_event_ids=["evt_a"],
    )
    d_bob = DetectionResult(
        detection_id="det_bob",
        rule_id="DET-001",
        rule_name="Brute Force",
        severity=EventSeverity.MEDIUM,
        summary="Failed logins on bob",
        detection_timestamp=now,
        entity_key="user:bob",
        triggering_event_ids=["evt_b"],
    )

    engine = IncidentCorrelationEngine()
    incidents = engine.correlate([d_alice, d_bob], [ev_alice, ev_bob])

    # Must NOT merge into 1 incident; must create 2 distinct incidents
    assert len(incidents) == 2
    assert set(incidents[0].detection_ids).isdisjoint(set(incidents[1].detection_ids))


def test_shared_public_ip_safeguard():
    """Verify that sharing only a public IP or DNS resolver does NOT merge incidents."""
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    ev_1 = create_mock_event("evt_pub_1", now, src_ip="8.8.8.8")
    ev_2 = create_mock_event("evt_pub_2", now, src_ip="8.8.8.8")

    d1 = DetectionResult(
        detection_id="det_pub_1",
        rule_id="DET-001",
        rule_name="Rule 1",
        severity=EventSeverity.MEDIUM,
        summary="Activity from 8.8.8.8",
        detection_timestamp=now,
        entity_key="ip:8.8.8.8",
        triggering_event_ids=["evt_pub_1"],
    )
    d2 = DetectionResult(
        detection_id="det_pub_2",
        rule_id="DET-001",
        rule_name="Rule 1",
        severity=EventSeverity.MEDIUM,
        summary="Different activity from 8.8.8.8",
        detection_timestamp=now,
        entity_key="ip:8.8.8.8",
        triggering_event_ids=["evt_pub_2"],
    )

    config = CorrelationConfig()
    rel = evaluate_detection_pair(d1, d2, {"evt_pub_1": ev_1, "evt_pub_2": ev_2}, config)
    assert rel is None  # Safeguard rejected the merge


def test_temporal_threshold_safeguard():
    """Verify that detections exceeding max_time_delta_seconds are not merged."""
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    later = now + timedelta(hours=3)  # 3 hours later > 1 hour limit

    ev1 = create_mock_event("evt_t1", now, user="svc_deploy")
    ev2 = create_mock_event("evt_t2", later, user="svc_deploy")

    d1 = DetectionResult(
        detection_id="det_t1",
        rule_id="DET-001",
        rule_name="Burst 1",
        severity=EventSeverity.MEDIUM,
        summary="Morning burst",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_t1"],
    )
    d2 = DetectionResult(
        detection_id="det_t2",
        rule_id="DET-001",
        rule_name="Burst 2",
        severity=EventSeverity.MEDIUM,
        summary="Afternoon burst",
        detection_timestamp=later,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_t2"],
    )

    engine = IncidentCorrelationEngine(CorrelationConfig(max_time_delta_seconds=3600))
    incidents = engine.correlate([d1, d2], [ev1, ev2])

    assert len(incidents) == 2


def test_deterministic_correlation_keys():
    """Verify identical inputs yield identical correlation keys and incident IDs."""
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    ev = create_mock_event("evt_det", now, user="svc_deploy")
    det = DetectionResult(
        detection_id="det_det",
        rule_id="DET-001",
        rule_name="Burst",
        severity=EventSeverity.MEDIUM,
        summary="Burst",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_det"],
    )

    engine = IncidentCorrelationEngine()
    incidents_run1 = engine.correlate([det], [ev])
    incidents_run2 = engine.correlate([det], [ev])

    assert incidents_run1[0].correlation_key == incidents_run2[0].correlation_key
    assert incidents_run1[0].incident_id == incidents_run2[0].incident_id


def test_shared_service_account_safeguard():
    """Verify that generic service accounts like 'anonymous' or disallowed accounts alone do not bridge incidents."""
    config = CorrelationConfig(disallowed_merge_entities=["user:anonymous", "user:guest"])
    assert is_disallowed_merge_entity("user:anonymous", config) is True
    assert is_disallowed_merge_entity("user:guest", config) is True
    assert is_disallowed_merge_entity("user:svc_deploy", config) is False


def test_two_independent_users_same_host_stay_separate():
    """
    CRITICAL REGRESSION TEST:
    Two independent users (alice and bob) exhibiting suspicious activity on the same server (SERVER-01)
    MUST NOT be merged into a single incident through host-based transitive bridging.
    """
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    ev_alice_1 = create_mock_event("evt_a1", now, user="alice", host="SERVER-01", src_ip="198.51.100.10")
    ev_alice_2 = create_mock_event("evt_a2", now + timedelta(minutes=2), user="alice", host="SERVER-01", src_ip="198.51.100.10")

    ev_bob_1 = create_mock_event("evt_b1", now + timedelta(minutes=1), user="bob", host="SERVER-01", src_ip="198.51.100.20")
    ev_bob_2 = create_mock_event("evt_b2", now + timedelta(minutes=3), user="bob", host="SERVER-01", src_ip="198.51.100.20")

    d_alice_1 = DetectionResult(
        detection_id="det_a1",
        rule_id="DET-001",
        rule_name="Brute Force",
        severity=EventSeverity.MEDIUM,
        summary="Brute force on alice",
        detection_timestamp=now,
        entity_key="user:alice",
        triggering_event_ids=["evt_a1"],
    )
    d_alice_2 = DetectionResult(
        detection_id="det_a2",
        rule_id="DET-002",
        rule_name="Compromise",
        severity=EventSeverity.HIGH,
        summary="Logon for alice",
        detection_timestamp=now + timedelta(minutes=2),
        entity_key="user:alice",
        triggering_event_ids=["evt_a2"],
    )

    d_bob_1 = DetectionResult(
        detection_id="det_b1",
        rule_id="DET-001",
        rule_name="Brute Force",
        severity=EventSeverity.MEDIUM,
        summary="Brute force on bob",
        detection_timestamp=now + timedelta(minutes=1),
        entity_key="user:bob",
        triggering_event_ids=["evt_b1"],
    )
    d_bob_2 = DetectionResult(
        detection_id="det_b2",
        rule_id="DET-002",
        rule_name="Compromise",
        severity=EventSeverity.HIGH,
        summary="Logon for bob",
        detection_timestamp=now + timedelta(minutes=3),
        entity_key="user:bob",
        triggering_event_ids=["evt_b2"],
    )

    events = [ev_alice_1, ev_alice_2, ev_bob_1, ev_bob_2]
    detections = [d_alice_1, d_alice_2, d_bob_1, d_bob_2]

    engine = IncidentCorrelationEngine()
    incidents = engine.correlate(detections, events)

    # Must produce exactly TWO distinct incidents (one for alice, one for bob)
    assert len(incidents) == 2
    users_in_incidents = []
    for inc in incidents:
        u_vals = {e.entity_value for e in inc.entities if e.entity_type == "user"}
        users_in_incidents.append(u_vals)

    # Ensure no incident mixes alice and bob
    assert {"alice"} in users_in_incidents
    assert {"bob"} in users_in_incidents


def test_span_partitioning_cluster_within_max_span():
    """Cluster within max span forms exactly 1 incident."""
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    ev1 = create_mock_event("evt_w1", now, user="svc_deploy")
    ev2 = create_mock_event("evt_w2", now + timedelta(minutes=45), user="svc_deploy")

    d1 = DetectionResult(
        detection_id="det_w1",
        rule_id="DET-001",
        rule_name="Burst",
        severity=EventSeverity.MEDIUM,
        summary="Morning 1",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_w1"],
    )
    d2 = DetectionResult(
        detection_id="det_w2",
        rule_id="DET-001",
        rule_name="Burst",
        severity=EventSeverity.MEDIUM,
        summary="Morning 2",
        detection_timestamp=now + timedelta(minutes=45),
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_w2"],
    )

    engine = IncidentCorrelationEngine(CorrelationConfig(max_incident_span_seconds=3600))
    incidents = engine.correlate([d1, d2], [ev1, ev2])
    assert len(incidents) == 1
    assert set(incidents[0].detection_ids) == {"det_w1", "det_w2"}


def test_span_partitioning_cluster_exceeding_max_span():
    """Oversized clusters exceeding max span are partitioned chronologically instead of dropped."""
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    # 3 detections on Day 1, Day 2, Day 3
    ev1 = create_mock_event("evt_p1", now, user="svc_deploy")
    ev2 = create_mock_event("evt_p2", now + timedelta(hours=25), user="svc_deploy")
    ev3 = create_mock_event("evt_p3", now + timedelta(hours=50), user="svc_deploy")

    d1 = DetectionResult(
        detection_id="det_p1",
        rule_id="DET-001",
        rule_name="Burst",
        severity=EventSeverity.MEDIUM,
        summary="Day 1",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_p1"],
    )
    d2 = DetectionResult(
        detection_id="det_p2",
        rule_id="DET-001",
        rule_name="Burst",
        severity=EventSeverity.MEDIUM,
        summary="Day 2",
        detection_timestamp=now + timedelta(hours=25),
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_p2"],
    )
    d3 = DetectionResult(
        detection_id="det_p3",
        rule_id="DET-001",
        rule_name="Burst",
        severity=EventSeverity.MEDIUM,
        summary="Day 3",
        detection_timestamp=now + timedelta(hours=50),
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_p3"],
    )

    # Max span 24 hours (86400s)
    engine = IncidentCorrelationEngine(CorrelationConfig(max_incident_span_seconds=86400, max_time_delta_seconds=100000))
    incidents = engine.correlate([d1, d2, d3], [ev1, ev2, ev3])

    # Must NOT drop any detections! Must partition into 3 consecutive incidents
    assert len(incidents) == 3
    assert incidents[0].detection_ids == ["det_p1"]
    assert incidents[1].detection_ids == ["det_p2"]
    assert incidents[2].detection_ids == ["det_p3"]


def test_detections_exactly_at_span_boundary():
    """Detections occurring exactly at max_incident_span_seconds boundary remain in the same partition."""
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    exact_boundary = now + timedelta(seconds=3600)  # Exactly 1 hour

    ev1 = create_mock_event("evt_b1", now, user="svc_deploy")
    ev2 = create_mock_event("evt_b2", exact_boundary, user="svc_deploy")

    d1 = DetectionResult(
        detection_id="det_b1",
        rule_id="DET-001",
        rule_name="Burst",
        severity=EventSeverity.MEDIUM,
        summary="Start",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_b1"],
    )
    d2 = DetectionResult(
        detection_id="det_b2",
        rule_id="DET-001",
        rule_name="Burst",
        severity=EventSeverity.MEDIUM,
        summary="Boundary",
        detection_timestamp=exact_boundary,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_b2"],
    )

    engine = IncidentCorrelationEngine(CorrelationConfig(max_incident_span_seconds=3600, max_time_delta_seconds=3600))
    incidents = engine.correlate([d1, d2], [ev1, ev2])

    assert len(incidents) == 1
    assert set(incidents[0].detection_ids) == {"det_b1", "det_b2"}


def test_reprocessing_same_dataset_is_idempotent_and_deterministic():
    """Reprocessing the exact same dataset produces the same incident groups and keys."""
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    ev = create_mock_event("evt_rep", now, user="svc_deploy")
    d = DetectionResult(
        detection_id="det_rep",
        rule_id="DET-001",
        rule_name="Burst",
        severity=EventSeverity.MEDIUM,
        summary="Repeat",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_rep"],
    )

    engine = IncidentCorrelationEngine()
    run1 = engine.correlate([d], [ev])
    run2 = engine.correlate([d], [ev])

    assert len(run1) == len(run2) == 1
    assert run1[0].correlation_key == run2[0].correlation_key
    assert run1[0].incident_id == run2[0].incident_id


@pytest.mark.asyncio
async def test_end_to_end_synthetic_benchmark_correlation(db_session: AsyncSession):
    """
    End-to-end integration test:
    Ingests the enterprise synthetic attack and benign datasets, verifies that the 4-stage attack
    is correlated into exactly ONE multi-stage incident with full evidence provenance,
    while benign logs generate ZERO incidents.
    """
    with open(SAMPLE_DIR / "enterprise_combined_logs.json", "r", encoding="utf-8") as f:
        content = f.read()

    parser = GenericJsonParser()
    events = parser.parse(content)
    assert len(events) == 15

    service = IncidentService(db_session)
    incidents = await service.process_and_correlate_events(events)

    # Exactly 1 incident created for the multi-stage attack
    assert len(incidents) == 1
    incident = incidents[0]

    assert incident.severity == "critical"
    assert "Multi-Stage" in incident.title or "Exfiltration" in incident.title

    # Retrieve full dossier
    dossier = await service.get_incident_dossier(incident.id)
    assert dossier is not None
    distinct_rules = {d.rule_id for d in dossier["detections"]}
    assert distinct_rules == {"DET-001", "DET-002", "DET-003", "DET-004"}
    assert len(dossier["events"]) >= 9      # All 9 attack events captured

    # Verify key entities attributed
    entity_values = {e.entity_value for e in dossier["entities"]}
    assert "svc_deploy" in entity_values
    assert "SRV-APP-01" in entity_values
    assert "203.0.113.88" in entity_values
    assert "198.51.100.44" in entity_values
