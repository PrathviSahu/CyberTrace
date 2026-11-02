"""
Unit and integration tests for CyberTrace ThreatLab Benchmark & Incident Graph APIs.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import app
from app.db.repositories.event_repo import EventRepository
from app.db.repositories.incident_repo import IncidentRepository
from app.schemas.ces import CommonEvent
from app.threatlab.service import ThreatLabService


@pytest.mark.asyncio
async def test_threatlab_list_scenarios():
    service = ThreatLabService()
    scenarios = service.get_scenarios()
    assert len(scenarios) == 4
    scenario_ids = [s.scenario_id for s in scenarios]
    assert "SCN-001" in scenario_ids
    assert "SCN-002" in scenario_ids
    assert "SCN-003" in scenario_ids
    assert "SCN-004" in scenario_ids


@pytest.mark.asyncio
async def test_threatlab_replay_multi_stage_attack():
    service = ThreatLabService()
    result = service.replay_scenario("SCN-001")
    assert result.scenario_id == "SCN-001"
    assert result.status == "success"
    assert result.events_processed == 9
    assert result.detections_fired_count >= 4

    cm = result.confusion_matrix
    assert cm.true_positives == 4
    assert cm.false_positives == 0
    assert cm.false_negatives == 0
    assert cm.precision == 1.0
    assert cm.recall == 1.0
    assert cm.f1_score == 1.0

    rules_fired = {d.rule_id for d in result.detections}
    assert rules_fired == {"DET-001", "DET-002", "DET-003", "DET-004"}


@pytest.mark.asyncio
async def test_threatlab_replay_privilege_escalation():
    service = ThreatLabService()
    result = service.replay_scenario("SCN-002")
    assert result.scenario_id == "SCN-002"
    assert result.detections_fired_count >= 1
    assert any(d.rule_id == "DET-003" for d in result.detections)
    assert result.confusion_matrix.f1_score == 1.0


@pytest.mark.asyncio
async def test_threatlab_replay_shared_host_isolation():
    service = ThreatLabService()
    result = service.replay_scenario("SCN-003")
    assert result.scenario_id == "SCN-003"
    assert result.detections_fired_count >= 1
    assert any(d.rule_id == "DET-001" and "alice" in d.entity_value for d in result.detections)
    assert not any("bob" in d.entity_value for d in result.detections)
    assert result.confusion_matrix.precision == 1.0
    assert result.confusion_matrix.recall == 1.0


@pytest.mark.asyncio
async def test_threatlab_replay_benign_baseline():
    service = ThreatLabService()
    result = service.replay_scenario("SCN-004")
    assert result.scenario_id == "SCN-004"
    assert result.detections_fired_count == 0
    assert result.confusion_matrix.true_positives == 0
    assert result.confusion_matrix.false_positives == 0
    assert result.confusion_matrix.true_negatives == 20
    assert result.confusion_matrix.precision == 1.0
    assert result.confusion_matrix.recall == 1.0


@pytest.mark.asyncio
async def test_threatlab_replay_invalid_scenario_raises_error():
    service = ThreatLabService()
    with pytest.raises(ValueError, match="Scenario 'SCN-999' not found"):
        service.replay_scenario("SCN-999")


@pytest.mark.asyncio
async def test_threatlab_replay_in_memory_isolation(db_session: AsyncSession):
    repo = EventRepository(db_session)
    events_before, count_before = await repo.list_events(limit=100)

    service = ThreatLabService()
    service.replay_scenario("SCN-001")
    service.replay_scenario("SCN-002")

    events_after, count_after = await repo.list_events(limit=100)
    assert count_before == count_after, "ThreatLab replay must never mutate the persistent database"


@pytest.mark.asyncio
async def test_api_threatlab_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. List scenarios
        res = await client.get("/api/v1/threatlab/scenarios")
        assert res.status_code == 200
        scenarios = res.json()
        assert len(scenarios) == 4

        # 2. Replay valid scenario
        replay_res = await client.post("/api/v1/threatlab/replay/SCN-001")
        assert replay_res.status_code == 200
        data = replay_res.json()
        assert data["scenario_id"] == "SCN-001"
        assert data["confusion_matrix"]["f1_score"] == 1.0

        # 3. Replay invalid scenario
        invalid_res = await client.post("/api/v1/threatlab/replay/SCN-INVALID")
        assert invalid_res.status_code == 404


@pytest.mark.asyncio
async def test_api_incident_graph_endpoint():
    from pathlib import Path

    sample_path = Path(__file__).resolve().parent.parent / "app" / "data" / "sample_logs" / "multi_stage_attack.json"
    with open(sample_path, "rb") as f:
        attack_bytes = f.read()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Seed via upload endpoint
        files = {"file": ("graph_test_attack.json", attack_bytes, "application/json")}
        upload_res = await client.post("/api/v1/logs/upload", files=files)
        assert upload_res.status_code == 200

        # Retrieve incident ID
        inc_res = await client.get("/api/v1/incidents")
        assert inc_res.status_code == 200
        incidents = inc_res.json()
        assert len(incidents) > 0
        inc_id = incidents[0]["id"]

        # Fetch incident graph
        res = await client.get(f"/api/v1/incidents/{inc_id}/graph")
        assert res.status_code == 200
        data = res.json()
        assert "nodes" in data
        assert "edges" in data
        assert data["incident_id"] == inc_id

        # Verify nodes contain incident and entities
        node_types = {n["type"] for n in data["nodes"]}
        assert "incident" in node_types
        assert "user" in node_types or "host" in node_types or "ip" in node_types

        # Verify 404 for unknown incident
        not_found = await client.get("/api/v1/incidents/INC-NONEXISTENT/graph")
        assert not_found.status_code == 404
