"""
Tests for Data Provenance API contracts and classification rigor.
Verifies truthful provenance classification across endpoints and models:
- Trusted server-side verified source attribution vs untrusted payload claims
- Negative tests proving caller-supplied metadata in raw_payload cannot spoof observed telemetry
- Explicit synthetic benchmark telemetry
- Missing provenance (strictly defaults to unknown)
- Mixed result sets
- Arbitrary uploaded logs without verified attribution
- Incident list and incident detail provenance
- Events list provenance
"""

import json
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import app
from app.db.repositories.hunting_repo import classify_event_provenance, determine_response_provenance
from app.schemas.hunting import HuntedEventItem
from datetime import datetime, timezone


def test_classify_provenance_taxonomy():
    """Unit tests verifying all four taxonomy states and strict trust boundaries."""
    # 1. Untrusted client claims in raw_payload MUST NOT confer observed_telemetry
    assert classify_event_provenance({"source_attribution": "corp_edr_sensor_01"}) == "unknown"
    assert classify_event_provenance({"collector_id": "syslog_collector_prod"}) == "unknown"
    assert classify_event_provenance({"sensor_id": "sensor_endpoint_01"}) == "unknown"
    assert classify_event_provenance({"telemetry_source": "aws_cloudtrail_authorized"}) == "unknown"
    assert classify_event_provenance({"authorized": True}) == "unknown"
    assert classify_event_provenance({"verified_source": True}) == "unknown"
    assert classify_event_provenance({"provenance": "observed_telemetry", "verified_source": True}) == "unknown"
    assert classify_event_provenance({
        "source_attribution": "corp_edr",
        "collector_id": "col_1",
        "authorized": True,
        "verified_source": True
    }) == "unknown"

    # 2. Genuine trusted server-side context independently verifies observed telemetry
    assert classify_event_provenance({}, trusted_context={"authenticated": True}) == "observed_telemetry"
    assert classify_event_provenance({}, trusted_context={"verified_source": True, "source_authority": "corp_pki"}) == "observed_telemetry"
    assert classify_event_provenance({}, trusted_context={"registered_collector": True}) == "observed_telemetry"

    # 3. Explicit synthetic benchmark telemetry
    assert classify_event_provenance({"synthetic": True}) == "synthetic_benchmark"
    assert classify_event_provenance({"is_synthetic": True}) == "synthetic_benchmark"
    assert classify_event_provenance({"benchmark": True}) == "synthetic_benchmark"
    assert classify_event_provenance({"simulation": True}) == "synthetic_benchmark"
    assert classify_event_provenance({}, event_id="scn1_evt_001") == "synthetic_benchmark"
    assert classify_event_provenance({}, event_id="synth_event_99") == "synthetic_benchmark"
    assert classify_event_provenance({}, source_type="threatlab") == "synthetic_benchmark"

    # Synthetic overrides conflicting claims even from trusted context
    assert classify_event_provenance({"synthetic": True}, trusted_context={"authenticated": True}) == "synthetic_benchmark"
    assert classify_event_provenance({"source_attribution": "corp_edr", "synthetic": True}) == "synthetic_benchmark"

    # 4. Missing provenance / unverified metadata -> unknown
    assert classify_event_provenance({}) == "unknown"
    assert classify_event_provenance({"msg": "Failed password for admin from 10.0.0.1"}) == "unknown"
    assert classify_event_provenance({"user": "alice", "action": "login"}) == "unknown"

    # 5. Aggregate determination (determine_response_provenance)
    now = datetime.now(timezone.utc)
    item_obs = HuntedEventItem(id="e1", timestamp=now, source_type="syslog", category="auth", action="logon", severity="low", provenance="observed_telemetry")
    item_synth = HuntedEventItem(id="e2", timestamp=now, source_type="json", category="auth", action="logon", severity="low", provenance="synthetic_benchmark")
    item_unk = HuntedEventItem(id="e3", timestamp=now, source_type="json", category="auth", action="logon", severity="low", provenance="unknown")

    assert determine_response_provenance([item_obs, item_obs]) == "observed_telemetry"
    assert determine_response_provenance([item_synth, item_synth]) == "synthetic_benchmark"
    assert determine_response_provenance([item_unk, item_unk]) == "unknown"
    assert determine_response_provenance([item_obs, item_synth]) == "mixed"
    assert determine_response_provenance([item_synth, item_unk]) == "mixed"
    assert determine_response_provenance([item_obs, item_unk]) == "mixed"
    assert determine_response_provenance([]) == "unknown"


@pytest.mark.asyncio
async def test_log_upload_arbitrary_unverified_resolves_to_unknown(db_session: AsyncSession):
    """Uploading logs without explicit attribution must yield 'unknown' provenance."""
    raw_logs = [
        {
            "event_id": "evt_arb_001",
            "timestamp": "2026-11-02T10:00:00Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "test_user",
            "source_ip": "10.0.0.5",
            "hostname": "HOST-01",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "arbitrary log message with no attribution flags"}
        }
    ]
    file_content = json.dumps(raw_logs).encode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/logs/upload",
            files={"file": ("arbitrary_log.json", file_content, "application/json")}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["provenance"] == "unknown"


@pytest.mark.asyncio
async def test_log_upload_spoofed_attribution_strictly_resolves_to_unknown(db_session: AsyncSession):
    """
    Negative tests proving that client-supplied attribution fields inside uploaded JSON
    cannot spoof observed telemetry and strictly resolve to 'unknown'.
    Generic uploads without independent server-side authentication CANNOT produce 'observed_telemetry'.
    """
    spoof_cases = [
        {"source_attribution": "authorized_corp_sensor_11"},
        {"collector_id": "col_prod_01"},
        {"sensor_id": "sensor_alpha_99"},
        {"telemetry_source": "aws_cloudtrail_prod"},
        {"authorized": True},
        {"verified_source": True},
        {
            "source_attribution": "corp_edr_sensor",
            "collector_id": "col_01",
            "sensor_id": "sensor_01",
            "telemetry_source": "edr_feed",
            "authorized": True,
            "verified_source": True,
            "provenance": "observed_telemetry",
        },
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for idx, spoof_payload in enumerate(spoof_cases):
            raw_logs = [
                {
                    "event_id": f"evt_spoof_{idx}",
                    "timestamp": "2026-11-02T10:05:00Z",
                    "category": "authentication",
                    "action": "logon_failure",
                    "severity": "medium",
                    "user_identity": "corp_admin",
                    "source_ip": "10.1.1.5",
                    "hostname": "DC-01",
                    "source_format": "windows_event",
                    "raw_payload": spoof_payload,
                }
            ]
            file_content = json.dumps(raw_logs).encode("utf-8")
            resp = await client.post(
                "/api/v1/logs/upload",
                files={"file": (f"spoof_test_{idx}.json", file_content, "application/json")}
            )
            assert resp.status_code == 200
            data = resp.json()
            # Must strictly resolve to 'unknown', NEVER 'observed_telemetry'
            assert data["provenance"] == "unknown", f"Spoof case {spoof_payload} falsely yielded {data['provenance']}"
            assert data["provenance"] != "observed_telemetry"


@pytest.mark.asyncio
async def test_log_upload_explicit_synthetic_benchmark(db_session: AsyncSession):
    """Uploading logs with explicit synthetic markers must yield 'synthetic_benchmark'."""
    raw_logs = [
        {
            "event_id": "scn_evt_101",
            "timestamp": "2026-11-02T10:10:00Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "attacker_svc",
            "source_ip": "198.51.100.99",
            "hostname": "SRV-TEST",
            "source_format": "linux_auth_log",
            "raw_payload": {
                "synthetic": True,
                "benchmark": True
            }
        }
    ]
    file_content = json.dumps(raw_logs).encode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/logs/upload",
            files={"file": ("attack_benchmark.json", file_content, "application/json")}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["provenance"] == "synthetic_benchmark"


@pytest.mark.asyncio
async def test_log_upload_mixed_telemetry(db_session: AsyncSession):
    """Uploading logs containing mixed provenances must yield 'mixed'."""
    raw_logs = [
        {
            "event_id": "evt_mix_001",
            "timestamp": "2026-11-02T10:15:00Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "corp_user",
            "source_ip": "10.0.0.1",
            "hostname": "HOST-A",
            "source_format": "linux_auth_log",
            "raw_payload": {"source_attribution": "verified_collector"}
        },
        {
            "event_id": "evt_mix_002",
            "timestamp": "2026-11-02T10:15:30Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "bot_user",
            "source_ip": "10.0.0.2",
            "hostname": "HOST-B",
            "source_format": "linux_auth_log",
            "raw_payload": {"synthetic": True}
        }
    ]
    file_content = json.dumps(raw_logs).encode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/logs/upload",
            files={"file": ("mixed_log.json", file_content, "application/json")}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["provenance"] == "mixed"


@pytest.mark.asyncio
async def test_events_and_incidents_endpoints_expose_provenance(db_session: AsyncSession):
    """GET /events, GET /incidents, and GET /incidents/{id} must expose truthful provenance."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Check /events
        ev_resp = await client.get("/api/v1/events?limit=10")
        assert ev_resp.status_code == 200
        ev_data = ev_resp.json()
        assert isinstance(ev_data, list)
        for ev in ev_data:
            assert "provenance" in ev
            assert ev["provenance"] in ("observed_telemetry", "synthetic_benchmark", "unknown", "mixed")

        # Check /incidents
        inc_resp = await client.get("/api/v1/incidents?limit=10")
        assert inc_resp.status_code == 200
        inc_data = inc_resp.json()
        assert isinstance(inc_data, list)
        for inc in inc_data:
            assert "provenance" in inc
            assert inc["provenance"] in ("observed_telemetry", "synthetic_benchmark", "unknown", "mixed")

        # Check /incidents/{id} if any exist
        if inc_data:
            target_id = inc_data[0]["id"]
            detail_resp = await client.get(f"/api/v1/incidents/{target_id}")
            assert detail_resp.status_code == 200
            detail_data = detail_resp.json()
            assert "provenance" in detail_data["incident"]
            assert detail_data["incident"]["provenance"] in ("observed_telemetry", "synthetic_benchmark", "unknown", "mixed")
            for ev in detail_data.get("events", []):
                assert "provenance" in ev

