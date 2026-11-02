"""
CyberTrace Phase 6.3C Stage 5 — Complete End-to-End API Workflow Integration.
Exercises the complete 17-step lifecycle entirely via FastAPI HTTP endpoints:
1. Create a detection rule draft.
2. Validate the draft against historical telemetry and ThreatLab benchmarks.
3. Retrieve validation run history.
4. Approve draft as a distinct peer reviewer (four-eyes demonstration gate).
5. Retrieve resulting active rule by ID and canonical rule code.
6. Confirm presence in active-rule listing.
7. Upload synthetic telemetry matching the custom rule.
8. Confirm custom detection (CUST-001) is generated and stored.
9. Retrieve the correlated incident and evidence dossier.
10. Disable the custom rule via PATCH status endpoint.
11. Upload subsequent matching telemetry batch.
12. Confirm disabled rule does not generate a detection.
13. Reactivate the custom rule via PATCH status endpoint.
14. Upload subsequent matching telemetry and confirm execution resumes.
15. Deprecate the custom rule (terminal state).
16. Confirm deprecated rule cannot be reactivated (HTTP 409 Conflict).
17. Retrieve complete immutable audit ledger history.
"""

from datetime import datetime, timezone
import io
import json
from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import RuleCodeAllocatorModel, SavedHuntModel
from app.db.session import get_db_session
from app.main import app


@pytest.fixture(autouse=True)
def override_db(db_session: AsyncSession):
    async def _override():
        yield db_session
    app.dependency_overrides[get_db_session] = _override
    yield
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_full_17_step_http_lifecycle_e2e(db_session: AsyncSession):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:

        # Seed allocator and source saved hunt
        alloc = RuleCodeAllocatorModel(
            sequence_name="custom_rule",
            current_value=0,
            updated_at=datetime.now(timezone.utc),
        )
        hunt = SavedHuntModel(
            id="hunt_e2e_source",
            name="C2 Port 4444 Hunt",
            query_definition={"combinator": "AND", "conditions": []},
            version=1,
            created_by="analyst_alice",
        )
        db_session.add_all([alloc, hunt])
        await db_session.commit()

        # ----------------------------------------------------------------------
        # Step 1: Create a detection rule draft (POST /api/v1/rules/drafts)
        # ----------------------------------------------------------------------
        draft_payload = {
            "name": "Custom C2 Beaconing Rule",
            "description": "Detects outbound network connections to suspicious port 4444",
            "severity": "high",
            "mitre_attack_id": "T1041",
            "mitre_tactic": "exfiltration",
            "source_hunt_id": "hunt_e2e_source",
            "source_hunt_version": 1,
            "query_definition": {
                "filter_group": {
                    "logic": "AND",
                    "conditions": [
                        {"field": "action", "operator": "eq", "value": "network_connect"},
                        {"field": "destination_port", "operator": "eq", "value": 4444},
                    ],
                    "groups": [],
                }
            },
            "created_by": "analyst_alice",
        }
        res_step1 = await client.post("/api/v1/rules/drafts", json=draft_payload)
        assert res_step1.status_code == 201
        draft_data = res_step1.json()
        draft_id = draft_data["id"]
        assert draft_data["status"] == "DRAFT"
        assert draft_data["version"] == 1
        assert draft_data["created_by"] == "analyst_alice"

        # ----------------------------------------------------------------------
        # Step 2: Validate the draft (POST /api/v1/rules/drafts/{id}/validate)
        # ----------------------------------------------------------------------
        res_step2 = await client.post(f"/api/v1/rules/drafts/{draft_id}/validate", json={})
        assert res_step2.status_code == 200
        val_data = res_step2.json()
        assert val_data["status"] == "COMPLETED"
        assert val_data["is_stale"] is False

        # ----------------------------------------------------------------------
        # Step 3: Retrieve validation history (GET /api/v1/rules/drafts/{id}/validations)
        # ----------------------------------------------------------------------
        res_step3 = await client.get(f"/api/v1/rules/drafts/{draft_id}/validations")
        assert res_step3.status_code == 200
        assert res_step3.json()["total"] >= 1
        assert res_step3.json()["items"][0]["status"] == "COMPLETED"

        # ----------------------------------------------------------------------
        # Step 4: Approve as distinct reviewer (POST /api/v1/rules/drafts/{id}/approve)
        # ----------------------------------------------------------------------
        approve_payload = {
            "draft_version": 1,
            "approver_id": "lead_reviewer_bob",  # Four-eyes distinct from analyst_alice
            "justification": "Verified telemetry and ThreatLab benchmark scenarios with zero false alarms.",
            "activate_immediately": True,
        }
        res_step4 = await client.post(f"/api/v1/rules/drafts/{draft_id}/approve", json=approve_payload)
        assert res_step4.status_code == 200
        appr_data = res_step4.json()
        active_rule_id = appr_data["id"]
        rule_code = appr_data["rule_code"]
        assert rule_code == "CUST-001"
        assert appr_data["status"] == "ACTIVE"
        assert appr_data["approved_by"] == "lead_reviewer_bob"

        # ----------------------------------------------------------------------
        # Step 5: Retrieve resulting active rule (GET /api/v1/rules/active/{id})
        # ----------------------------------------------------------------------
        res_step5 = await client.get(f"/api/v1/rules/active/{active_rule_id}")
        assert res_step5.status_code == 200
        assert res_step5.json()["rule_code"] == "CUST-001"
        # Also verify lookup by rule_code
        res_step5_code = await client.get(f"/api/v1/rules/active/{rule_code}")
        assert res_step5_code.status_code == 200
        assert res_step5_code.json()["id"] == active_rule_id

        # ----------------------------------------------------------------------
        # Step 6: Confirm in active-rule listing (GET /api/v1/rules/active)
        # ----------------------------------------------------------------------
        res_step6 = await client.get("/api/v1/rules/active?status=ACTIVE")
        assert res_step6.status_code == 200
        assert res_step6.json()["total"] >= 1
        assert any(r["rule_code"] == "CUST-001" for r in res_step6.json()["items"])

        # ----------------------------------------------------------------------
        # Step 7: Ingest matching synthetic telemetry (POST /api/v1/logs/upload)
        # ----------------------------------------------------------------------
        suricata_sample_1 = json.dumps({
            "timestamp": "2026-11-03T01:00:00.000000Z",
            "action": "network_connect",
            "category": "network_connection",
            "src_ip": "192.168.1.100",
            "src_port": 51234,
            "dest_ip": "10.0.0.50",
            "destination_port": 4444,  # Matches port 4444!
            "protocol": "TCP",
        }) + "\n"

        file_payload_1 = {"file": ("suricata_e2e_1.json", io.BytesIO(suricata_sample_1.encode("utf-8")), "application/json")}
        res_step7 = await client.post("/api/v1/logs/upload", files=file_payload_1)
        assert res_step7.status_code == 200
        assert res_step7.json()["parsed_events_count"] == 1

        # ----------------------------------------------------------------------
        # Step 8: Confirm custom detection is generated (GET /api/v1/detections)
        # ----------------------------------------------------------------------
        res_step8 = await client.get(f"/api/v1/detections?rule_id={rule_code}")
        assert res_step8.status_code == 200
        detections = res_step8.json()
        assert len(detections) == 1
        assert detections[0]["rule_id"] == "CUST-001"
        assert detections[0]["entity_value"] in ["192.168.1.100", "10.0.0.50"]

        # ----------------------------------------------------------------------
        # Step 9: Retrieve associated incident and evidence (GET /api/v1/incidents)
        # ----------------------------------------------------------------------
        res_step9 = await client.get("/api/v1/incidents")
        assert res_step9.status_code == 200
        incidents = res_step9.json()
        assert len(incidents) >= 1
        incident_id = incidents[0]["id"]

        # Check dossier evidence linking
        res_dossier = await client.get(f"/api/v1/incidents/{incident_id}")
        assert res_dossier.status_code == 200
        dossier = res_dossier.json()
        assert any(d["rule_id"] == "CUST-001" for d in dossier["detections"])

        # ----------------------------------------------------------------------
        # Step 10: Disable custom rule (PATCH /api/v1/rules/active/{id}/status)
        # ----------------------------------------------------------------------
        disable_payload = {
            "version": 1,
            "status": "DISABLED",
            "justification": "Disabling rule during false positive tuning review.",
            "actor": "operator_dan",
        }
        res_step10 = await client.patch(f"/api/v1/rules/active/{active_rule_id}/status", json=disable_payload)
        assert res_step10.status_code == 200
        assert res_step10.json()["status"] == "DISABLED"
        assert res_step10.json()["version"] == 2

        # ----------------------------------------------------------------------
        # Step 11: Ingest subsequent matching batch
        # ----------------------------------------------------------------------
        suricata_sample_2 = json.dumps({
            "timestamp": "2026-11-03T01:10:00.000000Z",
            "action": "network_connect",
            "category": "network_connection",
            "src_ip": "192.168.1.101",
            "src_port": 51235,
            "dest_ip": "10.0.0.50",
            "destination_port": 4444,  # Matches port 4444!
            "protocol": "TCP",
        }) + "\n"

        file_payload_2 = {"file": ("suricata_e2e_2.json", io.BytesIO(suricata_sample_2.encode("utf-8")), "application/json")}
        res_step11 = await client.post("/api/v1/logs/upload", files=file_payload_2)
        assert res_step11.status_code == 200

        # ----------------------------------------------------------------------
        # Step 12: Confirm disabled rule generates no new detections
        # ----------------------------------------------------------------------
        res_step12 = await client.get(f"/api/v1/detections?rule_id={rule_code}")
        assert res_step12.status_code == 200
        # Still exactly 1 detection from the first batch
        assert len(res_step12.json()) == 1

        # ----------------------------------------------------------------------
        # Step 13: Reactivate the rule (PATCH /api/v1/rules/active/{id}/status)
        # ----------------------------------------------------------------------
        reactivate_payload = {
            "version": 2,
            "status": "ACTIVE",
            "justification": "Reactivating rule following completion of review.",
            "actor": "operator_dan",
        }
        res_step13 = await client.patch(f"/api/v1/rules/active/{active_rule_id}/status", json=reactivate_payload)
        assert res_step13.status_code == 200
        assert res_step13.json()["status"] == "ACTIVE"
        assert res_step13.json()["version"] == 3

        # ----------------------------------------------------------------------
        # Step 14: Confirm subsequent ingestion executes rule again
        # ----------------------------------------------------------------------
        suricata_sample_3 = json.dumps({
            "timestamp": "2026-11-03T01:20:00.000000Z",
            "action": "network_connect",
            "category": "network_connection",
            "src_ip": "192.168.1.102",
            "src_port": 51236,
            "dest_ip": "10.0.0.50",
            "destination_port": 4444,  # Matches port 4444!
            "protocol": "TCP",
        }) + "\n"

        file_payload_3 = {"file": ("suricata_e2e_3.json", io.BytesIO(suricata_sample_3.encode("utf-8")), "application/json")}
        res_step14 = await client.post("/api/v1/logs/upload", files=file_payload_3)
        assert res_step14.status_code == 200

        res_step14_dets = await client.get(f"/api/v1/detections?rule_id={rule_code}")
        assert res_step14_dets.status_code == 200
        # Now 2 detections!
        assert len(res_step14_dets.json()) == 2

        # ----------------------------------------------------------------------
        # Step 15: Deprecate the rule (PATCH /api/v1/rules/active/{id}/status)
        # ----------------------------------------------------------------------
        deprecate_payload = {
            "version": 3,
            "status": "DEPRECATED",
            "justification": "Permanently deprecating rule in favor of CUST-002.",
            "actor": "operator_dan",
        }
        res_step15 = await client.patch(f"/api/v1/rules/active/{active_rule_id}/status", json=deprecate_payload)
        assert res_step15.status_code == 200
        assert res_step15.json()["status"] == "DEPRECATED"
        assert res_step15.json()["version"] == 4

        # ----------------------------------------------------------------------
        # Step 16: Confirm deprecated rule cannot be reactivated (HTTP 409)
        # ----------------------------------------------------------------------
        illegal_reactivate_payload = {
            "version": 4,
            "status": "ACTIVE",
            "justification": "Attempting illegal reactivation of deprecated rule.",
            "actor": "operator_dan",
        }
        res_step16 = await client.patch(f"/api/v1/rules/active/{active_rule_id}/status", json=illegal_reactivate_payload)
        assert res_step16.status_code == 409
        assert "permanently deprecated" in res_step16.json()["detail"].lower()

        # ----------------------------------------------------------------------
        # Step 17: Retrieve complete audit history (GET /api/v1/rules/audit)
        # ----------------------------------------------------------------------
        res_step17 = await client.get("/api/v1/rules/audit")
        assert res_step17.status_code == 200
        audit_history = res_step17.json()
        assert audit_history["total"] == 4  # APPROVE_DRAFT, DEACTIVATE_RULE, REACTIVATE_RULE, DEPRECATE_RULE

        actions = [item["action"] for item in audit_history["items"]]
        assert "APPROVE_DRAFT" in actions
        assert "DEACTIVATE_RULE" in actions
        assert "REACTIVATE_RULE" in actions
        assert "DEPRECATE_RULE" in actions

        # Verify application-level append-only disclosure
        assert all(item["storage_classification"] == "application_level_append_only" for item in audit_history["items"])
