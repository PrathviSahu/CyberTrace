"""
API Integration Tests for CyberTrace Detection Rule Lifecycle & Governance (Phase 6.3C Stage 4).
Tests endpoints:
- POST   /api/v1/rules/drafts/{id}/approve
- POST   /api/v1/rules/drafts/{id}/reject
- GET    /api/v1/rules/active
- GET    /api/v1/rules/active/{id}
- PATCH  /api/v1/rules/active/{id}/status
- GET    /api/v1/rules/audit
"""

from datetime import datetime, timezone
from unittest.mock import patch
from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import (
    ActiveDetectionRuleModel,
    DetectionRuleDraftModel,
    RuleAuditEntryModel,
    RuleCodeAllocatorModel,
    RuleValidationRunModel,
    SavedHuntModel,
)
from app.db.session import get_db_session
from app.main import app


@pytest.fixture(autouse=True)
def override_db_session(db_session: AsyncSession):
    """Ensure all API integration tests use isolated database session."""
    async def _override():
        yield db_session
    app.dependency_overrides[get_db_session] = _override
    yield
    app.dependency_overrides.clear()


async def _seed_draft_and_validation(
    session: AsyncSession,
    draft_id: str = "draft_api_test",
    created_by: str = "analyst_alice",
    status: str = "VALIDATED",
    val_status: str = "COMPLETED",
    is_stale: bool = False,
    draft_version: int = 1,
    val_version: int = 1,
) -> DetectionRuleDraftModel:
    alloc_stmt = select(RuleCodeAllocatorModel).where(RuleCodeAllocatorModel.sequence_name == "custom_rule")
    res = await session.execute(alloc_stmt)
    alloc = res.scalar_one_or_none()
    if not alloc:
        session.add(
            RuleCodeAllocatorModel(
                sequence_name="custom_rule",
                current_value=0,
                updated_at=datetime.now(timezone.utc),
            )
        )
    hunt = SavedHuntModel(
        id=f"hunt_{draft_id}",
        name="Source Hunt",
        query_definition={"combinator": "AND", "conditions": []},
        version=1,
    )
    draft = DetectionRuleDraftModel(
        id=draft_id,
        name="Suspicious Outbound Port",
        description="Candidate draft for API testing",
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
        version=draft_version,
        created_by=created_by,
        is_archived=False,
    )
    val = RuleValidationRunModel(
        id=f"val_{draft_id}",
        draft_id=draft.id,
        draft_version=val_version,
        query_definition_snapshot={},
        events_scanned=50,
        matches_found=2,
        status=val_status,
        is_stale=is_stale,
    )
    session.add_all([hunt, draft, val])
    await session.commit()
    return draft


# ==============================================================================
# 1. Approval Endpoint Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_api_approve_draft_success(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_appr_ok", created_by="analyst_alice")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "approver_id": "lead_bob",  # Distinct peer reviewer
            "justification": "Verified telemetry and ThreatLab benchmark scenarios with zero benign false positives.",
            "activate_immediately": True,
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/approve", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["rule_code"] == "CUST-001"
        assert data["status"] == "ACTIVE"
        assert data["approved_by"] == "lead_bob"
        assert data["source_draft_id"] == draft.id
        assert data["governance_classification"] == "demonstration_level_approval_gate"
        assert "Caller-supplied demo identity" in data["author_attribution_note"]

        # Audit persistence verification
        res_audit = await client.get(f"/api/v1/rules/audit?target_id={draft.id}")
        assert res_audit.status_code == 200
        assert res_audit.json()["total"] == 1
        assert res_audit.json()["items"][0]["action"] == "APPROVE_DRAFT"


@pytest.mark.asyncio
async def test_api_approve_draft_fails_four_eyes_violation(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_appr_self", created_by="analyst_alice")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "approver_id": "analyst_alice",  # Self-approval!
            "justification": "Attempting self approval on my candidate draft.",
        }
        with patch.object(settings, "ALLOW_DEMO_SELF_APPROVAL", False):
            res = await client.post(f"/api/v1/rules/drafts/{draft.id}/approve", json=payload)
            assert res.status_code == 403
            assert "four-eyes principle violation" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_approve_draft_allows_self_approval_when_demo_override_enabled(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_appr_override", created_by="analyst_alice")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "approver_id": "analyst_alice",  # Self-approval with server override
            "justification": "Demonstration self approval under server-side override configuration.",
        }
        with patch.object(settings, "ALLOW_DEMO_SELF_APPROVAL", True):
            res = await client.post(f"/api/v1/rules/drafts/{draft.id}/approve", json=payload)
            assert res.status_code == 200
            data = res.json()
            assert data["rule_code"] == "CUST-001"

        # Verify audit entry recorded demo override flag and security warning accurately
        res_audit = await client.get(f"/api/v1/rules/audit?target_id={draft.id}")
        assert res_audit.status_code == 200
        audit_items = res_audit.json()["items"]
        assert len(audit_items) == 1
        assert audit_items[0]["demo_override_flag"] is True
        assert "SECURITY AUDIT WARNING: Four-eyes principle violated" in audit_items[0]["security_warning"]


@pytest.mark.asyncio
async def test_api_approve_draft_fails_stale_validation(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_appr_stale", is_stale=True)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "approver_id": "lead_bob",
            "justification": "Valid justification text for approval.",
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/approve", json=payload)
        assert res.status_code == 409
        assert "stale" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_approve_draft_fails_short_justification(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_appr_short")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "approver_id": "lead_bob",
            "justification": "short",  # < 10 characters
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/approve", json=payload)
        assert res.status_code == 422  # Pydantic validation error


@pytest.mark.asyncio
async def test_api_approve_draft_fails_draft_not_found():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "approver_id": "lead_bob",
            "justification": "Valid justification text for non-existent draft.",
        }
        res = await client.post("/api/v1/rules/drafts/draft_non_existent/approve", json=payload)
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_api_approve_draft_fails_already_approved(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_appr_dup", status="APPROVED")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "approver_id": "lead_bob",
            "justification": "Attempting duplicate approval on already approved draft.",
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/approve", json=payload)
        assert res.status_code == 409
        assert "already approved" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_approve_draft_fails_not_validated(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_appr_unval", status="DRAFT")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "approver_id": "lead_bob",
            "justification": "Attempting approval on draft that is in DRAFT status.",
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/approve", json=payload)
        assert res.status_code == 409
        assert "only drafts in validated status" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_approve_draft_fails_version_conflict_propagation(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_appr_ver_conf", draft_version=1)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 99,  # Stale expected version
            "approver_id": "lead_bob",
            "justification": "Valid justification with stale version passed.",
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/approve", json=payload)
        assert res.status_code == 409
        assert "version conflict" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_approve_draft_failure_leaves_no_partial_active_rule_or_audit(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_appr_atomic_fail", created_by="analyst_alice")
    draft_id = draft.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Deliberately fail approval via four-eyes self-approval
        payload = {
            "draft_version": 1,
            "approver_id": "analyst_alice",
            "justification": "Attempting self-approval to test atomicity.",
        }
        with patch.object(settings, "ALLOW_DEMO_SELF_APPROVAL", False):
            res = await client.post(f"/api/v1/rules/drafts/{draft_id}/approve", json=payload)
            assert res.status_code == 403

        # Verify no active rule was created
        res_rules = await client.get("/api/v1/rules/active")
        assert res_rules.status_code == 200
        assert res_rules.json()["total"] == 0

        # Verify no audit entry was created for this target
        res_audit = await client.get(f"/api/v1/rules/audit?target_id={draft_id}")
        assert res_audit.status_code == 200
        assert res_audit.json()["total"] == 0


# ==============================================================================
# 2. Rejection Endpoint Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_api_reject_draft_success(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_rej_ok")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "reviewer_id": "lead_reviewer_charlie",
            "justification": "Rule logic triggers too much noise on administrative baseline traffic.",
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/reject", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "DRAFT"
        assert data["version"] == 2


@pytest.mark.asyncio
async def test_api_reject_draft_fails_not_validated(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_rej_not_val", status="DRAFT")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "reviewer_id": "lead_charlie",
            "justification": "Attempting rejection on draft that was not validated.",
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/reject", json=payload)
        assert res.status_code == 409
        assert "only drafts in validated status" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_reject_draft_fails_draft_not_found():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "reviewer_id": "lead_charlie",
            "justification": "Attempting rejection on non-existent draft ID.",
        }
        res = await client.post("/api/v1/rules/drafts/draft_404_rej/reject", json=payload)
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_api_reject_draft_fails_short_justification(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_rej_short")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "reviewer_id": "lead_reviewer",
            "justification": "short",  # < 10 characters
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/reject", json=payload)
        assert res.status_code == 422


@pytest.mark.asyncio
async def test_api_reject_draft_fails_archived_draft(db_session: AsyncSession):
    draft = await _seed_draft_and_validation(db_session, "draft_rej_archived")
    draft.is_archived = True
    await db_session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "reviewer_id": "lead_reviewer",
            "justification": "Attempting rejection on archived draft.",
        }
        res = await client.post(f"/api/v1/rules/drafts/{draft.id}/reject", json=payload)
        assert res.status_code == 409
        assert "archived" in res.json()["detail"].lower()


# ==============================================================================
# 3. Active Rule Management Endpoint Tests
# ==============================================================================

async def _seed_active_rule(
    session: AsyncSession,
    rule_id: str = "rule_api_active",
    rule_code: str = "CUST-001",
    status: str = "ACTIVE",
    version: int = 1,
) -> ActiveDetectionRuleModel:
    draft = await _seed_draft_and_validation(session, f"draft_{rule_id}")
    now = datetime.now(timezone.utc)
    rule = ActiveDetectionRuleModel(
        id=rule_id,
        rule_code=rule_code,
        name="Production Active Rule",
        description="Active rule API endpoint test",
        severity="high",
        mitre_attack_id="T1041",
        mitre_tactic="exfiltration",
        source_draft_id=draft.id,
        source_draft_version=1,
        validation_run_id=f"val_draft_{rule_id}",
        query_definition={
            "filter_group": {
                "logic": "AND",
                "conditions": [
                    {"field": "action", "operator": "eq", "value": "network_connect"}
                ],
                "groups": [],
            }
        },
        status=status,
        version=version,
        approved_by="lead_bob",
        approved_at=now,
        activated_at=now,
    )
    session.add(rule)
    await session.commit()
    return rule


@pytest.mark.asyncio
async def test_api_list_active_rules(db_session: AsyncSession):
    await _seed_active_rule(db_session, "r1", "CUST-001", status="ACTIVE")
    await _seed_active_rule(db_session, "r2", "CUST-002", status="DISABLED")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # All rules
        res_all = await client.get("/api/v1/rules/active")
        assert res_all.status_code == 200
        assert res_all.json()["total"] == 2

        # Filter by status=ACTIVE
        res_active = await client.get("/api/v1/rules/active?status=ACTIVE")
        assert res_active.status_code == 200
        assert res_active.json()["total"] == 1
        assert res_active.json()["items"][0]["rule_code"] == "CUST-001"


@pytest.mark.asyncio
async def test_api_get_active_rule_by_id_and_code(db_session: AsyncSession):
    rule = await _seed_active_rule(db_session, "rule_by_code_test", "CUST-005")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Get by ID
        res_id = await client.get(f"/api/v1/rules/active/{rule.id}")
        assert res_id.status_code == 200
        assert res_id.json()["rule_code"] == "CUST-005"

        # Get by canonical rule code
        res_code = await client.get("/api/v1/rules/active/CUST-005")
        assert res_code.status_code == 200
        assert res_code.json()["id"] == rule.id

        # Not found
        res_nf = await client.get("/api/v1/rules/active/CUST-999")
        assert res_nf.status_code == 404


@pytest.mark.asyncio
async def test_api_get_active_rule_preserves_lineage_and_clean_ast(db_session: AsyncSession):
    rule = await _seed_active_rule(db_session, "rule_lineage_test", "CUST-009")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(f"/api/v1/rules/active/{rule.id}")
        assert res.status_code == 200
        data = res.json()
        assert data["source_draft_id"] == rule.source_draft_id
        assert data["source_draft_version"] == 1
        assert data["validation_run_id"] == rule.validation_run_id
        # Verify internal query_definition AST is omitted from public response contract
        assert "query_definition" not in data
        assert data["status"] == "ACTIVE"
        assert data["rule_code"] == rule.rule_code


@pytest.mark.asyncio
async def test_api_update_active_rule_status_lifecycle(db_session: AsyncSession):
    rule = await _seed_active_rule(db_session, "rule_status_cycle", "CUST-001", status="ACTIVE", version=1)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Disable rule
        res_disable = await client.patch(
            f"/api/v1/rules/active/{rule.id}/status",
            json={
                "version": 1,
                "status": "DISABLED",
                "justification": "Temporarily disabling rule during scheduled maintenance.",
                "actor": "operator_dan",
            },
        )
        assert res_disable.status_code == 200
        assert res_disable.json()["status"] == "DISABLED"
        assert res_disable.json()["version"] == 2

        # 2. Reactivate rule
        res_reactivate = await client.patch(
            f"/api/v1/rules/active/{rule.id}/status",
            json={
                "version": 2,
                "status": "ACTIVE",
                "justification": "Reactivating rule following completion of maintenance window.",
                "actor": "operator_dan",
            },
        )
        assert res_reactivate.status_code == 200
        assert res_reactivate.json()["status"] == "ACTIVE"
        assert res_reactivate.json()["version"] == 3

        # 3. Deprecate rule (terminal)
        res_deprecate = await client.patch(
            f"/api/v1/rules/active/{rule.id}/status",
            json={
                "version": 3,
                "status": "DEPRECATED",
                "justification": "Permanently deprecating rule in favor of CUST-010.",
                "actor": "operator_dan",
            },
        )
        assert res_deprecate.status_code == 200
        assert res_deprecate.json()["status"] == "DEPRECATED"
        assert res_deprecate.json()["version"] == 4

        # 4. Attempting reactivation of DEPRECATED rule fails with 409
        res_forbidden_reactivate = await client.patch(
            f"/api/v1/rules/active/{rule.id}/status",
            json={
                "version": 4,
                "status": "ACTIVE",
                "justification": "Attempting forbidden reactivation of permanently deprecated rule.",
                "actor": "operator_dan",
            },
        )
        assert res_forbidden_reactivate.status_code == 409
        assert "permanently deprecated" in res_forbidden_reactivate.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_update_active_rule_status_version_conflict(db_session: AsyncSession):
    rule = await _seed_active_rule(db_session, "rule_ver_conflict", "CUST-001", version=2)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Pass stale version 1
        res = await client.patch(
            f"/api/v1/rules/active/{rule.id}/status",
            json={
                "version": 1,
                "status": "DISABLED",
                "justification": "Passing stale expected version 1 instead of 2.",
                "actor": "operator_dan",
            },
        )
        assert res.status_code == 409
        assert "version conflict" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_update_active_rule_status_noop_fails_400(db_session: AsyncSession):
    rule = await _seed_active_rule(db_session, "rule_noop_test", "CUST-088", status="ACTIVE", version=1)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.patch(
            f"/api/v1/rules/active/{rule.id}/status",
            json={
                "version": 1,
                "status": "ACTIVE",  # No-op: already ACTIVE
                "justification": "Attempting no-op status transition to same status.",
                "actor": "operator_dan",
            },
        )
        assert res.status_code == 400
        assert "already in status" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_update_active_rule_status_not_found_fails_404():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.patch(
            "/api/v1/rules/active/rule_not_exists/status",
            json={
                "version": 1,
                "status": "DISABLED",
                "justification": "Attempting status update on non-existent rule.",
                "actor": "operator_dan",
            },
        )
        assert res.status_code == 404


# ==============================================================================
# 4. Audit Ledger Endpoint Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_api_list_audit_entries(db_session: AsyncSession):
    now = datetime.now(timezone.utc)
    entry1 = RuleAuditEntryModel(
        id="audit_api_1",
        target_type="DRAFT",
        target_id="draft_123",
        action="APPROVE_DRAFT",
        actor="lead_bob",
        timestamp=now,
        justification="Verified pre-flight metrics on ThreatLab scenarios with zero false positives.",
        state_before={"status": "VALIDATED"},
        state_after={"status": "APPROVED"},
    )
    entry2 = RuleAuditEntryModel(
        id="audit_api_2",
        target_type="ACTIVE_RULE",
        target_id="rule_456",
        action="DEACTIVATE_RULE",
        actor="operator_dan",
        timestamp=now,
        justification="Disabling rule for index maintenance.",
        state_before={"status": "ACTIVE"},
        state_after={"status": "DISABLED"},
    )
    db_session.add_all([entry1, entry2])
    await db_session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # All audit entries
        res = await client.get("/api/v1/rules/audit")
        assert res.status_code == 200
        assert res.json()["total"] == 2

        # Filter by action=APPROVE_DRAFT
        res_filter = await client.get("/api/v1/rules/audit?action=APPROVE_DRAFT")
        assert res_filter.status_code == 200
        assert res_filter.json()["total"] == 1
        assert res_filter.json()["items"][0]["action"] == "APPROVE_DRAFT"
        assert res_filter.json()["items"][0]["actor"] == "lead_bob"
        assert res_filter.json()["items"][0]["storage_classification"] == "application_level_append_only"

        # Filter by target_type=ACTIVE_RULE
        res_type = await client.get("/api/v1/rules/audit?target_type=ACTIVE_RULE")
        assert res_type.status_code == 200
        assert res_type.json()["total"] == 1
        assert res_type.json()["items"][0]["target_id"] == "rule_456"

        # Pagination limit
        res_limit = await client.get("/api/v1/rules/audit?limit=1&offset=0")
        assert res_limit.status_code == 200
        assert len(res_limit.json()["items"]) == 1
        assert res_limit.json()["total"] == 2


@pytest.mark.asyncio
async def test_api_audit_endpoints_reject_mutations():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # POST to audit endpoint must be rejected (405 Method Not Allowed)
        res_post = await client.post("/api/v1/rules/audit", json={"some": "data"})
        assert res_post.status_code == 405

        # DELETE to audit endpoint must be rejected (405 Method Not Allowed)
        res_del = await client.delete("/api/v1/rules/audit")
        assert res_del.status_code == 405
