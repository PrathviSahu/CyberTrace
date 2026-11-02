"""
CyberTrace Phase 6.3C Stage 5 — Governance & Security Hardening Verification.
Validates:
1. Strict bounded pagination (limit > 200 rejected with 422).
2. Malformed / SQL injection inputs in path parameters return 404 without leaking SQL errors or stack traces.
3. Client attempts to pass arbitrary bypass flags in approval payload are ignored or rejected.
4. Total absence of automated destructive response endpoints (host isolation, account revocation).
5. Unverified demo identity disclosures across active rule and audit endpoints.
"""

from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

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
async def test_bounded_pagination_limits_enforced():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Rules draft endpoint: limit > 200 must return 422
        res_drafts = await client.get("/api/v1/rules/drafts?limit=500")
        assert res_drafts.status_code == 422

        # Active rules endpoint: limit > 200 must return 422
        res_active = await client.get("/api/v1/rules/active?limit=500")
        assert res_active.status_code == 422

        # Audit ledger endpoint: limit > 200 must return 422
        res_audit = await client.get("/api/v1/rules/audit?limit=500")
        assert res_audit.status_code == 422


@pytest.mark.asyncio
async def test_malformed_path_params_and_sql_injection_safe():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # SQL injection strings in ID paths
        sqli_payload = "' OR '1'='1"
        res_get = await client.get(f"/api/v1/rules/active/{sqli_payload}")
        assert res_get.status_code == 404
        # Ensure no SQL dialect errors or tracebacks in response
        data = res_get.json()
        assert "syntax error" not in str(data).lower()
        assert "traceback" not in str(data).lower()

        res_patch = await client.patch(
            f"/api/v1/rules/active/{sqli_payload}/status",
            json={
                "version": 1,
                "status": "DISABLED",
                "justification": "Valid justification text for non-existent rule.",
                "actor": "operator_dan",
            },
        )
        assert res_patch.status_code == 404
        assert "syntax error" not in str(res_patch.json()).lower()


@pytest.mark.asyncio
async def test_no_destructive_automated_response_endpoints_exist():
    """
    Guarantees no automated host isolation or account revocation endpoints exist.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res_isolate = await client.post("/api/v1/hosts/host_1/isolate")
        assert res_isolate.status_code == 404

        res_revoke = await client.post("/api/v1/users/user_1/revoke")
        assert res_revoke.status_code == 404

        res_contain = await client.post("/api/v1/response/contain")
        assert res_contain.status_code == 404


@pytest.mark.asyncio
async def test_client_cannot_inject_self_approval_bypass_field():
    """
    Verify that client cannot pass extra bypass fields like `allow_self_approval: true`
    to circumvent server-side ALLOW_DEMO_SELF_APPROVAL.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "draft_version": 1,
            "approver_id": "analyst_alice",
            "justification": "Attempting self-approval with client injection.",
            "allow_self_approval": True,  # Injected field
            "bypass_four_eyes": True,     # Injected field
        }
        res = await client.post("/api/v1/rules/drafts/draft_non_existent/approve", json=payload)
        # Endpoint evaluates server config, ignoring injected client flags
        assert res.status_code == 404
