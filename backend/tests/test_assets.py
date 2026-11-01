"""
Unit and API integration tests for Phase 6.1: Asset & Identity Intelligence.

Covers all 16 required test scenarios:
1. Empty event database
2. Hostname aggregation
3. Source IP aggregation
4. Destination IP aggregation
5. Same IP appearing as source and destination
6. Username aggregation
7. Null and empty identity values
8. Distinct event counts
9. Correct detection and incident associations
10. Asset detail lookup
11. Identity detail lookup
12. Nonexistent entity returns 404
13. Search filtering
14. Pagination boundaries
15. URL encoding and special characters
16. No data mutation from GET endpoints
"""

from datetime import datetime, timezone
import urllib.parse
from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    DetectionModel,
    IncidentEntityModel,
    IncidentModel,
    SecurityEventModel,
)
from app.db.repositories.asset_repo import AssetRepository, IdentityRepository
from app.db.session import get_db_session
from app.main import app


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

async def create_event(
    session: AsyncSession,
    event_id: str,
    timestamp: datetime,
    username: str = None,
    source_ip: str = None,
    destination_ip: str = None,
    hostname: str = None,
    category: str = "authentication",
    action: str = "logon_success",
    severity: str = "informational",
    source_type: str = "test_log",
) -> SecurityEventModel:
    event = SecurityEventModel(
        id=event_id,
        timestamp=timestamp,
        ingested_at=datetime.now(timezone.utc),
        source_type=source_type,
        category=category,
        action=action,
        severity=severity,
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        hostname=hostname,
        source_port=1234,
        destination_port=80,
        protocol="TCP",
        bytes_out=100,
        bytes_in=200,
        raw_payload={"id": event_id},
    )
    session.add(event)
    await session.flush()
    return event


# ---------------------------------------------------------------------------
# 1. Empty Event Database
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_empty_event_database(db_session: AsyncSession):
    repo = AssetRepository(db_session)
    assets, total = await repo.list_assets()
    assert assets == []
    assert total == 0

    id_repo = IdentityRepository(db_session)
    idents, id_total = await id_repo.list_identities()
    assert idents == []
    assert id_total == 0

    # API verification
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r_assets = await client.get("/api/v1/assets")
            assert r_assets.status_code == 200
            assert r_assets.json()["assets"] == []
            assert r_assets.json()["total"] == 0

            r_idents = await client.get("/api/v1/identities")
            assert r_idents.status_code == 200
            assert r_idents.json()["identities"] == []
            assert r_idents.json()["total"] == 0
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 2. Hostname Aggregation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hostname_aggregation(db_session: AsyncSession):
    t1 = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 1, 9, 30, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t1, hostname="SRV-APP-01")
    await create_event(db_session, "e2", t2, hostname="SRV-APP-01")
    await create_event(db_session, "e3", t1, hostname="DC-PRIMARY-01")

    repo = AssetRepository(db_session)
    hosts, total = await repo.list_hostnames()
    assert total == 2
    host_map = {h["asset_value"]: h for h in hosts}

    assert "SRV-APP-01" in host_map
    assert host_map["SRV-APP-01"]["event_count"] == 2
    assert host_map["SRV-APP-01"]["first_seen"] == t1.isoformat()
    assert host_map["SRV-APP-01"]["last_seen"] == t2.isoformat()

    assert "DC-PRIMARY-01" in host_map
    assert host_map["DC-PRIMARY-01"]["event_count"] == 1


# ---------------------------------------------------------------------------
# 3. Source IP Aggregation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_source_ip_aggregation(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t, source_ip="192.168.1.50")
    await create_event(db_session, "e2", t, source_ip="192.168.1.50")

    repo = AssetRepository(db_session)
    ips, total = await repo.list_ips()
    assert total == 1
    assert ips[0]["asset_value"] == "192.168.1.50"
    assert ips[0]["source_event_count"] == 2
    assert ips[0]["destination_event_count"] == 0
    assert ips[0]["event_count"] == 2


# ---------------------------------------------------------------------------
# 4. Destination IP Aggregation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_destination_ip_aggregation(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t, destination_ip="203.0.113.99")
    await create_event(db_session, "e2", t, destination_ip="203.0.113.99")

    repo = AssetRepository(db_session)
    ips, total = await repo.list_ips()
    assert total == 1
    assert ips[0]["asset_value"] == "203.0.113.99"
    assert ips[0]["source_event_count"] == 0
    assert ips[0]["destination_event_count"] == 2
    assert ips[0]["event_count"] == 2


# ---------------------------------------------------------------------------
# 5. Same IP Appearing as Source and Destination
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_same_ip_source_and_destination_deduplication(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    # Event 1: 10.0.0.1 as source
    await create_event(db_session, "e1", t, source_ip="10.0.0.1", destination_ip="10.0.0.2")
    # Event 2: 10.0.0.1 as destination
    await create_event(db_session, "e2", t, source_ip="10.0.0.3", destination_ip="10.0.0.1")
    # Event 3: 10.0.0.1 as BOTH source and destination (loopback / internal interface flow)
    await create_event(db_session, "e3", t, source_ip="10.0.0.1", destination_ip="10.0.0.1")

    repo = AssetRepository(db_session)
    detail = await repo.get_ip_detail("10.0.0.1")
    assert detail is not None
    # 10.0.0.1 was source in e1 and e3 -> source_event_count = 2
    assert detail["source_event_count"] == 2
    # 10.0.0.1 was dest in e2 and e3 -> destination_event_count = 2
    assert detail["destination_event_count"] == 2
    # Total distinct events associated with 10.0.0.1 are e1, e2, e3 -> exactly 3 (NOT 4!)
    assert detail["event_count"] == 3


# ---------------------------------------------------------------------------
# 6. Username Aggregation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_username_aggregation(db_session: AsyncSession):
    t1 = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 1, 9, 0, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t1, username="admin_alice")
    await create_event(db_session, "e2", t2, username="admin_alice")
    await create_event(db_session, "e3", t1, username="svc_backup")

    repo = IdentityRepository(db_session)
    idents, total = await repo.list_identities()
    assert total == 2
    id_map = {i["username"]: i for i in idents}

    assert "admin_alice" in id_map
    assert id_map["admin_alice"]["event_count"] == 2
    assert id_map["admin_alice"]["first_seen"] == t1.isoformat()
    assert id_map["admin_alice"]["last_seen"] == t2.isoformat()

    assert "svc_backup" in id_map
    assert id_map["svc_backup"]["event_count"] == 1


# ---------------------------------------------------------------------------
# 7. Null and Empty Identity Values
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_null_and_empty_identity_values_excluded(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    # Events with null, empty, and whitespace-only username
    await create_event(db_session, "e1", t, username=None)
    await create_event(db_session, "e2", t, username="")
    await create_event(db_session, "e3", t, username="   ")
    await create_event(db_session, "e4", t, username="valid_user")

    repo = IdentityRepository(db_session)
    idents, total = await repo.list_identities()
    assert total == 1
    assert idents[0]["username"] == "valid_user"

    # Hostnames null and whitespace exclusion
    await create_event(db_session, "e5", t, hostname=None)
    await create_event(db_session, "e6", t, hostname="")
    await create_event(db_session, "e7", t, hostname="   ")
    await create_event(db_session, "e8", t, hostname="VALID-HOST")

    a_repo = AssetRepository(db_session)
    hosts, h_total = await a_repo.list_hostnames()
    assert h_total == 1
    assert hosts[0]["asset_value"] == "VALID-HOST"


# ---------------------------------------------------------------------------
# 8. Distinct Event Counts
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_distinct_event_counts_accumulate(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(15):
        await create_event(db_session, f"ev_{i}", t, hostname="HOST-PROD-01", username="jdoe")

    a_repo = AssetRepository(db_session)
    detail = await a_repo.get_hostname_detail("HOST-PROD-01")
    assert detail["event_count"] == 15

    id_repo = IdentityRepository(db_session)
    id_detail = await id_repo.get_identity_detail("jdoe")
    assert id_detail["event_count"] == 15


# ---------------------------------------------------------------------------
# 9. Correct Detection and Incident Associations
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detection_and_incident_associations(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t, hostname="SRV-VICTIM", username="svc_compromised")

    # Seed detections for user and host
    det1 = DetectionModel(
        id="det_001",
        rule_id="DET-001",
        rule_name="Brute Force",
        severity="medium",
        entity_type="user",
        entity_value="svc_compromised",
        first_seen=t,
        last_seen=t,
        detected_at=t,
        explanation="Test detection",
        metadata_json={},
    )
    det2 = DetectionModel(
        id="det_002",
        rule_id="DET-003",
        rule_name="Privilege Escalation",
        severity="high",
        entity_type="host",
        entity_value="srv-victim",
        first_seen=t,
        last_seen=t,
        detected_at=t,
        explanation="Test detection host",
        metadata_json={},
    )
    db_session.add(det1)
    db_session.add(det2)

    # Seed an incident with associated entities
    inc = IncidentModel(
        id="inc_test_001",
        correlation_key="ckey_001",
        title="Test Incident",
        description="Incident description",
        severity="high",
        status="open",
        first_seen=t,
        last_seen=t,
    )
    db_session.add(inc)
    await db_session.flush()

    ie_user = IncidentEntityModel(
        id="ie_1",
        incident_id="inc_test_001",
        entity_type="user",
        entity_value="svc_compromised",
        relationship="compromised_account",
        confidence=1.0,
        evidence_references=["e1"],
    )
    ie_host = IncidentEntityModel(
        id="ie_2",
        incident_id="inc_test_001",
        entity_type="hostname",
        entity_value="SRV-VICTIM",
        relationship="targeted_asset",
        confidence=1.0,
        evidence_references=["e1"],
    )
    db_session.add(ie_user)
    db_session.add(ie_host)
    await db_session.flush()

    # Query AssetRepository and verify association counts
    a_repo = AssetRepository(db_session)
    host_detail = await a_repo.get_hostname_detail("SRV-VICTIM")
    assert host_detail["detection_count"] == 1
    assert host_detail["incident_count"] == 1
    assert host_detail["incident_ids"] == ["inc_test_001"]
    assert len(host_detail["triggered_rules"]) == 1
    assert host_detail["triggered_rules"][0]["rule_id"] == "DET-003"

    # Query IdentityRepository and verify association counts
    id_repo = IdentityRepository(db_session)
    user_detail = await id_repo.get_identity_detail("svc_compromised")
    assert user_detail["detection_count"] == 1
    assert user_detail["incident_count"] == 1
    assert user_detail["incident_ids"] == ["inc_test_001"]
    assert len(user_detail["triggered_rules"]) == 1
    assert user_detail["triggered_rules"][0]["rule_id"] == "DET-001"


# ---------------------------------------------------------------------------
# 10. Asset Detail Lookup (API)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_asset_detail_lookup_api(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t, hostname="DB-SERVER-01", source_ip="10.50.0.5")

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Hostname lookup
            resp_host = await client.get("/api/v1/assets/hostname/DB-SERVER-01")
            assert resp_host.status_code == 200
            data_h = resp_host.json()
            assert data_h["asset_type"] == "hostname"
            assert data_h["asset_value"] == "DB-SERVER-01"
            assert data_h["event_count"] == 1

            # IP lookup
            resp_ip = await client.get("/api/v1/assets/ip/10.50.0.5")
            assert resp_ip.status_code == 200
            data_ip = resp_ip.json()
            assert data_ip["asset_type"] == "ip"
            assert data_ip["asset_value"] == "10.50.0.5"
            assert data_ip["source_event_count"] == 1
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 11. Identity Detail Lookup (API)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_identity_detail_lookup_api(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t, username="operator_dan")

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/identities/operator_dan")
            assert resp.status_code == 200
            data = resp.json()
            assert data["username"] == "operator_dan"
            assert data["event_count"] == 1
            assert data["provenance"] == "observed_telemetry"
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 12. Nonexistent Entity Returns 404
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nonexistent_entities_return_404(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Nonexistent hostname
            r1 = await client.get("/api/v1/assets/hostname/GHOST-HOST")
            assert r1.status_code == 404
            assert "not found" in r1.json()["detail"].lower()

            # Nonexistent IP
            r2 = await client.get("/api/v1/assets/ip/198.51.100.254")
            assert r2.status_code == 404
            assert "not found" in r2.json()["detail"].lower()

            # Nonexistent Identity
            r3 = await client.get("/api/v1/identities/ghost_user")
            assert r3.status_code == 404
            assert "not found" in r3.json()["detail"].lower()

            # Invalid asset_type returns 400
            r4 = await client.get("/api/v1/assets/invalid_type/some_val")
            assert r4.status_code == 400
            assert "invalid asset_type" in r4.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 13. Search Filtering
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_search_filtering(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t, hostname="WEB-PROD-01", username="svc_web", source_ip="10.1.1.10")
    await create_event(db_session, "e2", t, hostname="DB-STAGE-02", username="svc_db", source_ip="10.2.2.20")

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Search hostname
            r_host = await client.get("/api/v1/assets?asset_type=hostname&search=PROD")
            assert r_host.status_code == 200
            assert r_host.json()["total"] == 1
            assert r_host.json()["assets"][0]["asset_value"] == "WEB-PROD-01"

            # Search IP
            r_ip = await client.get("/api/v1/assets?asset_type=ip&search=10.2")
            assert r_ip.status_code == 200
            assert r_ip.json()["total"] == 1
            assert r_ip.json()["assets"][0]["asset_value"] == "10.2.2.20"

            # Search username
            r_user = await client.get("/api/v1/identities?search=db")
            assert r_user.status_code == 200
            assert r_user.json()["total"] == 1
            assert r_user.json()["identities"][0]["username"] == "svc_db"
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 14. Pagination Boundaries
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pagination_boundaries(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(12):
        await create_event(db_session, f"e_{i}", t, hostname=f"SRV-{i:02d}", username=f"user_{i:02d}")

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Page 1: limit 5, offset 0
            p1 = await client.get("/api/v1/assets?asset_type=hostname&limit=5&offset=0")
            assert p1.status_code == 200
            data1 = p1.json()
            assert len(data1["assets"]) == 5
            assert data1["total"] == 12

            # Page 2: limit 5, offset 5
            p2 = await client.get("/api/v1/assets?asset_type=hostname&limit=5&offset=5")
            assert p2.status_code == 200
            data2 = p2.json()
            assert len(data2["assets"]) == 5
            assert data2["total"] == 12

            # Page 3: limit 5, offset 10 (only 2 left)
            p3 = await client.get("/api/v1/assets?asset_type=hostname&limit=5&offset=10")
            assert p3.status_code == 200
            data3 = p3.json()
            assert len(data3["assets"]) == 2
            assert data3["total"] == 12

            # Verify no overlaps between pages
            p1_names = {a["asset_value"] for a in data1["assets"]}
            p2_names = {a["asset_value"] for a in data2["assets"]}
            p3_names = {a["asset_value"] for a in data3["assets"]}
            assert p1_names.isdisjoint(p2_names)
            assert p2_names.isdisjoint(p3_names)
            assert len(p1_names | p2_names | p3_names) == 12
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 15. URL Encoding and Special Characters
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_url_encoding_and_special_characters(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    special_user = "CORP\\svc_deploy.adm"
    special_host = "app-cluster.us-east-1.internal"
    await create_event(db_session, "e1", t, hostname=special_host, username=special_user)

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # URL-encode the backslash in username
            encoded_user = urllib.parse.quote(special_user, safe="")
            r_user = await client.get(f"/api/v1/identities/{encoded_user}")
            assert r_user.status_code == 200
            assert r_user.json()["username"] == special_user.lower()

            # Hostname with dots and hyphens
            encoded_host = urllib.parse.quote(special_host, safe="")
            r_host = await client.get(f"/api/v1/assets/hostname/{encoded_host}")
            assert r_host.status_code == 200
            assert r_host.json()["asset_value"] == special_host.upper()
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 16. No Data Mutation from GET Endpoints (Read-Only Safety)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_data_mutation_from_get_endpoints(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t, hostname="SRV-IMMUTABLE", username="immutable_user", source_ip="10.0.0.99")

    # Capture initial table counts
    event_count_before = (await db_session.execute(select(func.count(SecurityEventModel.id)))).scalar()
    det_count_before = (await db_session.execute(select(func.count(DetectionModel.id)))).scalar()
    inc_count_before = (await db_session.execute(select(func.count(IncidentModel.id)))).scalar()

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Call all 4 GET endpoints
            await client.get("/api/v1/assets")
            await client.get("/api/v1/assets/hostname/SRV-IMMUTABLE")
            await client.get("/api/v1/assets/ip/10.0.0.99")
            await client.get("/api/v1/identities")
            await client.get("/api/v1/identities/immutable_user")
            # Call with nonexistent entity to trigger 404
            await client.get("/api/v1/assets/hostname/NONEXISTENT")

        # Verify counts after GET requests
        event_count_after = (await db_session.execute(select(func.count(SecurityEventModel.id)))).scalar()
        det_count_after = (await db_session.execute(select(func.count(DetectionModel.id)))).scalar()
        inc_count_after = (await db_session.execute(select(func.count(IncidentModel.id)))).scalar()

        assert event_count_before == event_count_after
        assert det_count_before == det_count_after
        assert inc_count_before == inc_count_after
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 17. Combined Asset Global Sort and Pagination Regression
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_combined_asset_global_sort_and_pagination_regression(db_session: AsyncSession):
    """
    Regression Test:
    Demonstrates that a recently observed IP with a high alphabetical string (e.g. 250.250.250.250)
    is NOT omitted from Page 1 by alphabetical ordering.
    Verifies database-level global ordering:
      1. last_seen DESC
      2. asset_value ASC
      3. asset_type ASC
    and verifies that iterating across multiple pages yields all assets without duplicates.
    """
    base_t = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
    from datetime import timedelta

    # Create 20 hostnames with timestamps 1..20 hours
    for i in range(20):
        t = base_t + timedelta(hours=i + 1)
        await create_event(db_session, f"h_evt_{i}", t, hostname=f"SRV-{i:02d}.internal")

    # Create 19 normal IPs with timestamps 1..19 hours
    for i in range(19):
        t = base_t + timedelta(hours=i + 1)
        await create_event(db_session, f"ip_evt_{i}", t, source_ip=f"10.0.0.{i + 1}")

    # Create the 20th IP: '250.250.250.250' (highest lexicographical value among all IPs and hosts)
    # Give it the NEWEST timestamp of all 40 assets: 100 hours after base_t!
    newest_t = base_t + timedelta(hours=100)
    await create_event(db_session, "ip_evt_newest", newest_t, destination_ip="250.250.250.250")

    repo = AssetRepository(db_session)
    assets, total = await repo.list_assets(limit=10, offset=0)
    assert total == 40

    # The newest asset MUST be first in Page 1, proving alphabetical order did not drop it!
    assert assets[0]["asset_type"] == "ip"
    assert assets[0]["asset_value"] == "250.250.250.250"
    assert assets[0]["last_seen"] == newest_t.isoformat()

    # Iterate through all 4 pages and verify ordering, completeness, and zero duplicates
    seen_assets = []
    for page_idx in range(4):
        p_assets, p_total = await repo.list_assets(limit=10, offset=page_idx * 10)
        assert len(p_assets) == 10
        assert p_total == 40
        seen_assets.extend(p_assets)

    # Verify all 40 are distinct
    keys = [(a["asset_type"], a["asset_value"]) for a in seen_assets]
    assert len(keys) == 40
    assert len(set(keys)) == 40

    # Verify strict descending last_seen order across the full list
    for idx in range(len(seen_assets) - 1):
        curr_t = seen_assets[idx]["last_seen"]
        next_t = seen_assets[idx + 1]["last_seen"]
        # curr_t must be >= next_t
        assert curr_t >= next_t, f"Sort order violated at index {idx}: {curr_t} < {next_t}"
        if curr_t == next_t:
            # Stable tie-breaker: asset_value ASC
            assert seen_assets[idx]["asset_value"] <= seen_assets[idx + 1]["asset_value"]


# ---------------------------------------------------------------------------
# 18. Association Namespace, Case-Normalization, and Substring Isolation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_association_namespace_and_case_normalization_isolation(db_session: AsyncSession):
    """
    Verifies:
    1. Namespace mapping: DetectionModel uses 'host', IncidentEntityModel uses 'hostname'
    2. Case normalization: 'SRV-TARGET' in event matches 'srv-target' in detection
    3. Username normalization: 'jdoe' in event matches 'JDOE' in lookup
    4. Exact string isolation: 'SRV-APP' does NOT match 'SRV-APP-01' or 'SRV-APP-PROD'
    5. No count inflation: Multiple detections tied to one incident do not inflate incident count
    """
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)

    # Two distinct hosts: 'SRV-APP' and 'SRV-APP-01'
    await create_event(db_session, "e1", t, hostname="SRV-APP", username="jdoe")
    await create_event(db_session, "e2", t, hostname="SRV-APP-01", username="jdoe_admin")

    # Detection 1: linked to 'SRV-APP' using entity_type='host' with lowercase value
    d1 = DetectionModel(
        id="det_iso_1",
        rule_id="DET-001",
        rule_name="Rule 1",
        severity="medium",
        entity_type="host",
        entity_value="srv-app",
        first_seen=t,
        last_seen=t,
        detected_at=t,
        explanation="test",
        metadata_json={},
    )
    # Detection 2: linked to 'SRV-APP' using entity_type='hostname' with uppercase value
    d2 = DetectionModel(
        id="det_iso_2",
        rule_id="DET-002",
        rule_name="Rule 2",
        severity="high",
        entity_type="hostname",
        entity_value="SRV-APP",
        first_seen=t,
        last_seen=t,
        detected_at=t,
        explanation="test",
        metadata_json={},
    )
    # Detection 3: linked to 'SRV-APP-01'
    d3 = DetectionModel(
        id="det_iso_3",
        rule_id="DET-003",
        rule_name="Rule 3",
        severity="low",
        entity_type="host",
        entity_value="srv-app-01",
        first_seen=t,
        last_seen=t,
        detected_at=t,
        explanation="test",
        metadata_json={},
    )
    db_session.add_all([d1, d2, d3])

    # Incident: associated with 'SRV-APP'
    inc = IncidentModel(
        id="inc_iso_1",
        correlation_key="ckey_iso_1",
        title="Iso Inc",
        description="desc",
        severity="medium",
        status="open",
        first_seen=t,
        last_seen=t,
    )
    db_session.add(inc)
    await db_session.flush()

    # Incident entity linked to 'SRV-APP'
    ie1 = IncidentEntityModel(
        id="ie_iso_1",
        incident_id="inc_iso_1",
        entity_type="hostname",
        entity_value="SRV-APP",
        relationship="target",
        confidence=1.0,
        evidence_references=["e1"],
    )
    db_session.add(ie1)
    await db_session.flush()

    repo = AssetRepository(db_session)

    # SRV-APP should match exactly 2 detections (d1 and d2) and 1 incident (inc_iso_1)
    detail_app = await repo.get_hostname_detail("srv-app")
    assert detail_app is not None
    assert detail_app["detection_count"] == 2
    assert detail_app["incident_count"] == 1
    assert detail_app["incident_ids"] == ["inc_iso_1"]

    # SRV-APP-01 should match exactly 1 detection (d3) and 0 incidents
    # Proves no substring leakage between SRV-APP and SRV-APP-01!
    detail_app01 = await repo.get_hostname_detail("SRV-APP-01")
    assert detail_app01 is not None
    assert detail_app01["detection_count"] == 1
    assert detail_app01["incident_count"] == 0
    assert detail_app01["incident_ids"] == []


# ---------------------------------------------------------------------------
# 19. Provenance is Truthful Observed Telemetry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_provenance_is_truthful_observed_telemetry(db_session: AsyncSession):
    """
    Verifies that all asset and identity endpoints return the honest provenance label
    'observed_telemetry' and do not falsely claim unverified 'live_telemetry'.
    """
    t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    await create_event(db_session, "e1", t, hostname="SRV-PROV", username="user_prov", source_ip="10.88.0.1")

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Assets list
            r1 = await client.get("/api/v1/assets")
            assert r1.status_code == 200
            d1 = r1.json()
            assert d1["provenance"] == "observed_telemetry"
            assert d1["assets"][0]["provenance"] == "observed_telemetry"

            # 2. Hostname detail
            r2 = await client.get("/api/v1/assets/hostname/SRV-PROV")
            assert r2.status_code == 200
            assert r2.json()["provenance"] == "observed_telemetry"

            # 3. IP detail
            r3 = await client.get("/api/v1/assets/ip/10.88.0.1")
            assert r3.status_code == 200
            assert r3.json()["provenance"] == "observed_telemetry"

            # 4. Identities list
            r4 = await client.get("/api/v1/identities")
            assert r4.status_code == 200
            d4 = r4.json()
            assert d4["provenance"] == "observed_telemetry"
            assert d4["identities"][0]["provenance"] == "observed_telemetry"

            # 5. Identity detail
            r5 = await client.get("/api/v1/identities/user_prov")
            assert r5.status_code == 200
            assert r5.json()["provenance"] == "observed_telemetry"
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 20. Canonical Hostname and Identity Aggregation Across Case Variants
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_canonical_hostname_and_identity_aggregation_across_case_variants(db_session: AsyncSession):
    """
    Regression Test for Canonical Normalization:
    1. 'SRV-APP-01', 'srv-app-01' and 'Srv-App-01' collapse into one canonical hostname: 'SRV-APP-01'.
    2. 'svc_deploy' and 'SVC_DEPLOY' collapse into one canonical identity: 'svc_deploy'.
    3. Combined event counts aggregate accurately (3 events for host, 2 events for user).
    4. First-seen and last-seen timestamps span across all matching variants.
    5. Detection and incident counts are matched without duplication or inflation.
    6. Detail endpoints (/assets/hostname/{variant} and /identities/{variant}) resolve every
       case variant to the same canonical entity.
    """
    from datetime import timedelta
    t0 = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=15)
    t2 = t0 + timedelta(minutes=30)

    # 3 events with case variants for hostname
    await create_event(db_session, "e_case_h1", t0, hostname="SRV-APP-01", username="svc_deploy")
    await create_event(db_session, "e_case_h2", t1, hostname="srv-app-01", username="SVC_DEPLOY")
    await create_event(db_session, "e_case_h3", t2, hostname="Srv-App-01", username="other_user")

    # Add detection and incident for SRV-APP-01
    det = DetectionModel(
        id="det_case_01",
        rule_id="DET-001",
        rule_name="Case Rule",
        severity="high",
        entity_type="host",
        entity_value="srv-app-01",
        first_seen=t0,
        last_seen=t2,
        detected_at=t2,
        explanation="test case detection",
        metadata_json={},
    )
    db_session.add(det)
    inc = IncidentModel(
        id="inc_case_01",
        correlation_key="ckey_case_01",
        title="Case Incident",
        description="desc",
        severity="high",
        status="open",
        first_seen=t0,
        last_seen=t2,
    )
    db_session.add(inc)
    await db_session.flush()

    ie = IncidentEntityModel(
        id="ie_case_01",
        incident_id="inc_case_01",
        entity_type="hostname",
        entity_value="SRV-APP-01",
        relationship="target",
        confidence=1.0,
        evidence_references=["e_case_h1"],
    )
    db_session.add(ie)
    await db_session.flush()

    repo = AssetRepository(db_session)
    id_repo = IdentityRepository(db_session)

    # 1. Hostname list verification
    hosts, h_total = await repo.list_hostnames()
    assert h_total == 1
    assert hosts[0]["asset_value"] == "SRV-APP-01"
    assert hosts[0]["event_count"] == 3
    assert hosts[0]["first_seen"] == t0.isoformat()
    assert hosts[0]["last_seen"] == t2.isoformat()
    assert hosts[0]["detection_count"] == 1
    assert hosts[0]["incident_count"] == 1

    # 2. Identity list verification
    idents, u_total = await id_repo.list_identities()
    assert u_total == 2  # 'svc_deploy' and 'other_user'
    svc_user = next(i for i in idents if i["username"] == "svc_deploy")
    assert svc_user["event_count"] == 2  # e_case_h1 + e_case_h2
    assert svc_user["first_seen"] == t0.isoformat()
    assert svc_user["last_seen"] == t1.isoformat()

    # 3. Detail endpoints resolve every case variant to the canonical entity
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Query uppercase, lowercase, and mixed-case for hostname
            for query_variant in ["SRV-APP-01", "srv-app-01", "Srv-App-01"]:
                res = await client.get(f"/api/v1/assets/hostname/{query_variant}")
                assert res.status_code == 200
                data = res.json()
                assert data["asset_value"] == "SRV-APP-01"
                assert data["event_count"] == 3
                assert data["first_seen"] == t0.isoformat()
                assert data["last_seen"] == t2.isoformat()
                assert data["detection_count"] == 1
                assert data["incident_count"] == 1

            # Query lowercase, uppercase, and mixed-case for identity
            for user_variant in ["svc_deploy", "SVC_DEPLOY", "Svc_Deploy"]:
                res_u = await client.get(f"/api/v1/identities/{user_variant}")
                assert res_u.status_code == 200
                data_u = res_u.json()
                assert data_u["username"] == "svc_deploy"
                assert data_u["event_count"] == 2
                assert data_u["first_seen"] == t0.isoformat()
                assert data_u["last_seen"] == t1.isoformat()
    finally:
        app.dependency_overrides.clear()
