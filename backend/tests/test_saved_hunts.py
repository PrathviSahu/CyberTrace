"""
Comprehensive test suite for Phase 6.3A: Saved Threat Hunts & Query Persistence.

Covers:
1. Persistence & Data Integrity:
   - Create saved hunt with validated AST
   - Retrieve by ID
   - AST round-trip serialization and deserialization
   - Rejection of invalid AST payloads (operators, fields, types, nesting, condition caps)
2. Version Concurrency:
   - Initial version starts at 1
   - Successful update increments version to 2
   - Stale version update returns HTTP 409 Conflict
3. Querying & Search:
   - Pagination (limit, offset beyond total)
   - Search on name and description
   - Exact tag filtering on JSON tags
4. Archiving & Soft-Delete:
   - Soft-delete marks is_archived = True
   - Default listing excludes archived hunts
   - include_archived=True includes archived hunts
   - Direct lookup returns archived hunt
5. Duplication:
   - Cloned hunt is completely independent (new ID, version 1, zero runs, unarchived)
   - Modifying clone does not alter original
6. Execution Engine Integration:
   - Unified hunting compiler executes persisted query AST
   - run_count increments and last_run_at is updated
   - Overriding limit and offset at execution time
   - Provenance integrity preserved across execution
   - 404 on nonexistent hunt actions
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from httpx import ASGITransport, AsyncClient
import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SavedHuntModel, SecurityEventModel
from app.db.repositories.saved_hunt_repo import SavedHuntRepository, VersionConflictError
from app.db.session import get_db_session
from app.main import app
from app.schemas.hunting import (
    FilterCondition,
    FilterField,
    FilterGroup,
    FilterOperator,
    TimeRangeFilter,
)
from app.schemas.saved_hunt import (
    SavedHuntCreate,
    SavedHuntDuplicateRequest,
    SavedHuntExecuteRequest,
    SavedHuntQueryDefinition,
    SavedHuntUpdate,
)


# ---------------------------------------------------------------------------
# Fixture Helpers
# ---------------------------------------------------------------------------

async def seed_event(
    session: AsyncSession,
    event_id: str,
    timestamp: datetime,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    category: str = "authentication",
    action: str = "logon_success",
    severity: str = "informational",
    bytes_out: int = 100,
    bytes_in: int = 200,
    source_port: Optional[int] = 1024,
    destination_port: Optional[int] = 80,
    protocol: Optional[str] = "TCP",
    process_name: Optional[str] = None,
    source_file_hash: Optional[str] = "6ec34a29fdac36ef58e6aa712a724b6dfe8d724a85430ed2ede5151e9fac078d",
    source_attribution: Optional[str] = "corporate_edr_sensor",
    raw_payload: Optional[Dict[str, Any]] = None,
) -> SecurityEventModel:
    if raw_payload is None:
        payload = {"id": event_id, "test": True}
        if source_attribution:
            payload["source_attribution"] = source_attribution
    else:
        payload = dict(raw_payload)

    event = SecurityEventModel(
        id=event_id,
        timestamp=timestamp,
        ingested_at=datetime.now(timezone.utc),
        source_type="syslog",
        category=category,
        action=action,
        severity=severity,
        username=username,
        hostname=hostname,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        bytes_out=bytes_out,
        bytes_in=bytes_in,
        process_name=process_name,
        raw_payload=payload,
        source_file_hash=source_file_hash,
    )
    session.add(event)
    await session.flush()
    return event


# ---------------------------------------------------------------------------
# Section 1: Persistence & Data Integrity Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_saved_hunt_and_retrieve_by_id(db_session: AsyncSession):
    repo = SavedHuntRepository(db_session)
    create_req = SavedHuntCreate(
        name="Suspicious Outbound SSH",
        description="Detects large byte volume to SSH ports",
        tags=["network", "ssh", "exfiltration"],
        query_definition=SavedHuntQueryDefinition(
            filter_group=FilterGroup(
                logic="AND",
                conditions=[
                    FilterCondition(field=FilterField.DESTINATION_PORT, operator=FilterOperator.EQ, value=22),
                    FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.GTE, value=5000000),
                ]
            ),
            sort_by=FilterField.BYTES_OUT,
            sort_order="desc",
            limit=25,
        ),
        created_by="analyst_alice",
    )

    created = await repo.create_saved_hunt(create_req)
    assert created.id.startswith("hunt_")
    assert created.name == "Suspicious Outbound SSH"
    assert created.description == "Detects large byte volume to SSH ports"
    assert created.tags == ["network", "ssh", "exfiltration"]
    assert created.version == 1
    assert created.run_count == 0
    assert created.last_run_at is None
    assert created.is_archived is False
    assert created.created_by == "analyst_alice"
    assert created.created_at is not None
    assert created.updated_at is not None

    # Fetch from repository
    fetched = await repo.get_saved_hunt(created.id)
    assert fetched is not None
    assert fetched.id == created.id
    assert fetched.name == "Suspicious Outbound SSH"
    assert fetched.query_definition["sort_by"] == "bytes_out"
    assert len(fetched.query_definition["filter_group"]["conditions"]) == 2


@pytest.mark.asyncio
async def test_ast_persistence_and_round_trip(db_session: AsyncSession):
    repo = SavedHuntRepository(db_session)
    t_start = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 11, 2, 0, 0, 0, tzinfo=timezone.utc)

    ast_def = SavedHuntQueryDefinition(
        time_range=TimeRangeFilter(start=t_start, end=t_end),
        filter_group=FilterGroup(
            logic="AND",
            conditions=[
                FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="network_connect"),
            ],
            groups=[
                FilterGroup(
                    logic="OR",
                    conditions=[
                        FilterCondition(field=FilterField.SEVERITY, operator=FilterOperator.IN, value=["high", "critical"]),
                        FilterCondition(field=FilterField.DESTINATION_PORT, operator=FilterOperator.EQ, value=443),
                    ]
                )
            ]
        ),
        sort_by=FilterField.TIMESTAMP,
        sort_order="asc",
        limit=100,
        offset=10,
    )

    create_req = SavedHuntCreate(
        name="Complex Nested AST Hunt",
        query_definition=ast_def,
    )
    hunt = await repo.create_saved_hunt(create_req)

    # Validate model deserialization
    deserialized = SavedHuntQueryDefinition.model_validate(hunt.query_definition)
    assert deserialized.time_range.start == t_start
    assert deserialized.time_range.end == t_end
    assert deserialized.limit == 100
    assert deserialized.offset == 10
    assert len(deserialized.filter_group.conditions) == 1
    assert len(deserialized.filter_group.groups) == 1
    assert deserialized.filter_group.groups[0].logic == "OR"
    assert len(deserialized.filter_group.groups[0].conditions) == 2

    # Verify conversion to ThreatHuntQueryRequest
    exec_req = deserialized.to_threat_hunt_request(override_limit=20)
    assert exec_req.limit == 20
    assert exec_req.offset == 10
    assert exec_req.time_range.start == t_start


@pytest.mark.asyncio
async def test_invalid_ast_rejection(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Invalid field
            resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Invalid Field Hunt",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [{"field": "unsupported_field", "operator": "eq", "value": "test"}]
                        }
                    }
                }
            )
            assert resp.status_code == 422

            # 2. Invalid operator
            resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Invalid Operator Hunt",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [{"field": "username", "operator": "regex_match", "value": "admin"}]
                        }
                    }
                }
            )
            assert resp.status_code == 422

            # 3. Floating point port
            resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Decimal Port Hunt",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [{"field": "source_port", "operator": "eq", "value": 80.5}]
                        }
                    }
                }
            )
            assert resp.status_code == 422

            # 4. Boolean for integer port
            resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Boolean Port Hunt",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [{"field": "source_port", "operator": "eq", "value": True}]
                        }
                    }
                }
            )
            assert resp.status_code == 422

            # 5. Out of range port
            resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Port Out Of Range Hunt",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [{"field": "destination_port", "operator": "eq", "value": 70000}]
                        }
                    }
                }
            )
            assert resp.status_code == 422

            # 6. Negative bytes_out
            resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Negative Bytes Hunt",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [{"field": "bytes_out", "operator": "eq", "value": -1}]
                        }
                    }
                }
            )
            assert resp.status_code == 422

            # 7. Blank hunt name
            resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "   ",
                    "query_definition": {}
                }
            )
            assert resp.status_code == 422
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Section 2: Version Concurrency & Optimistic Locking Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_saved_hunt_version_concurrency(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Create hunt (version 1)
            create_resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Initial Hunt Name",
                    "description": "Initial description",
                    "query_definition": {},
                }
            )
            assert create_resp.status_code == 201
            hunt_data = create_resp.json()
            hunt_id = hunt_data["id"]
            assert hunt_data["version"] == 1

            # 2. Update with matching version (version 1 -> version 2)
            update_resp1 = await client.put(
                f"/api/v1/hunting/saved/{hunt_id}",
                json={
                    "version": 1,
                    "name": "Updated Hunt Name v2",
                    "description": "Updated description",
                }
            )
            assert update_resp1.status_code == 200
            updated_data1 = update_resp1.json()
            assert updated_data1["version"] == 2
            assert updated_data1["name"] == "Updated Hunt Name v2"

            # 3. Attempt update with stale version 1 -> MUST return HTTP 409 Conflict
            conflict_resp = await client.put(
                f"/api/v1/hunting/saved/{hunt_id}",
                json={
                    "version": 1,
                    "name": "Stale Concurrent Update",
                }
            )
            assert conflict_resp.status_code == 409
            conflict_json = conflict_resp.json()
            assert "Version conflict" in conflict_json["detail"]
            assert "current version is 2" in conflict_json["detail"]

            # 4. Attempt update with future version 99 -> MUST return HTTP 409 Conflict
            conflict_resp2 = await client.put(
                f"/api/v1/hunting/saved/{hunt_id}",
                json={
                    "version": 99,
                    "name": "Invalid Future Version",
                }
            )
            assert conflict_resp2.status_code == 409

            # 5. Successful second update with correct version 2 -> version becomes 3
            update_resp2 = await client.put(
                f"/api/v1/hunting/saved/{hunt_id}",
                json={
                    "version": 2,
                    "name": "Updated Hunt Name v3",
                }
            )
            assert update_resp2.status_code == 200
            assert update_resp2.json()["version"] == 3
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Section 3: List, Pagination, Search & Tag Filtering Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_pagination_and_filtering(db_session: AsyncSession):
    repo = SavedHuntRepository(db_session)

    # Seed 5 hunts with distinct tags and names
    for i in range(5):
        tags = ["common"]
        if i % 2 == 0:
            tags.append("lateral_movement")
        else:
            tags.append("privilege_escalation")

        await repo.create_saved_hunt(
            SavedHuntCreate(
                name=f"Hunt Pattern {i}",
                description=f"Automated test hunt index {i}",
                tags=tags,
                query_definition=SavedHuntQueryDefinition(),
                created_by=f"analyst_{i}",
            )
        )

    # 1. Total count and page size limit
    hunts, total = await repo.list_saved_hunts(limit=2, offset=0)
    assert total >= 5
    assert len(hunts) == 2

    # 2. Offset beyond total returns empty list
    hunts_empty, total_beyond = await repo.list_saved_hunts(limit=10, offset=9999)
    assert total_beyond >= 5
    assert len(hunts_empty) == 0

    # 3. Search substring on name
    hunts_search, total_search = await repo.list_saved_hunts(query="Pattern 3")
    assert total_search == 1
    assert hunts_search[0].name == "Hunt Pattern 3"

    # 4. Search substring on description
    hunts_desc, total_desc = await repo.list_saved_hunts(query="index 2")
    assert total_desc == 1
    assert hunts_desc[0].name == "Hunt Pattern 2"

    # 5. Filter by tag: exact match on 'lateral_movement'
    hunts_tag, total_tag = await repo.list_saved_hunts(tag="lateral_movement")
    assert total_tag == 3  # Indices 0, 2, 4
    for h in hunts_tag:
        assert "lateral_movement" in h.tags

    # 6. Substring of tag should NOT match exact tag (e.g. 'lateral' does not match 'lateral_movement')
    hunts_partial, total_partial = await repo.list_saved_hunts(tag="lateral")
    assert total_partial == 0


# ---------------------------------------------------------------------------
# Section 4: Archiving & Soft-Delete Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_archive_saved_hunt_soft_delete(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Create hunt
            create_resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Hunt To Be Archived",
                    "description": "Will be soft deleted",
                    "query_definition": {},
                }
            )
            hunt_id = create_resp.json()["id"]

            # 2. Verify it shows in default list
            list_before = (await client.get("/api/v1/hunting/saved?query=Archived")).json()
            assert any(h["id"] == hunt_id for h in list_before["items"])

            # 3. Archive via DELETE endpoint
            del_resp = await client.delete(f"/api/v1/hunting/saved/{hunt_id}")
            assert del_resp.status_code == 200
            del_data = del_resp.json()
            assert del_data["is_archived"] is True

            # 4. Excluded from default list (include_archived=False)
            list_after_default = (await client.get("/api/v1/hunting/saved?query=Archived")).json()
            assert not any(h["id"] == hunt_id for h in list_after_default["items"])

            # 5. Included when include_archived=True
            list_after_archived = (await client.get("/api/v1/hunting/saved?query=Archived&include_archived=true")).json()
            assert any(h["id"] == hunt_id for h in list_after_archived["items"])

            # 6. Direct lookup by ID still works and reflects is_archived=True
            get_resp = await client.get(f"/api/v1/hunting/saved/{hunt_id}")
            assert get_resp.status_code == 200
            assert get_resp.json()["is_archived"] is True
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Section 5: Duplication Independence Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_duplicate_saved_hunt_independence(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Create and update original hunt to version 2
            create_resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Original Master Hunt",
                    "description": "Master blueprint for hunting",
                    "tags": ["prod", "tier1"],
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [{"field": "action", "operator": "eq", "value": "logon_failure"}]
                        }
                    },
                    "created_by": "lead_hunter",
                }
            )
            orig_id = create_resp.json()["id"]

            # Update to version 2
            await client.put(
                f"/api/v1/hunting/saved/{orig_id}",
                json={"version": 1, "description": "Updated master blueprint"}
            )

            # 2. Duplicate hunt
            dup_resp = await client.post(
                f"/api/v1/hunting/saved/{orig_id}/duplicate",
                json={"name": "Cloned Branch Hunt", "created_by": "junior_hunter"}
            )
            assert dup_resp.status_code == 201
            clone = dup_resp.json()

            # 3. Verify clone independence
            assert clone["id"] != orig_id
            assert clone["id"].startswith("hunt_")
            assert clone["name"] == "Cloned Branch Hunt"
            assert clone["version"] == 1  # Reset to 1
            assert clone["run_count"] == 0
            assert clone["last_run_at"] is None
            assert clone["is_archived"] is False
            assert clone["created_by"] == "junior_hunter"
            assert clone["tags"] == ["prod", "tier1"]

            # 4. Modifying clone does not alter original
            await client.put(
                f"/api/v1/hunting/saved/{clone['id']}",
                json={"version": 1, "name": "Mutated Clone"}
            )
            orig_check = (await client.get(f"/api/v1/hunting/saved/{orig_id}")).json()
            assert orig_check["name"] == "Original Master Hunt"
            assert orig_check["version"] == 2
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Section 6: Query Re-Execution & Metric Tracking Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_saved_hunt_and_update_metrics(db_session: AsyncSession):
    now = datetime.now(timezone.utc)

    # 1. Seed events in database
    await seed_event(
        db_session,
        event_id="evt_hunt_match",
        timestamp=now,
        username="compromised_svc",
        action="privilege_escalation",
        bytes_out=50000000,
        source_attribution="corporate_edr_sensor",
    )
    await seed_event(
        db_session,
        event_id="evt_hunt_other",
        timestamp=now,
        username="benign_user",
        action="logon_success",
        bytes_out=100,
    )
    await db_session.commit()

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 2. Save hunt targeting high byte privilege escalations
            create_resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Privilege Escalation Exfil",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [
                                {"field": "action", "operator": "eq", "value": "privilege_escalation"},
                                {"field": "bytes_out", "operator": "gte", "value": 10000000},
                            ]
                        },
                        "limit": 10
                    }
                }
            )
            hunt_id = create_resp.json()["id"]

            # Initial state: run_count = 0, last_run_at = None
            hunt_pre = (await client.get(f"/api/v1/hunting/saved/{hunt_id}")).json()
            assert hunt_pre["run_count"] == 0
            assert hunt_pre["last_run_at"] is None

            # 3. Execute saved hunt
            exec_resp = await client.post(f"/api/v1/hunting/saved/{hunt_id}/execute", json={})
            assert exec_resp.status_code == 200
            exec_data = exec_resp.json()

            assert exec_data["hunt_id"] == hunt_id
            assert exec_data["executed_version"] == 1
            assert exec_data["run_count"] == 1
            assert exec_data["total"] == 1
            assert len(exec_data["items"]) == 1
            assert exec_data["items"][0]["id"] == "evt_hunt_match"
            assert exec_data["items"][0]["username"] == "compromised_svc"
            assert exec_data["provenance"] == "unknown"

            # 4. Verify persisted metrics updated on hunt
            hunt_post = (await client.get(f"/api/v1/hunting/saved/{hunt_id}")).json()
            assert hunt_post["run_count"] == 1
            assert hunt_post["last_run_at"] is not None

            # 5. Execute second time with pagination override
            exec_resp2 = await client.post(
                f"/api/v1/hunting/saved/{hunt_id}/execute",
                json={"limit": 5, "offset": 0}
            )
            assert exec_resp2.status_code == 200
            assert exec_resp2.json()["run_count"] == 2

            hunt_post2 = (await client.get(f"/api/v1/hunting/saved/{hunt_id}")).json()
            assert hunt_post2["run_count"] == 2
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_provenance_preserved_in_saved_hunt_execution(db_session: AsyncSession):
    now = datetime.now(timezone.utc)

    # Synthetic event with SHA-256 hash
    await seed_event(
        db_session,
        event_id="evt_synth_1",
        timestamp=now,
        username="synth_actor",
        action="network_connect",
        source_attribution="test_mock_simulator",
        source_file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        raw_payload={"synthetic": True, "benchmark": True},
    )
    await db_session.commit()

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            create_resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Synthetic Benchmark Hunt",
                    "query_definition": {
                        "filter_group": {
                            "logic": "AND",
                            "conditions": [{"field": "username", "operator": "eq", "value": "synth_actor"}]
                        }
                    }
                }
            )
            hunt_id = create_resp.json()["id"]

            exec_resp = await client.post(f"/api/v1/hunting/saved/{hunt_id}/execute")
            assert exec_resp.status_code == 200
            data = exec_resp.json()
            assert data["total"] == 1
            assert data["items"][0]["provenance"] == "synthetic_benchmark"
            assert data["provenance"] == "synthetic_benchmark"
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Section 7: Error Handling & 404 Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nonexistent_hunt_returns_404(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. GET nonexistent
            resp = await client.get("/api/v1/hunting/saved/hunt_nonexistent_123")
            assert resp.status_code == 404

            # 2. PUT nonexistent
            resp = await client.put(
                "/api/v1/hunting/saved/hunt_nonexistent_123",
                json={"version": 1, "name": "New Name"}
            )
            assert resp.status_code == 404

            # 3. DELETE nonexistent
            resp = await client.delete("/api/v1/hunting/saved/hunt_nonexistent_123")
            assert resp.status_code == 404

            # 4. EXECUTE nonexistent
            resp = await client.post("/api/v1/hunting/saved/hunt_nonexistent_123/execute")
            assert resp.status_code == 404

            # 5. DUPLICATE nonexistent
            resp = await client.post("/api/v1/hunting/saved/hunt_nonexistent_123/duplicate")
            assert resp.status_code == 404
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Section 8: Edge-Case & Hydration Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_saved_hunt_duplicate_default_name_and_truncation(db_session: AsyncSession):
    repo = SavedHuntRepository(db_session)
    long_name = "A" * 125  # 125 chars
    orig = await repo.create_saved_hunt(
        SavedHuntCreate(
            name=long_name,
            query_definition=SavedHuntQueryDefinition(),
        )
    )

    # Duplicate without explicit name
    dup = await repo.duplicate_saved_hunt(orig.id, SavedHuntDuplicateRequest())
    assert dup.name.startswith("Copy of AAAAA")
    assert len(dup.name) <= 128
    assert dup.version == 1
    assert dup.id != orig.id


@pytest.mark.asyncio
async def test_update_partial_fields_preserves_other_state(db_session: AsyncSession):
    repo = SavedHuntRepository(db_session)
    orig = await repo.create_saved_hunt(
        SavedHuntCreate(
            name="Immutable Name Hunt",
            description="Original description",
            tags=["tag1", "tag2"],
            query_definition=SavedHuntQueryDefinition(limit=75),
            created_by="hunter_1",
        )
    )
    assert orig.version == 1

    # Update ONLY description
    updated = await repo.update_saved_hunt(
        orig.id,
        SavedHuntUpdate(version=1, description="New mutated description")
    )
    assert updated.version == 2
    assert updated.name == "Immutable Name Hunt"
    assert updated.tags == ["tag1", "tag2"]
    assert updated.description == "New mutated description"
    assert updated.query_definition["limit"] == 75

    # Update ONLY tags
    updated2 = await repo.update_saved_hunt(
        orig.id,
        SavedHuntUpdate(version=2, tags=["tag3"])
    )
    assert updated2.version == 3
    assert updated2.tags == ["tag3"]
    assert updated2.description == "New mutated description"


@pytest.mark.asyncio
async def test_author_attribution_security_disclaimer(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/hunting/saved",
                json={
                    "name": "Attribution Check Hunt",
                    "query_definition": {},
                    "created_by": "unverified_demo_user"
                }
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["created_by"] == "unverified_demo_user"
            assert "author_attribution_note" in data
            assert "Caller-supplied demo identity" in data["author_attribution_note"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_execute_saved_hunt_hydrates_related_detections_and_incidents(db_session: AsyncSession):
    from app.db.models import DetectionModel, DetectionEventModel, IncidentModel, IncidentDetectionModel

    now = datetime.now(timezone.utc)
    # Seed event
    event = await seed_event(
        db_session,
        event_id="evt_with_rel",
        timestamp=now,
        username="compromised_admin",
        action="privilege_escalation",
        source_attribution="corporate_edr_sensor",
    )

    # Seed detection
    det = DetectionModel(
        id="det_rel_1",
        rule_id="DET-001",
        rule_name="Excessive Failed Logins",
        severity="high",
        entity_type="user",
        entity_value="compromised_admin",
        first_seen=now,
        last_seen=now,
        detected_at=now,
        explanation="Suspicious repeated logins followed by escalation",
        metadata_json={},
    )
    db_session.add(det)
    await db_session.flush()

    # Link event to detection
    det_evt = DetectionEventModel(detection_id=det.id, event_id=event.id)
    db_session.add(det_evt)

    # Seed incident
    inc = IncidentModel(
        id="inc_rel_1",
        correlation_key="user:compromised_admin",
        title="Admin Account Compromise",
        description="Correlated account escalation incident",
        severity="critical",
        status="open",
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    db_session.add(inc)
    await db_session.flush()

    # Link detection to incident
    inc_det = IncidentDetectionModel(incident_id=inc.id, detection_id=det.id, correlation_reason="escalation")
    db_session.add(inc_det)
    await db_session.commit()

    repo = SavedHuntRepository(db_session)
    hunt = await repo.create_saved_hunt(
        SavedHuntCreate(
            name="Admin Escalation Hunt",
            query_definition=SavedHuntQueryDefinition(
                filter_group=FilterGroup(
                    logic="AND",
                    conditions=[
                        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="compromised_admin")
                    ]
                )
            ),
        )
    )

    result = await repo.execute_saved_hunt(hunt.id)
    assert result.total == 1
    assert len(result.items) == 1
    item = result.items[0]
    assert item.id == "evt_with_rel"
    assert len(item.related_detections) == 1
    assert item.related_detections[0].rule_id == "DET-001"
    assert len(item.related_incidents) == 1
    assert item.related_incidents[0].id == "inc_rel_1"
    assert item.related_incidents[0].title == "Admin Account Compromise"


# ---------------------------------------------------------------------------
# Section 9: Concurrency & Lifecycle Hardening Tests (Phase 6.3A Final)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_updates_same_version_exactly_one_succeeds(db_session: AsyncSession, async_test_engine):
    import asyncio
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(bind=async_test_engine, expire_on_commit=False, class_=AsyncSession)

    # 1. Seed initial hunt in session 0
    async with factory() as s0:
        repo0 = SavedHuntRepository(s0)
        h = await repo0.create_saved_hunt(
            SavedHuntCreate(name="Race Test Hunt", query_definition=SavedHuntQueryDefinition())
        )
        hunt_id = h.id
        assert h.version == 1

    # 2. Worker that attempts conditional update with version=1
    async def update_worker(worker_id: int):
        async with factory() as session:
            repo = SavedHuntRepository(session)
            return await repo.update_saved_hunt(
                hunt_id,
                SavedHuntUpdate(version=1, name=f"Updated by Worker {worker_id}")
            )

    # Run both updates simultaneously
    results = await asyncio.gather(
        update_worker(1),
        update_worker(2),
        return_exceptions=True
    )

    successes = [r for r in results if not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, Exception)]

    # Exactly one must succeed, exactly one must receive VersionConflictError
    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], VersionConflictError)

    # Database must have version incremented by exactly 1 (version 2)
    async with factory() as s_check:
        repo_check = SavedHuntRepository(s_check)
        final_hunt = await repo_check.get_saved_hunt(hunt_id)
        assert final_hunt.version == 2
        assert final_hunt.name in ("Updated by Worker 1", "Updated by Worker 2")


@pytest.mark.asyncio
async def test_archived_hunt_cannot_be_updated(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Create hunt
            create_resp = await client.post(
                "/api/v1/hunting/saved",
                json={"name": "To Archive For Update", "query_definition": {}}
            )
            hunt_id = create_resp.json()["id"]

            # Archive it
            del_resp = await client.delete(f"/api/v1/hunting/saved/{hunt_id}")
            assert del_resp.status_code == 200
            assert del_resp.json()["is_archived"] is True

            # Attempt update on archived hunt -> MUST return HTTP 409 Conflict
            update_resp = await client.put(
                f"/api/v1/hunting/saved/{hunt_id}",
                json={"version": 1, "name": "Illegal Mutation"}
            )
            assert update_resp.status_code == 409
            detail = update_resp.json()["detail"]
            assert "Archived threat hunt" in detail
            assert "cannot be modified" in detail
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_archived_hunt_cannot_be_executed(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Create hunt
            create_resp = await client.post(
                "/api/v1/hunting/saved",
                json={"name": "To Archive For Exec", "query_definition": {}}
            )
            hunt_id = create_resp.json()["id"]

            # Archive it
            del_resp = await client.delete(f"/api/v1/hunting/saved/{hunt_id}")
            assert del_resp.status_code == 200

            # Attempt execution on archived hunt -> MUST return HTTP 409 Conflict
            exec_resp = await client.post(f"/api/v1/hunting/saved/{hunt_id}/execute")
            assert exec_resp.status_code == 409
            detail = exec_resp.json()["detail"]
            assert "Archived threat hunt" in detail
            assert "cannot be executed" in detail
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_repeated_archive_is_idempotent(db_session: AsyncSession):
    repo = SavedHuntRepository(db_session)
    hunt = await repo.create_saved_hunt(
        SavedHuntCreate(name="Repeated Archive Test", query_definition=SavedHuntQueryDefinition())
    )

    # First archive
    archived1 = await repo.archive_saved_hunt(hunt.id)
    assert archived1.is_archived is True
    first_updated_at = archived1.updated_at

    # Repeated archive call
    archived2 = await repo.archive_saved_hunt(hunt.id)
    assert archived2.is_archived is True
    # Verify updated_at is preserved without redundant mutation
    assert archived2.updated_at == first_updated_at


@pytest.mark.asyncio
async def test_duplicate_archived_hunt_creates_active_independent_copy(db_session: AsyncSession):
    repo = SavedHuntRepository(db_session)
    orig = await repo.create_saved_hunt(
        SavedHuntCreate(name="Archived Original", query_definition=SavedHuntQueryDefinition())
    )
    await repo.archive_saved_hunt(orig.id)

    # Duplicate the archived hunt
    clone = await repo.duplicate_saved_hunt(
        orig.id,
        SavedHuntDuplicateRequest(name="Forked Active Clone")
    )

    # Clone must be an independent active hunt
    assert clone.id != orig.id
    assert clone.name == "Forked Active Clone"
    assert clone.version == 1
    assert clone.run_count == 0
    assert clone.last_run_at is None
    assert clone.is_archived is False

    # Original archived hunt must remain archived
    orig_check = await repo.get_saved_hunt(orig.id)
    assert orig_check.is_archived is True


@pytest.mark.asyncio
async def test_concurrent_executions_do_not_lose_counter_increments(db_session: AsyncSession, async_test_engine):
    import asyncio
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(bind=async_test_engine, expire_on_commit=False, class_=AsyncSession)

    # 1. Create hunt
    async with factory() as s0:
        repo0 = SavedHuntRepository(s0)
        h = await repo0.create_saved_hunt(
            SavedHuntCreate(name="Concurrent Run Hunt", query_definition=SavedHuntQueryDefinition())
        )
        hunt_id = h.id
        assert h.run_count == 0

    # 2. Worker to execute hunt in its own session
    async def exec_worker():
        async with factory() as session:
            repo = SavedHuntRepository(session)
            return await repo.execute_saved_hunt(hunt_id)

    # 3. Launch 2 concurrent executions
    results = await asyncio.gather(
        exec_worker(),
        exec_worker(),
        return_exceptions=True
    )

    for r in results:
        assert not isinstance(r, Exception), f"Execution raised {r}"

    # Verify final run_count in database is incremented by exactly 2
    async with factory() as s_check:
        repo_check = SavedHuntRepository(s_check)
        final_hunt = await repo_check.get_saved_hunt(hunt_id)
        assert final_hunt.run_count == 2
        assert final_hunt.last_run_at is not None


@pytest.mark.asyncio
async def test_failed_execution_does_not_increment_counter(db_session: AsyncSession, monkeypatch):
    from app.db.repositories.hunting_repo import HuntingRepository

    repo = SavedHuntRepository(db_session)
    hunt = await repo.create_saved_hunt(
        SavedHuntCreate(name="Fail Run Hunt", query_definition=SavedHuntQueryDefinition())
    )
    assert hunt.run_count == 0
    assert hunt.last_run_at is None

    # Simulate query failure during execute_hunt
    async def mock_fail(*args, **kwargs):
        raise RuntimeError("Simulated database timeout during query execution")

    monkeypatch.setattr(HuntingRepository, "execute_hunt", mock_fail)

    with pytest.raises(RuntimeError, match="Simulated database timeout"):
        await repo.execute_saved_hunt(hunt.id)

    # Confirm run_count is still 0 and last_run_at is still None
    check_hunt = await repo.get_saved_hunt(hunt.id)
    assert check_hunt.run_count == 0
    assert check_hunt.last_run_at is None


@pytest.mark.asyncio
async def test_execution_uses_original_query_snapshot_if_concurrently_edited(
    db_session: AsyncSession, async_test_engine, monkeypatch
):
    import asyncio
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from app.db.repositories.hunting_repo import HuntingRepository

    factory = async_sessionmaker(bind=async_test_engine, expire_on_commit=False, class_=AsyncSession)
    now = datetime.now(timezone.utc)

    # 1. Seed events
    async with factory() as s_seed:
        await seed_event(s_seed, "evt_snap_1", now, action="logon_success")
        await seed_event(s_seed, "evt_snap_2", now, action="network_connect")
        await s_seed.commit()

    # 2. Seed hunt targeting logon_success (version 1)
    async with factory() as s0:
        repo0 = SavedHuntRepository(s0)
        h = await repo0.create_saved_hunt(
            SavedHuntCreate(
                name="Snapshot Test Hunt",
                query_definition=SavedHuntQueryDefinition(
                    filter_group=FilterGroup(
                        logic="AND",
                        conditions=[
                            FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="logon_success")
                        ]
                    )
                )
            )
        )
        hunt_id = h.id
        assert h.version == 1

    # 3. Intercept HuntingRepository.execute_hunt so that while executing,
    # another session edits the hunt in the database to target network_connect (version 2)
    orig_execute = HuntingRepository.execute_hunt

    async def concurrent_edit_during_execution(self, req):
        # Concurrently edit the hunt to version 2 with a different query in a separate session
        async with factory() as s_concurrent:
            repo_c = SavedHuntRepository(s_concurrent)
            await repo_c.update_saved_hunt(
                hunt_id,
                SavedHuntUpdate(
                    version=1,
                    name="Mutated Query Hunt v2",
                    query_definition=SavedHuntQueryDefinition(
                        filter_group=FilterGroup(
                            logic="AND",
                            conditions=[
                                FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="network_connect")
                            ]
                        )
                    )
                )
            )
        # Proceed with original query execution
        return await orig_execute(self, req)

    monkeypatch.setattr(HuntingRepository, "execute_hunt", concurrent_edit_during_execution)

    # 4. Execute the hunt
    async with factory() as s_exec:
        repo_exec = SavedHuntRepository(s_exec)
        exec_res = await repo_exec.execute_saved_hunt(hunt_id)

    # 5. Assert:
    # - Execution result reflects the original query (matched evt_snap_1 logon_success)
    # - executed_version is 1
    # - Database reflects the concurrent update to version 2
    assert exec_res.executed_version == 1
    assert exec_res.total == 1
    assert exec_res.items[0].id == "evt_snap_1"
    assert exec_res.items[0].action == "logon_success"

    async with factory() as s_check:
        repo_check = SavedHuntRepository(s_check)
        current_hunt = await repo_check.get_saved_hunt(hunt_id)
        assert current_hunt.version == 2
        assert current_hunt.name == "Mutated Query Hunt v2"
        assert current_hunt.run_count == 1



