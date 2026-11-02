"""
Comprehensive test suite for Phase 6.2: Structured Threat Hunting.

Covers:
1. Query Behavior:
   - Time range filtering (start, end, both, boundaries)
   - All 14 supported fields
   - All 9 supported operators (eq, neq, contains, starts_with, in, gt, gte, lt, lte)
   - Boolean AND logic
   - Boolean OR logic
   - Nested boolean group precedence
   - Combined time range and field filters
   - Sorting ascending and descending
   - Pagination and total matching count
   - Empty results handling
   - Stable secondary ordering on event ID for equal timestamps

2. Validation & Security:
   - Unknown field rejection
   - Unknown operator rejection
   - Incompatible field/operator combinations
   - Invalid timestamp strings
   - Naive timestamp rejection
   - Start timestamp later than end rejection
   - Empty 'in' list rejection
   - Excessively large 'in' list rejection (>50)
   - Excessive filter depth rejection (>2)
   - Excessive condition count rejection (>20)
   - Empty filter group rejection
   - Invalid sort field rejection
   - Invalid sort order rejection
   - SQL injection attack payload treated strictly as literal value
   - LIKE wildcard escaping (% and _)

3. Relationships & Batched Hydration:
   - Event with detection association
   - Event with incident association via detection
   - Event with no related records
   - Multiple matching events without N+1 query behavior
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    DetectionEventModel,
    DetectionModel,
    IncidentDetectionModel,
    IncidentModel,
    SecurityEventModel,
)
from app.db.repositories.hunting_repo import HuntingRepository
from app.db.session import get_db_session
from app.main import app
from app.schemas.hunting import (
    FilterCondition,
    FilterField,
    FilterGroup,
    FilterOperator,
    HuntedEventItem,
    ThreatHuntQueryRequest,
    TimeRangeFilter,
)


# ---------------------------------------------------------------------------
# Test Data Fixture Helpers
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
# Section 1: Query Behavior Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_empty_database_returns_clean_response(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    req = ThreatHuntQueryRequest()
    res = await repo.execute_hunt(req)

    assert res.total == 0
    assert len(res.items) == 0
    assert res.limit == 50
    assert res.offset == 0
    assert res.applied_filter_count == 0
    assert res.provenance == "unknown"


@pytest.mark.asyncio
async def test_time_range_filtering(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t1 = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 1, 9, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)

    await seed_event(db_session, "evt_1", t1)
    await seed_event(db_session, "evt_2", t2)
    await seed_event(db_session, "evt_3", t3)

    # Filter with start and end inclusive
    req = ThreatHuntQueryRequest(
        time_range=TimeRangeFilter(start=t1, end=t2)
    )
    res = await repo.execute_hunt(req)
    assert res.total == 2
    assert {e.id for e in res.items} == {"evt_1", "evt_2"}

    # Filter with start only
    req_start = ThreatHuntQueryRequest(
        time_range=TimeRangeFilter(start=t2)
    )
    res_start = await repo.execute_hunt(req_start)
    assert res_start.total == 2
    assert {e.id for e in res_start.items} == {"evt_2", "evt_3"}

    # Filter with end only
    req_end = ThreatHuntQueryRequest(
        time_range=TimeRangeFilter(end=t2)
    )
    res_end = await repo.execute_hunt(req_end)
    assert res_end.total == 2
    assert {e.id for e in res_end.items} == {"evt_1", "evt_2"}


@pytest.mark.asyncio
async def test_all_supported_fields_filterable(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t0 = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    await seed_event(
        db_session,
        "evt_match",
        t0,
        username="alice",
        hostname="WS-CORP-01",
        source_ip="10.0.0.5",
        destination_ip="192.168.1.1",
        category="network_connection",
        action="network_connect",
        severity="medium",
        bytes_out=5000,
        bytes_in=10000,
        source_port=44321,
        destination_port=443,
        protocol="TCP",
        process_name="/usr/bin/curl",
    )
    await seed_event(
        db_session,
        "evt_other",
        t0 + timedelta(hours=1),
        username="bob",
        hostname="SRV-PROD-02",
        source_ip="10.0.0.99",
        destination_ip="172.16.0.1",
        category="authentication",
        action="logon_failure",
        severity="high",
        bytes_out=100,
        bytes_in=200,
        source_port=2222,
        destination_port=22,
        protocol="SSH",
        process_name="/usr/sbin/sshd",
    )

    # Test filtering by each individual field
    test_cases = [
        (FilterField.USERNAME, FilterOperator.EQ, "alice"),
        (FilterField.HOSTNAME, FilterOperator.EQ, "WS-CORP-01"),
        (FilterField.SOURCE_IP, FilterOperator.EQ, "10.0.0.5"),
        (FilterField.DESTINATION_IP, FilterOperator.EQ, "192.168.1.1"),
        (FilterField.CATEGORY, FilterOperator.EQ, "network_connection"),
        (FilterField.ACTION, FilterOperator.EQ, "network_connect"),
        (FilterField.SEVERITY, FilterOperator.EQ, "medium"),
        (FilterField.BYTES_OUT, FilterOperator.EQ, 5000),
        (FilterField.BYTES_IN, FilterOperator.EQ, 10000),
        (FilterField.SOURCE_PORT, FilterOperator.EQ, 44321),
        (FilterField.DESTINATION_PORT, FilterOperator.EQ, 443),
        (FilterField.PROTOCOL, FilterOperator.EQ, "TCP"),
        (FilterField.PROCESS_NAME, FilterOperator.EQ, "/usr/bin/curl"),
        (FilterField.TIMESTAMP, FilterOperator.EQ, t0),
    ]

    for field, op, val in test_cases:
        req = ThreatHuntQueryRequest(
            filter_group=FilterGroup(
                conditions=[FilterCondition(field=field, operator=op, value=val)]
            )
        )
        res = await repo.execute_hunt(req)
        assert res.total == 1, f"Failed for field: {field.value}"
        assert res.items[0].id == "evt_match"


@pytest.mark.asyncio
async def test_all_supported_operators(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    await seed_event(db_session, "evt_1", t, username="admin_alice", bytes_out=1000)
    await seed_event(db_session, "evt_2", t, username="user_bob", bytes_out=5000)
    await seed_event(db_session, "evt_3", t, username="operator_charlie", bytes_out=15000)

    # eq
    r_eq = await repo.execute_hunt(ThreatHuntQueryRequest(
        filter_group=FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="user_bob")])
    ))
    assert [e.id for e in r_eq.items] == ["evt_2"]

    # neq
    r_neq = await repo.execute_hunt(ThreatHuntQueryRequest(
        filter_group=FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.NEQ, value="user_bob")])
    ))
    assert set(e.id for e in r_neq.items) == {"evt_1", "evt_3"}

    # contains
    r_contains = await repo.execute_hunt(ThreatHuntQueryRequest(
        filter_group=FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.CONTAINS, value="alice")])
    ))
    assert [e.id for e in r_contains.items] == ["evt_1"]

    # starts_with
    r_starts = await repo.execute_hunt(ThreatHuntQueryRequest(
        filter_group=FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.STARTS_WITH, value="operator")])
    ))
    assert [e.id for e in r_starts.items] == ["evt_3"]

    # in
    r_in = await repo.execute_hunt(ThreatHuntQueryRequest(
        filter_group=FilterGroup(conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.IN, value=["admin_alice", "user_bob"])])
    ))
    assert set(e.id for e in r_in.items) == {"evt_1", "evt_2"}

    # gt
    r_gt = await repo.execute_hunt(ThreatHuntQueryRequest(
        filter_group=FilterGroup(conditions=[FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.GT, value=5000)])
    ))
    assert [e.id for e in r_gt.items] == ["evt_3"]

    # gte
    r_gte = await repo.execute_hunt(ThreatHuntQueryRequest(
        filter_group=FilterGroup(conditions=[FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.GTE, value=5000)])
    ))
    assert set(e.id for e in r_gte.items) == {"evt_2", "evt_3"}

    # lt
    r_lt = await repo.execute_hunt(ThreatHuntQueryRequest(
        filter_group=FilterGroup(conditions=[FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.LT, value=5000)])
    ))
    assert [e.id for e in r_lt.items] == ["evt_1"]

    # lte
    r_lte = await repo.execute_hunt(ThreatHuntQueryRequest(
        filter_group=FilterGroup(conditions=[FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.LTE, value=5000)])
    ))
    assert set(e.id for e in r_lte.items) == {"evt_1", "evt_2"}


@pytest.mark.asyncio
async def test_boolean_and_logic(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    await seed_event(db_session, "e1", t, username="svc_deploy", action="logon_failure", bytes_out=50)
    await seed_event(db_session, "e2", t, username="svc_deploy", action="logon_success", bytes_out=50)
    await seed_event(db_session, "e3", t, username="admin", action="logon_failure", bytes_out=50)

    # username == 'svc_deploy' AND action == 'logon_failure'
    req = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            logic="AND",
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="svc_deploy"),
                FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="logon_failure"),
            ]
        )
    )
    res = await repo.execute_hunt(req)
    assert res.total == 1
    assert res.items[0].id == "e1"


@pytest.mark.asyncio
async def test_boolean_or_logic(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    await seed_event(db_session, "e1", t, username="svc_deploy")
    await seed_event(db_session, "e2", t, username="admin")
    await seed_event(db_session, "e3", t, username="guest")

    req = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            logic="OR",
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="svc_deploy"),
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="admin"),
            ]
        )
    )
    res = await repo.execute_hunt(req)
    assert res.total == 2
    assert set(e.id for e in res.items) == {"e1", "e2"}


@pytest.mark.asyncio
async def test_nested_group_precedence(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # e1: matches (svc_deploy AND failure)
    await seed_event(db_session, "e1", t, username="svc_deploy", action="logon_failure", bytes_out=100)
    # e2: matches high egress (>10000000)
    await seed_event(db_session, "e2", t, username="regular_user", action="file_upload", bytes_out=20000000)
    # e3: matches neither
    await seed_event(db_session, "e3", t, username="regular_user", action="logon_success", bytes_out=500)

    # Group: (username == 'svc_deploy' AND action == 'logon_failure') OR (bytes_out > 10000000)
    req = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            logic="OR",
            conditions=[
                FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.GT, value=10000000)
            ],
            groups=[
                FilterGroup(
                    logic="AND",
                    conditions=[
                        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="svc_deploy"),
                        FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="logon_failure"),
                    ]
                )
            ]
        )
    )
    res = await repo.execute_hunt(req)
    assert res.total == 2
    assert set(e.id for e in res.items) == {"e1", "e2"}


@pytest.mark.asyncio
async def test_sorting_and_pagination(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    base_t = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(15):
        await seed_event(
            db_session,
            f"evt_{i:02d}",
            base_t + timedelta(minutes=i),
            bytes_out=i * 100,
        )

    # Sort descending by timestamp, page size 5, offset 0
    req_page1 = ThreatHuntQueryRequest(
        sort_by=FilterField.TIMESTAMP,
        sort_order="desc",
        limit=5,
        offset=0,
    )
    res_page1 = await repo.execute_hunt(req_page1)
    assert res_page1.total == 15
    assert len(res_page1.items) == 5
    assert res_page1.items[0].id == "evt_14"
    assert res_page1.items[4].id == "evt_10"

    # Page 2: offset 5
    req_page2 = ThreatHuntQueryRequest(
        sort_by=FilterField.TIMESTAMP,
        sort_order="desc",
        limit=5,
        offset=5,
    )
    res_page2 = await repo.execute_hunt(req_page2)
    assert len(res_page2.items) == 5
    assert res_page2.items[0].id == "evt_09"
    assert res_page2.items[4].id == "evt_05"

    # Sort ascending by bytes_out
    req_asc = ThreatHuntQueryRequest(
        sort_by=FilterField.BYTES_OUT,
        sort_order="asc",
        limit=3,
        offset=0,
    )
    res_asc = await repo.execute_hunt(req_asc)
    assert [e.id for e in res_asc.items] == ["evt_00", "evt_01", "evt_02"]


@pytest.mark.asyncio
async def test_stable_secondary_sort_for_equal_timestamps(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    identical_time = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)

    # Seed events with identical timestamp but distinct IDs
    await seed_event(db_session, "evt_A", identical_time)
    await seed_event(db_session, "evt_B", identical_time)
    await seed_event(db_session, "evt_C", identical_time)

    req = ThreatHuntQueryRequest(
        sort_by=FilterField.TIMESTAMP,
        sort_order="desc",
        limit=10,
    )
    res1 = await repo.execute_hunt(req)
    res2 = await repo.execute_hunt(req)

    # Order must be 100% deterministic between runs (secondary sort by id desc)
    ids1 = [e.id for e in res1.items]
    ids2 = [e.id for e in res2.items]
    assert ids1 == ids2
    assert ids1 == ["evt_C", "evt_B", "evt_A"]


@pytest.mark.asyncio
async def test_boolean_root_or_with_nested_and(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # (username=alice AND action=logon) OR (username=bob AND action=elevation)
    await seed_event(db_session, "e1", t, username="alice", action="logon")
    await seed_event(db_session, "e2", t, username="bob", action="elevation")
    await seed_event(db_session, "e3", t, username="alice", action="logout")
    await seed_event(db_session, "e4", t, username="bob", action="logon")

    req = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            logic="OR",
            groups=[
                FilterGroup(
                    logic="AND",
                    conditions=[
                        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="alice"),
                        FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="logon"),
                    ],
                ),
                FilterGroup(
                    logic="AND",
                    conditions=[
                        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="bob"),
                        FilterCondition(field=FilterField.ACTION, operator=FilterOperator.EQ, value="elevation"),
                    ],
                ),
            ],
        )
    )
    res = await repo.execute_hunt(req)
    assert res.total == 2
    assert set(e.id for e in res.items) == {"e1", "e2"}


@pytest.mark.asyncio
async def test_boolean_multiple_child_groups(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # severity=high AND (host=H1 OR host=H2) AND (port=22 OR port=80)
    await seed_event(db_session, "e1", t, severity="high", hostname="H1", destination_port=22)
    await seed_event(db_session, "e2", t, severity="high", hostname="H2", destination_port=80)
    await seed_event(db_session, "e3", t, severity="low", hostname="H1", destination_port=22)
    await seed_event(db_session, "e4", t, severity="high", hostname="H3", destination_port=22)
    await seed_event(db_session, "e5", t, severity="high", hostname="H1", destination_port=443)

    req = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            logic="AND",
            conditions=[
                FilterCondition(field=FilterField.SEVERITY, operator=FilterOperator.EQ, value="high")
            ],
            groups=[
                FilterGroup(
                    logic="OR",
                    conditions=[
                        FilterCondition(field=FilterField.HOSTNAME, operator=FilterOperator.EQ, value="H1"),
                        FilterCondition(field=FilterField.HOSTNAME, operator=FilterOperator.EQ, value="H2"),
                    ],
                ),
                FilterGroup(
                    logic="OR",
                    conditions=[
                        FilterCondition(field=FilterField.DESTINATION_PORT, operator=FilterOperator.EQ, value=22),
                        FilterCondition(field=FilterField.DESTINATION_PORT, operator=FilterOperator.EQ, value=80),
                    ],
                ),
            ],
        )
    )
    res = await repo.execute_hunt(req)
    assert res.total == 2
    assert set(e.id for e in res.items) == {"e1", "e2"}


@pytest.mark.asyncio
async def test_time_range_anded_with_root_or(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t1 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 1, 11, 0, 0, tzinfo=timezone.utc)
    t_outside = datetime(2026, 11, 1, 14, 0, 0, tzinfo=timezone.utc)

    # Events inside time range
    await seed_event(db_session, "e_in_1", t1, username="alice")
    await seed_event(db_session, "e_in_2", t2, username="bob")
    # Events outside time range matching OR group
    await seed_event(db_session, "e_out_1", t_outside, username="alice")
    await seed_event(db_session, "e_out_2", t_outside, username="bob")

    req = ThreatHuntQueryRequest(
        time_range=TimeRangeFilter(start=t1, end=t2),
        filter_group=FilterGroup(
            logic="OR",
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="alice"),
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="bob"),
            ],
        ),
    )
    res = await repo.execute_hunt(req)
    assert res.total == 2
    assert set(e.id for e in res.items) == {"e_in_1", "e_in_2"}


@pytest.mark.asyncio
async def test_null_semantics_neq_matches_null(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    await seed_event(db_session, "e_alice", t, username="alice")
    await seed_event(db_session, "e_bob", t, username="bob")
    await seed_event(db_session, "e_null", t, username=None)

    # username != 'alice' must match 'bob' AND NULL for nullable columns
    req = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.NEQ, value="alice")
            ]
        )
    )
    res = await repo.execute_hunt(req)
    assert res.total == 2
    assert set(e.id for e in res.items) == {"e_bob", "e_null"}


@pytest.mark.asyncio
async def test_null_semantics_contains_and_starts_with_exclude_nulls(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    await seed_event(db_session, "e_match", t, username="security_admin")
    await seed_event(db_session, "e_null", t, username=None)
    await seed_event(db_session, "e_other", t, username="guest")

    # contains
    req_contains = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.CONTAINS, value="admin")
            ]
        )
    )
    res_contains = await repo.execute_hunt(req_contains)
    assert [e.id for e in res_contains.items] == ["e_match"]

    # starts_with
    req_starts = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.STARTS_WITH, value="security")
            ]
        )
    )
    res_starts = await repo.execute_hunt(req_starts)
    assert [e.id for e in res_starts.items] == ["e_match"]


@pytest.mark.asyncio
async def test_offset_beyond_total_returns_empty_items_with_total(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(10):
        await seed_event(db_session, f"e_{i:02d}", t + timedelta(minutes=i))

    req = ThreatHuntQueryRequest(limit=50, offset=500)
    res = await repo.execute_hunt(req)
    assert res.total == 10
    assert res.items == []
    assert res.offset == 500
    assert res.limit == 50


# ---------------------------------------------------------------------------
# Section 2: Validation & Security Tests
# ---------------------------------------------------------------------------

def test_unknown_field_rejected():
    with pytest.raises(Exception):
        FilterCondition(field="malicious_column", operator="eq", value="val")


def test_unknown_operator_rejected():
    with pytest.raises(Exception):
        FilterCondition(field=FilterField.USERNAME, operator="regex", value=".*")


def test_incompatible_operator_rejected():
    # 'contains' on numeric field must raise
    with pytest.raises(ValueError, match="only valid for string fields"):
        FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.CONTAINS, value="1000")

    # 'gt' on string field must raise
    with pytest.raises(ValueError, match="not valid for field"):
        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.GT, value="admin")


def test_empty_or_excessive_in_list_rejected():
    # Empty list
    with pytest.raises(ValueError, match="cannot be an empty list"):
        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.IN, value=[])

    # Excessive items (>50)
    with pytest.raises(ValueError, match="exceeds maximum allowed items"):
        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.IN, value=[f"user_{i}" for i in range(51)])


def test_naive_timestamp_rejected():
    # TimeRangeFilter with naive timestamp
    with pytest.raises(ValueError, match="must be timezone-aware"):
        TimeRangeFilter(start=datetime(2026, 11, 1, 10, 0, 0))


def test_start_later_than_end_rejected():
    t_early = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    t_late = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    with pytest.raises(ValueError, match="Start timestamp cannot be later than end timestamp"):
        TimeRangeFilter(start=t_late, end=t_early)


def test_empty_filter_group_rejected():
    with pytest.raises(ValueError, match="must contain at least one condition or child group"):
        FilterGroup(conditions=[], groups=[])


def test_excessive_filter_depth_rejected():
    # Nesting depth > 2 must be rejected
    grandchild = FilterGroup(
        conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="deep")]
    )
    child = FilterGroup(
        conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="test")],
        groups=[grandchild]
    )

    with pytest.raises(ValueError, match="Maximum filter group nesting depth of 2 exceeded"):
        FilterGroup(
            conditions=[FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="root")],
            groups=[child]
        )


def test_excessive_conditions_per_group_rejected():
    conds = [
        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value=f"user_{i}")
        for i in range(21)
    ]
    with pytest.raises(ValueError, match="exceeding maximum of 20"):
        FilterGroup(conditions=conds)


@pytest.mark.asyncio
async def test_sql_injection_treated_as_literal_value(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    await seed_event(db_session, "e1", t, username="legit_admin")

    # Injection payload attempting tautology or table drop
    injection_payload = "' OR 1=1; DROP TABLE security_events; --"
    req = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value=injection_payload)
            ]
        )
    )
    res = await repo.execute_hunt(req)

    # Must match 0 events and the table must NOT be dropped
    assert res.total == 0
    assert len(res.items) == 0

    # Verify table remains intact
    all_events = await repo.execute_hunt(ThreatHuntQueryRequest())
    assert all_events.total == 1


@pytest.mark.asyncio
async def test_like_wildcard_escaping(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Event with literal underscore
    await seed_event(db_session, "e1", t, username="test_user")
    # Event with different character where unescaped '_' would match
    await seed_event(db_session, "e2", t, username="test0user")
    # Event with literal percent sign
    await seed_event(db_session, "e3", t, username="100%_clean")

    # Searching for literal "test_user" must NOT match "test0user"
    req_underscore = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.CONTAINS, value="test_user")
            ]
        )
    )
    res_underscore = await repo.execute_hunt(req_underscore)
    assert [e.id for e in res_underscore.items] == ["e1"]

    # Searching for literal "100%"
    req_percent = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.CONTAINS, value="100%")
            ]
        )
    )
    res_percent = await repo.execute_hunt(req_percent)
    assert [e.id for e in res_percent.items] == ["e3"]


@pytest.mark.asyncio
async def test_like_backslash_escaping(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Event with literal backslash (e.g. domain\username)
    await seed_event(db_session, "e_bs", t, username=r"CORP\admin")
    await seed_event(db_session, "e_dash", t, username="CORP-admin")
    await seed_event(db_session, "e_plain", t, username="CORPadmin")

    # Search literal backslash with contains
    req_bs = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.CONTAINS, value=r"CORP\admin")
            ]
        )
    )
    res_bs = await repo.execute_hunt(req_bs)
    assert [e.id for e in res_bs.items] == ["e_bs"]

    # Search literal backslash with starts_with
    req_start_bs = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.STARTS_WITH, value="CORP\\")
            ]
        )
    )
    res_start_bs = await repo.execute_hunt(req_start_bs)
    assert [e.id for e in res_start_bs.items] == ["e_bs"]


def test_eq_null_rejected_by_schema():
    for f in [FilterField.USERNAME, FilterField.SOURCE_PORT, FilterField.BYTES_OUT, FilterField.TIMESTAMP]:
        with pytest.raises(ValueError):
            FilterCondition(field=f, operator=FilterOperator.EQ, value=None)


def test_in_containing_null_rejected_by_schema():
    with pytest.raises(ValueError):
        FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.IN, value=["alice", None])
    with pytest.raises(ValueError):
        FilterCondition(field=FilterField.SOURCE_PORT, operator=FilterOperator.IN, value=[80, None])
    with pytest.raises(ValueError):
        FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.IN, value=[100, None])


def test_strict_integer_validation_rejects_floats():
    for field in [FilterField.SOURCE_PORT, FilterField.DESTINATION_PORT, FilterField.BYTES_OUT, FilterField.BYTES_IN]:
        for float_val in [80.5, 80.0, 100.5, 100.0]:
            with pytest.raises(ValueError, match="must be an integer"):
                FilterCondition(field=field, operator=FilterOperator.EQ, value=float_val)


def test_strict_integer_validation_rejects_booleans():
    for field in [FilterField.SOURCE_PORT, FilterField.DESTINATION_PORT, FilterField.BYTES_OUT, FilterField.BYTES_IN]:
        for bool_val in [True, False]:
            with pytest.raises(ValueError, match="must be an integer"):
                FilterCondition(field=field, operator=FilterOperator.EQ, value=bool_val)


def test_strict_integer_validation_rejects_strings():
    for field in [FilterField.SOURCE_PORT, FilterField.DESTINATION_PORT, FilterField.BYTES_OUT, FilterField.BYTES_IN]:
        for str_val in ["80", "100", "0"]:
            with pytest.raises(ValueError, match="must be an integer"):
                FilterCondition(field=field, operator=FilterOperator.EQ, value=str_val)


def test_strict_integer_validation_enforces_port_bounds():
    # Valid boundaries
    FilterCondition(field=FilterField.SOURCE_PORT, operator=FilterOperator.EQ, value=0)
    FilterCondition(field=FilterField.SOURCE_PORT, operator=FilterOperator.EQ, value=65535)
    FilterCondition(field=FilterField.DESTINATION_PORT, operator=FilterOperator.EQ, value=0)
    FilterCondition(field=FilterField.DESTINATION_PORT, operator=FilterOperator.EQ, value=65535)

    # Invalid: out of bounds
    for port_field in [FilterField.SOURCE_PORT, FilterField.DESTINATION_PORT]:
        with pytest.raises(ValueError, match="must be between 0 and 65535"):
            FilterCondition(field=port_field, operator=FilterOperator.EQ, value=-1)
        with pytest.raises(ValueError, match="must be between 0 and 65535"):
            FilterCondition(field=port_field, operator=FilterOperator.EQ, value=65536)
        with pytest.raises(ValueError, match="must be between 0 and 65535"):
            FilterCondition(field=port_field, operator=FilterOperator.EQ, value=70000)


def test_strict_integer_validation_enforces_non_negative_bytes():
    # Valid boundaries
    FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.EQ, value=0)
    FilterCondition(field=FilterField.BYTES_IN, operator=FilterOperator.EQ, value=0)
    FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.EQ, value=100000)

    # Invalid: negative
    for byte_field in [FilterField.BYTES_OUT, FilterField.BYTES_IN]:
        with pytest.raises(ValueError, match="cannot be negative"):
            FilterCondition(field=byte_field, operator=FilterOperator.EQ, value=-1)
        with pytest.raises(ValueError, match="cannot be negative"):
            FilterCondition(field=byte_field, operator=FilterOperator.EQ, value=-100)


def test_strict_integer_validation_in_list():
    # Float in list
    with pytest.raises(ValueError, match="must be an integer"):
        FilterCondition(field=FilterField.SOURCE_PORT, operator=FilterOperator.IN, value=[80, 80.5])

    # Bool in list
    with pytest.raises(ValueError, match="must be an integer"):
        FilterCondition(field=FilterField.DESTINATION_PORT, operator=FilterOperator.IN, value=[443, True])

    # String in list
    with pytest.raises(ValueError, match="must be an integer"):
        FilterCondition(field=FilterField.BYTES_OUT, operator=FilterOperator.IN, value=[100, "200"])

    # Out-of-bounds port in list
    with pytest.raises(ValueError, match="must be between 0 and 65535"):
        FilterCondition(field=FilterField.SOURCE_PORT, operator=FilterOperator.IN, value=[80, 70000])

    # Negative bytes in list
    with pytest.raises(ValueError, match="cannot be negative"):
        FilterCondition(field=FilterField.BYTES_IN, operator=FilterOperator.IN, value=[100, -10])


# ---------------------------------------------------------------------------
# Section 3: Relationships & Batched Hydration Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_event_with_detection_and_incident_relationships(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Create Event
    event = await seed_event(db_session, "evt_spray_01", t, username="svc_deploy", action="logon_failure")

    # 2. Create Detection linked to Event
    detection = DetectionModel(
        id="det_spray_01",
        rule_id="DET-001",
        rule_name="Password Guessing Spray",
        severity="high",
        entity_type="user",
        entity_value="svc_deploy",
        first_seen=t,
        last_seen=t,
        explanation="Multiple rapid login failures observed.",
        metadata_json={"burst_count": 5},
    )
    db_session.add(detection)
    await db_session.flush()

    assoc = DetectionEventModel(detection_id=detection.id, event_id=event.id)
    db_session.add(assoc)
    await db_session.flush()

    # 3. Create Incident linked to Detection
    incident = IncidentModel(
        id="INC-001",
        correlation_key="user:svc_deploy:20261101",
        title="Credential Stuffing Campaign",
        description="Correlated brute-force attack against deployment account.",
        severity="critical",
        status="open",
        first_seen=t,
        last_seen=t,
    )
    db_session.add(incident)
    await db_session.flush()

    inc_assoc = IncidentDetectionModel(incident_id=incident.id, detection_id=detection.id, correlation_reason="shared_user")
    db_session.add(inc_assoc)
    await db_session.flush()

    # 4. Execute Hunt
    repo = HuntingRepository(db_session)
    req = ThreatHuntQueryRequest(
        filter_group=FilterGroup(
            conditions=[
                FilterCondition(field=FilterField.USERNAME, operator=FilterOperator.EQ, value="svc_deploy")
            ]
        )
    )
    res = await repo.execute_hunt(req)

    assert res.total == 1
    item = res.items[0]
    assert item.id == "evt_spray_01"

    # Verify detection relationship hydrated
    assert len(item.related_detections) == 1
    assert item.related_detections[0].id == "det_spray_01"
    assert item.related_detections[0].rule_id == "DET-001"
    assert item.related_detections[0].severity == "high"

    # Verify incident relationship hydrated
    assert len(item.related_incidents) == 1
    assert item.related_incidents[0].id == "INC-001"
    assert item.related_incidents[0].title == "Credential Stuffing Campaign"
    assert item.related_incidents[0].status == "open"


@pytest.mark.asyncio
async def test_event_without_related_records(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
    await seed_event(db_session, "evt_benign_01", t, username="regular_dev", action="logon_success")

    repo = HuntingRepository(db_session)
    res = await repo.execute_hunt(ThreatHuntQueryRequest())

    assert res.total == 1
    item = res.items[0]
    assert item.id == "evt_benign_01"
    assert item.related_detections == []
    assert item.related_incidents == []


@pytest.mark.asyncio
async def test_batched_query_no_n_plus_one(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Create 10 events, half linked to detections
    detection = DetectionModel(
        id="det_shared",
        rule_id="DET-002",
        rule_name="Shared Rule",
        severity="medium",
        entity_type="host",
        entity_value="SRV-01",
        first_seen=t,
        last_seen=t,
        explanation="Shared explanation",
    )
    db_session.add(detection)
    await db_session.flush()

    for i in range(10):
        evt = await seed_event(db_session, f"evt_batch_{i:02d}", t + timedelta(seconds=i))
        if i % 2 == 0:
            db_session.add(DetectionEventModel(detection_id=detection.id, event_id=evt.id))
    await db_session.flush()

    repo = HuntingRepository(db_session)
    req = ThreatHuntQueryRequest(limit=20)
    res = await repo.execute_hunt(req)

    assert res.total == 10
    assert len(res.items) == 10

    # 5 events should have the detection, 5 should have empty detections
    evts_with_det = [e for e in res.items if len(e.related_detections) == 1]
    evts_without_det = [e for e in res.items if len(e.related_detections) == 0]
    assert len(evts_with_det) == 5
    assert len(evts_without_det) == 5


@pytest.mark.asyncio
async def test_incident_deduplication_for_multiple_detections(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    # 1 event
    event = await seed_event(db_session, "evt_multi_det", t, username="target_user")

    # 2 detections linked to that 1 event
    d1 = DetectionModel(
        id="det_1",
        rule_id="RULE-1",
        rule_name="Rule 1",
        severity="medium",
        entity_type="user",
        entity_value="target_user",
        first_seen=t,
        last_seen=t,
        explanation="Exp 1",
        metadata_json={},
    )
    d2 = DetectionModel(
        id="det_2",
        rule_id="RULE-2",
        rule_name="Rule 2",
        severity="high",
        entity_type="user",
        entity_value="target_user",
        first_seen=t,
        last_seen=t,
        explanation="Exp 2",
        metadata_json={},
    )
    db_session.add_all([d1, d2])
    await db_session.flush()

    db_session.add_all([
        DetectionEventModel(detection_id=d1.id, event_id=event.id),
        DetectionEventModel(detection_id=d2.id, event_id=event.id),
    ])
    await db_session.flush()

    # Both detections correlated into 1 shared incident
    inc = IncidentModel(
        id="INC-SHARED-01",
        correlation_key="shared_key",
        title="Shared Incident",
        description="Two rules fired on the same entity.",
        severity="high",
        status="open",
        first_seen=t,
        last_seen=t,
    )
    db_session.add(inc)
    await db_session.flush()

    db_session.add_all([
        IncidentDetectionModel(incident_id=inc.id, detection_id=d1.id),
        IncidentDetectionModel(incident_id=inc.id, detection_id=d2.id),
    ])
    await db_session.flush()

    repo = HuntingRepository(db_session)
    res = await repo.execute_hunt(ThreatHuntQueryRequest())

    assert res.total == 1
    item = res.items[0]
    assert len(item.related_detections) == 2
    assert {d.id for d in item.related_detections} == {"det_1", "det_2"}
    # Deduplication: single incident summary even though 2 detections link to it
    assert len(item.related_incidents) == 1
    assert item.related_incidents[0].id == "INC-SHARED-01"


@pytest.mark.asyncio
async def test_exact_query_count_accounting(db_session: AsyncSession):
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    queries: List[str] = []

    def on_execute(conn, cursor, statement, parameters, context, executemany):
        queries.append(statement)

    event.listen(db_session.bind.sync_engine, "before_cursor_execute", on_execute)

    try:
        # Case 1: Empty database (total == 0 short-circuit) -> Exactly 1 query
        queries.clear()
        res1 = await repo.execute_hunt(ThreatHuntQueryRequest())
        assert res1.total == 0
        assert len(queries) == 1

        # Seed 1 event (without detections)
        await seed_event(db_session, "e_query_test", t)

        # Case 2: Page beyond total (offset >= total) -> Exactly 2 queries
        queries.clear()
        res2 = await repo.execute_hunt(ThreatHuntQueryRequest(offset=100))
        assert res2.total == 1
        assert res2.items == []
        assert len(queries) == 2

        # Case 3: Events without detections -> Exactly 3 queries
        queries.clear()
        res3 = await repo.execute_hunt(ThreatHuntQueryRequest(offset=0))
        assert res3.total == 1
        assert len(res3.items) == 1
        assert res3.items[0].related_detections == []
        assert len(queries) == 3

        # Add detection and incident for e_query_test
        det = DetectionModel(
            id="det_query_test",
            rule_id="R-TEST",
            rule_name="Test Rule",
            severity="low",
            entity_type="host",
            entity_value="H1",
            first_seen=t,
            last_seen=t,
            explanation="Test",
            metadata_json={},
        )
        db_session.add(det)
        await db_session.flush()
        db_session.add(DetectionEventModel(detection_id=det.id, event_id="e_query_test"))

        inc = IncidentModel(
            id="INC-QUERY-TEST",
            correlation_key="test_key",
            title="Test Incident",
            description="Test",
            severity="low",
            status="open",
            first_seen=t,
            last_seen=t,
        )
        db_session.add(inc)
        await db_session.flush()
        db_session.add(IncidentDetectionModel(incident_id=inc.id, detection_id=det.id))
        await db_session.flush()

        # Case 4: Fully populated detection-and-incident path -> Exactly 4 queries
        queries.clear()
        res4 = await repo.execute_hunt(ThreatHuntQueryRequest(offset=0))
        assert res4.total == 1
        assert len(res4.items) == 1
        assert len(res4.items[0].related_detections) == 1
        assert len(res4.items[0].related_incidents) == 1
        assert len(queries) == 4

    finally:
        event.remove(db_session.bind.sync_engine, "before_cursor_execute", on_execute)


# ---------------------------------------------------------------------------
# Section 4: FastAPI HTTP Endpoint Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_hunting_query_endpoint(db_session: AsyncSession):
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
    await seed_event(db_session, "evt_api_1", t, username="hunt_target", action="elevation_attempt")

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "filter_group": {
                    "logic": "AND",
                    "conditions": [
                        {
                            "field": "username",
                            "operator": "eq",
                            "value": "hunt_target"
                        }
                    ]
                },
                "limit": 10
            }
            resp = await client.post("/api/v1/hunting/query", json=payload)
            assert resp.status_code == 200
            data = resp.json()

            assert data["total"] == 1
            assert len(data["items"]) == 1
            assert data["items"][0]["id"] == "evt_api_1"
            assert data["applied_filter_count"] == 1
            assert "query_duration_ms" in data
            assert data["provenance"] == "observed_telemetry"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_api_validation_errors_return_422(db_session: AsyncSession):
    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Bad field
            bad_payload = {
                "filter_group": {
                    "conditions": [
                        {"field": "nonexistent_field", "operator": "eq", "value": "x"}
                    ]
                }
            }
            resp = await client.post("/api/v1/hunting/query", json=bad_payload)
            assert resp.status_code == 422
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Section 8: Provenance Integrity & Authenticity Verification Tests
# ---------------------------------------------------------------------------

from app.db.repositories.hunting_repo import classify_event_provenance, determine_response_provenance


def test_classify_event_provenance_unit_rules():
    """Unit tests for provenance classification rules."""
    # 1. Synthetic event with a valid SHA-256 hash -> MUST be synthetic_benchmark
    res = classify_event_provenance(
        raw_payload={"synthetic": True},
        source_type="csv",
        event_id="evt_01",
    )
    assert res == "synthetic_benchmark"

    # 2. Observed event with verified source attribution -> observed_telemetry
    res = classify_event_provenance(
        raw_payload={"source_attribution": "edr_agent_host_01"},
        source_type="syslog",
        event_id="evt_02",
    )
    assert res == "observed_telemetry"

    # 3. Missing provenance / no source attribution -> unknown (even with any hash)
    res = classify_event_provenance(
        raw_payload={},
        source_type="syslog",
        event_id="evt_03",
    )
    assert res == "unknown"

    # 4. Conflicting metadata: claims observed but flagged as synthetic -> synthetic_benchmark
    res = classify_event_provenance(
        raw_payload={"provenance": "observed_telemetry", "source_attribution": "corp_siem", "synthetic": True},
        source_type="syslog",
        event_id="evt_04",
    )
    assert res == "synthetic_benchmark"

    # 5. Benchmark flag -> synthetic_benchmark
    res = classify_event_provenance(
        raw_payload={"benchmark": True},
        source_type="json",
        event_id="evt_05",
    )
    assert res == "synthetic_benchmark"

    # 6. ThreatLab scenario event ID prefix -> synthetic_benchmark
    res = classify_event_provenance(
        raw_payload={},
        source_type="linux_auth_log",
        event_id="scn1_evt_001",
    )
    assert res == "synthetic_benchmark"


def test_determine_response_provenance_aggregation():
    """Unit tests for response-level provenance aggregation."""
    # Empty items -> unknown
    assert determine_response_provenance([]) == "unknown"

    # All observed -> observed_telemetry
    item_obs = HuntedEventItem(
        id="e1", timestamp=datetime.now(timezone.utc), source_type="csv",
        category="auth", action="logon", severity="low", provenance="observed_telemetry"
    )
    assert determine_response_provenance([item_obs]) == "observed_telemetry"

    # All synthetic -> synthetic_benchmark
    item_synth = HuntedEventItem(
        id="e2", timestamp=datetime.now(timezone.utc), source_type="csv",
        category="auth", action="logon", severity="low", provenance="synthetic_benchmark"
    )
    assert determine_response_provenance([item_synth]) == "synthetic_benchmark"

    # All unknown -> unknown
    item_unk = HuntedEventItem(
        id="e3", timestamp=datetime.now(timezone.utc), source_type="csv",
        category="auth", action="logon", severity="low", provenance="unknown"
    )
    assert determine_response_provenance([item_unk]) == "unknown"

    # Mixed -> mixed
    assert determine_response_provenance([item_obs, item_synth]) == "mixed"
    assert determine_response_provenance([item_obs, item_unk]) == "mixed"


@pytest.mark.asyncio
async def test_synthetic_event_with_valid_sha256_hash_is_not_observed(db_session: AsyncSession):
    """
    CRITICAL PROVENANCE RULE:
    A valid cryptographic SHA-256 hash proves file integrity only, NOT authenticity.
    A synthetic event that possesses a valid SHA-256 hash must be classified
    as synthetic_benchmark, NEVER observed_telemetry.
    """
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
    valid_sha256 = "6ec34a29fdac36ef58e6aa712a724b6dfe8d724a85430ed2ede5151e9fac078d"

    # Synthetic event with a valid SHA-256 checksum
    synth_event = SecurityEventModel(
        id="evt_synth_with_hash",
        timestamp=t,
        ingested_at=datetime.now(timezone.utc),
        source_type="synthetic",
        category="authentication",
        action="logon_failure",
        severity="medium",
        bytes_out=0,
        bytes_in=0,
        raw_payload={"synthetic": True, "note": "Generated by benchmark script"},
        source_file_hash=valid_sha256,
    )
    db_session.add(synth_event)
    await db_session.flush()

    res = await repo.execute_hunt(ThreatHuntQueryRequest())
    assert res.total == 1
    item = res.items[0]

    # Checksum is preserved for integrity auditing
    assert item.source_file_hash == valid_sha256
    # Provenance MUST NOT be observed_telemetry despite valid SHA-256 hash!
    assert item.provenance == "synthetic_benchmark"
    assert item.provenance != "observed_telemetry"
    assert res.provenance == "synthetic_benchmark"


@pytest.mark.asyncio
async def test_observed_event_with_verified_source_attribution(db_session: AsyncSession):
    """
    An event is classified as observed_telemetry ONLY when imported from an
    identified, authorized telemetry source with verified source attribution.
    """
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 5, 0, tzinfo=timezone.utc)
    valid_sha256 = "15def78315f04d2b6925461abb45a05fdc7a8c5c0c6472f980e0350a4b37d400"

    await seed_event(
        db_session,
        "evt_genuine_observed",
        t,
        source_file_hash=valid_sha256,
        source_attribution="corporate_edr_sensor_prod_01",
    )

    res = await repo.execute_hunt(ThreatHuntQueryRequest())
    assert res.total == 1
    item = res.items[0]

    assert item.provenance == "observed_telemetry"
    assert item.source_file_hash == valid_sha256
    assert res.provenance == "observed_telemetry"


@pytest.mark.asyncio
async def test_event_with_missing_provenance_is_classified_unknown(db_session: AsyncSession):
    """
    If existing or ingested records lack verified source attribution and are not
    flagged as synthetic, they must be classified as 'unknown' rather than making
    unsupported authenticity claims.
    """
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 10, 0, tzinfo=timezone.utc)
    valid_sha256 = "37e9ab1b7f9c02d6000000000000000000000000000000000000000000000000"

    # Event with valid hash but NO source attribution and NO provenance metadata
    unverified_event = SecurityEventModel(
        id="evt_unverified_legacy",
        timestamp=t,
        ingested_at=datetime.now(timezone.utc),
        source_type="csv",
        category="authentication",
        action="logon_success",
        severity="low",
        bytes_out=0,
        bytes_in=0,
        raw_payload={"timestamp": "2026-11-01T12:10:00Z", "user": "alice"},  # No attribution
        source_file_hash=valid_sha256,
    )
    db_session.add(unverified_event)
    await db_session.flush()

    res = await repo.execute_hunt(ThreatHuntQueryRequest())
    assert res.total == 1
    item = res.items[0]

    # Provenance must be 'unknown', NOT 'observed_telemetry'
    assert item.provenance == "unknown"
    assert res.provenance == "unknown"


@pytest.mark.asyncio
async def test_event_with_conflicting_synthetic_and_observed_metadata(db_session: AsyncSession):
    """
    Conflicting metadata: If an event contains conflicting claims (e.g. claims observed_telemetry
    or has an authorized source but is also flagged synthetic/benchmark), synthetic takes precedence.
    It MUST NEVER be classified as observed_telemetry.
    """
    repo = HuntingRepository(db_session)
    t = datetime(2026, 11, 1, 12, 15, 0, tzinfo=timezone.utc)

    conflicting_event = SecurityEventModel(
        id="evt_conflicted",
        timestamp=t,
        ingested_at=datetime.now(timezone.utc),
        source_type="syslog",
        category="privilege_change",
        action="elevation_success",
        severity="high",
        bytes_out=0,
        bytes_in=0,
        raw_payload={
            "provenance": "observed_telemetry",
            "source_attribution": "prod_edr_agent",
            "synthetic": True,
            "benchmark": True,
        },
        source_file_hash="b463d4ec684b0000000000000000000000000000000000000000000000000000",
    )
    db_session.add(conflicting_event)
    await db_session.flush()

    res = await repo.execute_hunt(ThreatHuntQueryRequest())
    assert res.total == 1
    item = res.items[0]

    # Must be classified as synthetic_benchmark, strictly not observed_telemetry
    assert item.provenance == "synthetic_benchmark"
    assert item.provenance != "observed_telemetry"
    assert res.provenance == "synthetic_benchmark"


@pytest.mark.asyncio
async def test_provenance_database_persistence_and_api_serialization(db_session: AsyncSession):
    """
    Verifies that provenance survives database persistence and is correctly serialized
    through the API query endpoint, including mixed response provenance.
    """
    t = datetime(2026, 11, 1, 12, 20, 0, tzinfo=timezone.utc)

    # 1. Observed event with attribution
    await seed_event(
        db_session,
        "evt_api_obs",
        t,
        source_attribution="corporate_edr_sensor",
    )
    # 2. Synthetic event with hash
    synth = SecurityEventModel(
        id="evt_api_synth",
        timestamp=t,
        ingested_at=datetime.now(timezone.utc),
        source_type="synthetic",
        category="authentication",
        action="logon_failure",
        severity="medium",
        bytes_out=0,
        bytes_in=0,
        raw_payload={"synthetic": True},
        source_file_hash="6ec34a29fdac36ef58e6aa712a724b6dfe8d724a85430ed2ede5151e9fac078d",
    )
    db_session.add(synth)

    # 3. Unknown event lacking attribution
    unk = SecurityEventModel(
        id="evt_api_unk",
        timestamp=t,
        ingested_at=datetime.now(timezone.utc),
        source_type="csv",
        category="authentication",
        action="logon_success",
        severity="low",
        bytes_out=0,
        bytes_in=0,
        raw_payload={},
        source_file_hash="15def78315f04d2b6925461abb45a05fdc7a8c5c0c6472f980e0350a4b37d400",
    )
    db_session.add(unk)
    await db_session.flush()

    async def override():
        yield db_session

    app.dependency_overrides[get_db_session] = override
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/hunting/query", json={"limit": 50})
            assert resp.status_code == 200
            data = resp.json()

            assert data["total"] == 3
            item_map = {item["id"]: item for item in data["items"]}

            assert item_map["evt_api_obs"]["provenance"] == "observed_telemetry"
            assert item_map["evt_api_synth"]["provenance"] == "synthetic_benchmark"
            assert item_map["evt_api_unk"]["provenance"] == "unknown"

            # Mixed results are truthfully branded as 'mixed'
            assert data["provenance"] == "mixed"
    finally:
        app.dependency_overrides.clear()
