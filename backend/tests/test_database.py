"""
Database persistence and repository tests for CyberTrace.
Verifies idempotency, referential integrity, transaction rollbacks, and UTC timestamp handling.
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.correlation.models import CorrelatedEntity, CorrelatedIncidentGroup
from app.db.models import DetectionEventModel, IncidentDetectionModel, SecurityEventModel
from app.db.repositories.detection_repo import DetectionRepository
from app.db.repositories.event_repo import EventRepository
from app.db.repositories.incident_repo import IncidentRepository
from app.rules.base import DetectionResult
from app.schemas.ces import CommonEvent, EventAction, EventCategory, EventSeverity


@pytest.mark.asyncio
async def test_event_persistence_and_retrieval(db_session: AsyncSession):
    repo = EventRepository(db_session)
    now = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)

    event = CommonEvent(
        event_id="evt_test_001",
        timestamp=now,
        category=EventCategory.AUTHENTICATION,
        action=EventAction.LOGON_FAILURE,
        severity=EventSeverity.MEDIUM,
        user_identity="svc_deploy",
        source_ip="198.51.100.44",
        hostname="SRV-APP-01",
        source_format="linux_auth_log",
    )

    persisted = await repo.upsert_events([event], source_file_hash="hash123")
    assert len(persisted) == 1
    assert persisted[0].id == "evt_test_001"
    assert persisted[0].username == "svc_deploy"
    assert persisted[0].timestamp.tzinfo is not None

    # Retrieve by ID
    retrieved = await repo.get_by_id("evt_test_001")
    assert retrieved is not None
    assert retrieved.source_ip == "198.51.100.44"
    assert retrieved.source_file_hash == "hash123"


@pytest.mark.asyncio
async def test_duplicate_event_ingestion_is_idempotent(db_session: AsyncSession):
    repo = EventRepository(db_session)
    event = CommonEvent(
        event_id="evt_dup_001",
        timestamp=datetime.now(timezone.utc),
        category=EventCategory.SYSTEM_LOG,
        action=EventAction.UNKNOWN,
        source_format="test",
    )

    # Ingest first time
    await repo.upsert_events([event])
    # Ingest duplicate
    await repo.upsert_events([event])

    items, total = await repo.list_events()
    assert total == 1
    assert items[0].id == "evt_dup_001"


@pytest.mark.asyncio
async def test_detection_persistence_and_event_links(db_session: AsyncSession):
    ev_repo = EventRepository(db_session)
    det_repo = DetectionRepository(db_session)
    now = datetime.now(timezone.utc)

    # Create supporting event first
    event = CommonEvent(
        event_id="evt_support_001",
        timestamp=now,
        category=EventCategory.AUTHENTICATION,
        action=EventAction.LOGON_FAILURE,
        user_identity="svc_deploy",
        source_format="test",
    )
    await ev_repo.upsert_events([event])

    # Create detection referencing event
    detection = DetectionResult(
        detection_id="det_test_001",
        rule_id="DET-001",
        rule_name="Brute Force",
        severity=EventSeverity.MEDIUM,
        summary="Test explanation",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_support_001"],
    )

    persisted_dets = await det_repo.upsert_detections([detection])
    assert len(persisted_dets) == 1
    assert persisted_dets[0].id == "det_test_001"

    # Verify detection-event link
    linked_events = await det_repo.get_detection_events("det_test_001")
    assert len(linked_events) == 1
    assert linked_events[0].id == "evt_support_001"


@pytest.mark.asyncio
async def test_incident_persistence_entities_and_evidence(db_session: AsyncSession):
    ev_repo = EventRepository(db_session)
    det_repo = DetectionRepository(db_session)
    inc_repo = IncidentRepository(db_session)
    now = datetime(2026, 11, 1, 8, 30, 0, tzinfo=timezone.utc)

    # 1. Event
    event = CommonEvent(
        event_id="evt_inc_001",
        timestamp=now,
        category=EventCategory.AUTHENTICATION,
        action=EventAction.LOGON_FAILURE,
        user_identity="svc_deploy",
        source_format="test",
    )
    await ev_repo.upsert_events([event])

    # 2. Detection
    det = DetectionResult(
        detection_id="det_inc_001",
        rule_id="DET-001",
        rule_name="Brute Force",
        severity=EventSeverity.MEDIUM,
        summary="Brute force on svc_deploy",
        detection_timestamp=now,
        entity_key="user:svc_deploy",
        triggering_event_ids=["evt_inc_001"],
    )
    await det_repo.upsert_detections([det])

    # 3. Incident Group
    group = CorrelatedIncidentGroup(
        incident_id="inc_test_001",
        correlation_key="ckey_12345",
        title="Suspicious Brute Force on svc_deploy",
        description="Test incident description",
        severity=EventSeverity.MEDIUM,
        status="open",
        first_seen=now,
        last_seen=now,
        detection_ids=["det_inc_001"],
        entities=[
            CorrelatedEntity(
                entity_type="user",
                entity_value="svc_deploy",
                relationship="targeted_account",
                confidence=1.0,
                evidence_references=["evt_inc_001"],
            )
        ],
        supporting_event_ids=["evt_inc_001"],
    )

    inc = await inc_repo.upsert_incident(group)
    assert inc.id == "inc_test_001"

    # 4. Fetch full dossier
    dossier = await inc_repo.get_incident_evidence("inc_test_001")
    assert dossier is not None
    assert dossier["incident"].id == "inc_test_001"
    assert len(dossier["detections"]) == 1
    assert len(dossier["events"]) == 1
    assert len(dossier["entities"]) == 1
    assert dossier["entities"][0].entity_value == "svc_deploy"


@pytest.mark.asyncio
async def test_duplicate_incident_upsert_is_idempotent(db_session: AsyncSession):
    inc_repo = IncidentRepository(db_session)
    now = datetime.now(timezone.utc)

    group = CorrelatedIncidentGroup(
        incident_id="inc_dup_001",
        correlation_key="ckey_dup_001",
        title="Original Title",
        description="Original Desc",
        severity=EventSeverity.LOW,
        status="open",
        first_seen=now,
        last_seen=now,
        detection_ids=[],
        entities=[],
        supporting_event_ids=[],
    )

    # First upsert
    await inc_repo.upsert_incident(group)
    # Second upsert with updated title
    group.title = "Updated Title"
    await inc_repo.upsert_incident(group)

    incidents = await inc_repo.list_incidents()
    assert len(incidents) == 1
    assert incidents[0].title == "Updated Title"


@pytest.mark.asyncio
async def test_transaction_rollback_on_failure(async_test_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker
    session_factory = async_sessionmaker(bind=async_test_engine, expire_on_commit=False, class_=AsyncSession)

    async with session_factory() as session:
        repo = EventRepository(session)
        event = CommonEvent(
            event_id="evt_rollback_001",
            timestamp=datetime.now(timezone.utc),
            category=EventCategory.SYSTEM_LOG,
            action=EventAction.UNKNOWN,
            source_format="test",
        )
        await repo.upsert_events([event])
        # Force an error before commit
        try:
            # Insert broken manual object or raise exception
            raise RuntimeError("Simulated transaction failure")
        except RuntimeError:
            await session.rollback()

    # Verify event was NOT committed to the database
    async with session_factory() as session:
        repo = EventRepository(session)
        retrieved = await repo.get_by_id("evt_rollback_001")
        assert retrieved is None


@pytest.mark.asyncio
async def test_benign_event_persistence_across_sessions(async_test_engine):
    """
    Verify that IncidentService commits benign events to the database even when
    zero detections or incidents are generated, surviving across session boundaries.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from app.correlation.service import IncidentService

    session_factory = async_sessionmaker(bind=async_test_engine, expire_on_commit=False, class_=AsyncSession)

    benign_event_1 = CommonEvent(
        event_id="evt_benign_cross_1",
        timestamp=datetime(2026, 11, 1, 2, 0, 0, tzinfo=timezone.utc),
        category=EventCategory.AUTHENTICATION,
        action=EventAction.LOGON_SUCCESS,
        user_identity="backup_agent",
        source_ip="192.168.1.200",
        source_format="linux_auth_log",
    )
    benign_event_2 = CommonEvent(
        event_id="evt_benign_cross_2",
        timestamp=datetime(2026, 11, 1, 2, 0, 15, tzinfo=timezone.utc),
        category=EventCategory.PROCESS_EXECUTION,
        action=EventAction.PROCESS_START,
        user_identity="backup_agent",
        process_name="rsync",
        source_format="linux_auth_log",
    )

    # 1. First session: process benign events through IncidentService
    async with session_factory() as session1:
        service = IncidentService(session1)
        incidents = await service.process_and_correlate_events([benign_event_1, benign_event_2])
        # Zero incidents expected for benign events
        assert len(incidents) == 0

    # 2. Second independent session: verify events exist in persistent storage
    async with session_factory() as session2:
        repo = EventRepository(session2)
        ev1 = await repo.get_by_id("evt_benign_cross_1")
        ev2 = await repo.get_by_id("evt_benign_cross_2")
        assert ev1 is not None
        assert ev1.username == "backup_agent"
        assert ev2 is not None
        assert ev2.process_name == "rsync"

