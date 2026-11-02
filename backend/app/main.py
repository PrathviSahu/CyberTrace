"""
CyberTrace FastAPI Application.
Provides versioned REST API endpoints under /api/v1 for events, detections, and correlated incidents.
"""

from contextlib import asynccontextmanager
import hashlib
from typing import Any, Dict, List, Optional
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.correlation.service import IncidentService
from app.db.repositories.detection_repo import DetectionRepository
from app.db.repositories.event_repo import EventRepository
from app.db.repositories.incident_repo import IncidentRepository
from app.db.session import get_db_session, init_db
from app.parsers.pipeline import LogIngestionPipeline
from app.schemas.ces import CommonEvent
from app.schemas.detection import DetectionResponse
from app.schemas.incident import IncidentDetailResponse, IncidentSummaryResponse, LogUploadResponse
from app.schemas.investigation import InvestigationResponse
from app.investigation.service import InvestigationService
from app.threatlab.models import ScenarioReplayResponse, ScenarioSummary
from app.threatlab.service import ThreatLabService
from app.db.repositories.asset_repo import AssetRepository, IdentityRepository
from app.db.repositories.hunting_repo import HuntingRepository
from app.db.repositories.saved_hunt_repo import (
    ArchivedHuntError,
    SavedHuntRepository,
    VersionConflictError,
)
from app.db.repositories.rule_draft_repo import (
    ArchivedRuleError,
    RuleDraftRepository,
)
from app.schemas.asset import AssetDetail, AssetListResponse, AssetSummary, IdentityDetail, IdentityListResponse, IdentitySummary
from app.schemas.hunting import ThreatHuntQueryRequest, ThreatHuntQueryResponse
from app.schemas.saved_hunt import (
    SavedHuntCreate,
    SavedHuntDuplicateRequest,
    SavedHuntExecuteRequest,
    SavedHuntExecuteResponse,
    SavedHuntListResponse,
    SavedHuntResponse,
    SavedHuntUpdate,
)
from app.db.repositories.active_rule_repo import ActiveRuleRepository
from app.db.repositories.rule_audit_repo import RuleAuditRepository
from app.services.rule_lifecycle_service import (
    ActiveRuleNotFoundError,
    DeprecatedRuleTerminalError,
    DraftArchivedError,
    DraftNotFoundError,
    DraftNotValidatedError,
    DuplicateApprovalError,
    FourEyesViolationError,
    InvalidLifecycleTransitionError,
    RuleLifecycleService,
    StaleValidationError,
    ValidationRationaleError,
    VersionConflictError as LifecycleVersionConflictError,
)
from app.schemas.active_rule import (
    ActiveDetectionRuleListResponse,
    ActiveDetectionRuleResponse,
    ActiveRuleStatus,
    ActiveRuleStatusUpdateRequest,
)
from app.schemas.rule_audit import (
    RuleAuditEntryResponse,
    RuleAuditListResponse,
)
from app.schemas.rule_draft import (
    DetectionRuleDraftCreate,
    DetectionRuleDraftListResponse,
    DetectionRuleDraftResponse,
    DetectionRuleDraftUpdate,
    RuleDraftApprovalRequest,
    RuleDraftRejectionRequest,
    RuleValidationReportResponse,
    RuleValidationRunRequest,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables on startup
    await init_db()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-assisted SOC incident investigation platform for defensive cybersecurity",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(f"{settings.API_V1_STR}/health", tags=["Health"])
async def health_check() -> Dict[str, str]:
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
    }


@app.post(f"{settings.API_V1_STR}/logs/upload", response_model=LogUploadResponse, tags=["Ingestion"])
async def upload_log_file(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_db_session),
) -> LogUploadResponse:
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No filename provided")

    # Read file content in bounded chunks to prevent unbounded memory exhaustion
    CHUNK_SIZE = 64 * 1024  # 64 KB
    total_bytes = 0
    buffer = bytearray()

    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > settings.MAX_UPLOAD_SIZE_BYTES:
            max_mb = settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"Uploaded file exceeds maximum size limit of {max_mb} MB"
            )
        buffer.extend(chunk)

    if not buffer:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty")

    try:
        text_content = buffer.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File content could not be decoded as UTF-8 text"
        )

    if not text_content.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty")

    # Calculate SHA-256 hash of file content for audit provenance
    source_file_hash = hashlib.sha256(buffer).hexdigest()

    # Parse and normalize using multi-source ingestion pipeline
    pipeline = LogIngestionPipeline()
    events, detected_format = pipeline.ingest(text_content, filename=file.filename)

    if not events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to parse valid security events from '{file.filename}'. Unsupported or malformed format."
        )

    # Process events through rules and correlation engine
    service = IncidentService(session)
    incidents = await service.process_and_correlate_events(events, source_file_hash=source_file_hash)
    detections_count = len(service.latest_detections)

    return LogUploadResponse(
        filename=file.filename,
        detected_format=detected_format,
        source_file_hash=source_file_hash,
        parsed_events_count=len(events),
        persisted_events_count=len(events),
        detections_count=detections_count,
        incidents_count=len(incidents),
        status="success",
    )


@app.get(f"{settings.API_V1_STR}/events", response_model=List[Dict[str, Any]], tags=["Events"])
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    username: Optional[str] = None,
    source_ip: Optional[str] = None,
    session: AsyncSession = Depends(get_db_session),
):
    repo = EventRepository(session)
    events, total = await repo.list_events(limit=limit, offset=offset, username=username, source_ip=source_ip)
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "source_type": e.source_type,
            "category": e.category,
            "action": e.action,
            "severity": e.severity,
            "username": e.username,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "hostname": e.hostname,
            "bytes_out": e.bytes_out,
            "process_name": e.process_name,
        }
        for e in events
    ]


@app.post(
    f"{settings.API_V1_STR}/hunting/query",
    response_model=ThreatHuntQueryResponse,
    tags=["Threat Hunting"],
    summary="Execute structured threat hunting query",
    description=(
        "Executes a parameterized multi-condition search over security telemetry. "
        "Supports time ranges, allowlisted field operators (eq, neq, contains, starts_with, in, gt, gte, lt, lte), "
        "and nested boolean groups (AND/OR). Returns matching events with batched related detection and incident links."
    ),
)
async def execute_threat_hunt(
    request: ThreatHuntQueryRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ThreatHuntQueryResponse:
    repo = HuntingRepository(session)
    return await repo.execute_hunt(request)


# ---------------------------------------------------------------------------
# Phase 6.3A — Saved Threat Hunts & Query Persistence
# ---------------------------------------------------------------------------

@app.post(
    f"{settings.API_V1_STR}/hunting/saved",
    response_model=SavedHuntResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Threat Hunting", "Saved Hunts"],
    summary="Create a new saved threat hunt",
    description=(
        "Persists a validated threat hunt query AST definition. Starts at version 1 with zero executions. "
        "Created_by identity is caller-supplied demo metadata (no cryptographic auth or RBAC enforced)."
    ),
)
async def create_saved_hunt(
    data: SavedHuntCreate,
    session: AsyncSession = Depends(get_db_session),
) -> SavedHuntResponse:
    repo = SavedHuntRepository(session)
    hunt = await repo.create_saved_hunt(data)
    return SavedHuntResponse.model_validate(hunt)


@app.get(
    f"{settings.API_V1_STR}/hunting/saved",
    response_model=SavedHuntListResponse,
    tags=["Threat Hunting", "Saved Hunts"],
    summary="List saved threat hunts",
    description=(
        "Returns a paginated list of saved threat hunts. Excludes archived hunts by default unless include_archived=True. "
        "Supports substring search on hunt name/description and exact matching on categorization tags."
    ),
)
async def list_saved_hunts(
    query: Optional[str] = Query(None, max_length=128, description="Search term for name and description"),
    tag: Optional[str] = Query(None, max_length=64, description="Filter by categorization tag"),
    include_archived: bool = Query(False, description="Whether to include soft-deleted/archived hunts"),
    limit: int = Query(50, ge=1, le=200, description="Page limit (1-200)"),
    offset: int = Query(0, ge=0, le=10000, description="Page offset (0-10000)"),
    session: AsyncSession = Depends(get_db_session),
) -> SavedHuntListResponse:
    repo = SavedHuntRepository(session)
    items, total = await repo.list_saved_hunts(
        query=query,
        tag=tag,
        include_archived=include_archived,
        limit=limit,
        offset=offset,
    )
    return SavedHuntListResponse(
        items=[SavedHuntResponse.model_validate(h) for h in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    f"{settings.API_V1_STR}/hunting/saved/{{hunt_id}}",
    response_model=SavedHuntResponse,
    tags=["Threat Hunting", "Saved Hunts"],
    summary="Retrieve a saved threat hunt by ID",
    description="Fetches full details of a saved threat hunt, including persisted AST query definition.",
)
async def get_saved_hunt(
    hunt_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> SavedHuntResponse:
    repo = SavedHuntRepository(session)
    hunt = await repo.get_saved_hunt(hunt_id)
    if not hunt:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Saved threat hunt '{hunt_id}' was not found.",
        )
    return SavedHuntResponse.model_validate(hunt)


@app.put(
    f"{settings.API_V1_STR}/hunting/saved/{{hunt_id}}",
    response_model=SavedHuntResponse,
    tags=["Threat Hunting", "Saved Hunts"],
    summary="Update a saved threat hunt",
    description=(
        "Updates name, description, tags, or query AST. Requires providing the current 'version' for "
        "optimistic concurrency control. Returns HTTP 409 Conflict if the version is stale. Increments version on success."
    ),
)
async def update_saved_hunt(
    hunt_id: str,
    data: SavedHuntUpdate,
    session: AsyncSession = Depends(get_db_session),
) -> SavedHuntResponse:
    repo = SavedHuntRepository(session)
    try:
        updated = await repo.update_saved_hunt(hunt_id, data)
        return SavedHuntResponse.model_validate(updated)
    except (VersionConflictError, ArchivedHuntError) as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@app.delete(
    f"{settings.API_V1_STR}/hunting/saved/{{hunt_id}}",
    response_model=SavedHuntResponse,
    tags=["Threat Hunting", "Saved Hunts"],
    summary="Archive a saved threat hunt (soft delete)",
    description=(
        "Soft-deletes a saved threat hunt by setting is_archived = True. "
        "Preserves all query definition and historical metrics. Excludes it from default hunt listings."
    ),
)
async def archive_saved_hunt(
    hunt_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> SavedHuntResponse:
    repo = SavedHuntRepository(session)
    try:
        archived = await repo.archive_saved_hunt(hunt_id)
        return SavedHuntResponse.model_validate(archived)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@app.post(
    f"{settings.API_V1_STR}/hunting/saved/{{hunt_id}}/execute",
    response_model=SavedHuntExecuteResponse,
    tags=["Threat Hunting", "Saved Hunts"],
    summary="Re-execute a saved threat hunt",
    description=(
        "Re-runs the persisted query definition using the unified hunting compiler. "
        "Atomically increments run_count, updates last_run_at timestamp, and records the executed version."
    ),
)
async def execute_saved_hunt(
    hunt_id: str,
    request: Optional[SavedHuntExecuteRequest] = None,
    session: AsyncSession = Depends(get_db_session),
) -> SavedHuntExecuteResponse:
    repo = SavedHuntRepository(session)
    try:
        return await repo.execute_saved_hunt(hunt_id, request)
    except ArchivedHuntError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@app.post(
    f"{settings.API_V1_STR}/hunting/saved/{{hunt_id}}/duplicate",
    response_model=SavedHuntResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Threat Hunting", "Saved Hunts"],
    summary="Duplicate a saved threat hunt",
    description=(
        "Clones an existing hunt into a new, independent saved hunt record starting at version 1 "
        "with reset execution metrics (run_count=0, last_run_at=None, is_archived=False)."
    ),
)
async def duplicate_saved_hunt(
    hunt_id: str,
    request: Optional[SavedHuntDuplicateRequest] = None,
    session: AsyncSession = Depends(get_db_session),
) -> SavedHuntResponse:
    repo = SavedHuntRepository(session)
    req = request or SavedHuntDuplicateRequest()
    try:
        cloned = await repo.duplicate_saved_hunt(hunt_id, req)
        return SavedHuntResponse.model_validate(cloned)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


# ===========================================================================
# Section: Detection Rule Drafts & Pre-flight Validation (Phase 6.3B)
# ===========================================================================

@app.post(
    f"{settings.API_V1_STR}/rules/drafts",
    response_model=DetectionRuleDraftResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Detection Rules", "Rule Drafts"],
    summary="Create a detection rule draft (scratch or from saved hunt)",
    description=(
        "Persists a new detection rule draft. Can be created from scratch with a query definition, "
        "or promoted from an existing saved threat hunt (capturing an immutable snapshot of source_hunt_version)."
    ),
)
async def create_rule_draft(
    data: DetectionRuleDraftCreate,
    session: AsyncSession = Depends(get_db_session),
) -> DetectionRuleDraftResponse:
    repo = RuleDraftRepository(session)
    try:
        draft = await repo.create_draft(data)
        return DetectionRuleDraftResponse.model_validate(draft)
    except ArchivedRuleError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.get(
    f"{settings.API_V1_STR}/rules/drafts",
    response_model=DetectionRuleDraftListResponse,
    tags=["Detection Rules", "Rule Drafts"],
    summary="List detection rule drafts",
    description="Lists detection rule drafts with optional filtering by status and severity. Excludes archived drafts by default.",
)
async def list_rule_drafts(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    include_archived: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
) -> DetectionRuleDraftListResponse:
    repo = RuleDraftRepository(session)
    items, total = await repo.list_drafts(
        status=status_filter,
        severity=severity,
        include_archived=include_archived,
        limit=limit,
        offset=offset,
    )
    result_items: List[DetectionRuleDraftResponse] = []
    for item in items:
        resp_item = DetectionRuleDraftResponse.model_validate(item)
        resp_item.latest_validation = await repo.get_latest_validation_summary(item.id)
        result_items.append(resp_item)

    return DetectionRuleDraftListResponse(
        items=result_items,
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    f"{settings.API_V1_STR}/rules/drafts/{{draft_id}}",
    response_model=DetectionRuleDraftResponse,
    tags=["Detection Rules", "Rule Drafts"],
    summary="Get a detection rule draft by ID",
)
async def get_rule_draft(
    draft_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> DetectionRuleDraftResponse:
    repo = RuleDraftRepository(session)
    draft = await repo.get_draft(draft_id)
    if not draft:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule draft '{draft_id}' was not found.",
        )
    resp = DetectionRuleDraftResponse.model_validate(draft)
    resp.latest_validation = await repo.get_latest_validation_summary(draft.id)
    return resp


@app.put(
    f"{settings.API_V1_STR}/rules/drafts/{{draft_id}}",
    response_model=DetectionRuleDraftResponse,
    tags=["Detection Rules", "Rule Drafts"],
    summary="Update a detection rule draft",
    description=(
        "Updates a detection rule draft with optimistic version concurrency locking. "
        "Returns 409 Conflict if stale. Note: modifying the query_definition AST automatically "
        "resets status to DRAFT, invalidating prior validation."
    ),
)
async def update_rule_draft(
    draft_id: str,
    data: DetectionRuleDraftUpdate,
    session: AsyncSession = Depends(get_db_session),
) -> DetectionRuleDraftResponse:
    repo = RuleDraftRepository(session)
    try:
        updated = await repo.update_draft(draft_id, data)
        resp = DetectionRuleDraftResponse.model_validate(updated)
        resp.latest_validation = await repo.get_latest_validation_summary(updated.id)
        return resp
    except (VersionConflictError, ArchivedRuleError) as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.delete(
    f"{settings.API_V1_STR}/rules/drafts/{{draft_id}}",
    response_model=DetectionRuleDraftResponse,
    tags=["Detection Rules", "Rule Drafts"],
    summary="Archive a detection rule draft (soft delete)",
)
async def archive_rule_draft(
    draft_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> DetectionRuleDraftResponse:
    repo = RuleDraftRepository(session)
    try:
        archived = await repo.archive_draft(draft_id)
        resp = DetectionRuleDraftResponse.model_validate(archived)
        resp.latest_validation = await repo.get_latest_validation_summary(archived.id)
        return resp
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@app.post(
    f"{settings.API_V1_STR}/rules/drafts/{{draft_id}}/validate",
    response_model=RuleValidationReportResponse,
    tags=["Detection Rules", "Pre-flight Validation"],
    summary="Run pre-flight validation on a detection rule draft",
    description=(
        "Executes pre-flight simulation across historical database telemetry and ThreatLab benchmark scenarios. "
        "Evaluates daily alert volume, benign baseline false alarm risk, and provenance breakdown. "
        "Transitions draft status to VALIDATED if draft version matches; preserves result as historical evidence."
    ),
)
async def validate_rule_draft(
    draft_id: str,
    request: Optional[RuleValidationRunRequest] = None,
    session: AsyncSession = Depends(get_db_session),
) -> RuleValidationReportResponse:
    repo = RuleDraftRepository(session)
    try:
        return await repo.validate_draft(draft_id, request)
    except ArchivedRuleError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.get(
    f"{settings.API_V1_STR}/rules/drafts/{{draft_id}}/validations",
    tags=["Detection Rules", "Pre-flight Validation"],
    summary="List validation run history for a detection rule draft",
)
async def list_rule_draft_validations(
    draft_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    repo = RuleDraftRepository(session)
    draft = await repo.get_draft(draft_id)
    if not draft:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule draft '{draft_id}' was not found.",
        )
    runs, total = await repo.list_validations(draft_id, limit=limit, offset=offset)
    return {
        "items": [
            {
                "id": r.id,
                "draft_id": r.draft_id,
                "draft_version": r.draft_version,
                "run_at": r.run_at.isoformat(),
                "target_scope": r.target_scope,
                "events_scanned": r.events_scanned,
                "matches_found": r.matches_found,
                "estimated_daily_alert_volume": r.estimated_daily_alert_volume,
                "observation_duration_days": r.observation_duration_days,
                "observation_start": r.observation_start.isoformat() if r.observation_start else None,
                "observation_end": r.observation_end.isoformat() if r.observation_end else None,
                "duration_ms": r.duration_ms,
                "provenance_breakdown": r.provenance_breakdown,
                "threatlab_results": r.threatlab_results,
                "sample_matched_event_ids": r.sample_matched_event_ids,
                "status": r.status,
                "error_message": r.error_message,
                "is_stale": r.is_stale,
            }
            for r in runs
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ===========================================================================
# Section: Detection Rule Lifecycle, Governance, Active Rules & Audit Ledger (Phase 6.3C)
# ===========================================================================

@app.post(
    f"{settings.API_V1_STR}/rules/drafts/{{draft_id}}/approve",
    response_model=ActiveDetectionRuleResponse,
    tags=["Detection Rules", "Rule Governance"],
    summary="Approve detection rule draft and deploy active rule",
    description=(
        "Enforces demonstration four-eyes review gate. Requires completed non-stale validation run. "
        "Atomically allocates sequential rule code (CUST-xxx), transitions draft to APPROVED, "
        "creates frozen production active rule, and records an immutable audit ledger entry."
    ),
)
async def approve_rule_draft(
    draft_id: str,
    payload: RuleDraftApprovalRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ActiveDetectionRuleResponse:
    service = RuleLifecycleService(session)
    try:
        active_rule, _, _ = await service.approve_rule_draft(draft_id, payload)
        return ActiveDetectionRuleResponse.model_validate(active_rule)
    except DraftNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except FourEyesViolationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValidationRationaleError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except (
        DraftArchivedError,
        DraftNotValidatedError,
        StaleValidationError,
        DuplicateApprovalError,
        LifecycleVersionConflictError,
    ) as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@app.post(
    f"{settings.API_V1_STR}/rules/drafts/{{draft_id}}/reject",
    response_model=DetectionRuleDraftResponse,
    tags=["Detection Rules", "Rule Governance"],
    summary="Reject detection rule draft with justification",
    description=(
        "Rejects a validated detection rule draft with mandatory reviewer rationale (min 10 characters). "
        "Resets draft status back to editable DRAFT for author rework and records an immutable audit entry."
    ),
)
async def reject_rule_draft(
    draft_id: str,
    payload: RuleDraftRejectionRequest,
    session: AsyncSession = Depends(get_db_session),
) -> DetectionRuleDraftResponse:
    service = RuleLifecycleService(session)
    repo = RuleDraftRepository(session)
    try:
        rejected_draft, _ = await service.reject_rule_draft(draft_id, payload)
        resp = DetectionRuleDraftResponse.model_validate(rejected_draft)
        resp.latest_validation = await repo.get_latest_validation_summary(rejected_draft.id)
        return resp
    except DraftNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationRationaleError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except (DraftArchivedError, DraftNotValidatedError, LifecycleVersionConflictError) as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@app.get(
    f"{settings.API_V1_STR}/rules/active",
    response_model=ActiveDetectionRuleListResponse,
    tags=["Detection Rules", "Active Rules"],
    summary="List active production detection rules",
    description="Lists active, disabled, and deprecated custom detection rules with optional status filtering.",
)
async def list_active_rules(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by rule status (ACTIVE, DISABLED, DEPRECATED)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
) -> ActiveDetectionRuleListResponse:
    repo = ActiveRuleRepository(session)
    items, total = await repo.list_active_rules(status=status_filter, limit=limit, offset=offset)
    return ActiveDetectionRuleListResponse(
        items=[ActiveDetectionRuleResponse.model_validate(r) for r in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(
    f"{settings.API_V1_STR}/rules/active/{{rule_id}}",
    response_model=ActiveDetectionRuleResponse,
    tags=["Detection Rules", "Active Rules"],
    summary="Get active detection rule by ID or rule code",
)
async def get_active_rule(
    rule_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> ActiveDetectionRuleResponse:
    repo = ActiveRuleRepository(session)
    rule = await repo.get_active_rule_by_id(rule_id)
    if not rule:
        rule = await repo.get_active_rule_by_code(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Active detection rule '{rule_id}' was not found.",
        )
    return ActiveDetectionRuleResponse.model_validate(rule)


@app.patch(
    f"{settings.API_V1_STR}/rules/active/{{rule_id}}/status",
    response_model=ActiveDetectionRuleResponse,
    tags=["Detection Rules", "Active Rules"],
    summary="Update active rule status (ACTIVE <-> DISABLED -> DEPRECATED)",
    description=(
        "Updates active rule status using optimistic concurrency version locking. "
        "DEPRECATED is a permanent terminal state (cannot be reactivated). "
        "Appends before/after state diff to immutable audit ledger."
    ),
)
async def update_active_rule_status(
    rule_id: str,
    payload: ActiveRuleStatusUpdateRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ActiveDetectionRuleResponse:
    service = RuleLifecycleService(session)
    try:
        updated_rule, _ = await service.toggle_active_rule_status(rule_id, payload)
        return ActiveDetectionRuleResponse.model_validate(updated_rule)
    except ActiveRuleNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (ValidationRationaleError, InvalidLifecycleTransitionError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except (DeprecatedRuleTerminalError, LifecycleVersionConflictError) as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@app.get(
    f"{settings.API_V1_STR}/rules/audit",
    response_model=RuleAuditListResponse,
    tags=["Detection Rules", "Audit Ledger"],
    summary="Query immutable rule lifecycle audit ledger",
    description="Lists append-only audit entries recording all candidate draft and active rule state transitions.",
)
async def list_rule_audit_entries(
    target_type: Optional[str] = Query(None, description="Target entity type: 'DRAFT' or 'ACTIVE_RULE'"),
    target_id: Optional[str] = Query(None, description="Target entity ID"),
    actor: Optional[str] = Query(None, description="Filter by actor username"),
    action: Optional[str] = Query(None, description="Filter by audit action (e.g. APPROVE_DRAFT, DEACTIVATE_RULE)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
) -> RuleAuditListResponse:
    repo = RuleAuditRepository(session)
    items, total = await repo.list_audit_entries(
        target_type=target_type,
        target_id=target_id,
        actor=actor,
        action=action,
        limit=limit,
        offset=offset,
    )
    return RuleAuditListResponse(
        items=[RuleAuditEntryResponse.model_validate(e) for e in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.get(f"{settings.API_V1_STR}/detections", tags=["Detections"])
async def list_detections(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    session: AsyncSession = Depends(get_db_session),
):
    repo = DetectionRepository(session)
    detections = await repo.list_detections(limit=limit, offset=offset, rule_id=rule_id, severity=severity)
    return [
        {
            "id": d.id,
            "rule_id": d.rule_id,
            "rule_name": d.rule_name,
            "severity": d.severity,
            "entity_type": d.entity_type,
            "entity_value": d.entity_value,
            "first_seen": d.first_seen.isoformat(),
            "last_seen": d.last_seen.isoformat(),
            "detected_at": d.detected_at.isoformat(),
            "explanation": d.explanation,
        }
        for d in detections
    ]


@app.get(f"{settings.API_V1_STR}/incidents", tags=["Incidents"])
async def list_incidents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    session: AsyncSession = Depends(get_db_session),
):
    repo = IncidentRepository(session)
    incidents = await repo.list_incidents(limit=limit, offset=offset, status=status_filter, severity=severity)
    return [
        {
            "id": inc.id,
            "correlation_key": inc.correlation_key,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "status": inc.status,
            "first_seen": inc.first_seen.isoformat(),
            "last_seen": inc.last_seen.isoformat(),
            "entities": [
                {
                    "entity_type": ent.entity_type,
                    "entity_value": ent.entity_value,
                    "relationship": ent.relationship,
                    "confidence": ent.confidence,
                }
                for ent in inc.entities
            ],
        }
        for inc in incidents
    ]


@app.get(f"{settings.API_V1_STR}/incidents/{{incident_id}}", tags=["Incidents"])
async def get_incident(
    incident_id: str,
    session: AsyncSession = Depends(get_db_session),
):
    repo = IncidentRepository(session)
    dossier = await repo.get_incident_evidence(incident_id)
    if not dossier:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found")

    inc = dossier["incident"]
    return {
        "incident": {
            "id": inc.id,
            "correlation_key": inc.correlation_key,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "status": inc.status,
            "first_seen": inc.first_seen.isoformat(),
            "last_seen": inc.last_seen.isoformat(),
        },
        "detections": [
            {
                "id": d.id,
                "rule_id": d.rule_id,
                "rule_name": d.rule_name,
                "severity": d.severity,
                "entity_type": d.entity_type,
                "entity_value": d.entity_value,
                "explanation": d.explanation,
            }
            for d in dossier["detections"]
        ],
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "category": e.category,
                "action": e.action,
                "username": e.username,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "hostname": e.hostname,
                "bytes_out": e.bytes_out,
            }
            for e in dossier["events"]
        ],
        "entities": [
            {
                "entity_type": ent.entity_type,
                "entity_value": ent.entity_value,
                "relationship": ent.relationship,
                "confidence": ent.confidence,
                "evidence_references": ent.evidence_references,
            }
            for ent in dossier["entities"]
        ],
    }


_ALLOWED_INCIDENT_STATUSES = {"open", "in_progress", "contained", "resolved", "closed"}


@app.patch(f"{settings.API_V1_STR}/incidents/{{incident_id}}/status", tags=["Incidents"])
async def update_incident_status(
    incident_id: str,
    status_update: Dict[str, str],
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    new_status = status_update.get("status")
    if not new_status or new_status not in _ALLOWED_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{new_status}'. Allowed: {', '.join(sorted(_ALLOWED_INCIDENT_STATUSES))}",
        )
    repo = IncidentRepository(session)
    updated = await repo.update_status(incident_id, new_status)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return {"id": updated.id, "status": updated.status, "updated_at": updated.updated_at.isoformat()}


@app.post(
    f"{settings.API_V1_STR}/incidents/{{incident_id}}/investigate",
    response_model=InvestigationResponse,
    tags=["Investigations"],
)
async def trigger_investigation(
    incident_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> InvestigationResponse:
    service = InvestigationService(session)
    investigation = await service.investigate_incident(incident_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return InvestigationResponse.model_validate(investigation)


@app.get(
    f"{settings.API_V1_STR}/incidents/{{incident_id}}/investigations",
    response_model=List[InvestigationResponse],
    tags=["Investigations"],
)
async def list_investigations(
    incident_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> List[InvestigationResponse]:
    repo = IncidentRepository(session)
    incident = await repo.get_by_id(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    service = InvestigationService(session)
    investigations = await service.list_investigations(incident_id)
    return [InvestigationResponse.model_validate(inv) for inv in investigations]


@app.get(
    f"{settings.API_V1_STR}/incidents/{{incident_id}}/investigations/{{investigation_id}}",
    response_model=InvestigationResponse,
    tags=["Investigations"],
)
async def get_investigation(
    incident_id: str,
    investigation_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> InvestigationResponse:
    repo = IncidentRepository(session)
    incident = await repo.get_by_id(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    service = InvestigationService(session)
    inv = await service.get_investigation(incident_id, investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found for incident '{incident_id}'",
        )
    return InvestigationResponse.model_validate(inv)


@app.get(f"{settings.API_V1_STR}/incidents/{{incident_id}}/graph", tags=["Incidents", "Graph"])
async def get_incident_graph(
    incident_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    repo = IncidentRepository(session)
    dossier = await repo.get_incident_evidence(incident_id)
    if not dossier:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")

    inc = dossier["incident"]
    entities = dossier["entities"]
    detections = dossier["detections"]
    events = dossier["events"]

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    nodes.append({
        "id": f"node_inc_{inc.id}",
        "label": inc.id,
        "subLabel": inc.title[:35] + ("..." if len(inc.title) > 35 else ""),
        "type": "incident",
        "severity": inc.severity,
    })

    for idx, ent in enumerate(entities):
        node_id = f"node_ent_{ent.entity_type}_{idx}"
        node_type = "host"
        if ent.entity_type in ("user", "service_account"):
            node_type = "user"
        elif ent.entity_type in ("source_ip", "destination_ip"):
            node_type = "ip"

        nodes.append({
            "id": node_id,
            "label": ent.entity_value,
            "subLabel": ent.relationship.replace("_", " ").upper(),
            "type": node_type,
            "criticality": "tier_1" if "compromised" in ent.relationship else "tier_2",
        })

        edges.append({
            "id": f"edge_inc_ent_{idx}",
            "source": f"node_inc_{inc.id}",
            "target": node_id,
            "label": ent.relationship,
            "edgeType": "correlated",
        })

    for d_idx, det in enumerate(detections):
        det_node_id = f"node_det_{det.id or d_idx}"
        nodes.append({
            "id": det_node_id,
            "label": det.rule_id,
            "subLabel": det.rule_name,
            "type": "detection",
            "severity": det.severity,
        })

        triggering_event_ids = (
            det.metadata_json.get("triggering_event_ids", [])
            if hasattr(det, "metadata_json") and isinstance(det.metadata_json, dict)
            else (getattr(det, "triggering_event_ids", []) or [])
        )
        edges.append({
            "id": f"edge_det_inc_{d_idx}",
            "source": det_node_id,
            "target": f"node_inc_{inc.id}",
            "label": "DETECTED_STAGE",
            "edgeType": "observed",
            "evidenceEventId": triggering_event_ids[0] if triggering_event_ids else None,
        })

    for e_idx, evt in enumerate(events):
        if evt.destination_ip and evt.hostname:
            dest_node = next((n for n in nodes if n["label"] == evt.destination_ip), None)
            host_node = next((n for n in nodes if n["label"] == evt.hostname), None)
            if dest_node and host_node:
                edges.append({
                    "id": f"edge_evt_flow_{e_idx}",
                    "source": host_node["id"],
                    "target": dest_node["id"],
                    "label": f"Egress {round(evt.bytes_out / 1000000)}MB" if evt.bytes_out else "Network Flow",
                    "edgeType": "observed",
                    "evidenceEventId": evt.id,
                })

    return {"nodes": nodes, "edges": edges, "incident_id": inc.id}


@app.get(f"{settings.API_V1_STR}/threatlab/scenarios", response_model=List[ScenarioSummary], tags=["ThreatLab"])
async def list_threatlab_scenarios() -> List[ScenarioSummary]:
    service = ThreatLabService()
    return service.get_scenarios()


@app.post(f"{settings.API_V1_STR}/threatlab/replay/{{scenario_id}}", response_model=ScenarioReplayResponse, tags=["ThreatLab"])
async def replay_threatlab_scenario(scenario_id: str) -> ScenarioReplayResponse:
    service = ThreatLabService()
    try:
        return service.replay_scenario(scenario_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ---------------------------------------------------------------------------
# Phase 6.1 — Asset & Identity Inventory (read-only, telemetry-derived)
# ---------------------------------------------------------------------------

_VALID_ASSET_TYPES = {"hostname", "ip"}


@app.get(f"{settings.API_V1_STR}/assets", response_model=AssetListResponse, tags=["Assets"])
async def list_assets(
    asset_type: Optional[str] = Query(None, description="Filter by asset type: hostname or ip"),
    search: Optional[str] = Query(None, max_length=128, description="Substring search on asset value"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
) -> AssetListResponse:
    """
    List observed assets derived from ingested security telemetry.
    Assets are hostnames and IP addresses seen in security events.
    No fabricated data — returns an empty list when no events have been ingested.
    """
    if asset_type is not None and asset_type not in _VALID_ASSET_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid asset_type '{asset_type}'. Allowed values: hostname, ip",
        )
    repo = AssetRepository(session)
    assets, total = await repo.list_assets(
        asset_type=asset_type, search=search, limit=limit, offset=offset
    )
    return AssetListResponse(assets=[AssetSummary(**a) for a in assets], total=total)


@app.get(f"{settings.API_V1_STR}/assets/{{asset_type}}/{{asset_value:path}}", response_model=AssetDetail, tags=["Assets"])
async def get_asset(
    asset_type: str,
    asset_value: str,
    session: AsyncSession = Depends(get_db_session),
) -> AssetDetail:
    """
    Return observed detail for a single asset.
    asset_type must be 'hostname' or 'ip'.
    asset_value is URL-decoded automatically by FastAPI.
    Returns 404 when the asset has not been observed in any ingested event.
    """
    if asset_type not in _VALID_ASSET_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid asset_type '{asset_type}'. Allowed values: hostname, ip",
        )
    repo = AssetRepository(session)
    if asset_type == "hostname":
        detail = await repo.get_hostname_detail(asset_value)
    else:
        detail = await repo.get_ip_detail(asset_value)

    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_type}/{asset_value!r} not found in observed telemetry",
        )
    return AssetDetail(**detail)


@app.get(f"{settings.API_V1_STR}/identities", response_model=IdentityListResponse, tags=["Identities"])
async def list_identities(
    search: Optional[str] = Query(None, max_length=128, description="Substring search on username"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
) -> IdentityListResponse:
    """
    List observed user identities derived from ingested security telemetry.
    No fabricated data — returns an empty list when no events have been ingested.
    """
    repo = IdentityRepository(session)
    identities, total = await repo.list_identities(search=search, limit=limit, offset=offset)
    return IdentityListResponse(identities=[IdentitySummary(**i) for i in identities], total=total)


@app.get(f"{settings.API_V1_STR}/identities/{{username}}", response_model=IdentityDetail, tags=["Identities"])
async def get_identity(
    username: str,
    session: AsyncSession = Depends(get_db_session),
) -> IdentityDetail:
    """
    Return observed detail for a single user identity.
    username is URL-decoded automatically by FastAPI.
    Returns 404 when the username has not been observed in any ingested event.
    """
    repo = IdentityRepository(session)
    detail = await repo.get_identity_detail(username)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity {username!r} not found in observed telemetry",
        )
    return IdentityDetail(**detail)

