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
    detections = service.detection_engine.evaluate_all(events)
    detections_count = len(detections)

    incidents = await service.process_and_correlate_events(events, source_file_hash=source_file_hash)

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

