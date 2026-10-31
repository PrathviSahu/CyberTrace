"""
Pydantic schemas for Incidents and Entity details.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.ces import CommonEvent, EventSeverity
from app.schemas.detection import DetectionResponse


class IncidentEntityResponse(BaseModel):
    id: str
    incident_id: str
    entity_type: str
    entity_value: str
    relationship: str
    confidence: float
    evidence_references: List[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class IncidentSummaryResponse(BaseModel):
    id: str
    correlation_key: str
    title: str
    description: str
    severity: EventSeverity
    status: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    entities: List[IncidentEntityResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class IncidentDetailResponse(BaseModel):
    incident: IncidentSummaryResponse
    detections: List[DetectionResponse]
    events: List[CommonEvent]
    entities: List[IncidentEntityResponse]


class LogUploadResponse(BaseModel):
    filename: str
    detected_format: str
    source_file_hash: str
    parsed_events_count: int
    persisted_events_count: int
    detections_count: int
    incidents_count: int
    status: str = "success"

