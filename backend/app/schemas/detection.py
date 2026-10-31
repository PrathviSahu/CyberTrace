"""
Pydantic schemas for Detections.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.ces import EventSeverity


class DetectionResponse(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: EventSeverity
    entity_type: str
    entity_value: str
    first_seen: datetime
    last_seen: datetime
    detected_at: datetime
    explanation: str
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    triggering_event_ids: List[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}

