"""
Data models and contracts for the CyberTrace Incident Correlation Engine.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.ces import EventSeverity


class CorrelationStrength(float, Enum):
    STRONG = 1.0
    MODERATE = 0.7
    WEAK = 0.3


class RelationshipType(str, Enum):
    SAME_USER_AUTH_SEQUENCE = "same_user_auth_sequence"
    SAME_USER_PRIVILEGE_ELEVATION = "same_user_privilege_elevation"
    HOST_POST_COMPROMISE_ACTIVITY = "host_post_compromise_activity"
    DIRECT_EVIDENCE_PROVENANCE = "direct_evidence_provenance"
    TEMPORAL_ENTITY_CO_OCCURRENCE = "temporal_entity_co_occurrence"


class CorrelationRelationship(BaseModel):
    """Auditable record explaining why two detections were linked."""
    source_detection_id: str
    target_detection_id: str
    relationship_type: RelationshipType
    matching_entity: str
    time_difference_seconds: float
    explanation: str
    correlation_strength: CorrelationStrength
    supporting_event_ids: List[str] = Field(default_factory=list)


class CorrelatedEntity(BaseModel):
    """Entity discovered and attributed within an incident."""
    entity_type: str  # user, source_ip, destination_ip, hostname, process
    entity_value: str
    relationship: str  # e.g., compromised_account, attacker_source_ip, compromised_host, c2_destination
    confidence: float = 1.0
    evidence_references: List[str] = Field(default_factory=list)


class CorrelatedIncidentGroup(BaseModel):
    """A cohesive cluster of detections and evidence forming a distinct security incident."""
    incident_id: str
    correlation_key: str
    title: str
    description: str
    severity: EventSeverity
    status: str = "open"
    first_seen: datetime
    last_seen: datetime
    detection_ids: List[str]
    relationships: List[CorrelationRelationship] = Field(default_factory=list)
    entities: List[CorrelatedEntity] = Field(default_factory=list)
    supporting_event_ids: List[str] = Field(default_factory=list)


class CorrelationConfig(BaseModel):
    """Configurable thresholds and safeguards for the correlation engine."""
    max_time_delta_seconds: int = 3600  # 1 hour between consecutive related detections
    max_incident_span_seconds: int = 86400  # 24 hours maximum total duration of a single incident
    min_correlation_strength: float = 0.6  # Weak links (<0.6) are never merged automatically
    disallowed_merge_entities: List[str] = Field(
        default_factory=lambda: ["ip:public_nat", "host:generic_dc", "user:anonymous"]
    )
    # Known public gateways or external resolvers that must never be used alone to merge incidents
    public_ip_blocklist: List[str] = Field(
        default_factory=lambda: [
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
            "127.0.0.1", "0.0.0.0", "255.255.255.255"
        ]
    )

