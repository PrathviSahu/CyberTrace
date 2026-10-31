"""
Base definitions and models for CyberTrace Deterministic Detection Rules.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List
import uuid
from pydantic import BaseModel, Field
from app.schemas.ces import CommonEvent, EventSeverity


class DetectionResult(BaseModel):
    """
    Structured outcome of a deterministic detection rule.
    Captures exact triggering event IDs and auditable parameters.
    """
    detection_id: str = Field(default_factory=lambda: f"det_{uuid.uuid4().hex[:10]}")
    rule_id: str = Field(..., description="Unique rule identifier (e.g., DET-001)")
    rule_name: str = Field(..., description="Human-readable rule title")
    severity: EventSeverity = Field(..., description="Severity classification")
    summary: str = Field(..., description="Evidence-backed description of why the rule fired")
    detection_timestamp: datetime = Field(..., description="Timestamp of the detection")
    entity_key: str = Field(..., description="Primary entity implicated (e.g., user:svc_deploy, ip:198.51.100.44)")
    triggering_event_ids: List[str] = Field(default_factory=list, description="Explicit event IDs that satisfied the rule")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic parameters, thresholds, and calculations")


class BaseDetectionRule(ABC):
    """Abstract interface for all deterministic detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        pass

    @property
    @abstractmethod
    def rule_name(self) -> str:
        pass

    @property
    @abstractmethod
    def default_severity(self) -> EventSeverity:
        pass

    @abstractmethod
    def evaluate(self, events: List[CommonEvent], prior_detections: List[DetectionResult]) -> List[DetectionResult]:
        """
        Evaluate chronological events and prior detections.
        Returns newly triggered detections.
        """
        pass
