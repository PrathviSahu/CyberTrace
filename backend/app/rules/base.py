"""
Base definitions and models for CyberTrace Deterministic Detection Rules.
"""

from abc import ABC, abstractmethod
from datetime import datetime
import hashlib
from typing import Any, Dict, List
from pydantic import BaseModel, Field
from app.schemas.ces import CommonEvent, EventSeverity


def generate_deterministic_detection_id(
    rule_id: str,
    entity_key: str,
    triggering_event_ids: List[str],
    detection_timestamp: datetime,
) -> str:
    """
    Generate an auditable, deterministic detection ID from rule, entity,
    ordered triggering events, and timestamp.
    Guarantees idempotency across pipeline evaluations.
    """
    ts_str = detection_timestamp.isoformat() if hasattr(detection_timestamp, "isoformat") else str(detection_timestamp)
    sorted_events = ",".join(sorted(triggering_event_ids or []))
    raw = f"{rule_id}:{entity_key}:{sorted_events}:{ts_str}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    return f"det_{digest}"


class DetectionResult(BaseModel):
    """
    Structured outcome of a deterministic detection rule.
    Captures exact triggering event IDs and auditable parameters.
    """
    detection_id: str = Field(default="")
    rule_id: str = Field(..., description="Unique rule identifier (e.g., DET-001)")
    rule_name: str = Field(..., description="Human-readable rule title")
    severity: EventSeverity = Field(..., description="Severity classification")
    summary: str = Field(..., description="Evidence-backed description of why the rule fired")
    detection_timestamp: datetime = Field(..., description="Timestamp of the detection")
    entity_key: str = Field(..., description="Primary entity implicated (e.g., user:svc_deploy, ip:198.51.100.44)")
    triggering_event_ids: List[str] = Field(default_factory=list, description="Explicit event IDs that satisfied the rule")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic parameters, thresholds, and calculations")

    def model_post_init(self, __context: Any) -> None:
        if not self.detection_id:
            self.detection_id = generate_deterministic_detection_id(
                rule_id=self.rule_id,
                entity_key=self.entity_key,
                triggering_event_ids=self.triggering_event_ids,
                detection_timestamp=self.detection_timestamp,
            )


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
