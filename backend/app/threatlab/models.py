"""
Pydantic models and schemas for CyberTrace ThreatLab Benchmark Engine.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfusionMatrix(BaseModel):
    true_positives: int = Field(..., description="Number of expected detections correctly identified")
    false_positives: int = Field(..., description="Number of false alarms on benign events")
    false_negatives: int = Field(..., description="Number of expected attack detections missed")
    true_negatives: int = Field(..., description="Number of benign events correctly ignored")
    precision: float = Field(..., description="Precision score: TP / (TP + FP)")
    recall: float = Field(..., description="Recall score: TP / (TP + FN)")
    f1_score: float = Field(..., description="Harmonic mean: 2 * (P * R) / (P + R)")


class ScenarioSummary(BaseModel):
    scenario_id: str
    name: str
    description: str
    event_count: int
    expected_detection_count: int
    category: str
    mitre_techniques: List[str] = Field(default_factory=list)


class ReplayDetectionResult(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    entity_value: str
    detected_at: str
    explanation: str
    triggering_event_ids: List[str] = Field(default_factory=list)


class ScenarioReplayResponse(BaseModel):
    scenario_id: str
    scenario_name: str
    events_processed: int
    detections_fired_count: int
    detections: List[ReplayDetectionResult]
    confusion_matrix: ConfusionMatrix
    duration_ms: float
    status: str
    evaluation_notes: List[str] = Field(default_factory=list)
