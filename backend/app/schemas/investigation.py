"""
Pydantic schemas for CyberTrace AI Investigations.
Defines evidence-grounded facts, hypotheses, unknowns, and recommended defensive actions.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ImpactLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ObservedFact(BaseModel):
    statement: str = Field(..., description="Fact strictly observed from verifiable telemetry")
    event_ids: List[str] = Field(default_factory=list, description="Explicit event IDs supporting this observation")


class Hypothesis(BaseModel):
    statement: str = Field(..., description="Investigative hypothesis regarding attacker behavior or technique")
    supporting_event_ids: List[str] = Field(default_factory=list, description="Supporting telemetry event IDs")
    contradicting_event_ids: List[str] = Field(default_factory=list, description="Contradicting event IDs if any")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM, description="Analyst confidence level")
    caveats: List[str] = Field(default_factory=list, description="Assumptions or uncertainties")


class UnknownGap(BaseModel):
    question: str = Field(..., description="Crucial investigative question that cannot be answered from current logs")
    reason: str = Field(..., description="Explanation of why the telemetry is currently missing or inconclusive")


class RecommendedAction(BaseModel):
    action: str = Field(..., description="Recommended defensive action (e.g., Revoke session, isolate endpoint)")
    rationale: str = Field(..., description="Evidence-based justification for this action")
    supporting_event_ids: List[str] = Field(default_factory=list, description="Associated event IDs justifying response")
    impact: ImpactLevel = Field(default=ImpactLevel.MEDIUM, description="Operational impact on normal business activity")
    requires_human_approval: bool = Field(default=True, description="Always true - requires explicit analyst sign-off")
    is_generic_guidance: bool = Field(default=False, description="True if action is general defensive posture guidance rather than incident-specific evidence-backed remediation")


class StructuredInvestigation(BaseModel):
    """Normalized structured outcome of an AI-assisted or fallback incident investigation."""
    executive_summary: str = Field(..., description="Concise executive synthesis of the incident")
    observed_facts: List[ObservedFact] = Field(default_factory=list, description="Verified facts linked to event IDs")
    hypotheses: List[Hypothesis] = Field(default_factory=list, description="Plausible hypotheses explaining the observations")
    unknowns: List[UnknownGap] = Field(default_factory=list, description="Investigative gaps and missing telemetry")
    recommended_actions: List[RecommendedAction] = Field(default_factory=list, description="Defensive playbooks for analyst review")
    limitations: List[str] = Field(default_factory=list, description="Analytical limitations of the investigation model")


class InvestigationResponse(BaseModel):
    """API representation of an investigation record."""
    id: str
    incident_id: str
    model_id: str
    status: str
    executive_summary: str
    structured_result: StructuredInvestigation
    event_citations: List[str] = Field(default_factory=list)
    tool_call_count: int = 0
    duration_seconds: float = 0.0
    request_id: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

