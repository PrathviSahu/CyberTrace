"""
Pydantic schemas and contracts for Phase 6.3B Detection Rule Drafts and Pre-flight Validation.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from app.schemas.hunting import FilterGroup
from app.schemas.saved_hunt import SavedHuntQueryDefinition


class DraftStatus(str, Enum):
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    ARCHIVED = "ARCHIVED"


class RuleSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationScope(str, Enum):
    ALL = "all"
    HISTORICAL_TELEMETRY = "historical_telemetry"
    THREATLAB_BENCHMARKS = "threatlab_benchmarks"


class DetectionRuleDraftCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Human-readable title of the rule draft")
    description: Optional[str] = Field(None, description="Detailed explanation of the detection objective")
    severity: RuleSeverity = Field(default=RuleSeverity.MEDIUM, description="Initial rule severity")
    mitre_attack_id: Optional[str] = Field(None, max_length=64, description="Optional MITRE ATT&CK technique (e.g. T1110.001)")
    mitre_tactic: Optional[str] = Field(None, max_length=64, description="Optional MITRE ATT&CK tactic (e.g. credential_access)")
    source_hunt_id: Optional[str] = Field(None, max_length=64, description="Optional saved hunt ID to promote from")
    query_definition: Optional[SavedHuntQueryDefinition] = Field(
        None,
        description="Validated AST query definition. Required if source_hunt_id is not provided."
    )
    created_by: str = Field(default="analyst_user", max_length=128, description="Caller-supplied demo analyst identity")

    @model_validator(mode="after")
    def validate_source_or_query(self) -> "DetectionRuleDraftCreate":
        if not self.source_hunt_id and not self.query_definition:
            raise ValueError("Either 'source_hunt_id' (for promotion) or 'query_definition' (for scratch) must be provided.")
        return self


class DetectionRuleDraftUpdate(BaseModel):
    version: int = Field(..., ge=1, description="Expected current draft version for optimistic concurrency control")
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = None
    severity: Optional[RuleSeverity] = None
    mitre_attack_id: Optional[str] = Field(None, max_length=64)
    mitre_tactic: Optional[str] = Field(None, max_length=64)
    query_definition: Optional[SavedHuntQueryDefinition] = Field(
        None,
        description="Updated AST. Note: updating query_definition automatically invalidates VALIDATED status, resetting draft to DRAFT."
    )


class RuleValidationRunRequest(BaseModel):
    target_scope: ValidationScope = Field(
        default=ValidationScope.ALL,
        description="Scope of simulation: 'historical_telemetry', 'threatlab_benchmarks', or 'all'"
    )


class HistoricalTelemetryMetrics(BaseModel):
    events_scanned: int = Field(default=0, description="Total historical events in database evaluated")
    matches_found: int = Field(default=0, description="Number of events matching the rule AST")
    observation_start: Optional[datetime] = None
    observation_end: Optional[datetime] = None
    observation_duration_days: float = Field(default=0.0, description="Observation timespan in days")
    estimated_daily_alert_volume: float = Field(default=0.0, description="Extrapolated alerts per day")
    daily_volume_formula: str = Field(..., description="Explanation of daily alert calculation method")
    insufficient_history_warning: bool = Field(default=False, description="Flagged true if observation period is < 1 day or 0 events")
    provenance_breakdown: Dict[str, int] = Field(
        default_factory=dict,
        description="Breakdown by provenance: observed_telemetry, synthetic_benchmark, unknown"
    )
    sample_matched_event_ids: List[str] = Field(default_factory=list, description="Top 10 matching event IDs for evidence inspection")


class ThreatLabScenarioResult(BaseModel):
    scenario_id: str
    name: str
    category: str
    total_events: int
    matches_found: int
    classification: str = Field(..., description="Scenario ground-truth outcome: true_positive, true_negative, or benign_baseline_warning")
    is_benign_baseline_warning: bool = Field(default=False, description="True if rule triggered matches on benign baseline scenario (SCN-004)")
    matched_event_ids: List[str] = Field(default_factory=list)


class ThreatLabMetrics(BaseModel):
    scenarios_evaluated: int = Field(default=0)
    total_benchmark_events: int = Field(default=0)
    total_matches: int = Field(default=0)
    benign_baseline_matches: int = Field(default=0, description="Matches on SCN-004 Benign Administrative Baseline")
    has_benign_baseline_warning: bool = Field(default=False, description="True if rule triggered false alarms on benign noise")
    scenario_results: List[ThreatLabScenarioResult] = Field(default_factory=list)


class RuleValidationSummary(BaseModel):
    validation_id: str
    draft_version: int
    run_at: datetime
    target_scope: str
    matches_found: int
    estimated_daily_alert_volume: float
    status: str
    is_stale: bool = False
    has_benign_baseline_warning: bool = False


class RuleValidationReportResponse(BaseModel):
    validation_id: str
    draft_id: str
    draft_version: int
    run_at: datetime
    target_scope: str
    duration_ms: float
    status: str
    error_message: Optional[str] = None
    is_stale: bool = Field(
        default=False,
        description="True if the draft was concurrently modified to a newer version during validation."
    )
    draft_status_updated: bool = Field(
        default=True,
        description="True if draft status was updated to VALIDATED; False if stale validation preserved draft in DRAFT."
    )
    historical_metrics: Optional[HistoricalTelemetryMetrics] = None
    threatlab_metrics: Optional[ThreatLabMetrics] = None
    provenance_disclaimer: str = Field(
        default="Synthetic benchmark matches are evaluated separately and not counted as production alerts.",
        description="Data provenance truthfulness notice"
    )


class DetectionRuleDraftResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    severity: str
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    source_hunt_id: Optional[str] = None
    source_hunt_version: Optional[int] = None
    query_definition: Dict[str, Any]
    status: DraftStatus
    version: int
    created_by: str
    is_archived: bool
    created_at: datetime
    updated_at: datetime
    latest_validation: Optional[RuleValidationSummary] = None
    author_attribution_note: str = Field(
        default="Caller-supplied demo identity. Not cryptographically verified.",
        description="Security attribution transparency notice"
    )

    model_config = {"from_attributes": True}


class DetectionRuleDraftListResponse(BaseModel):
    items: List[DetectionRuleDraftResponse]
    total: int
    limit: int
    offset: int
