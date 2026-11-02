"""
CyberTrace Active Detection Rule Schemas (Phase 6.3C).
Defines contracts for active production rules, status updates, and governance disclosures.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ActiveRuleStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    DEPRECATED = "DEPRECATED"


class ActiveRuleStatusUpdateRequest(BaseModel):
    version: int = Field(..., ge=1, description="Expected rule version for optimistic concurrency control")
    status: ActiveRuleStatus = Field(..., description="Target status: ACTIVE, DISABLED, or DEPRECATED")
    justification: str = Field(..., min_length=10, description="Mandatory rationale for status change (min 10 characters)")
    actor: str = Field(default="soc_operator", min_length=1, max_length=128, description="Caller-supplied operator identity")


class ActiveDetectionRuleResponse(BaseModel):
    id: str
    rule_code: str
    name: str
    description: Optional[str] = None
    severity: str
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    source_draft_id: str
    source_draft_version: int
    validation_run_id: str
    query_definition: Dict[str, Any]
    status: ActiveRuleStatus
    version: int
    approved_by: str
    approved_at: datetime
    activated_at: datetime
    deactivated_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    governance_classification: str = Field(
        default="demonstration_level_approval_gate",
        description="Governance classification notice"
    )
    author_attribution_note: str = Field(
        default="Caller-supplied demo identity. Not cryptographically verified or backed by enterprise RBAC.",
        description="Attribution transparency notice"
    )

    model_config = {"from_attributes": True}


class ActiveDetectionRuleListResponse(BaseModel):
    items: List[ActiveDetectionRuleResponse]
    total: int
    limit: int
    offset: int
