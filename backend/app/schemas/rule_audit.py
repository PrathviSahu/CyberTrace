"""
CyberTrace Rule Audit Ledger Schemas (Phase 6.3C).
Defines contracts for append-only audit entries, lifecycle transition diffs, and query filtering.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditAction(str, Enum):
    CREATE_DRAFT = "CREATE_DRAFT"
    VALIDATE_DRAFT = "VALIDATE_DRAFT"
    APPROVE_DRAFT = "APPROVE_DRAFT"
    REJECT_DRAFT = "REJECT_DRAFT"
    ACTIVATE_RULE = "ACTIVATE_RULE"
    DEACTIVATE_RULE = "DEACTIVATE_RULE"
    REACTIVATE_RULE = "REACTIVATE_RULE"
    DEPRECATE_RULE = "DEPRECATE_RULE"
    ARCHIVE_DRAFT = "ARCHIVE_DRAFT"


class RuleAuditEntryResponse(BaseModel):
    id: str
    target_type: str
    target_id: str
    action: str
    actor: str
    timestamp: datetime
    justification: str
    state_before: Dict[str, Any]
    state_after: Dict[str, Any]
    demo_override_flag: bool = False
    security_warning: Optional[str] = None
    storage_classification: str = Field(
        default="application_level_append_only",
        description="Audit storage security classification"
    )

    model_config = {"from_attributes": True}


class RuleAuditListResponse(BaseModel):
    items: List[RuleAuditEntryResponse]
    total: int
    limit: int
    offset: int
