"""
Pydantic schemas and validation contracts for Phase 6.3A Saved Threat Hunts & Query Persistence.
Enforces strict AST validation, optimistic version concurrency, and transparent author attribution disclaimer.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator

from app.schemas.hunting import (
    FilterField,
    FilterGroup,
    HuntedEventItem,
    ThreatHuntQueryRequest,
    TimeRangeFilter,
)


class SavedHuntQueryDefinition(BaseModel):
    """
    Validated AST and query execution parameters persisted inside a saved hunt.
    Reuses Phase 6.2 FilterGroup, TimeRangeFilter, and FilterField.
    """
    time_range: Optional[TimeRangeFilter] = Field(
        None,
        description="Optional time range filter with timezone-aware start/end bounds."
    )
    filter_group: Optional[FilterGroup] = Field(
        None,
        description="Optional root boolean filter group. If omitted, queries match all events within time_range."
    )
    sort_by: FilterField = Field(
        default=FilterField.TIMESTAMP,
        description="Event field to sort results by (default: 'timestamp')."
    )
    sort_order: Literal["asc", "desc"] = Field(
        default="desc",
        description="Sort direction ('asc' or 'desc', default: 'desc')."
    )
    limit: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Default execution page limit (min: 1, max: 200, default: 50)."
    )
    offset: int = Field(
        default=0,
        ge=0,
        le=10000,
        description="Default execution offset (min: 0, max: 10000, default: 0)."
    )

    def to_threat_hunt_request(
        self,
        override_limit: Optional[int] = None,
        override_offset: Optional[int] = None,
    ) -> ThreatHuntQueryRequest:
        """Convert persisted AST parameters into a ThreatHuntQueryRequest for execution."""
        return ThreatHuntQueryRequest(
            time_range=self.time_range,
            filter_group=self.filter_group,
            sort_by=self.sort_by,
            sort_order=self.sort_order,
            limit=override_limit if override_limit is not None else self.limit,
            offset=override_offset if override_offset is not None else self.offset,
        )


class SavedHuntCreate(BaseModel):
    """Payload to create a new Saved Threat Hunt."""
    name: str = Field(..., min_length=1, max_length=128, description="Human-readable name for the saved hunt.")
    description: Optional[str] = Field(None, max_length=2000, description="Optional description or hypothesis.")
    tags: List[str] = Field(default_factory=list, description="Categorization tags (e.g. ['mitre:t1078', 'lateral_movement']).")
    query_definition: SavedHuntQueryDefinition = Field(..., description="Validated AST query definition.")
    created_by: str = Field(
        default="analyst_user",
        max_length=128,
        description="Caller-supplied demo analyst identity. Note: Demo metadata only; no cryptographic auth or RBAC enforced.",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Hunt name cannot be blank or whitespace only")
        return s

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, tags: List[str]) -> List[str]:
        if len(tags) > 30:
            raise ValueError("A saved hunt cannot have more than 30 tags")
        cleaned: List[str] = []
        for t in tags:
            s = t.strip()
            if s and s not in cleaned:
                if len(s) > 64:
                    raise ValueError(f"Tag exceeds maximum length of 64 characters: '{s[:20]}...'")
                cleaned.append(s)
        return cleaned


class SavedHuntUpdate(BaseModel):
    """
    Payload to update an existing Saved Threat Hunt.
    Enforces optimistic concurrency control via mandatory expected version.
    """
    version: int = Field(
        ...,
        ge=1,
        description="Expected current version of the saved hunt. Must match database version or HTTP 409 Conflict is raised.",
    )
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=2000)
    tags: Optional[List[str]] = Field(None)
    query_definition: Optional[SavedHuntQueryDefinition] = Field(None)
    updated_by: Optional[str] = Field(
        None,
        max_length=128,
        description="Caller-supplied demo analyst identity for update tracking.",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            s = v.strip()
            if not s:
                raise ValueError("Hunt name cannot be blank or whitespace only")
            return s
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, tags: Optional[List[str]]) -> Optional[List[str]]:
        if tags is None:
            return None
        if len(tags) > 30:
            raise ValueError("A saved hunt cannot have more than 30 tags")
        cleaned: List[str] = []
        for t in tags:
            s = t.strip()
            if s and s not in cleaned:
                if len(s) > 64:
                    raise ValueError(f"Tag exceeds maximum length of 64 characters: '{s[:20]}...'")
                cleaned.append(s)
        return cleaned


class SavedHuntResponse(BaseModel):
    """Full detail of a saved threat hunt record."""
    id: str
    name: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    query_definition: SavedHuntQueryDefinition
    created_by: str
    created_at: datetime
    updated_at: datetime
    version: int
    last_run_at: Optional[datetime] = None
    run_count: int = 0
    is_archived: bool = False
    author_attribution_note: str = Field(
        default="Caller-supplied demo identity. No cryptographic auth or RBAC enforced.",
        description="Security notice clarifying that author attribution is unauthenticated demo metadata.",
    )

    model_config = {"from_attributes": True}


class SavedHuntListResponse(BaseModel):
    """Paginated list of saved threat hunts."""
    items: List[SavedHuntResponse]
    total: int
    limit: int
    offset: int


class SavedHuntExecuteRequest(BaseModel):
    """Optional execution overrides for running a saved hunt."""
    limit: Optional[int] = Field(None, ge=1, le=200, description="Optional override page limit (1-200).")
    offset: Optional[int] = Field(None, ge=0, le=10000, description="Optional override offset (0-10000).")
    executed_by: Optional[str] = Field(
        None,
        max_length=128,
        description="Caller-supplied demo analyst identity. Note: Demo metadata only.",
    )


class SavedHuntExecuteResponse(BaseModel):
    """Results from executing a saved threat hunt with execution tracking metadata."""
    hunt_id: str
    hunt_name: str
    executed_version: int
    executed_at: datetime
    run_count: int
    items: List[HuntedEventItem]
    total: int
    limit: int
    offset: int
    query_duration_ms: float
    applied_filter_count: int
    provenance: str = Field(
        default="unknown",
        description="Aggregate dataset provenance: 'observed_telemetry', 'synthetic_benchmark', 'unknown', or 'mixed'.",
    )


class SavedHuntDuplicateRequest(BaseModel):
    """Request payload to duplicate an existing saved threat hunt."""
    name: Optional[str] = Field(None, min_length=1, max_length=128, description="Optional custom name for duplicated hunt. Defaults to 'Copy of {original.name}'.")
    created_by: str = Field(
        default="analyst_user",
        max_length=128,
        description="Caller-supplied demo analyst identity. Note: Demo metadata only.",
    )

