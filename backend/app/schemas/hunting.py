"""
Pydantic schemas and validation contracts for Phase 6.2 Structured Threat Hunting.
Enforces allowlisted fields, operators, type compatibility, and bounded query trees.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set, Union
from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
)


class FilterField(str, Enum):
    TIMESTAMP = "timestamp"
    HOSTNAME = "hostname"
    USERNAME = "username"
    SOURCE_IP = "source_ip"
    DESTINATION_IP = "destination_ip"
    CATEGORY = "category"
    ACTION = "action"
    SEVERITY = "severity"
    BYTES_OUT = "bytes_out"
    BYTES_IN = "bytes_in"
    SOURCE_PORT = "source_port"
    DESTINATION_PORT = "destination_port"
    PROTOCOL = "protocol"
    PROCESS_NAME = "process_name"


class FilterOperator(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    IN = "in"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"


STRING_FIELDS: Set[FilterField] = {
    FilterField.HOSTNAME,
    FilterField.USERNAME,
    FilterField.SOURCE_IP,
    FilterField.DESTINATION_IP,
    FilterField.CATEGORY,
    FilterField.ACTION,
    FilterField.SEVERITY,
    FilterField.PROTOCOL,
    FilterField.PROCESS_NAME,
}

NUMERIC_FIELDS: Set[FilterField] = {
    FilterField.BYTES_OUT,
    FilterField.BYTES_IN,
    FilterField.SOURCE_PORT,
    FilterField.DESTINATION_PORT,
}

PORT_FIELDS: Set[FilterField] = {
    FilterField.SOURCE_PORT,
    FilterField.DESTINATION_PORT,
}

TIMESTAMP_FIELDS: Set[FilterField] = {
    FilterField.TIMESTAMP,
}


def _validate_strict_integer(val: Any, field: FilterField) -> int:
    """
    Validate that a value is strictly a Python int.
    Rejects booleans, floating-point numbers (e.g. 80.0, 80.5), and numeric strings (e.g. '80').
    Enforces port ranges (0-65535) and non-negative byte counts.
    """
    if isinstance(val, bool) or not isinstance(val, int) or isinstance(val, float):
        raise ValueError(
            f"Value for integer field '{field.value}' must be an integer, got {val!r} ({type(val).__name__})"
        )
    if field in PORT_FIELDS and not (0 <= val <= 65535):
        raise ValueError(f"Port number for '{field.value}' must be between 0 and 65535, got {val}")
    if field in (FilterField.BYTES_OUT, FilterField.BYTES_IN) and val < 0:
        raise ValueError(f"Byte count for '{field.value}' cannot be negative, got {val}")
    return val


def _validate_tz_aware(dt_val: Any, field_name: str) -> datetime:
    """Ensure a datetime is timezone-aware."""
    if isinstance(dt_val, str):
        try:
            dt = datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
        except Exception as exc:
            raise ValueError(f"Invalid ISO-8601 timestamp string for '{field_name}': {dt_val}") from exc
    elif isinstance(dt_val, datetime):
        dt = dt_val
    else:
        raise ValueError(f"Expected datetime or ISO string for '{field_name}', got {type(dt_val).__name__}")

    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"Timestamp for '{field_name}' must be timezone-aware (e.g. UTC ISO-8601 with 'Z' or offset)")
    return dt


class TimeRangeFilter(BaseModel):
    """Optional time range filter with inclusive boundaries."""
    start: Optional[datetime] = Field(None, description="Inclusive start timestamp (timezone-aware)")
    end: Optional[datetime] = Field(None, description="Inclusive end timestamp (timezone-aware)")

    @field_validator("start", "end", mode="after")
    @classmethod
    def validate_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and (v.tzinfo is None or v.tzinfo.utcoffset(v) is None):
            raise ValueError("Timestamp must be timezone-aware (e.g. UTC ISO-8601)")
        return v

    @model_validator(mode="after")
    def validate_bounds(self) -> "TimeRangeFilter":
        if self.start and self.end and self.start > self.end:
            raise ValueError("Start timestamp cannot be later than end timestamp")
        return self


class FilterCondition(BaseModel):
    """Single predicate filtering an allowlisted field using an allowlisted operator."""
    field: FilterField
    operator: FilterOperator
    value: Any

    @model_validator(mode="after")
    def validate_field_operator_compatibility(self) -> "FilterCondition":
        f = self.field
        op = self.operator
        val = self.value

        # 1. Operators 'contains' and 'starts_with' only valid for string fields
        if op in (FilterOperator.CONTAINS, FilterOperator.STARTS_WITH):
            if f not in STRING_FIELDS:
                raise ValueError(
                    f"Operator '{op.value}' is only valid for string fields ({', '.join(sorted([x.value for x in STRING_FIELDS]))}), got '{f.value}'"
                )
            if not isinstance(val, str) or len(val.strip()) == 0:
                raise ValueError(f"Value for '{op.value}' must be a non-empty string, got {val!r}")
            if len(val) > 256:
                raise ValueError(f"Value for '{op.value}' exceeds maximum length of 256 characters")

        # 2. Operators 'gt', 'gte', 'lt', 'lte' only valid for numeric or timestamp fields
        elif op in (FilterOperator.GT, FilterOperator.GTE, FilterOperator.LT, FilterOperator.LTE):
            if f in NUMERIC_FIELDS:
                self.value = _validate_strict_integer(val, f)
            elif f in TIMESTAMP_FIELDS:
                self.value = _validate_tz_aware(val, f.value)
            else:
                raise ValueError(
                    f"Comparison operator '{op.value}' is not valid for field '{f.value}'. Valid for numeric and timestamp fields only."
                )

        # 3. Operator 'in' requires a non-empty bounded list of compatible values
        elif op == FilterOperator.IN:
            if not isinstance(val, list):
                raise ValueError(f"Value for 'in' operator must be a list, got {type(val).__name__}")
            if len(val) == 0:
                raise ValueError("Value for 'in' operator cannot be an empty list")
            if len(val) > 50:
                raise ValueError(f"Value for 'in' operator exceeds maximum allowed items (50), got {len(val)}")

            # Validate each item
            if f in STRING_FIELDS:
                for item in val:
                    if not isinstance(item, str) or len(item.strip()) == 0:
                        raise ValueError(f"All items in 'in' list for string field '{f.value}' must be non-empty strings, got {item!r}")
                    if len(item) > 256:
                        raise ValueError(f"Item in 'in' list exceeds maximum length of 256 characters: {item[:30]}...")
            elif f in NUMERIC_FIELDS:
                validated_ints = []
                for item in val:
                    validated_ints.append(_validate_strict_integer(item, f))
                self.value = validated_ints
            elif f in TIMESTAMP_FIELDS:
                validated_dts = []
                for item in val:
                    validated_dts.append(_validate_tz_aware(item, f.value))
                self.value = validated_dts

        # 4. Operators 'eq' and 'neq'
        elif op in (FilterOperator.EQ, FilterOperator.NEQ):
            if isinstance(val, (list, dict)):
                raise ValueError(f"Value for '{op.value}' cannot be a list or dict, got {type(val).__name__}")
            if f in STRING_FIELDS:
                if not isinstance(val, str):
                    raise ValueError(f"Value for string field '{f.value}' must be a string, got {type(val).__name__}")
                if len(val) > 256:
                    raise ValueError(f"Value for '{f.value}' exceeds maximum length of 256 characters")
            elif f in NUMERIC_FIELDS:
                self.value = _validate_strict_integer(val, f)
            elif f in TIMESTAMP_FIELDS:
                self.value = _validate_tz_aware(val, f.value)

        return self


class FilterGroup(BaseModel):
    """
    Boolean expression group combining conditions with AND or OR logic.
    Supports nested groups up to maximum depth of 2.
    """
    logic: Literal["AND", "OR"] = "AND"
    conditions: List[FilterCondition] = Field(default_factory=list)
    groups: List["FilterGroup"] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_group_constraints(self) -> "FilterGroup":
        # 1. Reject empty group
        if len(self.conditions) == 0 and len(self.groups) == 0:
            raise ValueError("Filter group must contain at least one condition or child group")

        # 2. Maximum conditions per group
        if len(self.conditions) > 20:
            raise ValueError(f"Filter group contains {len(self.conditions)} conditions, exceeding maximum of 20")

        # 3. Maximum nested groups per group
        if len(self.groups) > 5:
            raise ValueError(f"Filter group contains {len(self.groups)} child groups, exceeding maximum of 5")

        # 4. Enforce max nesting depth of 2 (child groups cannot contain further groups)
        for child in self.groups:
            if child.groups:
                raise ValueError("Maximum filter group nesting depth of 2 exceeded: child groups cannot contain nested groups")
            if len(child.conditions) == 0:
                raise ValueError("Child filter group cannot be empty")
            if len(child.conditions) > 20:
                raise ValueError(f"Child filter group contains {len(child.conditions)} conditions, exceeding maximum of 20")

        return self


class ThreatHuntQueryRequest(BaseModel):
    """
    Structured Threat Hunting query request.
    Allows searching full event telemetry using validated parameterized AST.
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
        description="Page size limit (min: 1, max: 200, default: 50)."
    )
    offset: int = Field(
        default=0,
        ge=0,
        le=10000,
        description="Pagination offset (min: 0, max: 10000, default: 0)."
    )


class RelatedDetectionSummary(BaseModel):
    """Summary of a detection rule fired on this event."""
    id: str
    rule_id: str
    rule_name: str
    severity: str
    explanation: str

    model_config = {"from_attributes": True}


class RelatedIncidentSummary(BaseModel):
    """Summary of an incident associated with this event via detections."""
    id: str
    title: str
    severity: str
    status: str

    model_config = {"from_attributes": True}


class HuntedEventItem(BaseModel):
    """
    Enriched security event item returned by Threat Hunting queries.
    Includes normalized CES attributes and verified relationship links.
    """
    id: str
    timestamp: datetime
    source_type: str
    category: str
    action: str
    severity: str
    username: Optional[str] = None
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_out: int = 0
    bytes_in: int = 0
    process_name: Optional[str] = None
    process_command_line: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    source_file_hash: Optional[str] = Field(
        default=None,
        description="Cryptographic SHA-256 checksum of ingested file for integrity verification (not proof of authenticity).",
    )
    provenance: str = Field(
        default="unknown",
        description="Explicit provenance classification: 'observed_telemetry', 'synthetic_benchmark', 'unknown', or 'mixed'.",
    )
    related_detections: List[RelatedDetectionSummary] = Field(default_factory=list)
    related_incidents: List[RelatedIncidentSummary] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ThreatHuntQueryResponse(BaseModel):
    """Paginated Threat Hunting query execution result."""
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

