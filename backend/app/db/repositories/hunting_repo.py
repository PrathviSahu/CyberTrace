"""
Threat Hunting Query Repository for CyberTrace (Phase 6.2).
Converts validated AST expressions into parameterized SQLAlchemy queries,
performs batched resolution of related detections/incidents without N+1 queries,
and computes execution metadata.

Database Query Accounting:
- 1 query for an empty result (total == 0 short-circuit).
- 2 queries when the requested page is beyond the result set (offset >= total).
- 3 queries when events exist but no detections are associated.
- 4 queries in the fully populated detection-and-incident path (count, page, detections, incidents).
Batched joins ensure the query count is constant O(1) and never scales with page size.
"""

from collections import defaultdict
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Sequence, Set
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import BinaryExpression, BooleanClauseList, ColumnElement

from app.db.models import (
    DetectionEventModel,
    DetectionModel,
    IncidentDetectionModel,
    IncidentModel,
    SecurityEventModel,
)
from app.schemas.hunting import (
    FilterCondition,
    FilterField,
    FilterGroup,
    FilterOperator,
    HuntedEventItem,
    RelatedDetectionSummary,
    RelatedIncidentSummary,
    ThreatHuntQueryRequest,
    ThreatHuntQueryResponse,
)

# Explicit column mapping for allowlisted fields
FIELD_COLUMN_MAP: Dict[FilterField, ColumnElement] = {
    FilterField.TIMESTAMP: SecurityEventModel.timestamp,
    FilterField.HOSTNAME: SecurityEventModel.hostname,
    FilterField.USERNAME: SecurityEventModel.username,
    FilterField.SOURCE_IP: SecurityEventModel.source_ip,
    FilterField.DESTINATION_IP: SecurityEventModel.destination_ip,
    FilterField.CATEGORY: SecurityEventModel.category,
    FilterField.ACTION: SecurityEventModel.action,
    FilterField.SEVERITY: SecurityEventModel.severity,
    FilterField.BYTES_OUT: SecurityEventModel.bytes_out,
    FilterField.BYTES_IN: SecurityEventModel.bytes_in,
    FilterField.SOURCE_PORT: SecurityEventModel.source_port,
    FilterField.DESTINATION_PORT: SecurityEventModel.destination_port,
    FilterField.PROTOCOL: SecurityEventModel.protocol,
    FilterField.PROCESS_NAME: SecurityEventModel.process_name,
}

NULLABLE_COLUMNS: Set[FilterField] = {
    FilterField.HOSTNAME,
    FilterField.USERNAME,
    FilterField.SOURCE_IP,
    FilterField.DESTINATION_IP,
    FilterField.SOURCE_PORT,
    FilterField.DESTINATION_PORT,
    FilterField.PROTOCOL,
    FilterField.PROCESS_NAME,
}


def escape_like(value: str, escape_char: str = "\\") -> str:
    """Escape LIKE wildcard characters (%, _, and escape_char) to prevent wildcard injection."""
    return (
        value.replace(escape_char, escape_char + escape_char)
        .replace("%", escape_char + "%")
        .replace("_", escape_char + "_")
    )


def count_leaf_conditions(group: FilterGroup) -> int:
    """Recursively count all leaf filter conditions in a group tree."""
    count = len(group.conditions)
    for child in group.groups:
        count += count_leaf_conditions(child)
    return count


def classify_event_provenance(
    raw_payload: Optional[Dict[str, Any]],
    source_type: Optional[str] = None,
    event_id: Optional[str] = None,
) -> str:
    """
    Classify the provenance of a security event using explicit, trustworthy metadata.

    Provenance Principles:
    1. A cryptographic SHA-256 hash (source_file_hash) establishes integrity/checksum
       of the ingested file content only; it does NOT establish authenticity, authorization,
       or that the telemetry originated from a genuine organization.
    2. Synthetic / benchmark indicators take strict precedence. If any synthetic, benchmark,
       or simulation flag is present, the event is classified as 'synthetic_benchmark',
       and any conflicting claims of observed telemetry are rejected.
    3. An event is classified as 'observed_telemetry' ONLY if it possesses explicit, verified
       source attribution from an identified, authorized telemetry source (e.g. collector_id,
       sensor_id, authorized source_attribution, or telemetry_source).
    4. If provenance cannot be reliably established from available metadata, it is labeled
       'unknown' rather than making unsupported authenticity claims.
    """
    raw = raw_payload or {}
    nested = raw.get("raw_payload") if isinstance(raw.get("raw_payload"), dict) else {}
    effective = {**nested, **raw}
    eid = str(event_id or "").strip().lower()
    src_type = str(source_type or "").strip().lower()
    raw_prov = str(effective.get("provenance", "")).strip().lower()

    # Rule 1: Check for explicit synthetic/benchmark markers (High Precedence)
    raw_synthetic = effective.get("synthetic")
    raw_is_synthetic = effective.get("is_synthetic")
    raw_benchmark = effective.get("benchmark")
    raw_simulation = effective.get("simulation")

    is_synthetic = (
        raw_synthetic is True
        or raw_is_synthetic is True
        or raw_benchmark is True
        or raw_simulation is True
        or raw_prov in ("synthetic_benchmark", "synthetic", "benchmark", "simulated_attack", "demo_benchmark")
        or src_type in ("synthetic", "benchmark", "simulation", "threatlab")
        or eid.startswith("scn")
        or eid.startswith("synth_")
    )

    # Any synthetic indicator classifies as synthetic_benchmark, overriding contradictory observed claims.
    if is_synthetic:
        return "synthetic_benchmark"

    # Rule 2: Explicit verified source attribution for observed telemetry
    # Telemetry is only considered 'observed_telemetry' if imported from an identified,
    # authorized telemetry source, verified by explicit source attribution metadata.
    source_attr = (
        effective.get("source_attribution")
        or effective.get("telemetry_source")
        or effective.get("source_authority")
        or effective.get("collector_id")
        or effective.get("sensor_id")
    )

    if source_attr:
        # Check if source_attr itself indicates synthetic or test data
        if isinstance(source_attr, str):
            attr_lower = source_attr.lower()
            if any(marker in attr_lower for marker in ("synthetic", "benchmark", "simulat", "test_mock")):
                return "synthetic_benchmark"
            if attr_lower.strip():
                return "observed_telemetry"
        elif isinstance(source_attr, dict):
            if source_attr.get("synthetic") or source_attr.get("benchmark"):
                return "synthetic_benchmark"
            if source_attr.get("source_id") or source_attr.get("collector") or source_attr.get("authorized"):
                return "observed_telemetry"

    # Rule 3: Explicit provenance claim in raw_payload requires verified source flag
    if raw_prov == "observed_telemetry" and (effective.get("verified_source") is True or effective.get("authorized") is True):
        return "observed_telemetry"

    # Rule 4: Default fallback: provenance cannot be verified from available metadata
    return "unknown"


def determine_response_provenance(items: Sequence[HuntedEventItem]) -> str:
    """
    Determine aggregate response-level provenance based on actual items returned.

    Returns:
    - 'observed_telemetry' if all items are observed_telemetry
    - 'synthetic_benchmark' if all items are synthetic_benchmark
    - 'unknown' if all items are unknown or if items is empty
    - 'mixed' if items contain multiple distinct provenances
    """
    if not items:
        return "unknown"
    distinct_provenances = {item.provenance for item in items}
    if len(distinct_provenances) == 1:
        return next(iter(distinct_provenances))
    return "mixed"


class HuntingRepository:
    """Repository handling structured queries over the security events dataset."""

    def __init__(self, session: AsyncSession):
        self.session = session

    def _compile_condition(self, cond: FilterCondition) -> ColumnElement:
        """Compile a single FilterCondition into a parameterized SQLAlchemy expression."""
        col = FIELD_COLUMN_MAP[cond.field]
        op = cond.operator
        val = cond.value

        if op == FilterOperator.EQ:
            return col == val

        elif op == FilterOperator.NEQ:
            # For nullable columns in SQL, (col != val) evaluates to UNKNOWN if col is NULL.
            # To match analyst expectations, match rows where col != val OR col IS NULL.
            if cond.field in NULLABLE_COLUMNS:
                return or_(col != val, col.is_(None))
            return col != val

        elif op == FilterOperator.CONTAINS:
            escaped = escape_like(str(val))
            return col.ilike(f"%{escaped}%", escape="\\")

        elif op == FilterOperator.STARTS_WITH:
            escaped = escape_like(str(val))
            return col.ilike(f"{escaped}%", escape="\\")

        elif op == FilterOperator.IN:
            return col.in_(val)

        elif op == FilterOperator.GT:
            return col > val

        elif op == FilterOperator.GTE:
            return col >= val

        elif op == FilterOperator.LT:
            return col < val

        elif op == FilterOperator.LTE:
            return col <= val

        raise ValueError(f"Unsupported operator: {op}")

    def _compile_group(self, group: FilterGroup) -> ColumnElement:
        """Recursively compile a FilterGroup into an AND/OR BooleanClauseList."""
        clauses: List[ColumnElement] = []

        for cond in group.conditions:
            clauses.append(self._compile_condition(cond))

        for child_group in group.groups:
            clauses.append(self._compile_group(child_group))

        if not clauses:
            raise ValueError("Cannot compile an empty filter group")

        if len(clauses) == 1:
            return clauses[0]

        if group.logic == "OR":
            return or_(*clauses)
        return and_(*clauses)

    async def execute_hunt(self, req: ThreatHuntQueryRequest) -> ThreatHuntQueryResponse:
        """
        Execute a structured hunt query with parameter binding, pagination,
        batched hydration of related detections and incidents, and diagnostic execution timing.

        Query Cardinality:
        - 1 query if total == 0 (count query only).
        - 2 queries if offset >= total (count + page).
        - 3 queries if matching events have zero triggered detections (count + page + detections).
        - 4 queries in the fully populated path (count + page + detections + incidents).
        """
        t0 = time.perf_counter()
        root_clauses: List[ColumnElement] = []
        applied_filter_count = 0

        # 1. Apply Time Range Filters
        if req.time_range:
            if req.time_range.start is not None:
                root_clauses.append(SecurityEventModel.timestamp >= req.time_range.start)
                applied_filter_count += 1
            if req.time_range.end is not None:
                root_clauses.append(SecurityEventModel.timestamp <= req.time_range.end)
                applied_filter_count += 1

        # 2. Apply Boolean Filter Group
        if req.filter_group is not None:
            root_clauses.append(self._compile_group(req.filter_group))
            applied_filter_count += count_leaf_conditions(req.filter_group)

        # 3. Compute Total Matching Event Count
        count_stmt = select(func.count(SecurityEventModel.id))
        if root_clauses:
            count_stmt = count_stmt.where(and_(*root_clauses))

        count_result = await self.session.execute(count_stmt)
        total = count_result.scalar() or 0

        # Short-circuit if zero events match
        if total == 0:
            query_duration_ms = round((time.perf_counter() - t0) * 1000, 2)
            return ThreatHuntQueryResponse(
                items=[],
                total=0,
                limit=req.limit,
                offset=req.offset,
                query_duration_ms=query_duration_ms,
                applied_filter_count=applied_filter_count,
                provenance="unknown",
            )

        # 4. Fetch Paginated Event Rows
        sort_col = FIELD_COLUMN_MAP[req.sort_by]
        sort_expr = sort_col.asc() if req.sort_order == "asc" else sort_col.desc()

        # Stable secondary sort on ID ensures deterministic pagination for equal values
        query_stmt = (
            select(SecurityEventModel)
            .order_by(sort_expr, SecurityEventModel.id.desc())
            .offset(req.offset)
            .limit(req.limit)
        )
        if root_clauses:
            query_stmt = query_stmt.where(and_(*root_clauses))

        event_rows = list((await self.session.execute(query_stmt)).scalars().all())

        if not event_rows:
            query_duration_ms = round((time.perf_counter() - t0) * 1000, 2)
            return ThreatHuntQueryResponse(
                items=[],
                total=total,
                limit=req.limit,
                offset=req.offset,
                query_duration_ms=query_duration_ms,
                applied_filter_count=applied_filter_count,
                provenance="unknown",
            )

        event_ids = [e.id for e in event_rows]

        # 5. Batched Resolution of Related Detections (Avoid N+1 queries)
        det_stmt = (
            select(
                DetectionEventModel.event_id,
                DetectionModel.id,
                DetectionModel.rule_id,
                DetectionModel.rule_name,
                DetectionModel.severity,
                DetectionModel.explanation,
            )
            .join(DetectionModel, DetectionEventModel.detection_id == DetectionModel.id)
            .where(DetectionEventModel.event_id.in_(event_ids))
        )
        det_result = await self.session.execute(det_stmt)
        det_rows = det_result.all()

        event_to_detections: Dict[str, List[RelatedDetectionSummary]] = defaultdict(list)
        detection_to_event_ids: Dict[str, Set[str]] = defaultdict(set)
        all_detection_ids: Set[str] = set()

        for row in det_rows:
            det_summary = RelatedDetectionSummary(
                id=row.id,
                rule_id=row.rule_id,
                rule_name=row.rule_name,
                severity=row.severity,
                explanation=row.explanation,
            )
            event_to_detections[row.event_id].append(det_summary)
            detection_to_event_ids[row.id].add(row.event_id)
            all_detection_ids.add(row.id)

        # 6. Batched Resolution of Related Incidents via Detections
        event_to_incidents: Dict[str, Dict[str, RelatedIncidentSummary]] = defaultdict(dict)
        if all_detection_ids:
            inc_stmt = (
                select(
                    IncidentDetectionModel.detection_id,
                    IncidentModel.id,
                    IncidentModel.title,
                    IncidentModel.severity,
                    IncidentModel.status,
                )
                .join(IncidentModel, IncidentDetectionModel.incident_id == IncidentModel.id)
                .where(IncidentDetectionModel.detection_id.in_(all_detection_ids))
            )
            inc_result = await self.session.execute(inc_stmt)
            inc_rows = inc_result.all()

            for inc_row in inc_rows:
                inc_summary = RelatedIncidentSummary(
                    id=inc_row.id,
                    title=inc_row.title,
                    severity=inc_row.severity,
                    status=inc_row.status,
                )
                # Map incident to all events that triggered this detection
                for evt_id in detection_to_event_ids[inc_row.detection_id]:
                    event_to_incidents[evt_id][inc_row.id] = inc_summary

        # 7. Construct Enriched Response Items
        items: List[HuntedEventItem] = []
        for e in event_rows:
            ts = e.timestamp if e.timestamp.tzinfo is not None else e.timestamp.replace(tzinfo=timezone.utc)
            evt_detections = event_to_detections.get(e.id, [])
            evt_incidents = list(event_to_incidents.get(e.id, {}).values())

            # Truthful provenance assessment using explicit, trustworthy metadata
            raw = e.raw_payload or {}
            evt_provenance = classify_event_provenance(
                raw_payload=raw,
                source_type=e.source_type,
                event_id=e.id,
            )

            items.append(
                HuntedEventItem(
                    id=e.id,
                    timestamp=ts,
                    source_type=e.source_type,
                    category=e.category,
                    action=e.action,
                    severity=e.severity,
                    username=e.username,
                    hostname=e.hostname,
                    source_ip=e.source_ip,
                    destination_ip=e.destination_ip,
                    source_port=e.source_port,
                    destination_port=e.destination_port,
                    protocol=e.protocol,
                    bytes_out=e.bytes_out,
                    bytes_in=e.bytes_in,
                    process_name=e.process_name,
                    process_command_line=e.process_command_line,
                    raw_payload=raw,
                    source_file_hash=e.source_file_hash,
                    provenance=evt_provenance,
                    related_detections=evt_detections,
                    related_incidents=evt_incidents,
                )
            )

        query_duration_ms = round((time.perf_counter() - t0) * 1000, 2)
        response_provenance = determine_response_provenance(items)

        return ThreatHuntQueryResponse(
            items=items,
            total=total,
            limit=req.limit,
            offset=req.offset,
            query_duration_ms=query_duration_ms,
            applied_filter_count=applied_filter_count,
            provenance=response_provenance,
        )

