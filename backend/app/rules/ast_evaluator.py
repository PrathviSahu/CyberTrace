"""
In-Memory Threat Hunting AST Evaluator for CyberTrace.
Provides pure in-memory evaluation of FilterCondition and FilterGroup ASTs
against CommonEvent and SecurityEventModel instances with exact semantic parity
to SQL compilation in HuntingRepository.
"""

from datetime import datetime
from typing import Any, Sequence, Set, Union
from app.db.models import SecurityEventModel
from app.schemas.ces import CommonEvent
from app.schemas.hunting import (
    FilterCondition,
    FilterField,
    FilterGroup,
    FilterOperator,
)

NULLABLE_FIELDS: Set[FilterField] = {
    FilterField.HOSTNAME,
    FilterField.USERNAME,
    FilterField.SOURCE_IP,
    FilterField.DESTINATION_IP,
    FilterField.SOURCE_PORT,
    FilterField.DESTINATION_PORT,
    FilterField.PROTOCOL,
    FilterField.PROCESS_NAME,
}


def extract_event_field_value(
    event: Union[CommonEvent, SecurityEventModel],
    field: FilterField,
) -> Any:
    """
    Extract the normalized attribute value corresponding to a FilterField
    from either a CommonEvent (in-memory CES) or a SecurityEventModel (database model).
    """
    if field == FilterField.TIMESTAMP:
        return event.timestamp

    elif field == FilterField.HOSTNAME:
        return event.hostname

    elif field == FilterField.USERNAME:
        if hasattr(event, "user_identity"):
            return getattr(event, "user_identity")
        return getattr(event, "username", None)

    elif field == FilterField.SOURCE_IP:
        return event.source_ip

    elif field == FilterField.DESTINATION_IP:
        return event.destination_ip

    elif field == FilterField.CATEGORY:
        val = event.category
        return val.value if hasattr(val, "value") else val

    elif field == FilterField.ACTION:
        val = event.action
        return val.value if hasattr(val, "value") else val

    elif field == FilterField.SEVERITY:
        val = event.severity
        return val.value if hasattr(val, "value") else val

    elif field == FilterField.BYTES_OUT:
        if hasattr(event, "bytes_sent"):
            return getattr(event, "bytes_sent")
        return getattr(event, "bytes_out", 0)

    elif field == FilterField.BYTES_IN:
        if hasattr(event, "bytes_received"):
            return getattr(event, "bytes_received")
        return getattr(event, "bytes_in", 0)

    elif field == FilterField.SOURCE_PORT:
        return event.source_port

    elif field == FilterField.DESTINATION_PORT:
        return event.destination_port

    elif field == FilterField.PROTOCOL:
        return event.protocol

    elif field == FilterField.PROCESS_NAME:
        return event.process_name

    raise ValueError(f"Unknown filter field: {field}")


def evaluate_condition(
    event: Union[CommonEvent, SecurityEventModel],
    cond: FilterCondition,
) -> bool:
    """
    Evaluate a single FilterCondition against an event with exact SQL parity:
    - Case-insensitive matching for string contains / starts_with (matching SQL ilike).
    - Nullable NEQ semantics: event.field != val OR event.field IS NULL.
    - None comparisons: if event field is None, EQ/CONTAINS/STARTS_WITH/IN/GT/GTE/LT/LTE return False.
    """
    event_val = extract_event_field_value(event, cond.field)
    op = cond.operator
    expected_val = cond.value

    # Handle NULL semantics
    if event_val is None:
        if op == FilterOperator.NEQ:
            # Matches SQL: or_(col != val, col.is_(None)) -> True when col is NULL
            return True
        # All other operators on NULL evaluate to False in SQL 3-valued logic
        return False

    if op == FilterOperator.EQ:
        # String comparison is exact matching SQL `col == val`
        return event_val == expected_val

    elif op == FilterOperator.NEQ:
        # Event value is not None here
        return event_val != expected_val

    elif op == FilterOperator.CONTAINS:
        # Mirrors SQL ilike('%escaped%', escape='\\')
        return str(expected_val).lower() in str(event_val).lower()

    elif op == FilterOperator.STARTS_WITH:
        # Mirrors SQL ilike('escaped%', escape='\\')
        return str(event_val).lower().startswith(str(expected_val).lower())

    elif op == FilterOperator.IN:
        # Mirrors SQL col.in_(expected_val)
        return event_val in expected_val

    elif op == FilterOperator.GT:
        return event_val > expected_val

    elif op == FilterOperator.GTE:
        return event_val >= expected_val

    elif op == FilterOperator.LT:
        return event_val < expected_val

    elif op == FilterOperator.LTE:
        return event_val <= expected_val

    raise ValueError(f"Unsupported operator: {op}")


def evaluate_filter_group(
    event: Union[CommonEvent, SecurityEventModel],
    group: FilterGroup,
) -> bool:
    """
    Recursively evaluate a FilterGroup AST against an event with AND/OR logic.
    An empty group cannot be compiled (mirrors HuntingRepository).
    """
    results = []

    for cond in group.conditions:
        results.append(evaluate_condition(event, cond))

    for child_group in group.groups:
        results.append(evaluate_filter_group(event, child_group))

    if not results:
        raise ValueError("Cannot evaluate an empty filter group")

    if group.logic == "OR":
        return any(results)
    return all(results)


def filter_events(
    events: Sequence[Union[CommonEvent, SecurityEventModel]],
    group: FilterGroup,
) -> Sequence[Union[CommonEvent, SecurityEventModel]]:
    """Return all events matching the given FilterGroup AST."""
    return [ev for ev in events if evaluate_filter_group(ev, group)]
