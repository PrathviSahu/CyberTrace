"""
CyberTrace Dynamic Custom Detection Rule Adapter (Phase 6.3C Stage 3).
Provides frozen, deeply immutable runtime representations of approved active custom detection rules.
Reuses the validated AST evaluation engine (ast_evaluator.py) while strictly preventing
any state mutation across request-scoped ingestion passes.
"""

from dataclasses import dataclass
from datetime import datetime
import logging
from types import MappingProxyType
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from app.db.models import ActiveDetectionRuleModel
from app.rules.ast_evaluator import evaluate_filter_group
from app.rules.base import BaseDetectionRule, DetectionResult
from app.schemas.ces import CommonEvent, EventSeverity
from app.schemas.hunting import (
    FilterCondition,
    FilterField,
    FilterGroup,
    FilterOperator,
)

logger = logging.getLogger("cybertrace.rules.dynamic")


def _deep_freeze_value(val: Any) -> Any:
    """Recursively freeze lists, sets, and dicts into immutable tuples and MappingProxyTypes."""
    if isinstance(val, (list, tuple, set)):
        return tuple(_deep_freeze_value(x) for x in val)
    elif isinstance(val, dict):
        return MappingProxyType({k: _deep_freeze_value(v) for k, v in val.items()})
    return val


@dataclass(frozen=True, slots=True)
class FrozenFilterCondition:
    """Immutable, frozen AST leaf condition."""
    field: FilterField
    operator: FilterOperator
    value: Any  # If list, stored as immutable tuple

    @classmethod
    def from_condition(cls, cond: Union[FilterCondition, Dict[str, Any]]) -> "FrozenFilterCondition":
        if isinstance(cond, dict):
            field_raw = cond["field"]
            field_enum = FilterField(field_raw) if not isinstance(field_raw, FilterField) else field_raw
            op_raw = cond["operator"]
            op_enum = FilterOperator(op_raw) if not isinstance(op_raw, FilterOperator) else op_raw
            raw_val = cond.get("value")
        else:
            field_enum = cond.field
            op_enum = cond.operator
            raw_val = cond.value

        frozen_val = _deep_freeze_value(raw_val)
        return cls(field=field_enum, operator=op_enum, value=frozen_val)


@dataclass(frozen=True, slots=True)
class FrozenFilterGroup:
    """Immutable, frozen AST boolean expression group."""
    logic: str  # "AND" or "OR"
    conditions: Tuple[FrozenFilterCondition, ...] = ()
    groups: Tuple["FrozenFilterGroup", ...] = ()

    @classmethod
    def from_group(cls, group: Union[FilterGroup, Dict[str, Any]]) -> "FrozenFilterGroup":
        if isinstance(group, dict):
            logic = str(group.get("logic", "AND")).upper()
            raw_conds = group.get("conditions", [])
            raw_groups = group.get("groups", [])
        else:
            logic = str(group.logic).upper()
            raw_conds = group.conditions
            raw_groups = group.groups

        frozen_conds = tuple(FrozenFilterCondition.from_condition(c) for c in raw_conds)
        frozen_groups = tuple(cls.from_group(g) for g in raw_groups)

        if not frozen_conds and not frozen_groups:
            raise ValueError("FrozenFilterGroup cannot be empty: must contain at least one condition or child group.")

        return cls(logic=logic, conditions=frozen_conds, groups=frozen_groups)


def _map_severity(severity_str: str) -> EventSeverity:
    """Map string severity (low, medium, high, critical) to EventSeverity enum."""
    val = severity_str.lower().strip()
    if val == "critical":
        return EventSeverity.CRITICAL
    elif val == "high":
        return EventSeverity.HIGH
    elif val == "low":
        return EventSeverity.LOW
    return EventSeverity.MEDIUM


@dataclass(frozen=True, slots=True)
class DynamicCustomRule(BaseDetectionRule):
    """
    Immutable runtime adapter for active production detection rules.
    Holds a deeply frozen AST snapshot and metadata.
    Enforces frozen immutability across all attributes and nested structures.
    """
    active_rule_id: str
    rule_code: str
    name: str
    severity: EventSeverity
    filter_group: FrozenFilterGroup
    description: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    source_draft_id: Optional[str] = None
    source_draft_version: Optional[int] = None
    validation_run_id: Optional[str] = None
    query_definition_snapshot: Any = None

    @property
    def rule_id(self) -> str:
        return self.rule_code

    @property
    def rule_name(self) -> str:
        return self.name

    @property
    def default_severity(self) -> EventSeverity:
        return self.severity

    @classmethod
    def from_active_model(cls, model: ActiveDetectionRuleModel) -> "DynamicCustomRule":
        """
        Factory method to construct an immutable DynamicCustomRule from an ActiveDetectionRuleModel.
        Validates the stored AST and deep-freezes all nested data structures.
        Raises ValueError if the stored AST is invalid, corrupted, or empty.
        """
        if not model.query_definition or not isinstance(model.query_definition, dict):
            raise ValueError(f"Active rule '{model.rule_code}' has missing or invalid query_definition.")

        # Extract filter_group either from SavedHuntQueryDefinition or directly
        raw_def = model.query_definition
        if "filter_group" in raw_def and raw_def["filter_group"] is not None:
            raw_fg = raw_def["filter_group"]
        else:
            raw_fg = raw_def

        # Validate with Pydantic FilterGroup to ensure full syntactic & semantic compliance
        pydantic_fg = FilterGroup.model_validate(raw_fg)

        # Convert to deeply frozen immutable AST
        frozen_fg = FrozenFilterGroup.from_group(pydantic_fg)

        # Deep freeze entire query definition snapshot
        frozen_snapshot = _deep_freeze_value(raw_def)

        # Map severity
        sev = _map_severity(model.severity)

        return cls(
            active_rule_id=model.id,
            rule_code=model.rule_code,
            name=model.name,
            severity=sev,
            filter_group=frozen_fg,
            description=model.description,
            mitre_attack_id=model.mitre_attack_id,
            mitre_tactic=model.mitre_tactic,
            source_draft_id=model.source_draft_id,
            source_draft_version=model.source_draft_version,
            validation_run_id=model.validation_run_id,
            query_definition_snapshot=frozen_snapshot,
        )

    def evaluate(
        self,
        events: List[CommonEvent],
        prior_detections: List[DetectionResult],
    ) -> List[DetectionResult]:
        """
        Evaluate chronological events against the frozen AST using evaluate_filter_group.
        Produces deterministic DetectionResult records with evidence references and audit lineage.
        """
        detections: List[DetectionResult] = []

        for ev in events:
            try:
                matched = evaluate_filter_group(ev, self.filter_group)
            except Exception as exc:
                logger.error(
                    "Dynamic custom rule '%s' evaluation error on event '%s': %s",
                    self.rule_code,
                    getattr(ev, "event_id", "unknown"),
                    exc,
                )
                continue

            if matched:
                # Entity resolution logic
                if ev.user_identity:
                    entity_key = f"user:{ev.user_identity}"
                elif ev.source_ip:
                    entity_key = f"ip:{ev.source_ip}"
                elif ev.destination_ip:
                    entity_key = f"ip:{ev.destination_ip}"
                elif ev.hostname:
                    entity_key = f"host:{ev.hostname}"
                else:
                    entity_key = f"event:{ev.event_id}"

                action_val = ev.action.value if hasattr(ev.action, "value") else str(ev.action)
                category_val = ev.category.value if hasattr(ev.category, "value") else str(ev.category)

                summary = (
                    f"Custom detection rule {self.rule_code} ('{self.name}') triggered "
                    f"on event {ev.event_id} (action: {action_val}, entity: {entity_key})."
                )

                metadata: Dict[str, Any] = {
                    "rule_code": self.rule_code,
                    "active_rule_id": self.active_rule_id,
                    "source_draft_id": self.source_draft_id,
                    "source_draft_version": self.source_draft_version,
                    "validation_run_id": self.validation_run_id,
                    "mitre_attack_id": self.mitre_attack_id,
                    "mitre_tactic": self.mitre_tactic,
                    "action": action_val,
                    "category": category_val,
                    "source_ip": ev.source_ip,
                    "destination_ip": ev.destination_ip,
                    "user_identity": ev.user_identity,
                    "hostname": ev.hostname,
                }

                detections.append(
                    DetectionResult(
                        rule_id=self.rule_code,
                        rule_name=self.name,
                        severity=self.severity,
                        summary=summary,
                        detection_timestamp=ev.timestamp,
                        entity_key=entity_key,
                        triggering_event_ids=[ev.event_id],
                        metadata=metadata,
                    )
                )

        return detections
