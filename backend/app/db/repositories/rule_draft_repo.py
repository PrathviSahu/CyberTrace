"""
CyberTrace Detection Rule Draft Repository & Pre-flight Simulation Engine (Phase 6.3B).
Provides versioned rule draft persistence, saved hunt promotion, atomic optimistic locking,
archival lifecycle protection, and dual-scope pre-flight simulation (Historical DB + ThreatLab).
"""

from copy import deepcopy
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import uuid

from sqlalchemy import delete, desc, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    DetectionRuleDraftModel,
    RuleValidationRunModel,
    SavedHuntModel,
    SecurityEventModel,
)
from app.db.repositories.hunting_repo import (
    HuntingRepository,
    classify_event_provenance,
)
from app.db.repositories.saved_hunt_repo import (
    ArchivedHuntError,
    VersionConflictError,
)
from app.rules.ast_evaluator import evaluate_filter_group
from app.schemas.saved_hunt import SavedHuntQueryDefinition
from app.schemas.rule_draft import (
    DetectionRuleDraftCreate,
    DetectionRuleDraftUpdate,
    DraftStatus,
    HistoricalTelemetryMetrics,
    RuleSeverity,
    RuleValidationReportResponse,
    RuleValidationRunRequest,
    RuleValidationSummary,
    ThreatLabMetrics,
    ThreatLabScenarioResult,
    ValidationScope,
)
from app.threatlab.service import ThreatLabService


class ArchivedRuleError(Exception):
    """Raised when an operation is rejected on an archived rule draft (HTTP 409)."""
    pass


class RuleDraftRepository:
    """Repository handling lifecycle, persistence, and validation of detection rule drafts."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_draft(self, data: DetectionRuleDraftCreate) -> DetectionRuleDraftModel:
        """
        Create a new detection rule draft from scratch or promote from a saved threat hunt.
        If promoted, captures an immutable snapshot of source_hunt_version.
        Rejects promotion from archived hunts (ArchivedRuleError -> HTTP 409).
        """
        source_hunt_id: Optional[str] = None
        source_hunt_version: Optional[int] = None
        query_def_dict: Dict[str, Any]

        if data.source_hunt_id:
            hunt_stmt = select(SavedHuntModel).where(SavedHuntModel.id == data.source_hunt_id)
            source_hunt = (await self.session.execute(hunt_stmt)).scalar_one_or_none()
            if not source_hunt:
                raise ValueError(f"Source saved threat hunt '{data.source_hunt_id}' was not found.")
            if source_hunt.is_archived:
                raise ArchivedRuleError(
                    f"Cannot promote archived threat hunt '{data.source_hunt_id}' to a detection rule draft. "
                    f"Unarchive or duplicate the hunt to promote."
                )

            source_hunt_id = source_hunt.id
            source_hunt_version = source_hunt.version
            if data.query_definition:
                query_def_dict = data.query_definition.model_dump(mode="json")
            else:
                query_def_dict = deepcopy(source_hunt.query_definition)
        else:
            if not data.query_definition:
                raise ValueError("Query definition is required when creating a draft from scratch.")
            query_def_dict = data.query_definition.model_dump(mode="json")

        # Validate AST constraints
        query_def = SavedHuntQueryDefinition.model_validate(query_def_dict)
        if query_def.filter_group is None:
            raise ValueError("Rule draft query definition must contain a valid filter_group.")

        now = datetime.now(timezone.utc)
        draft_id = f"draft_{uuid.uuid4().hex[:12]}"

        draft = DetectionRuleDraftModel(
            id=draft_id,
            name=data.name,
            description=data.description,
            severity=data.severity.value,
            mitre_attack_id=data.mitre_attack_id,
            mitre_tactic=data.mitre_tactic,
            source_hunt_id=source_hunt_id,
            source_hunt_version=source_hunt_version,
            query_definition=query_def_dict,
            status=DraftStatus.DRAFT.value,
            version=1,
            created_by=data.created_by or "analyst_user",
            is_archived=False,
            created_at=now,
            updated_at=now,
        )
        self.session.add(draft)
        await self.session.commit()
        await self.session.refresh(draft)
        return draft

    async def get_draft(self, draft_id: str) -> Optional[DetectionRuleDraftModel]:
        """Retrieve a rule draft by ID."""
        stmt = select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_drafts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        include_archived: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[DetectionRuleDraftModel], int]:
        """List rule drafts with optional filters and pagination."""
        base_stmt = select(DetectionRuleDraftModel)
        count_stmt = select(func.count(DetectionRuleDraftModel.id))

        if not include_archived:
            base_stmt = base_stmt.where(DetectionRuleDraftModel.is_archived.is_(False))
            count_stmt = count_stmt.where(DetectionRuleDraftModel.is_archived.is_(False))

        if status:
            base_stmt = base_stmt.where(DetectionRuleDraftModel.status == status)
            count_stmt = count_stmt.where(DetectionRuleDraftModel.status == status)

        if severity:
            base_stmt = base_stmt.where(DetectionRuleDraftModel.severity == severity)
            count_stmt = count_stmt.where(DetectionRuleDraftModel.severity == severity)

        total = (await self.session.execute(count_stmt)).scalar() or 0

        paged_stmt = (
            base_stmt.order_by(desc(DetectionRuleDraftModel.updated_at))
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.execute(paged_stmt)).scalars().all())
        return items, total

    async def update_draft(
        self,
        draft_id: str,
        data: DetectionRuleDraftUpdate,
    ) -> DetectionRuleDraftModel:
        """
        Update a rule draft using atomic conditional optimistic concurrency locking.
        WHERE id = draft_id AND version = data.version AND is_archived = False.
        Refinement: modifying the query_definition AST automatically resets status to DRAFT.
        """
        now = datetime.now(timezone.utc)
        update_values: Dict[str, Any] = {}

        if data.name is not None:
            update_values["name"] = data.name
        if data.description is not None:
            update_values["description"] = data.description
        if data.severity is not None:
            update_values["severity"] = data.severity.value
        if data.mitre_attack_id is not None:
            update_values["mitre_attack_id"] = data.mitre_attack_id
        if data.mitre_tactic is not None:
            update_values["mitre_tactic"] = data.mitre_tactic

        if data.query_definition is not None:
            # Validate AST constraints
            if data.query_definition.filter_group is None:
                raise ValueError("Rule draft query definition must contain a valid filter_group.")
            update_values["query_definition"] = data.query_definition.model_dump(mode="json")
            # Invalidate any previous validation: resetting draft to DRAFT
            update_values["status"] = DraftStatus.DRAFT.value

        stmt = (
            update(DetectionRuleDraftModel)
            .where(
                DetectionRuleDraftModel.id == draft_id,
                DetectionRuleDraftModel.version == data.version,
                DetectionRuleDraftModel.is_archived.is_(False),
            )
            .values(
                **update_values,
                version=DetectionRuleDraftModel.version + 1,
                updated_at=now,
            )
        )
        result = await self.session.execute(stmt)
        await self.session.commit()

        if result.rowcount == 0:
            existing = await self.get_draft(draft_id)
            if not existing:
                raise ValueError(f"Detection rule draft '{draft_id}' was not found.")
            if existing.is_archived:
                raise ArchivedRuleError(
                    f"Archived detection rule draft '{draft_id}' cannot be modified. Unarchive or duplicate to modify."
                )
            raise VersionConflictError(current_version=existing.version, requested_version=data.version)

        updated = await self.get_draft(draft_id)
        if not updated:
            raise ValueError(f"Detection rule draft '{draft_id}' was not found.")
        return updated

    async def archive_draft(self, draft_id: str) -> DetectionRuleDraftModel:
        """
        Soft-delete a rule draft by setting is_archived = True, status = ARCHIVED.
        Idempotent: preserving updated_at if already archived.
        """
        draft = await self.get_draft(draft_id)
        if not draft:
            raise ValueError(f"Detection rule draft '{draft_id}' was not found.")

        if not draft.is_archived:
            draft.is_archived = True
            draft.status = DraftStatus.ARCHIVED.value
            draft.updated_at = datetime.now(timezone.utc)
            await self.session.commit()
            await self.session.refresh(draft)
        return draft

    async def validate_draft(
        self,
        draft_id: str,
        request: Optional[RuleValidationRunRequest] = None,
    ) -> RuleValidationReportResponse:
        """
        Execute pre-flight simulation across historical telemetry and ThreatLab benchmark suites.
        Adheres to mandatory refinements:
        1. Version-safe: if draft version changed during validation, record is preserved but draft remains DRAFT.
        2. Immutable history: every run is permanently inserted into rule_validation_runs.
        3. Lifecycle: only transitions DRAFT -> VALIDATED (never PENDING_APPROVAL).
        4. Honest metrics: transparent daily volume calculation, separate historical & benchmark metrics.
        """
        start_perf = time.perf_counter()
        target_scope = request.target_scope if request else ValidationScope.ALL

        draft = await self.get_draft(draft_id)
        if not draft:
            raise ValueError(f"Detection rule draft '{draft_id}' was not found.")
        if draft.is_archived:
            raise ArchivedRuleError(
                f"Archived detection rule draft '{draft_id}' cannot be validated. Unarchive or duplicate to run."
            )

        # Snapshot exact draft version and AST upfront before execution
        validated_version = draft.version
        query_snapshot = deepcopy(draft.query_definition)
        query_def = SavedHuntQueryDefinition.model_validate(query_snapshot)
        if not query_def.filter_group:
            raise ValueError(f"Draft '{draft_id}' has an empty or invalid query AST.")

        historical_metrics: Optional[HistoricalTelemetryMetrics] = None
        threatlab_metrics: Optional[ThreatLabMetrics] = None
        events_scanned_total = 0
        matches_found_total = 0
        estimated_daily_alert_volume = 0.0
        obs_duration_days = 0.0
        obs_start: Optional[datetime] = None
        obs_end: Optional[datetime] = None
        provenance_breakdown: Dict[str, int] = {}
        sample_matched_event_ids: List[str] = []

        # -------------------------------------------------------------------
        # Scope 1: Historical Telemetry Simulation (Database)
        # -------------------------------------------------------------------
        if target_scope in (ValidationScope.ALL, ValidationScope.HISTORICAL_TELEMETRY):
            hunting_repo = HuntingRepository(self.session)
            root_clause = hunting_repo._compile_group(query_def.filter_group)

            # 1. Total events scanned
            total_db_events = (await self.session.execute(select(func.count(SecurityEventModel.id)))).scalar() or 0
            events_scanned_total += total_db_events

            # 2. Total matches
            match_stmt = select(func.count(SecurityEventModel.id)).where(root_clause)
            db_matches = (await self.session.execute(match_stmt)).scalar() or 0
            matches_found_total += db_matches

            # 3. Observation window and duration calculation
            span_stmt = select(
                func.min(SecurityEventModel.timestamp),
                func.max(SecurityEventModel.timestamp),
            )
            span_res = (await self.session.execute(span_stmt)).first()
            obs_start = span_res[0] if span_res else None
            obs_end = span_res[1] if span_res else None

            insufficient_warning = False
            formula_desc = ""

            if total_db_events == 0 or obs_start is None or obs_end is None:
                obs_duration_days = 0.0
                estimated_daily_alert_volume = 0.0
                insufficient_warning = True
                formula_desc = "No historical events present in database to compute timespan."
            else:
                duration_seconds = max(0.0, (obs_end - obs_start).total_seconds())
                obs_duration_days = round(duration_seconds / 86400.0, 4)

                if obs_duration_days >= 1.0:
                    estimated_daily_alert_volume = round(db_matches / obs_duration_days, 2)
                    formula_desc = (
                        f"{db_matches} matches / {obs_duration_days:.2f} observation days = "
                        f"{estimated_daily_alert_volume:.2f} alerts/day."
                    )
                elif duration_seconds > 0.0:
                    # Extrapolation with explicit insufficiency warning
                    insufficient_warning = True
                    estimated_daily_alert_volume = round(db_matches / (duration_seconds / 86400.0), 2)
                    hours = duration_seconds / 3600.0
                    formula_desc = (
                        f"Extrapolated: {db_matches} matches over {hours:.1f} hours "
                        f"({obs_duration_days:.3f} days) = {estimated_daily_alert_volume:.2f} alerts/day."
                    )
                else:
                    # Single timestamp or zero duration
                    insufficient_warning = True
                    estimated_daily_alert_volume = float(db_matches)
                    formula_desc = (
                        f"Zero-duration telemetry span (all events at same timestamp): "
                        f"volume reported as direct match count ({db_matches})."
                    )

            # 4. Provenance Breakdown for historical matches
            sample_stmt = select(SecurityEventModel).where(root_clause).limit(100)
            sample_models = list((await self.session.execute(sample_stmt)).scalars().all())

            prov_counts: Dict[str, int] = {"observed_telemetry": 0, "synthetic_benchmark": 0, "unknown": 0}
            for model in sample_models:
                prov = classify_event_provenance(
                    raw_payload=model.raw_payload,
                    source_type=model.source_type,
                    event_id=model.id,
                )
                prov_counts[prov] = prov_counts.get(prov, 0) + 1

            provenance_breakdown = prov_counts
            sample_matched_event_ids = [m.id for m in sample_models[:10]]

            historical_metrics = HistoricalTelemetryMetrics(
                events_scanned=total_db_events,
                matches_found=db_matches,
                observation_start=obs_start,
                observation_end=obs_end,
                observation_duration_days=obs_duration_days,
                estimated_daily_alert_volume=estimated_daily_alert_volume,
                daily_volume_formula=formula_desc,
                insufficient_history_warning=insufficient_warning,
                provenance_breakdown=provenance_breakdown,
                sample_matched_event_ids=sample_matched_event_ids,
            )

        # -------------------------------------------------------------------
        # Scope 2: ThreatLab Benchmark Simulation (In-Memory Replay)
        # -------------------------------------------------------------------
        if target_scope in (ValidationScope.ALL, ValidationScope.THREATLAB_BENCHMARKS):
            threatlab = ThreatLabService()
            scenarios = threatlab.get_scenarios()
            scenario_results: List[ThreatLabScenarioResult] = []
            total_bench_events = 0
            total_bench_matches = 0
            benign_baseline_matches = 0

            for scn in scenarios:
                events, _ = threatlab._generate_scenario_events(scn.scenario_id)
                total_bench_events += len(events)
                matching_events = [e for e in events if evaluate_filter_group(e, query_def.filter_group)]
                match_count = len(matching_events)
                total_bench_matches += match_count

                matched_ids = [e.event_id for e in matching_events]

                # Specific ground-truth classification
                if scn.scenario_id == "SCN-004":  # Benign Administrative Baseline
                    if match_count > 0:
                        classification = "benign_baseline_warning"
                        is_warning = True
                        benign_baseline_matches += match_count
                    else:
                        classification = "true_negative"
                        is_warning = False
                else:
                    if match_count > 0:
                        classification = "true_positive"
                        is_warning = False
                    else:
                        classification = "true_negative"
                        is_warning = False

                scenario_results.append(
                    ThreatLabScenarioResult(
                        scenario_id=scn.scenario_id,
                        name=scn.name,
                        category=scn.category,
                        total_events=len(events),
                        matches_found=match_count,
                        classification=classification,
                        is_benign_baseline_warning=is_warning,
                        matched_event_ids=matched_ids,
                    )
                )

            threatlab_metrics = ThreatLabMetrics(
                scenarios_evaluated=len(scenarios),
                total_benchmark_events=total_bench_events,
                total_matches=total_bench_matches,
                benign_baseline_matches=benign_baseline_matches,
                has_benign_baseline_warning=(benign_baseline_matches > 0),
                scenario_results=scenario_results,
            )

        duration_ms = round((time.perf_counter() - start_perf) * 1000, 2)
        run_now = datetime.now(timezone.utc)
        validation_id = f"val_{uuid.uuid4().hex[:12]}"

        # -------------------------------------------------------------------
        # Refinement 1: Version-Safe Draft State Transition
        # Update draft to VALIDATED ONLY IF version == validated_version AND is_archived = False
        # -------------------------------------------------------------------
        update_draft_stmt = (
            update(DetectionRuleDraftModel)
            .where(
                DetectionRuleDraftModel.id == draft_id,
                DetectionRuleDraftModel.version == validated_version,
                DetectionRuleDraftModel.is_archived.is_(False),
            )
            .values(
                status=DraftStatus.VALIDATED.value,
                updated_at=run_now,
            )
        )
        transition_result = await self.session.execute(update_draft_stmt)
        draft_status_updated = (transition_result.rowcount > 0)
        is_stale = not draft_status_updated

        # -------------------------------------------------------------------
        # Refinement 2: Immutable Validation Record Insertion
        # -------------------------------------------------------------------
        val_run = RuleValidationRunModel(
            id=validation_id,
            draft_id=draft_id,
            draft_version=validated_version,
            run_at=run_now,
            target_scope=target_scope.value,
            query_definition_snapshot=query_snapshot,
            events_scanned=events_scanned_total,
            matches_found=matches_found_total,
            estimated_daily_alert_volume=estimated_daily_alert_volume,
            observation_duration_days=obs_duration_days,
            observation_start=obs_start,
            observation_end=obs_end,
            duration_ms=duration_ms,
            provenance_breakdown=provenance_breakdown,
            threatlab_results=threatlab_metrics.model_dump(mode="json") if threatlab_metrics else None,
            sample_matched_event_ids=sample_matched_event_ids,
            status="COMPLETED",
            error_message=None,
            is_stale=is_stale,
        )
        self.session.add(val_run)
        await self.session.commit()

        return RuleValidationReportResponse(
            validation_id=validation_id,
            draft_id=draft_id,
            draft_version=validated_version,
            run_at=run_now,
            target_scope=target_scope.value,
            duration_ms=duration_ms,
            status="COMPLETED",
            error_message=None,
            is_stale=is_stale,
            draft_status_updated=draft_status_updated,
            historical_metrics=historical_metrics,
            threatlab_metrics=threatlab_metrics,
        )

    async def list_validations(
        self,
        draft_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[RuleValidationRunModel], int]:
        """List historical immutable validation runs for a draft, ordered newest first."""
        count_stmt = select(func.count(RuleValidationRunModel.id)).where(RuleValidationRunModel.draft_id == draft_id)
        total = (await self.session.execute(count_stmt)).scalar() or 0

        stmt = (
            select(RuleValidationRunModel)
            .where(RuleValidationRunModel.draft_id == draft_id)
            .order_by(desc(RuleValidationRunModel.run_at))
            .limit(limit)
            .offset(offset)
        )
        runs = list((await self.session.execute(stmt)).scalars().all())
        return runs, total

    async def get_latest_validation_summary(
        self,
        draft_id: str,
    ) -> Optional[RuleValidationSummary]:
        """Fetch the most recent validation summary for a draft."""
        stmt = (
            select(RuleValidationRunModel)
            .where(RuleValidationRunModel.draft_id == draft_id)
            .order_by(desc(RuleValidationRunModel.run_at))
            .limit(1)
        )
        run = (await self.session.execute(stmt)).scalar_one_or_none()
        if not run:
            return None

        has_warning = False
        if run.threatlab_results and run.threatlab_results.get("has_benign_baseline_warning"):
            has_warning = True

        return RuleValidationSummary(
            validation_id=run.id,
            draft_version=run.draft_version,
            run_at=run.run_at,
            target_scope=run.target_scope,
            matches_found=run.matches_found,
            estimated_daily_alert_volume=run.estimated_daily_alert_volume,
            status=run.status,
            is_stale=run.is_stale,
            has_benign_baseline_warning=has_warning,
        )
