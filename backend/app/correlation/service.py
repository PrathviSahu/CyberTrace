"""
Incident Service for CyberTrace.
Coordinates end-to-end ingestion, detection, correlation, and persistence workflows.
Constructs request-scoped detection engine snapshots preserving deterministic isolation.
"""

import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.correlation.engine import IncidentCorrelationEngine
from app.correlation.models import CorrelatedIncidentGroup, CorrelationConfig
from app.db.models import IncidentModel, SecurityEventModel
from app.db.repositories.active_rule_repo import ActiveRuleRepository
from app.db.repositories.detection_repo import DetectionRepository
from app.db.repositories.event_repo import EventRepository
from app.db.repositories.incident_repo import IncidentRepository
from app.rules.dynamic_rule import DynamicCustomRule
from app.rules.rule_engine import DetectionEngine
from app.schemas.active_rule import ActiveRuleStatus
from app.schemas.ces import CommonEvent

logger = logging.getLogger("cybertrace.correlation.service")


class IncidentService:
    def __init__(
        self,
        session: AsyncSession,
        correlation_config: Optional[CorrelationConfig] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ):
        self.session = session
        self.event_repo = EventRepository(session)
        self.detection_repo = DetectionRepository(session)
        self.incident_repo = IncidentRepository(session)
        self.active_rule_repo = ActiveRuleRepository(session)
        self.correlation_engine = IncidentCorrelationEngine(correlation_config)
        self._detection_engine = detection_engine
        self.latest_detections: List[Any] = []

    async def get_or_create_detection_engine(self) -> DetectionEngine:
        """
        Build or return the request-scoped DetectionEngine snapshot for this ingestion batch.
        Loads approved active rules from the database once, excludes DISABLED and DEPRECATED rules,
        converts valid rules to frozen DynamicCustomRule instances, and constructs an isolated snapshot.
        If a rule's stored AST is invalid or corrupted, logs an actionable diagnostic and skips it
        without failing the batch or suppressing foundational detections.
        """
        if self._detection_engine is not None:
            return self._detection_engine

        # Load active rules from DB once per batch
        active_models = await self.active_rule_repo.get_all_active_for_detection()
        custom_rules: List[DynamicCustomRule] = []

        for model in active_models:
            # Explicitly ensure only ACTIVE rules participate
            if model.status != ActiveRuleStatus.ACTIVE.value:
                continue
            try:
                custom_rule = DynamicCustomRule.from_active_model(model)
                custom_rules.append(custom_rule)
            except Exception as exc:
                logger.error(
                    "Skipping invalid/corrupted custom detection rule '%s' (ID: %s): %s",
                    model.rule_code,
                    model.id,
                    exc,
                )

        self._detection_engine = DetectionEngine(custom_rules=custom_rules)
        return self._detection_engine

    @property
    def detection_engine(self) -> DetectionEngine:
        """
        Synchronous property for backward compatibility with existing callers.
        If a request-scoped engine hasn't been built yet, returns foundational engine.
        """
        if self._detection_engine is None:
            return DetectionEngine()
        return self._detection_engine

    async def process_and_correlate_events(
        self, events: List[CommonEvent], source_file_hash: Optional[str] = None
    ) -> List[IncidentModel]:
        """
        Orchestrates full pipeline:
        1. Idempotently persist events.
        2. Load request-scoped detection engine snapshot (once per batch).
        3. Evaluate deterministic detection rules.
        4. Persist detection results and their explicit event links.
        5. Run safeguarded correlation engine.
        6. Persist correlated incidents and extracted entities.
        """
        if not events:
            return []

        # 1. Persist events
        await self.event_repo.upsert_events(events, source_file_hash=source_file_hash)

        # 2. Build or obtain request-scoped detection engine snapshot
        engine = await self.get_or_create_detection_engine()

        # 3. Run deterministic detection rules
        detections = engine.evaluate_all(events)
        self.latest_detections = detections
        if not detections:
            await self.session.commit()
            return []

        # 4. Persist detections and event references
        await self.detection_repo.upsert_detections(detections)

        # 5. Run correlation engine
        incident_groups = self.correlation_engine.correlate(detections, events)
        if not incident_groups:
            await self.session.commit()
            return []

        # 6. Persist incidents
        persisted_incidents: List[IncidentModel] = []
        for group in incident_groups:
            inc = await self.incident_repo.upsert_incident(group)
            persisted_incidents.append(inc)

        await self.session.commit()
        return persisted_incidents

    async def get_incident_dossier(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve complete incident dossier with detections, events, and entities."""
        return await self.incident_repo.get_incident_evidence(incident_id)

