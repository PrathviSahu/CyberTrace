"""
Incident Service for CyberTrace.
Coordinates end-to-end ingestion, detection, correlation, and persistence workflows.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.correlation.engine import IncidentCorrelationEngine
from app.correlation.models import CorrelatedIncidentGroup, CorrelationConfig
from app.db.models import IncidentModel, SecurityEventModel
from app.db.repositories.detection_repo import DetectionRepository
from app.db.repositories.event_repo import EventRepository
from app.db.repositories.incident_repo import IncidentRepository
from app.rules.rule_engine import DetectionEngine
from app.schemas.ces import CommonEvent


class IncidentService:
    def __init__(
        self,
        session: AsyncSession,
        correlation_config: Optional[CorrelationConfig] = None,
    ):
        self.session = session
        self.event_repo = EventRepository(session)
        self.detection_repo = DetectionRepository(session)
        self.incident_repo = IncidentRepository(session)
        self.detection_engine = DetectionEngine()
        self.correlation_engine = IncidentCorrelationEngine(correlation_config)

    async def process_and_correlate_events(
        self, events: List[CommonEvent], source_file_hash: Optional[str] = None
    ) -> List[IncidentModel]:
        """
        Orchestrates full pipeline:
        1. Idempotently persist events.
        2. Evaluate deterministic detection rules.
        3. Persist detection results and their explicit event links.
        4. Run safeguarded correlation engine.
        5. Persist correlated incidents and extracted entities.
        """
        if not events:
            return []

        # 1. Persist events
        await self.event_repo.upsert_events(events, source_file_hash=source_file_hash)

        # 2. Run deterministic detection rules
        detections = self.detection_engine.evaluate_all(events)
        if not detections:
            await self.session.commit()
            return []

        # 3. Persist detections and event references
        await self.detection_repo.upsert_detections(detections)

        # 4. Run correlation engine
        incident_groups = self.correlation_engine.correlate(detections, events)
        if not incident_groups:
            await self.session.commit()
            return []

        # 5. Persist incidents
        persisted_incidents: List[IncidentModel] = []
        for group in incident_groups:
            inc = await self.incident_repo.upsert_incident(group)
            persisted_incidents.append(inc)

        await self.session.commit()
        return persisted_incidents

    async def get_incident_dossier(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve complete incident dossier with detections, events, and entities."""
        return await self.incident_repo.get_incident_evidence(incident_id)

