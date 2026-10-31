"""
Incident Repository for CyberTrace.
Provides idempotent persistence and full-graph retrieval of security incidents and their evidence.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

if TYPE_CHECKING:
    from app.correlation.models import CorrelatedIncidentGroup
from app.db.models import (
    DetectionEventModel,
    DetectionModel,
    IncidentDetectionModel,
    IncidentEntityModel,
    IncidentModel,
    SecurityEventModel,
)


class IncidentRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def upsert_incident(self, group: CorrelatedIncidentGroup) -> IncidentModel:
        """
        Idempotently create or update an incident and its associated detections and entities.
        """
        stmt = select(IncidentModel).where(
            (IncidentModel.id == group.incident_id) | (IncidentModel.correlation_key == group.correlation_key)
        )
        existing = (await self.session.execute(stmt)).scalar_one_or_none()

        if existing:
            incident = existing
            incident.title = group.title
            incident.description = group.description
            incident.severity = group.severity.value
            incident.first_seen = group.first_seen
            incident.last_seen = group.last_seen
            incident.updated_at = datetime.now(timezone.utc)
        else:
            incident = IncidentModel(
                id=group.incident_id,
                correlation_key=group.correlation_key,
                title=group.title,
                description=group.description,
                severity=group.severity.value,
                status=group.status,
                first_seen=group.first_seen,
                last_seen=group.last_seen,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            self.session.add(incident)

        await self.session.flush()

        # Link detections
        det_stmt = select(IncidentDetectionModel.detection_id).where(
            IncidentDetectionModel.incident_id == incident.id
        )
        existing_det_ids = set((await self.session.execute(det_stmt)).scalars().all())

        for did in group.detection_ids:
            if did not in existing_det_ids:
                # Find correlation reason if present
                reason = next(
                    (r.explanation for r in group.relationships if r.source_detection_id == did or r.target_detection_id == did),
                    "Correlated into incident group"
                )
                self.session.add(
                    IncidentDetectionModel(
                        incident_id=incident.id,
                        detection_id=did,
                        correlation_reason=reason[:255] if reason else None,
                    )
                )

        # Upsert entities
        ent_stmt = select(IncidentEntityModel).where(IncidentEntityModel.incident_id == incident.id)
        existing_entities = (await self.session.execute(ent_stmt)).scalars().all()
        ent_map = {(e.entity_type, e.entity_value): e for e in existing_entities}

        for ent in group.entities:
            key = (ent.entity_type, ent.entity_value)
            if key in ent_map:
                existing_ent = ent_map[key]
                existing_ent.relationship = ent.relationship
                existing_ent.confidence = ent.confidence
                existing_ent.evidence_references = ent.evidence_references
            else:
                self.session.add(
                    IncidentEntityModel(
                        id=f"ient_{incident.id}_{ent.entity_type}_{ent.entity_value}".replace(":", "_"),
                        incident_id=incident.id,
                        entity_type=ent.entity_type,
                        entity_value=ent.entity_value,
                        relationship=ent.relationship,
                        confidence=ent.confidence,
                        evidence_references=ent.evidence_references,
                    )
                )

        await self.session.flush()
        return incident

    async def get_by_id(self, incident_id: str) -> Optional[IncidentModel]:
        stmt = (
            select(IncidentModel)
            .where(IncidentModel.id == incident_id)
            .options(
                selectinload(IncidentModel.detection_associations).selectinload(IncidentDetectionModel.detection),
                selectinload(IncidentModel.entities),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_incidents(
        self,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[IncidentModel]:
        stmt = select(IncidentModel).options(selectinload(IncidentModel.entities))
        if status:
            stmt = stmt.where(IncidentModel.status == status)
        if severity:
            stmt = stmt.where(IncidentModel.severity == severity)
        stmt = stmt.order_by(IncidentModel.first_seen.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_incident_evidence(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full incident dossier with all supporting detections and events."""
        incident = await self.get_by_id(incident_id)
        if not incident:
            return None

        # Fetch all detection IDs
        det_ids = [assoc.detection_id for assoc in incident.detection_associations]

        # Fetch all detections with their event IDs
        det_stmt = (
            select(DetectionModel)
            .where(DetectionModel.id.in_(det_ids))
            .options(selectinload(DetectionModel.event_associations))
        )
        detections = list((await self.session.execute(det_stmt)).scalars().all())

        all_event_ids = set()
        for d in detections:
            for ea in d.event_associations:
                all_event_ids.add(ea.event_id)

        # Fetch all unique events
        ev_stmt = select(SecurityEventModel).where(SecurityEventModel.id.in_(list(all_event_ids))).order_by(SecurityEventModel.timestamp)
        events = list((await self.session.execute(ev_stmt)).scalars().all())

        return {
            "incident": incident,
            "detections": detections,
            "events": events,
            "entities": incident.entities,
        }
