"""
Detection Repository for CyberTrace.
Provides persistence and retrieval of deterministic detections and their event linkages.
"""

from datetime import datetime, timezone
from typing import List, Optional, Sequence
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from app.db.models import DetectionEventModel, DetectionModel, SecurityEventModel
from app.rules.base import DetectionResult


class DetectionRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def upsert_detections(self, detections: List[DetectionResult]) -> List[DetectionModel]:
        """
        Persist detection results and their explicit event links.
        Avoids creating duplicate detection records if IDs already exist.
        """
        if not detections:
            return []

        det_ids = [d.detection_id for d in detections]
        stmt = select(DetectionModel.id).where(DetectionModel.id.in_(det_ids))
        existing_ids = set((await self.session.execute(stmt)).scalars().all())

        new_models: List[DetectionModel] = []
        for det in detections:
            if det.detection_id in existing_ids:
                continue

            # Parse entity key into type and value
            if ":" in det.entity_key:
                etype, evalue = det.entity_key.split(":", 1)
            else:
                etype, evalue = "unknown", det.entity_key

            # Determine first and last seen timestamps
            meta_start = det.metadata.get("start_time")
            meta_end = det.metadata.get("end_time")
            first_seen = datetime.fromisoformat(meta_start) if meta_start else det.detection_timestamp
            last_seen = datetime.fromisoformat(meta_end) if meta_end else det.detection_timestamp

            # Ensure timezone
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)

            model = DetectionModel(
                id=det.detection_id,
                rule_id=det.rule_id,
                rule_name=det.rule_name,
                severity=det.severity.value,
                entity_type=etype,
                entity_value=evalue,
                first_seen=first_seen,
                last_seen=last_seen,
                detected_at=det.detection_timestamp,
                explanation=det.summary,
                metadata_json=det.metadata,
            )
            self.session.add(model)
            new_models.append(model)

            # Add many-to-many links to triggering events
            for eid in set(det.triggering_event_ids):
                link = DetectionEventModel(detection_id=det.detection_id, event_id=eid)
                self.session.add(link)

        await self.session.flush()
        return await self.get_by_ids(det_ids)

    async def get_by_id(self, detection_id: str) -> Optional[DetectionModel]:
        stmt = (
            select(DetectionModel)
            .where(DetectionModel.id == detection_id)
            .options(selectinload(DetectionModel.event_associations).selectinload(DetectionEventModel.event))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_ids(self, detection_ids: Sequence[str]) -> List[DetectionModel]:
        if not detection_ids:
            return []
        stmt = (
            select(DetectionModel)
            .where(DetectionModel.id.in_(detection_ids))
            .options(selectinload(DetectionModel.event_associations).selectinload(DetectionEventModel.event))
            .order_by(DetectionModel.detected_at)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_detections(
        self,
        limit: int = 100,
        offset: int = 0,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[DetectionModel]:
        stmt = select(DetectionModel)
        if rule_id:
            stmt = stmt.where(DetectionModel.rule_id == rule_id)
        if severity:
            stmt = stmt.where(DetectionModel.severity == severity)
        stmt = stmt.order_by(DetectionModel.detected_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_detection_events(self, detection_id: str) -> List[SecurityEventModel]:
        stmt = (
            select(SecurityEventModel)
            .join(DetectionEventModel, DetectionEventModel.event_id == SecurityEventModel.id)
            .where(DetectionEventModel.detection_id == detection_id)
            .order_by(SecurityEventModel.timestamp)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

