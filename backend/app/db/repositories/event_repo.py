"""
Security Event Repository for CyberTrace.
Provides idempotent persistence, querying, and retrieval of normalized security events.
"""

from datetime import datetime
from typing import List, Optional, Sequence, Tuple
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import SecurityEventModel
from app.schemas.ces import CommonEvent


class EventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def upsert_events(
        self, events: List[CommonEvent], source_file_hash: Optional[str] = None
    ) -> List[SecurityEventModel]:
        """
        Idempotently persist events.
        Existing event IDs are preserved and not duplicated.
        """
        if not events:
            return []

        # Find existing event IDs in batch
        event_ids = [e.event_id for e in events]
        stmt = select(SecurityEventModel.id).where(SecurityEventModel.id.in_(event_ids))
        result = await self.session.execute(stmt)
        existing_ids = set(result.scalars().all())

        new_models: List[SecurityEventModel] = []
        for e in events:
            if e.event_id in existing_ids:
                continue

            model = SecurityEventModel(
                id=e.event_id,
                timestamp=e.timestamp,
                source_type=e.source_format,
                category=e.category.value,
                action=e.action.value,
                severity=e.severity.value,
                username=e.user_identity,
                source_ip=e.source_ip,
                destination_ip=e.destination_ip,
                hostname=e.hostname,
                source_port=e.source_port,
                destination_port=e.destination_port,
                protocol=e.protocol,
                bytes_out=e.bytes_sent,
                bytes_in=e.bytes_received,
                process_name=e.process_name,
                process_command_line=e.process_command_line,
                raw_payload=e.raw_payload,
                source_file_hash=source_file_hash,
            )
            self.session.add(model)
            new_models.append(model)

        await self.session.flush()

        # Fetch and return all requested models
        return await self.get_by_ids(event_ids)

    async def get_by_id(self, event_id: str) -> Optional[SecurityEventModel]:
        stmt = select(SecurityEventModel).where(SecurityEventModel.id == event_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_ids(self, event_ids: Sequence[str]) -> List[SecurityEventModel]:
        if not event_ids:
            return []
        stmt = select(SecurityEventModel).where(SecurityEventModel.id.in_(event_ids)).order_by(SecurityEventModel.timestamp)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_events(
        self,
        limit: int = 100,
        offset: int = 0,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        hostname: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Tuple[List[SecurityEventModel], int]:
        stmt = select(SecurityEventModel)
        count_stmt = select(func.count(SecurityEventModel.id))

        if username:
            stmt = stmt.where(SecurityEventModel.username == username)
            count_stmt = count_stmt.where(SecurityEventModel.username == username)
        if source_ip:
            stmt = stmt.where(SecurityEventModel.source_ip == source_ip)
            count_stmt = count_stmt.where(SecurityEventModel.source_ip == source_ip)
        if hostname:
            stmt = stmt.where(SecurityEventModel.hostname == hostname)
            count_stmt = count_stmt.where(SecurityEventModel.hostname == hostname)
        if start_time:
            stmt = stmt.where(SecurityEventModel.timestamp >= start_time)
            count_stmt = count_stmt.where(SecurityEventModel.timestamp >= start_time)
        if end_time:
            stmt = stmt.where(SecurityEventModel.timestamp <= end_time)
            count_stmt = count_stmt.where(SecurityEventModel.timestamp <= end_time)

        total = (await self.session.execute(count_stmt)).scalar() or 0
        stmt = stmt.order_by(SecurityEventModel.timestamp).offset(offset).limit(limit)
        items = list((await self.session.execute(stmt)).scalars().all())
        return items, total

