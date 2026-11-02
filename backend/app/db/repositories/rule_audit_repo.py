"""
CyberTrace Rule Audit Repository (Phase 6.3C).
Provides append-only persistence and querying for detection rule lifecycle audit records.
Contains zero UPDATE or DELETE methods, ensuring application-level append-only guarantees.
All mutations use flush() and do not call commit(), ensuring transaction ownership by RuleLifecycleService.
"""

from typing import List, Optional, Tuple
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import RuleAuditEntryModel


class RuleAuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_audit_entry(
        self,
        audit_entry: RuleAuditEntryModel,
    ) -> RuleAuditEntryModel:
        """
        Append a new audit entry to the session and flush.
        Does NOT commit — transaction ownership belongs to caller/service.
        """
        self.session.add(audit_entry)
        await self.session.flush()
        return audit_entry

    async def get_audit_entry_by_id(self, audit_id: str) -> Optional[RuleAuditEntryModel]:
        """Fetch audit entry by ID."""
        stmt = select(RuleAuditEntryModel).where(RuleAuditEntryModel.id == audit_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_audit_entries(
        self,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[RuleAuditEntryModel], int]:
        """Query audit records with optional filtering and pagination."""
        base_stmt = select(RuleAuditEntryModel)
        count_stmt = select(func.count(RuleAuditEntryModel.id))

        if target_type:
            base_stmt = base_stmt.where(RuleAuditEntryModel.target_type == target_type)
            count_stmt = count_stmt.where(RuleAuditEntryModel.target_type == target_type)
        if target_id:
            base_stmt = base_stmt.where(RuleAuditEntryModel.target_id == target_id)
            count_stmt = count_stmt.where(RuleAuditEntryModel.target_id == target_id)
        if actor:
            base_stmt = base_stmt.where(RuleAuditEntryModel.actor == actor)
            count_stmt = count_stmt.where(RuleAuditEntryModel.actor == actor)
        if action:
            base_stmt = base_stmt.where(RuleAuditEntryModel.action == action)
            count_stmt = count_stmt.where(RuleAuditEntryModel.action == action)

        base_stmt = base_stmt.order_by(desc(RuleAuditEntryModel.timestamp)).limit(limit).offset(offset)

        total_res = await self.session.execute(count_stmt)
        total = total_res.scalar() or 0

        entries_res = await self.session.execute(base_stmt)
        items = list(entries_res.scalars().all())

        return items, total
