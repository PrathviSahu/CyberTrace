"""
Investigation Repository for CyberTrace.
Provides persistence and retrieval of AI-assisted and fallback incident investigations.
"""

from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import AIInvestigationModel


class InvestigationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_investigation(self, investigation: AIInvestigationModel) -> AIInvestigationModel:
        self.session.add(investigation)
        await self.session.flush()
        return investigation

    async def get_by_id(self, investigation_id: str) -> Optional[AIInvestigationModel]:
        stmt = select(AIInvestigationModel).where(AIInvestigationModel.id == investigation_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_incident(self, incident_id: str) -> List[AIInvestigationModel]:
        stmt = (
            select(AIInvestigationModel)
            .where(AIInvestigationModel.incident_id == incident_id)
            .order_by(AIInvestigationModel.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_latest_by_incident(self, incident_id: str) -> Optional[AIInvestigationModel]:
        stmt = (
            select(AIInvestigationModel)
            .where(AIInvestigationModel.incident_id == incident_id)
            .order_by(AIInvestigationModel.created_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

