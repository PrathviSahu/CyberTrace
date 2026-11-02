"""
CyberTrace Active Detection Rule Repository (Phase 6.3C).
Manages persistence, querying, and optimistic concurrency status updates for active production rules.
All mutations use flush() and do not call commit(), ensuring transaction ownership by RuleLifecycleService.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ActiveDetectionRuleModel
from app.schemas.active_rule import ActiveRuleStatus


class ActiveRuleRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_active_rule(
        self,
        active_rule: ActiveDetectionRuleModel,
    ) -> ActiveDetectionRuleModel:
        """
        Add a new active rule to the session and flush.
        Does NOT commit — transaction ownership belongs to caller/service.
        """
        self.session.add(active_rule)
        await self.session.flush()
        return active_rule

    async def get_active_rule_by_id(self, rule_id: str) -> Optional[ActiveDetectionRuleModel]:
        """Fetch active rule by ID."""
        stmt = select(ActiveDetectionRuleModel).where(ActiveDetectionRuleModel.id == rule_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_active_rule_by_code(self, rule_code: str) -> Optional[ActiveDetectionRuleModel]:
        """Fetch active rule by canonical rule code (e.g. CUST-001)."""
        stmt = select(ActiveDetectionRuleModel).where(ActiveDetectionRuleModel.rule_code == rule_code)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_active_rules(
        self,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[ActiveDetectionRuleModel], int]:
        """List active rules with optional status filter and total count."""
        base_stmt = select(ActiveDetectionRuleModel)
        count_stmt = select(func.count(ActiveDetectionRuleModel.id))

        if status:
            base_stmt = base_stmt.where(ActiveDetectionRuleModel.status == status)
            count_stmt = count_stmt.where(ActiveDetectionRuleModel.status == status)

        base_stmt = base_stmt.order_by(desc(ActiveDetectionRuleModel.created_at)).limit(limit).offset(offset)

        total_res = await self.session.execute(count_stmt)
        total = total_res.scalar() or 0

        rules_res = await self.session.execute(base_stmt)
        items = list(rules_res.scalars().all())

        return items, total

    async def get_all_active_for_detection(self) -> List[ActiveDetectionRuleModel]:
        """
        Fetch all active detection rules for live ingestion evaluation snapshot.
        Ordered deterministically by rule_code ascending.
        """
        stmt = (
            select(ActiveDetectionRuleModel)
            .where(ActiveDetectionRuleModel.status == ActiveRuleStatus.ACTIVE.value)
            .order_by(ActiveDetectionRuleModel.rule_code.asc())
        )
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def update_rule_status_atomic(
        self,
        rule_id: str,
        expected_version: int,
        new_status: str,
        deactivated_at: Optional[datetime] = None,
        activated_at: Optional[datetime] = None,
    ) -> Optional[ActiveDetectionRuleModel]:
        """
        Perform atomic conditional update on active rule status with optimistic locking.
        Flushes to session without committing.
        Returns the updated ActiveDetectionRuleModel if successful; None if version conflict or not found.
        """
        now = datetime.now(timezone.utc)
        update_values: Dict[str, Any] = {
            "status": new_status,
            "version": ActiveDetectionRuleModel.version + 1,
            "updated_at": now,
        }
        if deactivated_at is not None:
            update_values["deactivated_at"] = deactivated_at
        if activated_at is not None:
            update_values["activated_at"] = activated_at
            update_values["deactivated_at"] = None

        stmt = (
            update(ActiveDetectionRuleModel)
            .where(
                ActiveDetectionRuleModel.id == rule_id,
                ActiveDetectionRuleModel.version == expected_version,
            )
            .values(**update_values)
        )
        result = await self.session.execute(stmt)
        if result.rowcount == 0:
            return None

        stmt_refresh = (
            select(ActiveDetectionRuleModel)
            .where(ActiveDetectionRuleModel.id == rule_id)
            .execution_options(populate_existing=True)
        )
        res = await self.session.execute(stmt_refresh)
        return res.scalar_one_or_none()
