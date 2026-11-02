"""
CyberTrace Detection Rule Lifecycle Service (Phase 6.3C).
Governs approval, rejection, atomic rule-code allocation, active rule generation,
and immutable audit logging with strict single-transaction atomicity.
"""

from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
import uuid

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import (
    ActiveDetectionRuleModel,
    DetectionRuleDraftModel,
    RuleAuditEntryModel,
    RuleCodeAllocatorModel,
    RuleValidationRunModel,
)
from app.db.repositories.active_rule_repo import ActiveRuleRepository
from app.db.repositories.rule_audit_repo import RuleAuditRepository
from app.db.repositories.rule_draft_repo import RuleDraftRepository
from app.schemas.active_rule import ActiveRuleStatus, ActiveRuleStatusUpdateRequest
from app.schemas.rule_audit import AuditAction
from app.schemas.rule_draft import (
    DraftStatus,
    RuleDraftApprovalRequest,
    RuleDraftRejectionRequest,
)


class LifecycleError(Exception):
    """Base exception for rule lifecycle errors."""
    pass


class DraftNotFoundError(LifecycleError):
    """Raised when a draft ID is not found (HTTP 404)."""
    pass


class DraftArchivedError(LifecycleError):
    """Raised when an operation is attempted on an archived draft (HTTP 409)."""
    pass


class DraftNotValidatedError(LifecycleError):
    """Raised when approval or rejection is attempted on a non-VALIDATED draft (HTTP 409)."""
    pass


class StaleValidationError(LifecycleError):
    """Raised when a draft's validation run is stale or version-mismatched (HTTP 409)."""
    pass


class FourEyesViolationError(LifecycleError):
    """Raised when author attempts to self-approve without demo bypass (HTTP 403)."""
    pass


class ValidationRationaleError(LifecycleError):
    """Raised when justification rationale is missing or < 10 characters (HTTP 400)."""
    pass


class ActiveRuleNotFoundError(LifecycleError):
    """Raised when an active rule ID is not found (HTTP 404)."""
    pass


class DeprecatedRuleTerminalError(LifecycleError):
    """Raised when attempting to reactivate or modify a permanently DEPRECATED rule (HTTP 409)."""
    pass


class VersionConflictError(LifecycleError):
    """Raised on optimistic locking version mismatch (HTTP 409)."""
    pass


class DuplicateApprovalError(LifecycleError):
    """Raised when attempting to approve an already approved draft (HTTP 409)."""
    pass


class InvalidLifecycleTransitionError(LifecycleError):
    """Raised on invalid lifecycle transitions, e.g. no-op status changes (HTTP 400/409)."""
    pass


class RuleLifecycleService:
    """
    Coordinates detection rule governance workflows.
    Owns the outer database transaction boundary across composite operations.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.draft_repo = RuleDraftRepository(session)
        self.active_rule_repo = ActiveRuleRepository(session)
        self.audit_repo = RuleAuditRepository(session)

    @asynccontextmanager
    async def _transaction_scope(self):
        """
        Manages the atomic service-owned transaction boundary.
        - If no transaction is active (normal FastAPI request): uses `async with self.session.begin()`
          to own the transaction lifecycle, committing on success and rolling back on exception.
        - If an outer transaction is already active (e.g. external transaction or test fixture):
          uses `async with self.session.begin_nested()` (SAVEPOINT) so internal failures roll back
          cleanly to the savepoint without prematurely committing or corrupting the outer transaction.
        """
        if self.session.in_transaction():
            async with self.session.begin_nested():
                yield
        else:
            async with self.session.begin():
                yield

    async def _allocate_next_rule_code(self, session: AsyncSession) -> str:
        """
        Atomically increment the rule code sequence allocator and return canonical CUST-xxx code.
        Works inside the active transaction via atomic UPDATE ... RETURNING.
        Handles missing allocator row explicitly by seeding 'custom_rule' at value 1.
        """
        now = datetime.now(timezone.utc)
        stmt = (
            update(RuleCodeAllocatorModel)
            .where(RuleCodeAllocatorModel.sequence_name == "custom_rule")
            .values(
                current_value=RuleCodeAllocatorModel.current_value + 1,
                updated_at=now,
            )
            .returning(RuleCodeAllocatorModel.current_value)
        )
        res = await session.execute(stmt)
        val = res.scalar_one_or_none()

        if val is None:
            # Seed allocator if missing
            new_alloc = RuleCodeAllocatorModel(
                sequence_name="custom_rule",
                current_value=1,
                updated_at=now,
            )
            session.add(new_alloc)
            await session.flush()
            val = 1

        return f"CUST-{val:03d}"

    async def approve_rule_draft(
        self,
        draft_id: str,
        payload: RuleDraftApprovalRequest,
    ) -> Tuple[ActiveDetectionRuleModel, DetectionRuleDraftModel, RuleAuditEntryModel]:
        """
        Approve a validated detection rule draft and deploy it as an active production rule.
        All mutations are executed inside a single service-owned transaction:
        1. Verify draft exists, not archived, version matches, and status is VALIDATED.
        2. Verify valid, completed, non-stale validation run matching draft version.
        3. Enforce four-eyes demonstration governance (author != approver).
        4. Validate mandatory justification rationale (>= 10 chars).
        5. Atomically allocate next canonical rule code (e.g. CUST-001).
        6. Create ActiveDetectionRuleModel with independent deep-copied AST snapshot.
        7. Transition draft status to APPROVED and increment draft version.
        8. Append immutable audit ledger entry.
        """
        if not payload.justification or len(payload.justification.strip()) < 10:
            raise ValidationRationaleError("Mandatory approval justification rationale must be at least 10 characters.")

        async with self._transaction_scope():
            # 1. Fetch draft
            draft_stmt = select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id)
            draft_res = await self.session.execute(draft_stmt)
            draft = draft_res.scalar_one_or_none()

            if not draft:
                raise DraftNotFoundError(f"Detection rule draft '{draft_id}' was not found.")

            if draft.is_archived:
                raise DraftArchivedError(f"Detection rule draft '{draft_id}' is archived and cannot be approved.")

            if draft.version != payload.draft_version:
                raise VersionConflictError(
                    f"Draft version conflict: expected version {payload.draft_version}, found version {draft.version}."
                )

            if draft.status == DraftStatus.APPROVED.value:
                raise DuplicateApprovalError(f"Detection rule draft '{draft_id}' is already approved.")

            if draft.status != DraftStatus.VALIDATED.value:
                raise DraftNotValidatedError(
                    f"Detection rule draft '{draft_id}' is in status '{draft.status}'. "
                    f"Only drafts in VALIDATED status can be approved."
                )

            # 2. Verify validation evidence
            val_stmt = (
                select(RuleValidationRunModel)
                .where(RuleValidationRunModel.draft_id == draft.id)
                .order_by(RuleValidationRunModel.run_at.desc())
            )
            val_res = await self.session.execute(val_stmt)
            latest_val = val_res.scalars().first()

            if not latest_val:
                raise DraftNotValidatedError(
                    f"Detection rule draft '{draft_id}' has no validation runs and cannot be approved."
                )

            if latest_val.is_stale:
                raise StaleValidationError(
                    f"Latest validation run '{latest_val.id}' is stale. "
                    f"A new pre-flight validation must be completed before approval."
                )

            if latest_val.draft_version != draft.version:
                raise StaleValidationError(
                    f"Validation run '{latest_val.id}' was executed against draft version {latest_val.draft_version}, "
                    f"but draft is at version {draft.version}. Re-validation required."
                )

            if latest_val.status != "COMPLETED":
                raise DraftNotValidatedError(
                    f"Latest validation run '{latest_val.id}' did not complete successfully (status: {latest_val.status})."
                )

            # 3. Four-eyes demonstration governance check
            is_self_approval = payload.approver_id.strip().lower() == draft.created_by.strip().lower()
            demo_override_flag = False
            security_warning = None

            if is_self_approval:
                if not settings.ALLOW_DEMO_SELF_APPROVAL:
                    raise FourEyesViolationError(
                        f"Four-eyes principle violation: Approver '{payload.approver_id}' matches draft author. "
                        f"Independent peer review is required. (Self-approval is blocked by server configuration)."
                    )
                else:
                    demo_override_flag = True
                    security_warning = (
                        f"SECURITY AUDIT WARNING: Four-eyes principle violated. Self-approval permitted under "
                        f"server-side ALLOW_DEMO_SELF_APPROVAL configuration. Approver matches author ('{payload.approver_id}')."
                    )

            now = datetime.now(timezone.utc)
            draft_state_before = {
                "status": draft.status,
                "version": draft.version,
            }

            # 4. Atomic conditional draft state update (Optimistic Concurrency Gate)
            draft_update_stmt = (
                update(DetectionRuleDraftModel)
                .where(
                    DetectionRuleDraftModel.id == draft_id,
                    DetectionRuleDraftModel.version == payload.draft_version,
                    DetectionRuleDraftModel.status == DraftStatus.VALIDATED.value,
                    DetectionRuleDraftModel.is_archived.is_(False),
                )
                .values(
                    status=DraftStatus.APPROVED.value,
                    version=DetectionRuleDraftModel.version + 1,
                    updated_at=now,
                )
            )
            draft_update_res = await self.session.execute(draft_update_stmt)
            if draft_update_res.rowcount == 0:
                raise VersionConflictError(
                    f"Draft '{draft_id}' state or version conflict: draft was concurrently approved, modified, or archived."
                )

            # Refresh draft entity in session with updated database state
            stmt_refresh_draft = (
                select(DetectionRuleDraftModel)
                .where(DetectionRuleDraftModel.id == draft_id)
                .execution_options(populate_existing=True)
            )
            draft_refresh_res = await self.session.execute(stmt_refresh_draft)
            draft = draft_refresh_res.scalar_one()

            # 5. Atomic sequential rule-code allocation
            rule_code = await self._allocate_next_rule_code(self.session)

            # 6. Create Active Detection Rule with independent frozen AST snapshot
            active_rule_id = f"rule_{uuid.uuid4().hex[:12]}"
            initial_status = ActiveRuleStatus.ACTIVE.value if payload.activate_immediately else ActiveRuleStatus.DISABLED.value

            active_rule = ActiveDetectionRuleModel(
                id=active_rule_id,
                rule_code=rule_code,
                name=draft.name,
                description=draft.description,
                severity=draft.severity,
                mitre_attack_id=draft.mitre_attack_id,
                mitre_tactic=draft.mitre_tactic,
                source_draft_id=draft.id,
                source_draft_version=payload.draft_version,
                validation_run_id=latest_val.id,
                query_definition=deepcopy(draft.query_definition),
                status=initial_status,
                version=1,
                approved_by=payload.approver_id,
                approved_at=now,
                activated_at=now,
                created_at=now,
                updated_at=now,
            )
            await self.active_rule_repo.create_active_rule(active_rule)

            draft_state_after = {
                "status": draft.status,
                "version": draft.version,
                "active_rule_id": active_rule.id,
                "rule_code": active_rule.rule_code,
            }

            # 7. Append audit ledger entry
            audit_id = f"audit_{uuid.uuid4().hex[:12]}"
            audit_entry = RuleAuditEntryModel(
                id=audit_id,
                target_type="DRAFT",
                target_id=draft.id,
                action=AuditAction.APPROVE_DRAFT.value,
                actor=payload.approver_id,
                timestamp=now,
                justification=payload.justification.strip(),
                state_before=draft_state_before,
                state_after=draft_state_after,
                demo_override_flag=demo_override_flag,
                security_warning=security_warning,
            )
            await self.audit_repo.create_audit_entry(audit_entry)

        # Transaction commits upon exit of async with self.session.begin()
        return active_rule, draft, audit_entry

    async def reject_rule_draft(
        self,
        draft_id: str,
        payload: RuleDraftRejectionRequest,
    ) -> Tuple[DetectionRuleDraftModel, RuleAuditEntryModel]:
        """
        Reject a validated detection rule draft with mandatory reviewer rationale.
        Resets draft status back to editable DRAFT state for rework.
        Appends REJECT_DRAFT entry to the immutable audit ledger.
        """
        if not payload.justification or len(payload.justification.strip()) < 10:
            raise ValidationRationaleError("Mandatory rejection justification rationale must be at least 10 characters.")

        async with self._transaction_scope():
            draft_stmt = select(DetectionRuleDraftModel).where(DetectionRuleDraftModel.id == draft_id)
            draft_res = await self.session.execute(draft_stmt)
            draft = draft_res.scalar_one_or_none()

            if not draft:
                raise DraftNotFoundError(f"Detection rule draft '{draft_id}' was not found.")

            if draft.is_archived:
                raise DraftArchivedError(f"Detection rule draft '{draft_id}' is archived and cannot be rejected.")

            if draft.version != payload.draft_version:
                raise VersionConflictError(
                    f"Draft version conflict: expected version {payload.draft_version}, found version {draft.version}."
                )

            if draft.status != DraftStatus.VALIDATED.value:
                raise DraftNotValidatedError(
                    f"Detection rule draft '{draft_id}' is in status '{draft.status}'. "
                    f"Only drafts in VALIDATED status can be reviewed and rejected."
                )

            now = datetime.now(timezone.utc)
            state_before = {
                "status": draft.status,
                "version": draft.version,
            }

            # Atomic conditional draft state update (Optimistic Concurrency Gate)
            draft_update_stmt = (
                update(DetectionRuleDraftModel)
                .where(
                    DetectionRuleDraftModel.id == draft_id,
                    DetectionRuleDraftModel.version == payload.draft_version,
                    DetectionRuleDraftModel.status == DraftStatus.VALIDATED.value,
                    DetectionRuleDraftModel.is_archived.is_(False),
                )
                .values(
                    status=DraftStatus.DRAFT.value,
                    version=DetectionRuleDraftModel.version + 1,
                    updated_at=now,
                )
            )
            draft_update_res = await self.session.execute(draft_update_stmt)
            if draft_update_res.rowcount == 0:
                raise VersionConflictError(
                    f"Draft '{draft_id}' state or version conflict: draft was concurrently reviewed, modified, or archived."
                )

            stmt_refresh_draft = (
                select(DetectionRuleDraftModel)
                .where(DetectionRuleDraftModel.id == draft_id)
                .execution_options(populate_existing=True)
            )
            draft_refresh_res = await self.session.execute(stmt_refresh_draft)
            draft = draft_refresh_res.scalar_one()

            state_after = {
                "status": draft.status,
                "version": draft.version,
                "rejected_by": payload.reviewer_id,
            }

            audit_id = f"audit_{uuid.uuid4().hex[:12]}"
            audit_entry = RuleAuditEntryModel(
                id=audit_id,
                target_type="DRAFT",
                target_id=draft.id,
                action=AuditAction.REJECT_DRAFT.value,
                actor=payload.reviewer_id,
                timestamp=now,
                justification=payload.justification.strip(),
                state_before=state_before,
                state_after=state_after,
                demo_override_flag=False,
                security_warning=None,
            )
            await self.audit_repo.create_audit_entry(audit_entry)

        return draft, audit_entry

    async def toggle_active_rule_status(
        self,
        rule_id: str,
        payload: ActiveRuleStatusUpdateRequest,
    ) -> Tuple[ActiveDetectionRuleModel, RuleAuditEntryModel]:
        """
        Update the status of an active detection rule (ACTIVE <-> DISABLED or -> DEPRECATED).
        Enforces:
        - DEPRECATED is a permanent terminal state (reactivation prohibited).
        - Optimistic concurrency control via version locking.
        - Mandatory justification rationale (>= 10 chars).
        - Appends audit ledger entry with before/after state snapshots.
        """
        if not payload.justification or len(payload.justification.strip()) < 10:
            raise ValidationRationaleError("Mandatory status update justification rationale must be at least 10 characters.")

        async with self._transaction_scope():
            stmt = select(ActiveDetectionRuleModel).where(
                or_(
                    ActiveDetectionRuleModel.id == rule_id,
                    ActiveDetectionRuleModel.rule_code == rule_id,
                )
            )
            res = await self.session.execute(stmt)
            rule = res.scalar_one_or_none()

            if not rule:
                raise ActiveRuleNotFoundError(f"Active detection rule '{rule_id}' was not found.")

            if rule.version != payload.version:
                raise VersionConflictError(
                    f"Rule version conflict: expected version {payload.version}, found version {rule.version}."
                )

            # DEPRECATED is terminal
            if rule.status == ActiveRuleStatus.DEPRECATED.value:
                raise DeprecatedRuleTerminalError(
                    f"Active detection rule '{rule.rule_code}' is permanently DEPRECATED. Reactivation is strictly prohibited."
                )

            if rule.status == payload.status.value:
                raise InvalidLifecycleTransitionError(
                    f"Rule '{rule.rule_code}' is already in status '{payload.status.value}'."
                )

            now = datetime.now(timezone.utc)
            state_before = {
                "status": rule.status,
                "version": rule.version,
            }

            # Map action and timestamps
            deactivated_at = None
            activated_at = None
            if payload.status == ActiveRuleStatus.DISABLED:
                action = AuditAction.DEACTIVATE_RULE.value
                deactivated_at = now
            elif payload.status == ActiveRuleStatus.ACTIVE:
                action = AuditAction.REACTIVATE_RULE.value
                activated_at = now
            elif payload.status == ActiveRuleStatus.DEPRECATED:
                action = AuditAction.DEPRECATE_RULE.value
                deactivated_at = now

            # Atomic conditional status update via repository (Optimistic Concurrency Gate)
            updated_rule = await self.active_rule_repo.update_rule_status_atomic(
                rule_id=rule.id,
                expected_version=payload.version,
                new_status=payload.status.value,
                deactivated_at=deactivated_at,
                activated_at=activated_at,
            )
            if not updated_rule:
                raise VersionConflictError(
                    f"Active detection rule '{rule.rule_code}' version conflict: concurrent update detected."
                )

            state_after = {
                "status": updated_rule.status,
                "version": updated_rule.version,
            }

            audit_id = f"audit_{uuid.uuid4().hex[:12]}"
            audit_entry = RuleAuditEntryModel(
                id=audit_id,
                target_type="ACTIVE_RULE",
                target_id=updated_rule.id,
                action=action,
                actor=payload.actor,
                timestamp=now,
                justification=payload.justification.strip(),
                state_before=state_before,
                state_after=state_after,
                demo_override_flag=False,
                security_warning=None,
            )
            await self.audit_repo.create_audit_entry(audit_entry)

        return updated_rule, audit_entry
