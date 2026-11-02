"""
Saved Threat Hunt Repository for CyberTrace (Phase 6.3A).
Provides persistence, atomic versioning with optimistic concurrency locking,
query re-execution via the unified hunting compiler, soft-delete archiving,
and duplication of saved threat hunt definitions.
"""

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import func, or_, select, String, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SavedHuntModel
from app.db.repositories.hunting_repo import HuntingRepository
from app.schemas.saved_hunt import (
    SavedHuntCreate,
    SavedHuntDuplicateRequest,
    SavedHuntExecuteRequest,
    SavedHuntExecuteResponse,
    SavedHuntQueryDefinition,
    SavedHuntUpdate,
)


class VersionConflictError(Exception):
    """Raised when an update specifies a stale version (optimistic concurrency violation)."""
    def __init__(self, current_version: int, requested_version: int):
        self.current_version = current_version
        self.requested_version = requested_version
        super().__init__(
            f"Version conflict: current version is {current_version}, but update request provided {requested_version}."
        )


class ArchivedHuntError(Exception):
    """Raised when an operation is attempted on an archived hunt that requires an active hunt."""
    def __init__(self, message: str):
        super().__init__(message)


def _escape_like_param(val: str) -> str:
    """Escape LIKE wildcards (%, _, \\) to treat user input as literal text."""
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class SavedHuntRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_saved_hunt(self, data: SavedHuntCreate) -> SavedHuntModel:
        """
        Persist a new validated saved threat hunt.
        Always starts at version 1 with zero executions.
        """
        hunt_id = f"hunt_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        model = SavedHuntModel(
            id=hunt_id,
            name=data.name,
            description=data.description,
            tags=data.tags,
            query_definition=data.query_definition.model_dump(mode="json"),
            created_by=data.created_by,
            created_at=now,
            updated_at=now,
            version=1,
            last_run_at=None,
            run_count=0,
            is_archived=False,
        )

        self.session.add(model)
        await self.session.commit()
        await self.session.refresh(model)
        return model

    async def get_saved_hunt(self, hunt_id: str) -> Optional[SavedHuntModel]:
        """Fetch a saved hunt by its ID, regardless of archive status."""
        stmt = select(SavedHuntModel).where(SavedHuntModel.id == hunt_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_saved_hunts(
        self,
        query: Optional[str] = None,
        tag: Optional[str] = None,
        include_archived: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[SavedHuntModel], int]:
        """
        List saved threat hunts with optional search, tag filtering, and pagination.
        Excludes archived hunts by default unless include_archived=True.
        """
        clauses = []

        if not include_archived:
            clauses.append(SavedHuntModel.is_archived.is_(False))

        if query:
            clean_q = _escape_like_param(query.strip())
            pattern = f"%{clean_q}%"
            clauses.append(
                or_(
                    SavedHuntModel.name.ilike(pattern, escape="\\"),
                    SavedHuntModel.description.ilike(pattern, escape="\\"),
                )
            )

        if tag:
            clean_tag = tag.strip().replace('"', "")
            if clean_tag:
                escaped_tag = _escape_like_param(clean_tag)
                # Exact quoted match inside JSON array string serialization
                tag_pattern = f'%"{escaped_tag}"%'
                clauses.append(func.cast(SavedHuntModel.tags, String).like(tag_pattern, escape="\\"))

        # Count total
        count_stmt = select(func.count(SavedHuntModel.id))
        if clauses:
            count_stmt = count_stmt.where(*clauses)
        total = (await self.session.execute(count_stmt)).scalar() or 0

        if total == 0 or offset >= total:
            return [], total

        # Query page
        page_stmt = (
            select(SavedHuntModel)
            .order_by(SavedHuntModel.updated_at.desc(), SavedHuntModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if clauses:
            page_stmt = page_stmt.where(*clauses)

        items = (await self.session.execute(page_stmt)).scalars().all()
        return list(items), total

    async def update_saved_hunt(self, hunt_id: str, data: SavedHuntUpdate) -> SavedHuntModel:
        """
        Update an existing saved hunt with atomic conditional SQL optimistic concurrency control.
        Atomic conditional criteria:
          - id == hunt_id
          - version == data.version
          - is_archived == False
        Atomically increments version and updates timestamp in database.
        If zero rows affected:
          - Missing hunt -> ValueError (mapped to 404)
          - Archived hunt -> ArchivedHuntError (mapped to 409 Conflict)
          - Stale version -> VersionConflictError (mapped to 409 Conflict)
        """
        now = datetime.now(timezone.utc)
        update_values: Dict[str, Any] = {}
        if data.name is not None:
            update_values["name"] = data.name
        if data.description is not None:
            update_values["description"] = data.description
        if data.tags is not None:
            update_values["tags"] = data.tags
        if data.query_definition is not None:
            update_values["query_definition"] = data.query_definition.model_dump(mode="json")

        stmt = (
            update(SavedHuntModel)
            .where(
                SavedHuntModel.id == hunt_id,
                SavedHuntModel.version == data.version,
                SavedHuntModel.is_archived.is_(False),
            )
            .values(
                **update_values,
                version=SavedHuntModel.version + 1,
                updated_at=now,
            )
        )
        result = await self.session.execute(stmt)
        await self.session.commit()

        if result.rowcount == 0:
            existing = await self.get_saved_hunt(hunt_id)
            if not existing:
                raise ValueError(f"Saved threat hunt '{hunt_id}' was not found.")
            if existing.is_archived:
                raise ArchivedHuntError(
                    f"Archived threat hunt '{hunt_id}' cannot be modified. Unarchive or duplicate to modify."
                )
            raise VersionConflictError(current_version=existing.version, requested_version=data.version)

        updated_hunt = await self.get_saved_hunt(hunt_id)
        if not updated_hunt:
            raise ValueError(f"Saved threat hunt '{hunt_id}' was not found.")
        return updated_hunt

    async def archive_saved_hunt(self, hunt_id: str) -> SavedHuntModel:
        """
        Soft-delete a saved hunt by marking is_archived = True.
        Preserves complete query and execution history.
        Idempotent: if already archived, returns existing record without mutating timestamps.
        """
        hunt = await self.get_saved_hunt(hunt_id)
        if not hunt:
            raise ValueError(f"Saved threat hunt '{hunt_id}' was not found.")

        if not hunt.is_archived:
            hunt.is_archived = True
            hunt.updated_at = datetime.now(timezone.utc)
            await self.session.commit()
            await self.session.refresh(hunt)

        return hunt

    async def duplicate_saved_hunt(self, hunt_id: str, data: SavedHuntDuplicateRequest) -> SavedHuntModel:
        """
        Clone an existing saved hunt into a new, completely independent hunt record.
        Starts at version 1 with zero executions and is_archived = False.
        Can duplicate active or archived hunts.
        """
        original = await self.get_saved_hunt(hunt_id)
        if not original:
            raise ValueError(f"Saved threat hunt '{hunt_id}' was not found.")

        new_id = f"hunt_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        new_name = data.name or f"Copy of {original.name}"
        if len(new_name) > 128:
            new_name = new_name[:128]

        cloned = SavedHuntModel(
            id=new_id,
            name=new_name,
            description=original.description,
            tags=deepcopy(original.tags),
            query_definition=deepcopy(original.query_definition),
            created_by=data.created_by,
            created_at=now,
            updated_at=now,
            version=1,
            last_run_at=None,
            run_count=0,
            is_archived=False,
        )

        self.session.add(cloned)
        await self.session.commit()
        await self.session.refresh(cloned)
        return cloned

    async def execute_saved_hunt(
        self,
        hunt_id: str,
        exec_request: Optional[SavedHuntExecuteRequest] = None,
    ) -> SavedHuntExecuteResponse:
        """
        Re-execute a saved hunt query definition using the unified hunting compiler.
        Rejects archived hunts with ArchivedHuntError.
        Snapshots exact version and AST definition upfront before query execution.
        Safely increments run_count and updates last_run_at atomically upon query success.
        Failed query executions leave run counters unchanged.
        """
        hunt = await self.get_saved_hunt(hunt_id)
        if not hunt:
            raise ValueError(f"Saved threat hunt '{hunt_id}' was not found.")

        if hunt.is_archived:
            raise ArchivedHuntError(
                f"Archived threat hunt '{hunt_id}' cannot be executed. Unarchive or duplicate to run."
            )

        # Snapshot exact version, name, and AST query definition BEFORE execution
        executed_version = hunt.version
        hunt_name = hunt.name
        query_def = SavedHuntQueryDefinition.model_validate(deepcopy(hunt.query_definition))

        # Build threat hunt query with optional pagination overrides
        override_limit = exec_request.limit if exec_request else None
        override_offset = exec_request.offset if exec_request else None
        threat_request = query_def.to_threat_hunt_request(
            override_limit=override_limit,
            override_offset=override_offset,
        )

        # Execute query via HuntingRepository
        hunting_repo = HuntingRepository(self.session)
        # If this fails or raises an error, execution metrics below are NOT committed
        query_result = await hunting_repo.execute_hunt(threat_request)

        # Atomically increment run_count and update last_run_at in the database
        now = datetime.now(timezone.utc)
        update_stmt = (
            update(SavedHuntModel)
            .where(SavedHuntModel.id == hunt_id)
            .values(
                run_count=SavedHuntModel.run_count + 1,
                last_run_at=now,
            )
        )
        await self.session.execute(update_stmt)
        await self.session.commit()

        # Fetch current run_count
        count_stmt = select(SavedHuntModel.run_count).where(SavedHuntModel.id == hunt_id)
        new_run_count = (await self.session.execute(count_stmt)).scalar() or 1

        return SavedHuntExecuteResponse(
            hunt_id=hunt_id,
            hunt_name=hunt_name,
            executed_version=executed_version,
            executed_at=now,
            run_count=new_run_count,
            items=query_result.items,
            total=query_result.total,
            limit=query_result.limit,
            offset=query_result.offset,
            query_duration_ms=query_result.query_duration_ms,
            applied_filter_count=query_result.applied_filter_count,
            provenance=query_result.provenance,
        )
