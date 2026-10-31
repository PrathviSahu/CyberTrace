"""
Investigation Service for CyberTrace.
Coordinates AI agent orchestration, deterministic fallback failover, and database persistence.
"""

from datetime import datetime, timezone
import logging
import time
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import AIInvestigationModel
from app.db.repositories.incident_repo import IncidentRepository
from app.db.repositories.investigation_repo import InvestigationRepository
from app.investigation.agent import BharatCodeAgent
from app.investigation.fallback import DeterministicFallbackEngine
from app.investigation.tools import InvestigationToolExecutor
from app.schemas.investigation import StructuredInvestigation

logger = logging.getLogger(__name__)


class InvestigationService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.incident_repo = IncidentRepository(session)
        self.investigation_repo = InvestigationRepository(session)

    async def investigate_incident(self, incident_id: str) -> Optional[AIInvestigationModel]:
        """
        Executes an AI-assisted or fallback investigation for an authorized incident.
        Returns None if incident does not exist.
        """
        dossier = await self.incident_repo.get_incident_evidence(incident_id)
        if not dossier:
            return None

        start_utc = datetime.now(timezone.utc)
        t0 = time.time()
        tool_executor = InvestigationToolExecutor(self.session, incident_id)

        model_id = settings.BHARATCODE_MODEL
        status = "completed"
        request_id: Optional[str] = None
        error_message: Optional[str] = None
        tool_call_count = 0
        structured_result: StructuredInvestigation
        event_citations: List[str] = []

        # Check if BharatCode API key is configured
        if not settings.BHARATCODE_API_KEY or not settings.BHARATCODE_API_KEY.strip():
            logger.info("BHARATCODE_API_KEY not set. Using DeterministicFallbackEngine.")
            status = "fallback"
            model_id = "deterministic-fallback"
            error_message = "BHARATCODE_API_KEY is not configured"
            fallback_res = DeterministicFallbackEngine.generate_fallback_investigation(
                dossier, fallback_reason=error_message
            )
            structured_result = fallback_res
            # Extract cited event IDs
            citations = set()
            for f in fallback_res.observed_facts:
                citations.update(f.event_ids)
            for h in fallback_res.hypotheses:
                citations.update(h.supporting_event_ids)
            for a in fallback_res.recommended_actions:
                citations.update(a.supporting_event_ids)
            event_citations = sorted(list(citations))
        else:
            agent = BharatCodeAgent()
            try:
                ai_result, citations, req_id = await agent.run_investigation(
                    incident_id=incident_id,
                    dossier=dossier,
                    executor=tool_executor,
                )
                structured_result = ai_result
                event_citations = citations
                request_id = req_id
                tool_call_count = agent.tool_call_count
            except Exception as exc:
                safe_err_reason = f"{type(exc).__name__}: {str(exc)}"
                logger.warning(
                    "BharatCode investigation failed (%s). Failing over to DeterministicFallbackEngine.",
                    safe_err_reason,
                )
                status = "fallback"
                model_id = "deterministic-fallback"
                error_message = safe_err_reason
                request_id = getattr(agent, "last_request_id", None)
                tool_call_count = getattr(agent, "tool_call_count", 0)

                fallback_res = DeterministicFallbackEngine.generate_fallback_investigation(
                    dossier, fallback_reason=safe_err_reason
                )
                structured_result = fallback_res
                citations = set()
                for f in fallback_res.observed_facts:
                    citations.update(f.event_ids)
                for h in fallback_res.hypotheses:
                    citations.update(h.supporting_event_ids)
                for a in fallback_res.recommended_actions:
                    citations.update(a.supporting_event_ids)
                event_citations = sorted(list(citations))

        duration_seconds = round(time.time() - t0, 3)
        completed_utc = datetime.now(timezone.utc)

        investigation_model = AIInvestigationModel(
            id=f"inv_{uuid.uuid4().hex[:16]}",
            incident_id=incident_id,
            model_id=model_id,
            status=status,
            executive_summary=structured_result.executive_summary,
            structured_result=structured_result.model_dump(),
            event_citations=event_citations,
            tool_call_count=tool_call_count,
            duration_seconds=duration_seconds,
            request_id=request_id,
            error_message=error_message,
            created_at=start_utc,
            completed_at=completed_utc,
        )

        try:
            await self.investigation_repo.save_investigation(investigation_model)
            await self.session.commit()
            await self.session.refresh(investigation_model)
        except Exception:
            await self.session.rollback()
            raise

        return investigation_model

    async def list_investigations(self, incident_id: str) -> List[AIInvestigationModel]:
        """Lists all investigations recorded for an incident."""
        incident = await self.incident_repo.get_by_id(incident_id)
        if not incident:
            return []
        return await self.investigation_repo.list_by_incident(incident_id)

    async def get_investigation(
        self, incident_id: str, investigation_id: str
    ) -> Optional[AIInvestigationModel]:
        """Retrieves an investigation record, ensuring boundary match with incident_id."""
        inv = await self.investigation_repo.get_by_id(investigation_id)
        if not inv or inv.incident_id != incident_id:
            return None
        return inv

