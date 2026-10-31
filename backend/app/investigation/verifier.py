"""
Server-side Evidence Verification for CyberTrace Investigations.
Validates all AI-generated citations against ground-truth incident events in the database.
Rejects hallucinated event IDs, purges unsupported claims, prevents ungrounded compound facts,
and strictly enforces human-in-the-loop approval on all defensive response actions.
"""

from typing import List, Set, Tuple
from app.schemas.investigation import (
    Hypothesis,
    ObservedFact,
    RecommendedAction,
    StructuredInvestigation,
)


class EvidenceVerifier:
    def __init__(self, valid_incident_event_ids: Set[str]):
        self.valid_event_ids = set(valid_incident_event_ids)

    def verify_and_clean(
        self, raw_investigation: StructuredInvestigation
    ) -> Tuple[StructuredInvestigation, List[str], List[str]]:
        """
        Validates event citations across facts, hypotheses, and recommendations.
        Enforces strict evidentiary grounding:
          - Facts with zero verified citations or mixed (valid + invalid) citations are omitted.
          - Hypotheses with zero verified supporting citations are omitted.
          - Recommendations with zero verified supporting citations are omitted unless explicitly generic.
          - All recommendations strictly enforce requires_human_approval = True.
        Returns: (cleaned_investigation, verified_citations, rejected_citations)
        """
        verified_citations: Set[str] = set()
        rejected_citations: Set[str] = set()
        limitations: List[str] = list(raw_investigation.limitations)

        # 1. Clean Observed Facts (Strict Grounding)
        verified_facts: List[ObservedFact] = []
        for fact in raw_investigation.observed_facts:
            if not fact.event_ids:
                # Omit facts that cite zero evidence
                continue

            valid_ids = []
            invalid_ids = []
            for eid in fact.event_ids:
                if eid in self.valid_event_ids:
                    valid_ids.append(eid)
                    verified_citations.add(eid)
                else:
                    invalid_ids.append(eid)
                    rejected_citations.add(eid)

            if invalid_ids and valid_ids:
                # Mixed citations: Do not assume valid IDs support the entire compound statement.
                # Omit the statement to prevent misleading or partially unverified narrative claims.
                limitations.append(
                    f"[Omitted Mixed-Citation Fact] Fact statement was omitted because its evidentiary basis "
                    f"was partially unverified: '{fact.statement[:80]}...' (unverified IDs: {invalid_ids})"
                )
            elif invalid_ids and not valid_ids:
                # 100% hallucinated citations: omit
                pass
            elif valid_ids and not invalid_ids:
                # Fully verified: all cited event IDs exist in the incident dossier
                verified_facts.append(
                    ObservedFact(statement=fact.statement, event_ids=valid_ids)
                )

        # 2. Clean Hypotheses
        verified_hypotheses: List[Hypothesis] = []
        for hyp in raw_investigation.hypotheses:
            valid_supporting = []
            invalid_supporting = []
            for eid in hyp.supporting_event_ids:
                if eid in self.valid_event_ids:
                    valid_supporting.append(eid)
                    verified_citations.add(eid)
                else:
                    invalid_supporting.append(eid)
                    rejected_citations.add(eid)

            valid_contradicting = []
            for eid in hyp.contradicting_event_ids:
                if eid in self.valid_event_ids:
                    valid_contradicting.append(eid)
                    verified_citations.add(eid)
                else:
                    rejected_citations.add(eid)

            # Preserve only hypotheses backed by at least one verified supporting event
            if not valid_supporting:
                limitations.append(
                    f"[Omitted Unsupported Hypothesis] Hypothesis removed due to lack of verified supporting evidence: "
                    f"'{hyp.statement[:80]}...'"
                )
                continue

            caveats = list(hyp.caveats)
            if invalid_supporting:
                caveats.append(
                    f"[Evidence Integrity Warning] {len(invalid_supporting)} unverified supporting event ID(s) "
                    f"were removed from this hypothesis."
                )

            verified_hypotheses.append(
                Hypothesis(
                    statement=hyp.statement,
                    supporting_event_ids=valid_supporting,
                    contradicting_event_ids=valid_contradicting,
                    confidence=hyp.confidence,
                    caveats=caveats,
                )
            )

        # 3. Clean Recommended Actions
        verified_actions: List[RecommendedAction] = []
        for act in raw_investigation.recommended_actions:
            valid_ids = []
            invalid_ids = []
            for eid in act.supporting_event_ids:
                if eid in self.valid_event_ids:
                    valid_ids.append(eid)
                    verified_citations.add(eid)
                else:
                    invalid_ids.append(eid)
                    rejected_citations.add(eid)

            is_generic = act.is_generic_guidance or act.action.strip().lower().startswith("[generic")

            if valid_ids:
                # Incident-specific action supported by real evidence
                verified_actions.append(
                    RecommendedAction(
                        action=act.action,
                        rationale=act.rationale,
                        supporting_event_ids=valid_ids,
                        impact=act.impact,
                        requires_human_approval=True,
                        is_generic_guidance=False,
                    )
                )
            elif is_generic:
                # Generic best-practice guidance: visibly distinguished from incident-specific recommendations
                action_text = (
                    act.action
                    if act.action.startswith("[Generic Best-Practice Guidance]")
                    else f"[Generic Best-Practice Guidance] {act.action}"
                )
                verified_actions.append(
                    RecommendedAction(
                        action=action_text,
                        rationale=act.rationale,
                        supporting_event_ids=[],
                        impact=act.impact,
                        requires_human_approval=True,
                        is_generic_guidance=True,
                    )
                )
            else:
                # Non-generic action with zero verified supporting evidence: Omit
                limitations.append(
                    f"[Omitted Unsupported Action] Recommended action removed due to lack of verified supporting evidence: "
                    f"'{act.action[:80]}...'"
                )

        # 4. Summary Integrity Notice in limitations
        if rejected_citations:
            limitations.append(
                f"[Evidence Integrity Notice] {len(rejected_citations)} unverified or out-of-scope event ID(s) "
                f"were stripped during server-side verification: {sorted(list(rejected_citations))[:5]}."
            )

        cleaned_investigation = StructuredInvestigation(
            executive_summary=raw_investigation.executive_summary,
            observed_facts=verified_facts,
            hypotheses=verified_hypotheses,
            unknowns=raw_investigation.unknowns,
            recommended_actions=verified_actions,
            limitations=limitations,
        )

        return (
            cleaned_investigation,
            sorted(list(verified_citations)),
            sorted(list(rejected_citations)),
        )
