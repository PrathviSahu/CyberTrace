"""
Deterministic Fallback Investigation Engine for CyberTrace.
Synthesizes verified telemetry, detection explanations, and entity relationships
when BharatCode AI is unavailable, rate-limited, or unconfigured.
"""

from typing import Any, Dict, List
from app.schemas.investigation import (
    ConfidenceLevel,
    Hypothesis,
    ImpactLevel,
    ObservedFact,
    RecommendedAction,
    StructuredInvestigation,
    UnknownGap,
)


class DeterministicFallbackEngine:
    """Builds completely evidence-grounded incident investigations without generative AI."""

    @classmethod
    def generate_fallback_investigation(
        cls,
        dossier: Dict[str, Any],
        fallback_reason: str = "BharatCode AI unavailable",
    ) -> StructuredInvestigation:
        incident = dossier["incident"]
        detections = dossier["detections"]
        events = dossier["events"]
        entities = dossier["entities"]

        # 1. Executive Summary
        exec_summary = (
            f"[Deterministic Heuristic Synthesis] Incident '{incident.title}' (Severity: {incident.severity.upper()}) "
            f"comprises {len(detections)} detection(s) across {len(events)} correlated security event(s). "
            f"AI generation unavailable ({fallback_reason}). Findings derived strictly from deterministic rule telemetry."
        )

        # 2. Observed Facts (Derived directly from triggered detection explanations and event IDs)
        observed_facts: List[ObservedFact] = []
        for det in detections:
            event_ids = [ea.event_id for ea in det.event_associations]
            observed_facts.append(
                ObservedFact(
                    statement=f"Rule {det.rule_id} ({det.rule_name}) fired on {det.entity_type} '{det.entity_value}': {det.explanation}",
                    event_ids=event_ids,
                )
            )

        # 3. Hypotheses (Conservative, rule-grounded, non-speculative)
        hypotheses: List[Hypothesis] = []
        rule_ids = {d.rule_id for d in detections}
        if "DET-001" in rule_ids and "DET-002" in rule_ids:
            hypotheses.append(
                Hypothesis(
                    statement="Authentication failures followed by successful login strongly suggest credential stuffing or brute-force compromise.",
                    supporting_event_ids=[e.id for e in events if e.category == "authentication"],
                    confidence=ConfidenceLevel.HIGH,
                    caveats=["Legitimate user password recovery or forgotten credentials must be ruled out by contacting the account owner."],
                )
            )
        if "DET-003" in rule_ids:
            hypotheses.append(
                Hypothesis(
                    statement="Post-authentication privilege escalation indicates an adversary or authorized operator elevating privileges via sudo or token assignment.",
                    supporting_event_ids=[e.id for e in events if e.category == "privilege_change"],
                    confidence=ConfidenceLevel.HIGH,
                    caveats=["Confirm whether an authorized system change or maintenance window was scheduled."],
                )
            )
        if "DET-004" in rule_ids:
            hypotheses.append(
                Hypothesis(
                    statement="High-volume outbound egress to an external IP indicates potential data exfiltration or staging.",
                    supporting_event_ids=[e.id for e in events if e.category == "network_connection"],
                    confidence=ConfidenceLevel.HIGH,
                    caveats=["Inspect perimeter firewall connection state and destination IP reputation."],
                )
            )

        # 4. Unknowns / Telemetry Gaps
        unknowns: List[UnknownGap] = [
            UnknownGap(
                question="Was the authenticated logon performed by the genuine user or an unauthorized threat actor?",
                reason="Logon telemetry confirms valid credentials but does not provide multi-factor device attestation.",
            ),
            UnknownGap(
                question="What specific files or data contents were transferred during the outbound connection?",
                reason="Network flow records capture byte volumes and endpoints but do not record application-layer payload contents.",
            ),
        ]

        # 5. Recommended Actions (Always requiring explicit human approval)
        recommended_actions: List[RecommendedAction] = []
        user_entities = [e.entity_value for e in entities if e.entity_type == "user"]
        host_entities = [e.entity_value for e in entities if e.entity_type == "hostname"]
        ext_ips = [e.entity_value for e in entities if e.entity_type in ("source_ip", "destination_ip")]

        if user_entities:
            u = user_entities[0]
            recommended_actions.append(
                RecommendedAction(
                    action=f"Revoke active sessions and force credential reset for user '{u}'.",
                    rationale=f"Compromised or targeted authentication observed on '{u}'.",
                    supporting_event_ids=[e.id for e in events if e.username == u],
                    impact=ImpactLevel.MEDIUM,
                    requires_human_approval=True,
                )
            )

        if ext_ips:
            ip = ext_ips[0]
            recommended_actions.append(
                RecommendedAction(
                    action=f"Simulate blocking external IP address '{ip}' at perimeter firewall.",
                    rationale=f"Associated with suspicious external connections or brute force bursts.",
                    supporting_event_ids=[e.id for e in events if e.source_ip == ip or e.destination_ip == ip],
                    impact=ImpactLevel.LOW,
                    requires_human_approval=True,
                )
            )

        if host_entities and "DET-004" in rule_ids:
            h = host_entities[0]
            recommended_actions.append(
                RecommendedAction(
                    action=f"Simulate isolating host '{h}' from internal network segment.",
                    rationale=f"Host participated in elevated execution and outbound data exfiltration.",
                    supporting_event_ids=[e.id for e in events if e.hostname == h],
                    impact=ImpactLevel.HIGH,
                    requires_human_approval=True,
                )
            )

        # 6. Limitations
        limitations: List[str] = [
            f"Fallback investigation generated due to: {fallback_reason}.",
            "Analysis is purely deterministic and limited to pre-programmed detection rules.",
            "No autonomous remediation has been performed; all actions are recommendations requiring human sign-off.",
        ]

        return StructuredInvestigation(
            executive_summary=exec_summary,
            observed_facts=observed_facts,
            hypotheses=hypotheses,
            unknowns=unknowns,
            recommended_actions=recommended_actions,
            limitations=limitations,
        )

