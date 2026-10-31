"""
Safeguards and pair evaluators for CyberTrace Incident Correlation.
Prevents false incident merges caused by shared public IPs, NAT gateways, or generic service hosts.
"""

from typing import Dict, Optional
from app.correlation.models import (
    CorrelationConfig,
    CorrelationRelationship,
    CorrelationStrength,
    RelationshipType,
)
from app.rules.base import DetectionResult
from app.schemas.ces import CommonEvent


def is_disallowed_merge_entity(entity_key: str, config: CorrelationConfig) -> bool:
    """Check if an entity key is a generic or public identifier that must not bridge incidents."""
    if not entity_key:
        return True

    kind, val = entity_key.split(":", 1) if ":" in entity_key else ("", entity_key)

    # Check public IP blocklist
    if kind == "ip" and val in config.public_ip_blocklist:
        return True

    # Check generic disallowed entities
    if entity_key in config.disallowed_merge_entities:
        return True

    # Common generic accounts that should not be merged without secondary evidence
    if kind == "user" and val.lower() in ("anonymous", "guest", "null", "none"):
        return True

    return False


def evaluate_detection_pair(
    d1: DetectionResult,
    d2: DetectionResult,
    events_by_id: Dict[str, CommonEvent],
    config: CorrelationConfig,
) -> Optional[CorrelationRelationship]:
    """
    Evaluate if two detections should be correlated into the same incident.
    Returns CorrelationRelationship if valid; returns None if link is rejected by safeguards.
    """
    # 1. Temporal Window Check
    time_diff = abs((d1.detection_timestamp - d2.detection_timestamp).total_seconds())
    if time_diff > config.max_time_delta_seconds:
        return None

    # Parse entities
    e1_kind, e1_val = d1.entity_key.split(":", 1) if ":" in d1.entity_key else ("unknown", d1.entity_key)
    e2_kind, e2_val = d2.entity_key.split(":", 1) if ":" in d2.entity_key else ("unknown", d2.entity_key)

    # Check if entity is explicitly blocked
    if is_disallowed_merge_entity(d1.entity_key, config) or is_disallowed_merge_entity(d2.entity_key, config):
        return None

    # Direct provenance overlap: do detections cite any of the same raw events?
    shared_events = list(set(d1.triggering_event_ids).intersection(set(d2.triggering_event_ids)))
    if shared_events:
        return CorrelationRelationship(
            source_detection_id=d1.detection_id,
            target_detection_id=d2.detection_id,
            relationship_type=RelationshipType.DIRECT_EVIDENCE_PROVENANCE,
            matching_entity="shared_event_provenance",
            time_difference_seconds=time_diff,
            explanation=f"Detections share {len(shared_events)} direct evidence event(s): {shared_events[:3]}.",
            correlation_strength=CorrelationStrength.STRONG,
            supporting_event_ids=shared_events,
        )

    # Case A: Same User Identity
    if e1_kind == "user" and e2_kind == "user" and e1_val.lower() == e2_val.lower():
        # Check rule progression
        rel_type = RelationshipType.TEMPORAL_ENTITY_CO_OCCURRENCE
        expl = f"Detections share the same user identity '{e1_val}' within {time_diff:.0f}s."
        
        if (d1.rule_id == "DET-001" and d2.rule_id == "DET-002") or (d1.rule_id == "DET-002" and d2.rule_id == "DET-001"):
            rel_type = RelationshipType.SAME_USER_AUTH_SEQUENCE
            expl = f"Authentication progression: brute force burst followed by logon success for '{e1_val}'."
        elif "DET-003" in (d1.rule_id, d2.rule_id):
            rel_type = RelationshipType.SAME_USER_PRIVILEGE_ELEVATION
            expl = f"Privilege elevation correlated with authentication activity for user '{e1_val}'."

        return CorrelationRelationship(
            source_detection_id=d1.detection_id,
            target_detection_id=d2.detection_id,
            relationship_type=rel_type,
            matching_entity=f"user:{e1_val}",
            time_difference_seconds=time_diff,
            explanation=expl,
            correlation_strength=CorrelationStrength.STRONG,
            supporting_event_ids=list(dict.fromkeys(d1.triggering_event_ids + d2.triggering_event_ids)),
        )

    # Safeguard: Two detections explicitly attributed to two DIFFERENT users must NEVER be merged
    # by a shared host or IP alone unless direct evidence provenance links them (checked above).
    if e1_kind == "user" and e2_kind == "user" and e1_val.lower() != e2_val.lower():
        return None

    # Case B: Host Post-Compromise Activity (e.g. Host where privilege escalation happened then exfiltrated data)
    # Check if supporting events for d1 and d2 share a common internal host or private IP
    hosts_d1 = {events_by_id[eid].hostname for eid in d1.triggering_event_ids if eid in events_by_id and events_by_id[eid].hostname}
    hosts_d2 = {events_by_id[eid].hostname for eid in d2.triggering_event_ids if eid in events_by_id and events_by_id[eid].hostname}
    shared_hosts = hosts_d1.intersection(hosts_d2)

    src_ips_d1 = {events_by_id[eid].source_ip for eid in d1.triggering_event_ids if eid in events_by_id and events_by_id[eid].source_ip}
    src_ips_d2 = {events_by_id[eid].source_ip for eid in d2.triggering_event_ids if eid in events_by_id and events_by_id[eid].source_ip}
    shared_internal_ips = {ip for ip in src_ips_d1.intersection(src_ips_d2) if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.")}

    if shared_hosts or shared_internal_ips:
        matching_host = next(iter(shared_hosts)) if shared_hosts else next(iter(shared_internal_ips))
        # Disallow merging purely on a generic host without behavioral progression
        if "DET-004" in (d1.rule_id, d2.rule_id) and any(r in (d1.rule_id, d2.rule_id) for r in ("DET-002", "DET-003")):
            return CorrelationRelationship(
                source_detection_id=d1.detection_id,
                target_detection_id=d2.detection_id,
                relationship_type=RelationshipType.HOST_POST_COMPROMISE_ACTIVITY,
                matching_entity=f"host:{matching_host}",
                time_difference_seconds=time_diff,
                explanation=f"Host '{matching_host}' exhibited post-compromise activity (elevation/exfiltration) within {time_diff:.0f}s.",
                correlation_strength=CorrelationStrength.STRONG,
                supporting_event_ids=list(dict.fromkeys(d1.triggering_event_ids + d2.triggering_event_ids)),
            )

    # Case C: Shared Public IP alone
    if e1_kind == "ip" and e2_kind == "ip" and e1_val == e2_val:
        # A shared IP alone without identical user or host is WEAK
        # Safeguard: weak links are rejected
        return None

    # No valid correlation criteria met
    return None

