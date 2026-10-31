"""
Incident Correlation Engine for CyberTrace.
Provides deterministic, explainable clustering of detections and evidence into security incidents.
"""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
from typing import Dict, List, Set
from app.correlation.models import (
    CorrelatedEntity,
    CorrelatedIncidentGroup,
    CorrelationConfig,
    CorrelationRelationship,
)
from app.correlation.safeguards import evaluate_detection_pair
from app.rules.base import DetectionResult
from app.schemas.ces import CommonEvent, EventSeverity, generate_event_id


class IncidentCorrelationEngine:
    def __init__(self, config: CorrelationConfig = None):
        self.config = config or CorrelationConfig()

    def correlate(
        self, detections: List[DetectionResult], events: List[CommonEvent]
    ) -> List[CorrelatedIncidentGroup]:
        """
        Pure function: correlates detections and supporting events into discrete,
        auditable Incident Groups.
        """
        if not detections:
            return []

        # Index events for O(1) retrieval
        events_by_id: Dict[str, CommonEvent] = {e.event_id: e for e in events}

        # Step 1: Pairwise evaluation with strict safeguards
        relationships_by_pair: Dict[tuple, CorrelationRelationship] = {}
        adj: Dict[str, Set[str]] = defaultdict(set)
        det_map: Dict[str, DetectionResult] = {d.detection_id: d for d in detections}

        n = len(detections)
        for i in range(n):
            d1 = detections[i]
            for j in range(i + 1, n):
                d2 = detections[j]
                rel = evaluate_detection_pair(d1, d2, events_by_id, self.config)
                if rel:
                    pair_key = (d1.detection_id, d2.detection_id)
                    relationships_by_pair[pair_key] = rel
                    adj[d1.detection_id].add(d2.detection_id)
                    adj[d2.detection_id].add(d1.detection_id)

        # Step 2: Connected Components Graph Traversal with Identity-Isolation Safeguard
        # Sort detections by timestamp to guarantee deterministic traversal order
        sorted_dets = sorted(detections, key=lambda x: x.detection_timestamp)
        visited: Set[str] = set()
        clusters: List[List[str]] = []

        for d in sorted_dets:
            did = d.detection_id
            if did in visited:
                continue

            # BFS traversal enforcing identity isolation across shared hubs
            cluster = []
            queue = [did]
            visited.add(did)

            # Track primary human/service user identities in this cluster
            cluster_users: Set[str] = set()
            if d.entity_key.startswith("user:"):
                u = d.entity_key.split(":", 1)[1].lower()
                if u not in ("root", "system", "administrator"):
                    cluster_users.add(u)

            while queue:
                curr = queue.pop(0)
                cluster.append(curr)
                # Sort neighbors for deterministic traversal
                for neighbor in sorted(list(adj[curr])):
                    if neighbor in visited:
                        continue

                    neighbor_det = det_map[neighbor]
                    # Check if neighbor introduces a conflicting distinct user identity
                    if neighbor_det.entity_key.startswith("user:"):
                        nu = neighbor_det.entity_key.split(":", 1)[1].lower()
                        if nu not in ("root", "system", "administrator"):
                            if cluster_users and nu not in cluster_users:
                                # Conflicting user: check if there is direct evidence provenance between them
                                pair = (curr, neighbor) if (curr, neighbor) in relationships_by_pair else (neighbor, curr)
                                rel = relationships_by_pair.get(pair)
                                if not rel or rel.relationship_type.value != "direct_evidence_provenance":
                                    # Do NOT merge conflicting user via a shared hub node
                                    continue
                            cluster_users.add(nu)

                    visited.add(neighbor)
                    queue.append(neighbor)

            clusters.append(cluster)

        # Step 3: Build CorrelatedIncidentGroups with Maximum Incident Span Partitioning
        incidents: List[CorrelatedIncidentGroup] = []
        for cluster_dids in clusters:
            raw_cluster_dets = [det_map[did] for did in cluster_dids]
            raw_cluster_dets.sort(key=lambda x: x.detection_timestamp)

            # Chronologically partition any cluster that exceeds max_incident_span_seconds
            partitioned_clusters = self._partition_by_max_span(raw_cluster_dets)

            for cluster_dets in partitioned_clusters:
                first_seen = cluster_dets[0].detection_timestamp
                last_seen = cluster_dets[-1].detection_timestamp
                part_dids = {cd.detection_id for cd in cluster_dets}

                # Gather relationships active within this partition
                cluster_relationships = [
                    rel for pair, rel in relationships_by_pair.items()
                    if pair[0] in part_dids and pair[1] in part_dids
                ]

                # Gather all supporting event IDs for this partition
                all_event_ids = set()
                for cd in cluster_dets:
                    all_event_ids.update(cd.triggering_event_ids)
                sorted_event_ids = sorted(list(all_event_ids))

                # Deterministic Correlation Key
                sorted_rule_entities = sorted([f"{d.rule_id}:{d.entity_key}" for d in cluster_dets])
                raw_fingerprint = f"{first_seen.date().isoformat()}_{first_seen.strftime('%H%M')}_{'|'.join(sorted_rule_entities)}"
                correlation_key = hashlib.sha256(raw_fingerprint.encode("utf-8")).hexdigest()[:16]

                # Deterministic Incident ID
                incident_id = f"inc_{correlation_key[:10]}"

                # Extract Entities and Roles
                entities = self._extract_incident_entities(cluster_dets, sorted_event_ids, events_by_id)

                # Determine Severity
                severity = self._determine_severity(cluster_dets)

                # Generate Title and Description
                title = self._generate_incident_title(cluster_dets, entities)
                description = self._generate_incident_description(cluster_dets, first_seen, last_seen, entities)

                incidents.append(
                    CorrelatedIncidentGroup(
                        incident_id=incident_id,
                        correlation_key=correlation_key,
                        title=title,
                        description=description,
                        severity=severity,
                        status="open",
                        first_seen=first_seen,
                        last_seen=last_seen,
                        detection_ids=[d.detection_id for d in cluster_dets],
                        relationships=cluster_relationships,
                        entities=entities,
                        supporting_event_ids=sorted_event_ids,
                    )
                )

        # Sort incidents chronologically
        incidents.sort(key=lambda x: x.first_seen)
        return incidents

    def _partition_by_max_span(
        self, cluster_dets: List[DetectionResult]
    ) -> List[List[DetectionResult]]:
        """
        Partition chronologically sorted detections into consecutive bounded sub-clusters
        such that no sub-cluster exceeds max_incident_span_seconds.
        """
        if not cluster_dets:
            return []

        partitions: List[List[DetectionResult]] = []
        current_partition: List[DetectionResult] = [cluster_dets[0]]
        partition_start = cluster_dets[0].detection_timestamp

        for d in cluster_dets[1:]:
            diff = (d.detection_timestamp - partition_start).total_seconds()
            if diff <= self.config.max_incident_span_seconds:
                current_partition.append(d)
            else:
                partitions.append(current_partition)
                current_partition = [d]
                partition_start = d.detection_timestamp

        if current_partition:
            partitions.append(current_partition)

        return partitions

    def _determine_severity(self, detections: List[DetectionResult]) -> EventSeverity:
        """Transparent, deterministic severity assignment policy."""
        rule_ids = {d.rule_id for d in detections}
        severities = {d.severity for d in detections}

        if "DET-004" in rule_ids or EventSeverity.CRITICAL in severities:
            return EventSeverity.CRITICAL
        if "DET-003" in rule_ids or "DET-002" in rule_ids or EventSeverity.HIGH in severities:
            return EventSeverity.HIGH
        if "DET-001" in rule_ids or EventSeverity.MEDIUM in severities:
            return EventSeverity.MEDIUM
        return EventSeverity.LOW

    def _extract_incident_entities(
        self,
        detections: List[DetectionResult],
        event_ids: List[str],
        events_by_id: Dict[str, CommonEvent],
    ) -> List[CorrelatedEntity]:
        """Classify and attribute roles to distinct entities involved in the incident."""
        entities_dict: Dict[tuple, CorrelatedEntity] = {}

        for eid in event_ids:
            ev = events_by_id.get(eid)
            if not ev:
                continue

            # User account
            if ev.user_identity:
                role = "targeted_account"
                if any(d.rule_id in ("DET-002", "DET-003") for d in detections):
                    role = "compromised_account"
                key = ("user", ev.user_identity.lower())
                if key not in entities_dict:
                    entities_dict[key] = CorrelatedEntity(
                        entity_type="user",
                        entity_value=ev.user_identity.lower(),
                        relationship=role,
                        confidence=1.0,
                        evidence_references=[eid],
                    )
                else:
                    entities_dict[key].evidence_references.append(eid)
                    if role == "compromised_account":
                        entities_dict[key].relationship = role

            # External Source IP
            if ev.source_ip and not (ev.source_ip.startswith("192.168.") or ev.source_ip.startswith("10.") or ev.source_ip.startswith("127.")):
                key = ("source_ip", ev.source_ip)
                if key not in entities_dict:
                    entities_dict[key] = CorrelatedEntity(
                        entity_type="source_ip",
                        entity_value=ev.source_ip,
                        relationship="attacker_source_ip",
                        confidence=0.95,
                        evidence_references=[eid],
                    )
                else:
                    entities_dict[key].evidence_references.append(eid)

            # Hostname
            if ev.hostname:
                key = ("hostname", ev.hostname.upper())
                role = "target_host"
                if any(d.rule_id in ("DET-003", "DET-004") for d in detections):
                    role = "compromised_host"
                if key not in entities_dict:
                    entities_dict[key] = CorrelatedEntity(
                        entity_type="hostname",
                        entity_value=ev.hostname.upper(),
                        relationship=role,
                        confidence=1.0,
                        evidence_references=[eid],
                    )
                else:
                    entities_dict[key].evidence_references.append(eid)
                    if role == "compromised_host":
                        entities_dict[key].relationship = role

            # External Destination IP (C2 / Exfil)
            if ev.destination_ip and ev.bytes_sent >= 50 * 1024 * 1024:
                key = ("destination_ip", ev.destination_ip)
                if key not in entities_dict:
                    entities_dict[key] = CorrelatedEntity(
                        entity_type="destination_ip",
                        entity_value=ev.destination_ip,
                        relationship="suspected_c2_exfil_destination",
                        confidence=0.9,
                        evidence_references=[eid],
                    )
                else:
                    entities_dict[key].evidence_references.append(eid)

        # Deduplicate evidence references
        for ent in entities_dict.values():
            ent.evidence_references = list(dict.fromkeys(ent.evidence_references))

        return list(entities_dict.values())

    def _generate_incident_title(
        self, detections: List[DetectionResult], entities: List[CorrelatedEntity]
    ) -> str:
        """Formulate an informative, standard SOC incident title."""
        rule_ids = {d.rule_id for d in detections}
        user_ent = next((e.entity_value for e in entities if e.entity_type == "user"), None)
        host_ent = next((e.entity_value for e in entities if e.entity_type == "hostname"), None)

        if "DET-004" in rule_ids and "DET-003" in rule_ids:
            return f"Multi-Stage Intrusion & Data Exfiltration targeting '{user_ent or 'Unknown'}' on {host_ent or 'Host'}"
        if "DET-003" in rule_ids:
            return f"Suspicious Privilege Escalation on {host_ent or 'Host'} by user '{user_ent or 'Unknown'}'"
        if "DET-002" in rule_ids:
            return f"Potential Account Compromise following failed login burst on '{user_ent or 'Unknown'}'"
        if "DET-001" in rule_ids:
            return f"Repeated Authentication Failures (Brute Force) against '{user_ent or 'Unknown'}'"
        return f"Suspicious Activity Cluster involving {user_ent or host_ent or 'Entity'}"

    def _generate_incident_description(
        self,
        detections: List[DetectionResult],
        first_seen: datetime,
        last_seen: datetime,
        entities: List[CorrelatedEntity],
    ) -> str:
        """Synthesize concise description of findings and chronological progression."""
        duration = (last_seen - first_seen).total_seconds()
        rule_names = [f"{d.rule_id} ({d.rule_name})" for d in detections]
        
        ent_summary = ", ".join([f"{e.entity_type}={e.entity_value} ({e.relationship})" for e in entities[:4]])
        return (
            f"Correlated incident comprising {len(detections)} detection(s) across a {duration:.0f}s span "
            f"({first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} to {last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}). "
            f"Rules triggered: {', '.join(rule_names)}. Key entities: {ent_summary}."
        )

