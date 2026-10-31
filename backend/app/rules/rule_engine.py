"""
Deterministic Detection Engine and Rule Implementations for CyberTrace.
Provides mathematically reproducible, explainable detection passes over normalized security telemetry.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from app.core.config import settings
from app.rules.base import BaseDetectionRule, DetectionResult
from app.schemas.ces import CommonEvent, EventAction, EventCategory, EventSeverity


class RuleDET001_BruteForce(BaseDetectionRule):
    """
    DET-001: Repeated Failed Logins Burst
    Triggers when a threshold number of failed logon events occur for an entity
    within a sliding time window.
    """
    def __init__(self, failure_threshold: int = 5, window_seconds: int = 300):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "DET-001"

    @property
    def rule_name(self) -> str:
        return "Repeated Failed Logins Burst"

    @property
    def default_severity(self) -> EventSeverity:
        return EventSeverity.MEDIUM

    def evaluate(self, events: List[CommonEvent], prior_detections: List[DetectionResult]) -> List[DetectionResult]:
        detections: List[DetectionResult] = []
        
        # Group failed authentication events by entity: user and source_ip
        entity_failures: Dict[str, List[CommonEvent]] = defaultdict(list)
        for ev in events:
            if ev.action == EventAction.LOGON_FAILURE:
                if ev.user_identity:
                    entity_failures[f"user:{ev.user_identity.lower()}"].append(ev)
                if ev.source_ip:
                    entity_failures[f"ip:{ev.source_ip}"].append(ev)

        for entity_key, failure_list in entity_failures.items():
            failure_list.sort(key=lambda x: x.timestamp)
            n = len(failure_list)
            if n < self.failure_threshold:
                continue

            # Sliding window over failures
            i = 0
            triggered_windows = []
            while i < n:
                window_events = [failure_list[i]]
                start_time = failure_list[i].timestamp
                j = i + 1
                while j < n and (failure_list[j].timestamp - start_time).total_seconds() <= self.window_seconds:
                    window_events.append(failure_list[j])
                    j += 1

                if len(window_events) >= self.failure_threshold:
                    event_ids = [e.event_id for e in window_events]
                    last_event = window_events[-1]
                    summary = (
                        f"Observed {len(window_events)} failed login attempts for {entity_key} "
                        f"within {(last_event.timestamp - start_time).total_seconds():.0f}s "
                        f"(threshold: {self.failure_threshold} in {self.window_seconds}s). "
                        f"Pattern indicates automated password spray or brute force activity."
                    )
                    detections.append(DetectionResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.default_severity,
                        summary=summary,
                        detection_timestamp=last_event.timestamp,
                        entity_key=entity_key,
                        triggering_event_ids=event_ids,
                        metadata={
                            "failure_count": len(window_events),
                            "duration_seconds": (last_event.timestamp - start_time).total_seconds(),
                            "start_time": start_time.isoformat(),
                            "end_time": last_event.timestamp.isoformat(),
                        }
                    ))
                    i = j  # advance past this cluster to avoid duplicate overlapping triggers
                else:
                    i += 1

        return detections


class RuleDET002_CompromiseAfterBurst(BaseDetectionRule):
    """
    DET-002: Successful Authentication Following Failed Login Burst
    Triggers when a successful logon is observed for an entity shortly after
    a detected brute-force burst (DET-001).
    """
    def __init__(self, window_seconds: int = 900):
        self.window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "DET-002"

    @property
    def rule_name(self) -> str:
        return "Successful Logon Following Failed Login Burst"

    @property
    def default_severity(self) -> EventSeverity:
        return EventSeverity.HIGH

    def evaluate(self, events: List[CommonEvent], prior_detections: List[DetectionResult]) -> List[DetectionResult]:
        detections: List[DetectionResult] = []

        # Find all DET-001 bursts
        bursts = [d for d in prior_detections if d.rule_id == "DET-001"]
        if not bursts:
            return detections

        # Index successful logins by user and IP
        success_events: List[CommonEvent] = [
            e for e in events if e.action == EventAction.LOGON_SUCCESS
        ]

        for burst in bursts:
            burst_time = burst.detection_timestamp
            burst_key = burst.entity_key  # e.g., 'user:svc_deploy' or 'ip:198.51.100.44'
            kind, val = burst_key.split(":", 1)

            for succ in success_events:
                # Check if matches entity
                matches_entity = False
                if kind == "user" and succ.user_identity and succ.user_identity.lower() == val.lower():
                    matches_entity = True
                elif kind == "ip" and succ.source_ip and succ.source_ip == val:
                    matches_entity = True

                if matches_entity:
                    diff_sec = (succ.timestamp - burst_time).total_seconds()
                    if 0 <= diff_sec <= self.window_seconds:
                        trigger_ids = list(dict.fromkeys(burst.triggering_event_ids + [succ.event_id]))
                        summary = (
                            f"Successful authentication observed for {burst_key} at {succ.timestamp.isoformat()} "
                            f"following a failed login burst (window: {diff_sec:.0f}s). "
                            f"High potential for account takeover or credential compromise."
                        )
                        detections.append(DetectionResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=self.default_severity,
                            summary=summary,
                            detection_timestamp=succ.timestamp,
                            entity_key=burst_key,
                            triggering_event_ids=trigger_ids,
                            metadata={
                                "prior_burst_id": burst.detection_id,
                                "burst_timestamp": burst_time.isoformat(),
                                "logon_timestamp": succ.timestamp.isoformat(),
                                "time_delta_seconds": diff_sec,
                                "source_ip": succ.source_ip,
                                "hostname": succ.hostname,
                            }
                        ))
        return detections


class RuleDET003_PrivilegeEscalation(BaseDetectionRule):
    """
    DET-003: Suspicious Privilege Escalation
    Triggers when a privilege elevation event (sudo, admin rights, token assignment)
    is observed on a host or account that recently had suspicious authentication activity.
    """
    def __init__(self, window_seconds: int = 1800):
        self.window_seconds = window_seconds

    @property
    def rule_id(self) -> str:
        return "DET-003"

    @property
    def rule_name(self) -> str:
        return "Suspicious Privilege Escalation"

    @property
    def default_severity(self) -> EventSeverity:
        return EventSeverity.HIGH

    def evaluate(self, events: List[CommonEvent], prior_detections: List[DetectionResult]) -> List[DetectionResult]:
        detections: List[DetectionResult] = []

        # Find privilege escalation events
        elevation_events = [
            e for e in events 
            if e.category == EventCategory.PRIVILEGE_CHANGE or e.action == EventAction.ELEVATION_SUCCESS
        ]
        if not elevation_events:
            return detections

        # Check for prior DET-002 (compromised logins) or DET-001
        suspicious_auths = [d for d in prior_detections if d.rule_id in ("DET-002", "DET-001")]

        for elev in elevation_events:
            user = (elev.user_identity or "").lower()
            elev_time = elev.timestamp

            matched_prior = None
            for prior in suspicious_auths:
                kind, val = prior.entity_key.split(":", 1)
                if kind == "user" and val.lower() == user:
                    diff_sec = (elev_time - prior.detection_timestamp).total_seconds()
                    if 0 <= diff_sec <= self.window_seconds:
                        matched_prior = prior
                        break

            # If matched with suspicious prior detection
            if matched_prior:
                trigger_ids = list(dict.fromkeys(matched_prior.triggering_event_ids + [elev.event_id]))
                summary = (
                    f"Privilege elevation executed by user '{user}' at {elev_time.isoformat()} "
                    f"(command: {elev.process_command_line or elev.process_name or 'N/A'}) "
                    f"following suspicious authentication ({matched_prior.rule_id}). "
                    f"Suggests post-exploitation privilege escalation."
                )
                detections.append(DetectionResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.default_severity,
                    summary=summary,
                    detection_timestamp=elev_time,
                    entity_key=f"user:{user}",
                    triggering_event_ids=trigger_ids,
                    metadata={
                        "associated_rule": matched_prior.rule_id,
                        "command_line": elev.process_command_line,
                        "process_name": elev.process_name,
                        "hostname": elev.hostname,
                    }
                ))
            elif elev.process_command_line and any(crit in elev.process_command_line for crit in ("/bin/bash", "/bin/sh", "cmd.exe", "powershell")):
                # Standalone root shell spawn
                summary = (
                    f"Interactive shell spawned with elevated privileges by '{user}': "
                    f"{elev.process_command_line} at {elev_time.isoformat()}."
                )
                detections.append(DetectionResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=EventSeverity.MEDIUM,
                    summary=summary,
                    detection_timestamp=elev_time,
                    entity_key=f"user:{user}" if user else f"host:{elev.hostname}",
                    triggering_event_ids=[elev.event_id],
                    metadata={
                        "command_line": elev.process_command_line,
                        "process_name": elev.process_name,
                        "hostname": elev.hostname,
                    }
                ))

        return detections


class RuleDET004_AnomalousOutbound(BaseDetectionRule):
    """
    DET-004: Anomalous Outbound Network Activity (Exfiltration / C2)
    Triggers when outbound traffic exceeds volume threshold (default 50MB)
    or demonstrates suspicious external data transfer patterns.
    """
    def __init__(self, egress_threshold_bytes: int = 50 * 1024 * 1024):
        self.egress_threshold_bytes = egress_threshold_bytes

    @property
    def rule_id(self) -> str:
        return "DET-004"

    @property
    def rule_name(self) -> str:
        return "Anomalous Outbound Network Activity"

    @property
    def default_severity(self) -> EventSeverity:
        return EventSeverity.HIGH

    def evaluate(self, events: List[CommonEvent], prior_detections: List[DetectionResult]) -> List[DetectionResult]:
        detections: List[DetectionResult] = []

        # Find network events
        net_events = [
            e for e in events if e.category == EventCategory.NETWORK_CONNECTION or e.bytes_sent > 0
        ]

        # Aggregate by (source_ip, destination_ip)
        pair_bytes: Dict[tuple, int] = defaultdict(int)
        pair_events: Dict[tuple, List[CommonEvent]] = defaultdict(list)

        for ne in net_events:
            if ne.source_ip and ne.destination_ip:
                pair = (ne.source_ip, ne.destination_ip)
                pair_bytes[pair] += ne.bytes_sent
                pair_events[pair].append(ne)

        for (src_ip, dst_ip), total_bytes in pair_bytes.items():
            if total_bytes >= self.egress_threshold_bytes:
                ev_list = pair_events[(src_ip, dst_ip)]
                latest = max(ev_list, key=lambda x: x.timestamp)
                mb = total_bytes / (1024 * 1024)
                summary = (
                    f"Anomalous high-volume outbound network egress detected from {src_ip} to {dst_ip}: "
                    f"{mb:.2f} MB transmitted across {len(ev_list)} connection session(s) "
                    f"(threshold: {self.egress_threshold_bytes / (1024 * 1024):.0f} MB). "
                    f"Pattern is consistent with potential data staging or exfiltration."
                )
                detections.append(DetectionResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=EventSeverity.CRITICAL if mb >= 100 else EventSeverity.HIGH,
                    summary=summary,
                    detection_timestamp=latest.timestamp,
                    entity_key=f"ip:{dst_ip}",
                    triggering_event_ids=[e.event_id for e in ev_list],
                    metadata={
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "total_bytes_sent": total_bytes,
                        "megabytes": round(mb, 2),
                        "connection_count": len(ev_list),
                    }
                ))

        return detections


class DetectionEngine:
    """
    Coordinating rule engine that runs multi-pass deterministic detection rules
    over normalized event streams.
    """
    def __init__(self):
        self.rules: List[BaseDetectionRule] = [
            RuleDET001_BruteForce(
                failure_threshold=settings.BRUTE_FORCE_FAILURE_THRESHOLD,
                window_seconds=settings.BRUTE_FORCE_WINDOW_SECONDS
            ),
            RuleDET002_CompromiseAfterBurst(
                window_seconds=settings.COMPROMISE_WINDOW_SECONDS
            ),
            RuleDET003_PrivilegeEscalation(
                window_seconds=settings.PRIVILEGE_ESCALATION_WINDOW_SECONDS
            ),
            RuleDET004_AnomalousOutbound(
                egress_threshold_bytes=settings.OUTBOUND_EGRESS_THRESHOLD_BYTES
            ),
        ]

    def evaluate_all(self, events: List[CommonEvent]) -> List[DetectionResult]:
        """
        Run all detection rules sequentially, allowing higher-order correlation
        rules (DET-002, DET-003) to reference detections from foundational rules.
        """
        all_detections: List[DetectionResult] = []
        # Sort events by timestamp first to guarantee determinism
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        for rule in self.rules:
            new_dets = rule.evaluate(sorted_events, all_detections)
            all_detections.extend(new_dets)

        return all_detections
