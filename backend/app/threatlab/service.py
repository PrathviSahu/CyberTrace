"""
CyberTrace ThreatLab Benchmark Service.
Executes isolated scenario replays against detection rules and computes empirical confusion matrices.
"""

from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Tuple
from app.rules.rule_engine import DetectionEngine
from app.schemas.ces import CommonEvent, EventAction, EventCategory, EventSeverity
from app.threatlab.models import (
    ConfusionMatrix,
    ReplayDetectionResult,
    ScenarioReplayResponse,
    ScenarioSummary,
)


class ThreatLabService:
    def __init__(self):
        self.rule_engine = DetectionEngine()

    def get_scenarios(self) -> List[ScenarioSummary]:
        return [
            ScenarioSummary(
                scenario_id="SCN-001",
                name="Multi-Stage Credential Stuffing & Exfiltration",
                description="Rapid authentication burst against svc_deploy followed by logon success, sudo elevation, and 150 MB egress.",
                event_count=9,
                expected_detection_count=4,
                category="multi_stage_attack",
                mitre_techniques=["T1110.001", "T1078.002", "T1548.003", "T1041"],
            ),
            ScenarioSummary(
                scenario_id="SCN-002",
                name="Targeted Sudo Privilege Escalation",
                description="Operator session executes unauthorized token elevation outside maintenance window.",
                event_count=3,
                expected_detection_count=1,
                category="privilege_escalation",
                mitre_techniques=["T1548.003"],
            ),
            ScenarioSummary(
                scenario_id="SCN-003",
                name="Shared-Host Multi-User Isolation",
                description="Independent user accounts active on a shared server, verifying no hub-node correlation pollution.",
                event_count=8,
                expected_detection_count=1,
                category="correlation_safeguards",
                mitre_techniques=["T1110.001"],
            ),
            ScenarioSummary(
                scenario_id="SCN-004",
                name="Benign Administrative Baseline",
                description="Routine enterprise administrative traffic, scheduled cron backups, and authorized internal logons.",
                event_count=20,
                expected_detection_count=0,
                category="benign_baseline",
                mitre_techniques=[],
            ),
        ]

    def _generate_scenario_events(self, scenario_id: str) -> Tuple[List[CommonEvent], List[str]]:
        events: List[CommonEvent] = []
        expected_rules: List[str] = []

        if scenario_id == "SCN-001":
            expected_rules = ["DET-001", "DET-002", "DET-003", "DET-004"]
            # 6 failed logons (triggers DET-001)
            for i in range(6):
                events.append(
                    CommonEvent(
                        event_id=f"scn1_evt_{i+1:03d}",
                        timestamp=datetime(2026, 11, 1, 8, i, 0, tzinfo=timezone.utc),
                        source_format="linux_auth_log",
                        category=EventCategory.AUTHENTICATION,
                        action=EventAction.LOGON_FAILURE,
                        severity=EventSeverity.MEDIUM,
                        user_identity="svc_deploy",
                        source_ip="198.51.100.44",
                        hostname="SRV-APP-01",
                    )
                )
            # Logon success (triggers DET-002)
            events.append(
                CommonEvent(
                    event_id="scn1_evt_007",
                    timestamp=datetime(2026, 11, 1, 8, 7, 0, tzinfo=timezone.utc),
                    source_format="linux_auth_log",
                    category=EventCategory.AUTHENTICATION,
                    action=EventAction.LOGON_SUCCESS,
                    severity=EventSeverity.LOW,
                    user_identity="svc_deploy",
                    source_ip="198.51.100.44",
                    hostname="SRV-APP-01",
                )
            )
            # Privilege escalation (triggers DET-003)
            events.append(
                CommonEvent(
                    event_id="scn1_evt_008",
                    timestamp=datetime(2026, 11, 1, 8, 8, 0, tzinfo=timezone.utc),
                    source_format="linux_auth_log",
                    category=EventCategory.PRIVILEGE_CHANGE,
                    action=EventAction.ELEVATION_SUCCESS,
                    severity=EventSeverity.HIGH,
                    user_identity="svc_deploy",
                    hostname="SRV-APP-01",
                    process_command_line="sudo -i",
                )
            )
            # Exfiltration (triggers DET-004)
            events.append(
                CommonEvent(
                    event_id="scn1_evt_009",
                    timestamp=datetime(2026, 11, 1, 8, 9, 0, tzinfo=timezone.utc),
                    source_format="zeek_conn_log",
                    category=EventCategory.NETWORK_CONNECTION,
                    action=EventAction.NETWORK_CONNECT,
                    severity=EventSeverity.CRITICAL,
                    user_identity="svc_deploy",
                    hostname="SRV-APP-01",
                    source_ip="192.168.1.50",
                    destination_ip="203.0.113.88",
                    destination_port=443,
                    bytes_sent=150000000,
                )
            )

        elif scenario_id == "SCN-002":
            expected_rules = ["DET-003"]
            events.append(
                CommonEvent(
                    event_id="scn2_evt_001",
                    timestamp=datetime(2026, 11, 1, 9, 0, 0, tzinfo=timezone.utc),
                    source_format="linux_auth_log",
                    category=EventCategory.AUTHENTICATION,
                    action=EventAction.LOGON_SUCCESS,
                    severity=EventSeverity.LOW,
                    user_identity="op_user",
                    hostname="SRV-APP-01",
                )
            )
            events.append(
                CommonEvent(
                    event_id="scn2_evt_002",
                    timestamp=datetime(2026, 11, 1, 9, 1, 0, tzinfo=timezone.utc),
                    source_format="linux_auth_log",
                    category=EventCategory.PRIVILEGE_CHANGE,
                    action=EventAction.ELEVATION_SUCCESS,
                    severity=EventSeverity.HIGH,
                    user_identity="op_user",
                    hostname="SRV-APP-01",
                    process_command_line="sudo /bin/bash",
                )
            )
            events.append(
                CommonEvent(
                    event_id="scn2_evt_003",
                    timestamp=datetime(2026, 11, 1, 9, 2, 0, tzinfo=timezone.utc),
                    source_format="linux_auth_log",
                    category=EventCategory.PROCESS_EXECUTION,
                    action=EventAction.PROCESS_START,
                    severity=EventSeverity.LOW,
                    user_identity="root",
                    hostname="SRV-APP-01",
                )
            )

        elif scenario_id == "SCN-003":
            expected_rules = ["DET-001"]
            for i in range(5):
                events.append(
                    CommonEvent(
                        event_id=f"scn3_evt_a_{i+1}",
                        timestamp=datetime(2026, 11, 1, 10, i, 0, tzinfo=timezone.utc),
                        source_format="linux_auth_log",
                        category=EventCategory.AUTHENTICATION,
                        action=EventAction.LOGON_FAILURE,
                        severity=EventSeverity.MEDIUM,
                        user_identity="alice",
                        source_ip="198.51.100.11",
                        hostname="SRV-SHARED-01",
                    )
                )
            for i in range(3):
                events.append(
                    CommonEvent(
                        event_id=f"scn3_evt_b_{i+1}",
                        timestamp=datetime(2026, 11, 1, 10, i + 1, 30, tzinfo=timezone.utc),
                        source_format="linux_auth_log",
                        category=EventCategory.AUTHENTICATION,
                        action=EventAction.LOGON_SUCCESS,
                        severity=EventSeverity.LOW,
                        user_identity="bob",
                        source_ip="10.0.1.5",
                        hostname="SRV-SHARED-01",
                    )
                )

        else:  # SCN-004 Benign baseline
            expected_rules = []
            for i in range(20):
                events.append(
                    CommonEvent(
                        event_id=f"scn4_evt_{i+1:03d}",
                        timestamp=datetime(2026, 11, 1, 11, i, 0, tzinfo=timezone.utc),
                        source_format="linux_auth_log",
                        category=EventCategory.AUTHENTICATION,
                        action=EventAction.LOGON_SUCCESS,
                        severity=EventSeverity.LOW,
                        user_identity=f"user_{i%3}",
                        source_ip=f"10.0.1.{10+i}",
                        hostname="SRV-PROD-01",
                        bytes_sent=1024,
                    )
                )

        return events, expected_rules

    def replay_scenario(self, scenario_id: str) -> ScenarioReplayResponse:
        start_time = time.perf_counter()

        scenarios = {s.scenario_id: s for s in self.get_scenarios()}
        scenario_meta = scenarios.get(scenario_id)
        if not scenario_meta:
            raise ValueError(f"Scenario '{scenario_id}' not found in ThreatLab catalog")

        events, expected_rule_ids = self._generate_scenario_events(scenario_id)

        detections = self.rule_engine.evaluate_all(events)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        fired_rule_ids = {d.rule_id for d in detections}
        expected_set = set(expected_rule_ids)

        tp = len(fired_rule_ids.intersection(expected_set))
        fp = len(fired_rule_ids - expected_set)
        fn = len(expected_set - fired_rule_ids)
        tn = max(0, len(events) - len(detections))

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
        f1_score = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

        cm = ConfusionMatrix(
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
        )

        detection_results = [
            ReplayDetectionResult(
                rule_id=d.rule_id,
                rule_name=d.rule_name,
                severity=d.severity.value if hasattr(d.severity, "value") else str(d.severity),
                entity_value=d.entity_key,
                detected_at=d.detection_timestamp.isoformat(),
                explanation=d.summary,
                triggering_event_ids=d.triggering_event_ids,
            )
            for d in detections
        ]

        notes = [
            f"Evaluated {len(events)} events against {len(self.rule_engine.rules)} declarative rules.",
            f"F1-Score: {cm.f1_score} (Precision: {cm.precision * 100}%, Recall: {cm.recall * 100}%).",
            "In-memory execution completed with zero production database mutations.",
        ]

        return ScenarioReplayResponse(
            scenario_id=scenario_id,
            scenario_name=scenario_meta.name,
            events_processed=len(events),
            detections_fired_count=len(detections),
            detections=detection_results,
            confusion_matrix=cm,
            duration_ms=duration_ms,
            status="success",
            evaluation_notes=notes,
        )
