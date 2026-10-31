"""
Unit and integration tests for CyberTrace Deterministic Detection Rules.
Verifies detection accuracy, reproducibility, and zero false positives against ground truth.
"""

import json
from pathlib import Path
from app.parsers.json_parser import GenericJsonParser
from app.rules.rule_engine import DetectionEngine
from app.schemas.ces import EventSeverity


SAMPLE_DIR = Path(__file__).resolve().parent.parent / "app" / "data" / "sample_logs"


def test_ground_truth_reproducibility():
    # Load combined logs
    with open(SAMPLE_DIR / "enterprise_combined_logs.json", "r", encoding="utf-8") as f:
        content = f.read()

    # Load ground truth
    with open(SAMPLE_DIR / "ground_truth.json", "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    parser = GenericJsonParser()
    events = parser.parse(content)
    assert len(events) == ground_truth["total_events"]

    engine = DetectionEngine()
    detections = engine.evaluate_all(events)

    # 1. Verify DET-001 (Brute Force)
    det_001 = [d for d in detections if d.rule_id == "DET-001"]
    assert len(det_001) >= 1
    # Check that svc_deploy is flagged
    assert any("svc_deploy" in d.entity_key for d in det_001)
    # Check triggering events include the failure events
    burst_det = next(d for d in det_001 if "svc_deploy" in d.entity_key)
    for expected_id in ["evt_atk_001", "evt_atk_002", "evt_atk_003", "evt_atk_004", "evt_atk_005", "evt_atk_006"]:
        assert expected_id in burst_det.triggering_event_ids

    # 2. Verify DET-002 (Compromise after burst)
    det_002 = [d for d in detections if d.rule_id == "DET-002"]
    assert len(det_002) >= 1
    assert any("svc_deploy" in d.entity_key for d in det_002)
    succ_det = next(d for d in det_002 if "svc_deploy" in d.entity_key)
    assert "evt_atk_007" in succ_det.triggering_event_ids

    # 3. Verify DET-003 (Privilege Escalation)
    det_003 = [d for d in detections if d.rule_id == "DET-003"]
    assert len(det_003) >= 1
    assert any("svc_deploy" in d.entity_key for d in det_003)
    priv_det = next(d for d in det_003 if "svc_deploy" in d.entity_key)
    assert "evt_atk_008" in priv_det.triggering_event_ids

    # 4. Verify DET-004 (Anomalous Outbound Exfiltration)
    det_004 = [d for d in detections if d.rule_id == "DET-004"]
    assert len(det_004) == 1
    assert "203.0.113.88" in det_004[0].entity_key
    assert "evt_atk_009" in det_004[0].triggering_event_ids
    assert det_004[0].metadata["total_bytes_sent"] > 50 * 1024 * 1024


def test_benign_noise_no_false_positives():
    """Verify that pure benign background logs trigger ZERO false alarms."""
    with open(SAMPLE_DIR / "benign_activity.json", "r", encoding="utf-8") as f:
        content = f.read()

    parser = GenericJsonParser()
    events = parser.parse(content)
    assert len(events) == 6

    engine = DetectionEngine()
    detections = engine.evaluate_all(events)

    # Bob's single password typo must NOT trigger DET-001 (threshold is 5)
    # Nightly backup rsync must NOT trigger DET-003 or DET-004
    # Normal web surfing must NOT trigger DET-004 (45KB is well below 50MB)
    assert len(detections) == 0, f"False positives triggered on benign noise: {[d.summary for d in detections]}"
