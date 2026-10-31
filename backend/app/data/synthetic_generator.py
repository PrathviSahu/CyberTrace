"""
Synthetic Enterprise Security Log Dataset Generator.
Generates reproducible, ground-truth-labeled attack scenarios and benign background activity.
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List


def generate_enterprise_datasets(output_dir: Path) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Multi-Stage Attack Events
    attack_events: List[Dict[str, Any]] = [
        # Stage 1: Repeated Failed Logins (Brute Force)
        {
            "event_id": "evt_atk_001",
            "timestamp": "2026-11-01T08:01:05Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "svc_deploy",
            "source_ip": "198.51.100.44",
            "source_port": 41201,
            "destination_ip": "192.168.1.105",
            "destination_port": 22,
            "hostname": "SRV-APP-01",
            "process_name": "sshd",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "Failed password for svc_deploy from 198.51.100.44 port 41201 ssh2"}
        },
        {
            "event_id": "evt_atk_002",
            "timestamp": "2026-11-01T08:01:32Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "svc_deploy",
            "source_ip": "198.51.100.44",
            "source_port": 41204,
            "destination_ip": "192.168.1.105",
            "destination_port": 22,
            "hostname": "SRV-APP-01",
            "process_name": "sshd",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "Failed password for svc_deploy from 198.51.100.44 port 41204 ssh2"}
        },
        {
            "event_id": "evt_atk_003",
            "timestamp": "2026-11-01T08:01:58Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "svc_deploy",
            "source_ip": "198.51.100.44",
            "source_port": 41209,
            "destination_ip": "192.168.1.105",
            "destination_port": 22,
            "hostname": "SRV-APP-01",
            "process_name": "sshd",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "Failed password for svc_deploy from 198.51.100.44 port 41209 ssh2"}
        },
        {
            "event_id": "evt_atk_004",
            "timestamp": "2026-11-01T08:02:25Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "svc_deploy",
            "source_ip": "198.51.100.44",
            "source_port": 41215,
            "destination_ip": "192.168.1.105",
            "destination_port": 22,
            "hostname": "SRV-APP-01",
            "process_name": "sshd",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "Failed password for svc_deploy from 198.51.100.44 port 41215 ssh2"}
        },
        {
            "event_id": "evt_atk_005",
            "timestamp": "2026-11-01T08:02:51Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "svc_deploy",
            "source_ip": "198.51.100.44",
            "source_port": 41220,
            "destination_ip": "192.168.1.105",
            "destination_port": 22,
            "hostname": "SRV-APP-01",
            "process_name": "sshd",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "Failed password for svc_deploy from 198.51.100.44 port 41220 ssh2"}
        },
        {
            "event_id": "evt_atk_006",
            "timestamp": "2026-11-01T08:03:18Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "medium",
            "user_identity": "svc_deploy",
            "source_ip": "198.51.100.44",
            "source_port": 41225,
            "destination_ip": "192.168.1.105",
            "destination_port": 22,
            "hostname": "SRV-APP-01",
            "process_name": "sshd",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "Failed password for svc_deploy from 198.51.100.44 port 41225 ssh2"}
        },
        # Stage 2: Successful Authentication After Burst
        {
            "event_id": "evt_atk_007",
            "timestamp": "2026-11-01T08:05:40Z",
            "category": "authentication",
            "action": "logon_success",
            "severity": "low",
            "user_identity": "svc_deploy",
            "source_ip": "198.51.100.44",
            "source_port": 41230,
            "destination_ip": "192.168.1.105",
            "destination_port": 22,
            "hostname": "SRV-APP-01",
            "process_name": "sshd",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "Accepted password for svc_deploy from 198.51.100.44 port 41230 ssh2"}
        },
        # Stage 3: Privilege Escalation
        {
            "event_id": "evt_atk_008",
            "timestamp": "2026-11-01T08:08:12Z",
            "category": "privilege_change",
            "action": "elevation_success",
            "severity": "high",
            "user_identity": "svc_deploy",
            "source_ip": "192.168.1.105",
            "hostname": "SRV-APP-01",
            "process_name": "sudo",
            "process_command_line": "sudo /bin/bash",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "svc_deploy : TTY=pts/2 ; PWD=/home/svc_deploy ; USER=root ; COMMAND=/bin/bash"}
        },
        # Stage 4: Anomalous Outbound Network Activity (Exfiltration)
        {
            "event_id": "evt_atk_009",
            "timestamp": "2026-11-01T08:12:05Z",
            "category": "network_connection",
            "action": "network_connect",
            "severity": "high",
            "user_identity": "root",
            "source_ip": "192.168.1.105",
            "source_port": 49152,
            "destination_ip": "203.0.113.88",
            "destination_port": 443,
            "hostname": "SRV-APP-01",
            "protocol": "TCP",
            "bytes_sent": 65011712,  # ~62 MB (exceeds 50MB threshold)
            "bytes_received": 14200,
            "source_format": "zeek_conn_log",
            "raw_payload": {"orig_bytes": 65011712, "resp_bytes": 14200, "proto": "tcp"}
        }
    ]

    # 2. Benign Background Activity
    benign_events: List[Dict[str, Any]] = [
        # Routine Nightly Backup
        {
            "event_id": "evt_ben_001",
            "timestamp": "2026-11-01T02:00:00Z",
            "category": "authentication",
            "action": "logon_success",
            "severity": "informational",
            "user_identity": "backup_agent",
            "source_ip": "192.168.1.200",
            "source_port": 50110,
            "destination_ip": "192.168.1.250",
            "destination_port": 22,
            "hostname": "SRV-BACKUP",
            "process_name": "sshd",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "Accepted publickey for backup_agent"}
        },
        {
            "event_id": "evt_ben_002",
            "timestamp": "2026-11-01T02:00:15Z",
            "category": "process_execution",
            "action": "process_start",
            "severity": "informational",
            "user_identity": "backup_agent",
            "hostname": "SRV-BACKUP",
            "process_name": "rsync",
            "process_command_line": "/usr/bin/rsync -a /data /mnt/backup",
            "source_format": "linux_auth_log",
            "raw_payload": {"msg": "Process started /usr/bin/rsync"}
        },
        # Normal Developer Login (Alice)
        {
            "event_id": "evt_ben_003",
            "timestamp": "2026-11-01T08:30:10Z",
            "category": "authentication",
            "action": "logon_success",
            "severity": "informational",
            "user_identity": "alice",
            "source_ip": "192.168.2.14",
            "source_port": 51042,
            "destination_ip": "192.168.1.10",
            "destination_port": 443,
            "hostname": "WKSTN-ALICE",
            "source_format": "windows_event_log",
            "raw_payload": {"EventID": 4624, "TargetUserName": "alice"}
        },
        # Normal Developer Accidental Typo (Bob - 1 fail, then immediate success)
        {
            "event_id": "evt_ben_004",
            "timestamp": "2026-11-01T08:35:00Z",
            "category": "authentication",
            "action": "logon_failure",
            "severity": "informational",
            "user_identity": "bob",
            "source_ip": "192.168.2.18",
            "source_port": 51100,
            "destination_ip": "192.168.1.10",
            "destination_port": 443,
            "hostname": "WKSTN-BOB",
            "source_format": "windows_event_log",
            "raw_payload": {"EventID": 4625, "TargetUserName": "bob"}
        },
        {
            "event_id": "evt_ben_005",
            "timestamp": "2026-11-01T08:35:12Z",
            "category": "authentication",
            "action": "logon_success",
            "severity": "informational",
            "user_identity": "bob",
            "source_ip": "192.168.2.18",
            "source_port": 51102,
            "destination_ip": "192.168.1.10",
            "destination_port": 443,
            "hostname": "WKSTN-BOB",
            "source_format": "windows_event_log",
            "raw_payload": {"EventID": 4624, "TargetUserName": "bob"}
        },
        # Normal Web Traffic (under 2MB egress)
        {
            "event_id": "evt_ben_006",
            "timestamp": "2026-11-01T08:40:00Z",
            "category": "network_connection",
            "action": "network_connect",
            "severity": "informational",
            "user_identity": "alice",
            "source_ip": "192.168.2.14",
            "source_port": 52140,
            "destination_ip": "142.250.190.46",  # Google CDN
            "destination_port": 443,
            "hostname": "WKSTN-ALICE",
            "protocol": "TCP",
            "bytes_sent": 45000,
            "bytes_received": 520000,
            "source_format": "zeek_conn_log",
            "raw_payload": {"orig_bytes": 45000, "resp_bytes": 520000}
        }
    ]

    # Combine and sort chronologically
    combined_events = sorted(attack_events + benign_events, key=lambda x: x["timestamp"])

    # Write JSON files
    with open(output_dir / "multi_stage_attack.json", "w", encoding="utf-8") as f:
        json.dump(attack_events, f, indent=2)

    with open(output_dir / "benign_activity.json", "w", encoding="utf-8") as f:
        json.dump(benign_events, f, indent=2)

    with open(output_dir / "enterprise_combined_logs.json", "w", encoding="utf-8") as f:
        json.dump(combined_events, f, indent=2)

    # Write CSV version
    headers = [
        "event_id", "timestamp", "category", "action", "severity",
        "user_identity", "source_ip", "destination_ip", "source_port",
        "destination_port", "hostname", "process_name", "process_command_line",
        "bytes_sent", "bytes_received", "protocol", "source_format"
    ]
    with open(output_dir / "enterprise_combined_logs.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for ev in combined_events:
            row = {h: ev.get(h, "") for h in headers}
            writer.writerow(row)

    # Ground Truth Manifest for Verification
    ground_truth = {
        "dataset_name": "CyberTrace Enterprise Benchmark 1.0",
        "total_events": len(combined_events),
        "attack_events_count": len(attack_events),
        "benign_events_count": len(benign_events),
        "expected_detections": [
            {
                "rule_id": "DET-001",
                "entity_key": "user:svc_deploy",
                "expected_trigger_events": ["evt_atk_001", "evt_atk_002", "evt_atk_003", "evt_atk_004", "evt_atk_005", "evt_atk_006"],
                "phase": "Credential Access (Brute Force)"
            },
            {
                "rule_id": "DET-002",
                "entity_key": "user:svc_deploy",
                "expected_trigger_events": ["evt_atk_007"],
                "phase": "Initial Access / Compromise"
            },
            {
                "rule_id": "DET-003",
                "entity_key": "user:svc_deploy",
                "expected_trigger_events": ["evt_atk_008"],
                "phase": "Privilege Escalation (sudo)"
            },
            {
                "rule_id": "DET-004",
                "entity_key": "ip:203.0.113.88",
                "expected_trigger_events": ["evt_atk_009"],
                "phase": "Exfiltration"
            }
        ],
        "expected_benign_non_detections": [
            "evt_ben_001", "evt_ben_002", "evt_ben_003", "evt_ben_004", "evt_ben_005", "evt_ben_006"
        ]
    }

    with open(output_dir / "ground_truth.json", "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)

    return ground_truth


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "sample_logs"
    gt = generate_enterprise_datasets(out)
    print(f"Generated {gt['total_events']} events in {out}")
