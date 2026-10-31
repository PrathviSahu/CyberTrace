"""
Linux Syslog / Auth Log Parser for CyberTrace.
Handles standard SSH and sudo log lines:
- Failed password for invalid user root from 198.51.100.44 port 43210 ssh2
- Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2
- sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash
"""

import re
from datetime import datetime, timezone
from typing import List
from app.parsers.base import BaseLogParser
from app.schemas.ces import (
    CommonEvent,
    EventAction,
    EventCategory,
    EventSeverity,
    generate_event_id,
)


class LinuxAuthParser(BaseLogParser):
    @property
    def format_name(self) -> str:
        return "linux_auth_log"

    def can_parse(self, sample_text: str) -> bool:
        sample_stripped = sample_text.strip()
        if sample_stripped.startswith("[") or sample_stripped.startswith("{"):
            return False
        sample_lower = sample_text.lower()
        if "sshd[" in sample_lower or "sudo:" in sample_lower or "failed password" in sample_lower:
            return True
        return False

    def parse(self, text_content: str) -> List[CommonEvent]:
        events: List[CommonEvent] = []
        lines = text_content.strip().splitlines()

        for idx, line in enumerate(lines):
            line_str = line.strip()
            if not line_str:
                continue

            evt = self._parse_line(line_str, idx)
            if evt:
                events.append(evt)

        return events

    def _parse_line(self, line: str, idx: int) -> CommonEvent:
        # Timestamp parsing
        # Try ISO timestamp first or standard syslog format (e.g. "Nov 01 08:01:00")
        iso_match = re.search(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)", line)
        if iso_match:
            timestamp = iso_match.group(1)
        else:
            # Fallback to current year syslog date
            syslog_date_match = re.search(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
            if syslog_date_match:
                year = datetime.now(timezone.utc).year
                timestamp = f"{year} {syslog_date_match.group(1)}"
            else:
                timestamp = datetime.now(timezone.utc).isoformat()

        # Hostname extraction
        host_match = re.search(r"^\S+\s+\S+\s+(\S+)\s+(?:sshd|sudo)", line)
        hostname = host_match.group(1) if host_match else None

        # SSH Failed Logon
        if "Failed password" in line or "invalid user" in line:
            user_match = re.search(r"(?:for invalid user|for)\s+([a-zA-Z0-9_\-\.]+)", line)
            user = user_match.group(1) if user_match else "unknown"

            ip_match = re.search(r"from\s+([0-9\.]+)", line)
            src_ip = ip_match.group(1) if ip_match else None

            port_match = re.search(r"port\s+(\d+)", line)
            port = int(port_match.group(1)) if port_match else None

            return CommonEvent(
                event_id=f"lin_ssh_fail_{idx}_{generate_event_id()}",
                timestamp=timestamp,
                category=EventCategory.AUTHENTICATION,
                action=EventAction.LOGON_FAILURE,
                severity=EventSeverity.MEDIUM,
                user_identity=user,
                source_ip=src_ip,
                source_port=port,
                hostname=hostname,
                process_name="sshd",
                source_format="linux_auth_log",
                raw_payload={"line": line}
            )

        # SSH Successful Logon
        if "Accepted password" in line or "Accepted publickey" in line:
            user_match = re.search(r"(?:for)\s+([a-zA-Z0-9_\-\.]+)", line)
            user = user_match.group(1) if user_match else "unknown"

            ip_match = re.search(r"from\s+([0-9\.]+)", line)
            src_ip = ip_match.group(1) if ip_match else None

            port_match = re.search(r"port\s+(\d+)", line)
            port = int(port_match.group(1)) if port_match else None

            return CommonEvent(
                event_id=f"lin_ssh_succ_{idx}_{generate_event_id()}",
                timestamp=timestamp,
                category=EventCategory.AUTHENTICATION,
                action=EventAction.LOGON_SUCCESS,
                severity=EventSeverity.LOW,
                user_identity=user,
                source_ip=src_ip,
                source_port=port,
                hostname=hostname,
                process_name="sshd",
                source_format="linux_auth_log",
                raw_payload={"line": line}
            )

        # Sudo Privilege Escalation
        if "sudo:" in line and "COMMAND=" in line:
            user_match = re.search(r"sudo:\s+([a-zA-Z0-9_\-\.]+)\s*:", line)
            user = user_match.group(1) if user_match else "unknown"

            cmd_match = re.search(r"COMMAND=(.*)$", line)
            cmd = cmd_match.group(1) if cmd_match else None

            return CommonEvent(
                event_id=f"lin_sudo_{idx}_{generate_event_id()}",
                timestamp=timestamp,
                category=EventCategory.PRIVILEGE_CHANGE,
                action=EventAction.ELEVATION_SUCCESS,
                severity=EventSeverity.HIGH,
                user_identity=user,
                hostname=hostname,
                process_name="sudo",
                process_command_line=cmd,
                source_format="linux_auth_log",
                raw_payload={"line": line}
            )

        # Generic Linux Log fallback
        return CommonEvent(
            event_id=f"lin_generic_{idx}_{generate_event_id()}",
            timestamp=timestamp,
            category=EventCategory.SYSTEM_LOG,
            action=EventAction.UNKNOWN,
            severity=EventSeverity.INFORMATIONAL,
            hostname=hostname,
            source_format="linux_auth_log",
            raw_payload={"line": line}
        )
