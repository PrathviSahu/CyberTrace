"""
Windows Security Event Log Parser for CyberTrace.
Handles Windows Event Log schemas, including Event IDs:
- 4624: Successful Logon
- 4625: Failed Logon
- 4672: Special Privileges Assigned to New Logon
- 4688: A new process has been created
"""

import json
import re
from typing import Any, Dict, List
from app.parsers.base import BaseLogParser
from app.schemas.ces import (
    CommonEvent,
    EventAction,
    EventCategory,
    EventSeverity,
    generate_event_id,
)


class WindowsEventParser(BaseLogParser):
    @property
    def format_name(self) -> str:
        return "windows_event_log"

    def can_parse(self, sample_text: str) -> bool:
        sample_lower = sample_text.lower()
        if "eventid" in sample_lower or "event_id: 462" in sample_lower or "microsoft-windows-security-auditing" in sample_lower:
            return True
        return False

    def parse(self, text_content: str) -> List[CommonEvent]:
        events: List[CommonEvent] = []
        stripped = text_content.strip()
        if not stripped:
            return events

        # Try JSON first
        try:
            parsed = json.loads(stripped)
            raw_items = parsed if isinstance(parsed, list) else [parsed]
            for idx, item in enumerate(raw_items):
                if isinstance(item, dict):
                    evt = self._parse_json_event(item, idx)
                    if evt:
                        events.append(evt)
            return events
        except json.JSONDecodeError:
            pass

        # Parse text/syslog format of Windows Events
        lines = stripped.splitlines()
        for idx, line in enumerate(lines):
            line_str = line.strip()
            if not line_str:
                continue
            evt = self._parse_text_line(line_str, idx)
            if evt:
                events.append(evt)

        return events

    def _parse_json_event(self, d: Dict[str, Any], idx: int) -> CommonEvent:
        event_data = d.get("EventData", {}) if isinstance(d.get("EventData"), dict) else d
        system_data = d.get("System", {}) if isinstance(d.get("System"), dict) else {}

        raw_event_id = str(system_data.get("EventID") or d.get("EventID") or d.get("event_id") or "0")
        timestamp = (
            system_data.get("TimeCreated", {}).get("@SystemTime")
            if isinstance(system_data.get("TimeCreated"), dict)
            else (d.get("TimeCreated") or d.get("timestamp") or d.get("TimeGenerated"))
        )

        target_user = (
            event_data.get("TargetUserName")
            or event_data.get("SubjectUserName")
            or d.get("user")
            or d.get("user_identity")
        )
        src_ip = event_data.get("IpAddress") or d.get("IpAddress") or d.get("source_ip")
        src_port = event_data.get("IpPort") or d.get("source_port")
        workstation = (
            event_data.get("WorkstationName")
            or system_data.get("Computer")
            or d.get("ComputerName")
            or d.get("hostname")
        )
        process_name = event_data.get("NewProcessName") or event_data.get("ProcessName") or d.get("process_name")
        cmd_line = event_data.get("CommandLine") or d.get("CommandLine") or d.get("process_command_line")

        # Map by Windows EventID
        category = EventCategory.SYSTEM_LOG
        action = EventAction.UNKNOWN
        severity = EventSeverity.INFORMATIONAL

        if raw_event_id == "4624":
            category = EventCategory.AUTHENTICATION
            action = EventAction.LOGON_SUCCESS
            severity = EventSeverity.LOW
        elif raw_event_id == "4625":
            category = EventCategory.AUTHENTICATION
            action = EventAction.LOGON_FAILURE
            severity = EventSeverity.MEDIUM
        elif raw_event_id == "4672":
            category = EventCategory.PRIVILEGE_CHANGE
            action = EventAction.ELEVATION_SUCCESS
            severity = EventSeverity.HIGH
        elif raw_event_id == "4688":
            category = EventCategory.PROCESS_EXECUTION
            action = EventAction.PROCESS_START
            severity = EventSeverity.LOW

        port_int = None
        if src_port:
            try:
                port_int = int(src_port)
            except ValueError:
                port_int = None

        return CommonEvent(
            event_id=f"win_{raw_event_id}_{idx}_{generate_event_id()}",
            timestamp=timestamp,
            category=category,
            action=action,
            severity=severity,
            user_identity=target_user,
            source_ip=src_ip,
            source_port=port_int,
            hostname=workstation,
            process_name=process_name,
            process_command_line=cmd_line,
            source_format="windows_event_log",
            raw_payload=d
        )

    def _parse_text_line(self, line: str, idx: int) -> CommonEvent:
        # Regex extraction for common text Windows security events
        # Example: "2026-11-01 08:01:00 WIN-DC01 Microsoft-Windows-Security-Auditing: 4625 An account failed to log on. Account: svc_deploy, Source IP: 198.51.100.44"
        event_id_match = re.search(r"\b(4624|4625|4672|4688)\b", line)
        raw_event_id = event_id_match.group(1) if event_id_match else "4625"

        ts_match = re.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)", line)
        timestamp = ts_match.group(1) if ts_match else "2026-11-01T00:00:00Z"

        user_match = re.search(r"(?:Account|User|TargetUserName)[:=]\s*([a-zA-Z0-9_\-\.\$]+)", line, re.I)
        user = user_match.group(1) if user_match else None

        ip_match = re.search(r"(?:Source IP|IpAddress|Client IP)[:=]\s*([0-9\.]+)", line, re.I)
        src_ip = ip_match.group(1) if ip_match else None

        host_match = re.search(r"(?:Computer|Workstation|Host)[:=]\s*([a-zA-Z0-9_\-]+)", line, re.I)
        host = host_match.group(1) if host_match else None

        category = EventCategory.AUTHENTICATION
        action = EventAction.LOGON_FAILURE
        severity = EventSeverity.MEDIUM

        if raw_event_id == "4624":
            action = EventAction.LOGON_SUCCESS
            severity = EventSeverity.LOW
        elif raw_event_id == "4672":
            category = EventCategory.PRIVILEGE_CHANGE
            action = EventAction.ELEVATION_SUCCESS
            severity = EventSeverity.HIGH
        elif raw_event_id == "4688":
            category = EventCategory.PROCESS_EXECUTION
            action = EventAction.PROCESS_START
            severity = EventSeverity.LOW

        return CommonEvent(
            event_id=f"win_txt_{raw_event_id}_{idx}",
            timestamp=timestamp,
            category=category,
            action=action,
            severity=severity,
            user_identity=user,
            source_ip=src_ip,
            hostname=host,
            source_format="windows_event_log",
            raw_payload={"line": line}
        )
