"""
JSON and JSONL log parser for CyberTrace.
Handles structured JSON arrays and line-delimited JSON log streams.
"""

import json
from typing import Any, Dict, List
from app.parsers.base import BaseLogParser
from app.schemas.ces import (
    CommonEvent,
    EventAction,
    EventCategory,
    EventSeverity,
    generate_event_id,
)


class GenericJsonParser(BaseLogParser):
    @property
    def format_name(self) -> str:
        return "generic_json"

    def can_parse(self, sample_text: str) -> bool:
        sample_stripped = sample_text.strip()
        if sample_stripped.startswith("[") or sample_stripped.startswith("{"):
            return True
        return False

    def parse(self, text_content: str) -> List[CommonEvent]:
        events: List[CommonEvent] = []
        stripped = text_content.strip()
        if not stripped:
            return events

        # Try parsing as JSON Array or single JSON object
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                raw_items = parsed
            elif isinstance(parsed, dict):
                raw_items = [parsed]
            else:
                raw_items = []
        except json.JSONDecodeError:
            # Fall back to line-by-line JSONL
            raw_items = []
            for line in stripped.splitlines():
                line = line.strip()
                if line:
                    try:
                        raw_items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for idx, item in enumerate(raw_items):
            if not isinstance(item, dict):
                continue
            event = self._normalize_dict(item, idx)
            if event:
                events.append(event)

        return events

    def _normalize_dict(self, d: Dict[str, Any], idx: int) -> CommonEvent:
        # Check if already has CES fields
        event_id = str(d.get("event_id") or d.get("id") or generate_event_id("evt", f"json_{idx}_{d}"))
        timestamp = d.get("timestamp") or d.get("@timestamp") or d.get("time") or d.get("datetime")
        
        # Category resolution
        raw_cat = str(d.get("category", "")).lower()
        category = EventCategory.SYSTEM_LOG
        for cat in EventCategory:
            if cat.value in raw_cat:
                category = cat
                break
        
        # Action resolution
        raw_act = str(d.get("action", "")).lower()
        action = EventAction.UNKNOWN
        for act in EventAction:
            if act.value in raw_act:
                action = act
                break
        
        # Heuristics if action/category were not explicitly mapped
        if action == EventAction.UNKNOWN:
            if "failed" in raw_act or "failure" in raw_act:
                action = EventAction.LOGON_FAILURE
                category = EventCategory.AUTHENTICATION
            elif "success" in raw_act or "logon" in raw_act:
                action = EventAction.LOGON_SUCCESS
                category = EventCategory.AUTHENTICATION
            elif "sudo" in raw_act or "escalat" in raw_act:
                action = EventAction.ELEVATION_SUCCESS
                category = EventCategory.PRIVILEGE_CHANGE
            elif "connect" in raw_act or "network" in raw_act:
                action = EventAction.NETWORK_CONNECT
                category = EventCategory.NETWORK_CONNECTION

        # Severity resolution
        raw_sev = str(d.get("severity", "informational")).lower()
        severity = EventSeverity.INFORMATIONAL
        for sev in EventSeverity:
            if sev.value == raw_sev:
                severity = sev
                break

        return CommonEvent(
            event_id=event_id,
            timestamp=timestamp,
            category=category,
            action=action,
            severity=severity,
            user_identity=d.get("user_identity") or d.get("user") or d.get("username"),
            source_ip=d.get("source_ip") or d.get("src_ip") or d.get("client_ip"),
            destination_ip=d.get("destination_ip") or d.get("dst_ip") or d.get("dest_ip"),
            source_port=d.get("source_port") or d.get("src_port"),
            destination_port=d.get("destination_port") or d.get("dst_port"),
            hostname=d.get("hostname") or d.get("host") or d.get("machine"),
            process_name=d.get("process_name") or d.get("process") or d.get("app"),
            process_command_line=d.get("process_command_line") or d.get("cmdline") or d.get("command"),
            parent_process_name=d.get("parent_process_name") or d.get("parent_process"),
            bytes_sent=int(d.get("bytes_sent") or d.get("bytes_out") or 0),
            bytes_received=int(d.get("bytes_received") or d.get("bytes_in") or 0),
            protocol=d.get("protocol") or d.get("proto"),
            source_format="json",
            raw_payload=d
        )
