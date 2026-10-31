"""
CSV Log Parser for CyberTrace.
Handles dynamic column name detection and normalizes rows into CommonEvent instances.
"""

import csv
import io
from typing import Any, Dict, List, Optional
from app.parsers.base import BaseLogParser
from app.schemas.ces import (
    CommonEvent,
    EventAction,
    EventCategory,
    EventSeverity,
    generate_event_id,
)


class GenericCsvParser(BaseLogParser):
    @property
    def format_name(self) -> str:
        return "generic_csv"

    def can_parse(self, sample_text: str) -> bool:
        sample_stripped = sample_text.strip()
        lines = sample_stripped.splitlines()
        if len(lines) >= 2 and "," in lines[0]:
            return True
        return False

    def parse(self, text_content: str) -> List[CommonEvent]:
        events: List[CommonEvent] = []
        stripped = text_content.strip()
        if not stripped:
            return events

        reader = csv.DictReader(io.StringIO(stripped))
        if not reader.fieldnames:
            return events

        # Map lowercase header names to canonical field positions
        field_map = self._detect_field_mappings(reader.fieldnames)

        for idx, row in enumerate(reader):
            event = self._normalize_row(row, field_map, idx)
            if event:
                events.append(event)

        return events

    def _detect_field_mappings(self, headers: List[str]) -> Dict[str, str]:
        canonical = {}
        for h in headers:
            clean = h.strip().lower().replace(" ", "_").replace("-", "_")
            if clean in ("timestamp", "time", "date_time", "@timestamp", "datetime"):
                canonical["timestamp"] = h
            elif clean in ("user", "username", "user_identity", "account", "target_user"):
                canonical["user_identity"] = h
            elif clean in ("src_ip", "source_ip", "client_ip", "ip_address", "src"):
                canonical["source_ip"] = h
            elif clean in ("dst_ip", "destination_ip", "dest_ip", "server_ip", "dst"):
                canonical["destination_ip"] = h
            elif clean in ("src_port", "source_port"):
                canonical["source_port"] = h
            elif clean in ("dst_port", "destination_port", "port"):
                canonical["destination_port"] = h
            elif clean in ("host", "hostname", "workstation", "computer_name"):
                canonical["hostname"] = h
            elif clean in ("category", "event_type"):
                canonical["category"] = h
            elif clean in ("action", "event_action", "status", "result"):
                canonical["action"] = h
            elif clean in ("severity", "level", "priority"):
                canonical["severity"] = h
            elif clean in ("process", "process_name", "app", "image"):
                canonical["process_name"] = h
            elif clean in ("command", "cmd", "command_line", "process_command_line"):
                canonical["process_command_line"] = h
            elif clean in ("bytes_sent", "bytes_out", "orig_bytes", "out_bytes"):
                canonical["bytes_sent"] = h
            elif clean in ("bytes_received", "bytes_in", "resp_bytes", "in_bytes"):
                canonical["bytes_received"] = h
            elif clean in ("protocol", "proto"):
                canonical["protocol"] = h
            elif clean in ("event_id", "id"):
                canonical["event_id"] = h
        return canonical

    def _normalize_row(self, row: Dict[str, Any], field_map: Dict[str, str], idx: int) -> Optional[CommonEvent]:
        # Extract timestamp
        ts_key = field_map.get("timestamp")
        raw_ts = row.get(ts_key) if ts_key else None
        if not raw_ts:
            return None

        # ID
        id_key = field_map.get("event_id")
        event_id = str(row.get(id_key)) if id_key and row.get(id_key) else generate_event_id("evt_csv", f"{idx}_{raw_ts}")

        # Action & Category
        act_key = field_map.get("action")
        raw_act = str(row.get(act_key, "")).lower() if act_key else ""
        
        cat_key = field_map.get("category")
        raw_cat = str(row.get(cat_key, "")).lower() if cat_key else ""

        category = EventCategory.SYSTEM_LOG
        action = EventAction.UNKNOWN

        # Match category
        for cat in EventCategory:
            if cat.value in raw_cat:
                category = cat
                break

        # Match action
        for act in EventAction:
            if act.value in raw_act:
                action = act
                break

        # Action heuristics if unknown
        if action == EventAction.UNKNOWN:
            if "fail" in raw_act:
                action = EventAction.LOGON_FAILURE
                category = EventCategory.AUTHENTICATION
            elif "success" in raw_act or "logon" in raw_act or "login" in raw_act:
                action = EventAction.LOGON_SUCCESS
                category = EventCategory.AUTHENTICATION
            elif "sudo" in raw_act or "elevat" in raw_act or "admin" in raw_act:
                action = EventAction.ELEVATION_SUCCESS
                category = EventCategory.PRIVILEGE_CHANGE
            elif "connect" in raw_act or "outbound" in raw_act:
                action = EventAction.NETWORK_CONNECT
                category = EventCategory.NETWORK_CONNECTION

        # Severity
        sev_key = field_map.get("severity")
        raw_sev = str(row.get(sev_key, "informational")).lower() if sev_key else "informational"
        severity = EventSeverity.INFORMATIONAL
        for sev in EventSeverity:
            if sev.value == raw_sev:
                severity = sev
                break

        def _get_val(k: str) -> Optional[Any]:
            mapped = field_map.get(k)
            return row.get(mapped) if mapped else None

        def _get_int(k: str) -> int:
            val = _get_val(k)
            try:
                return int(val) if val is not None and str(val).strip() != "" else 0
            except ValueError:
                return 0

        return CommonEvent(
            event_id=event_id,
            timestamp=raw_ts,
            category=category,
            action=action,
            severity=severity,
            user_identity=_get_val("user_identity"),
            source_ip=_get_val("source_ip"),
            destination_ip=_get_val("destination_ip"),
            source_port=_get_int("source_port") or None,
            destination_port=_get_int("destination_port") or None,
            hostname=_get_val("hostname"),
            process_name=_get_val("process_name"),
            process_command_line=_get_val("process_command_line"),
            bytes_sent=_get_int("bytes_sent"),
            bytes_received=_get_int("bytes_received"),
            protocol=_get_val("protocol"),
            source_format="csv",
            raw_payload=row,
        )
