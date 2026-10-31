"""
Zeek conn.log / NetFlow Log Parser for CyberTrace.
Handles network flow records, tracking source/destination IP pairs, ports, and egress byte volumes.
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


class ZeekConnParser(BaseLogParser):
    @property
    def format_name(self) -> str:
        return "zeek_conn_log"

    def can_parse(self, sample_text: str) -> bool:
        sample_lower = sample_text.lower()
        if "id.orig_h" in sample_lower or "#fields\tts\tuid\tid.orig_h" in sample_lower or ("orig_bytes" in sample_lower and "resp_bytes" in sample_lower):
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
                    events.append(self._parse_dict(item, idx))
            return events
        except json.JSONDecodeError:
            pass

        # Parse TSV / lines
        lines = stripped.splitlines()
        fields: List[str] = []
        for idx, line in enumerate(lines):
            line_str = line.strip()
            if not line_str or line_str.startswith("#close"):
                continue
            if line_str.startswith("#fields"):
                fields = line_str.split("\t")[1:]
                continue
            if line_str.startswith("#"):
                continue

            parts = line_str.split("\t")
            if fields and len(parts) == len(fields):
                d = dict(zip(fields, parts))
                events.append(self._parse_dict(d, idx))
            elif len(parts) >= 6:
                # Fallback positional TSV
                d = {
                    "ts": parts[0],
                    "id.orig_h": parts[2] if len(parts) > 2 else None,
                    "id.orig_p": parts[3] if len(parts) > 3 else None,
                    "id.resp_h": parts[4] if len(parts) > 4 else None,
                    "id.resp_p": parts[5] if len(parts) > 5 else None,
                    "proto": parts[6] if len(parts) > 6 else "tcp",
                    "orig_bytes": parts[9] if len(parts) > 9 else "0",
                    "resp_bytes": parts[10] if len(parts) > 10 else "0",
                }
                events.append(self._parse_dict(d, idx))

        return events

    def _parse_dict(self, d: Dict[str, Any], idx: int) -> CommonEvent:
        ts = d.get("ts") or d.get("timestamp") or "2026-11-01T00:00:00Z"
        src_ip = d.get("id.orig_h") or d.get("orig_h") or d.get("source_ip")
        src_p = d.get("id.orig_p") or d.get("orig_p") or d.get("source_port")
        dst_ip = d.get("id.resp_h") or d.get("resp_h") or d.get("destination_ip")
        dst_p = d.get("id.resp_p") or d.get("resp_p") or d.get("destination_port")
        proto = d.get("proto") or d.get("protocol")

        def _to_int(val: Any) -> int:
            try:
                if val in (None, "-", "", "null"):
                    return 0
                return int(val)
            except ValueError:
                return 0

        orig_b = _to_int(d.get("orig_bytes") or d.get("bytes_sent") or d.get("bytes_out"))
        resp_b = _to_int(d.get("resp_bytes") or d.get("bytes_received") or d.get("bytes_in"))

        severity = EventSeverity.INFORMATIONAL
        # If massive egress (>50MB), elevate to high
        if orig_b >= 50 * 1024 * 1024:
            severity = EventSeverity.HIGH

        return CommonEvent(
            event_id=f"zeek_conn_{idx}_{generate_event_id()}",
            timestamp=ts,
            category=EventCategory.NETWORK_CONNECTION,
            action=EventAction.NETWORK_CONNECT,
            severity=severity,
            source_ip=str(src_ip) if src_ip else None,
            source_port=_to_int(src_p) or None,
            destination_ip=str(dst_ip) if dst_ip else None,
            destination_port=_to_int(dst_p) or None,
            protocol=str(proto).upper() if proto else "TCP",
            bytes_sent=orig_b,
            bytes_received=resp_b,
            source_format="zeek_conn_log",
            raw_payload=d
        )
