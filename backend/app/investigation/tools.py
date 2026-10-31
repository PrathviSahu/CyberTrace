"""
Backend Investigation Tools for CyberTrace.
Provides secure, read-only analytical tools for the BharatCode AI investigation agent.
Restricted exclusively to authorized incident evidence without raw payload leakage.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.repositories.incident_repo import IncidentRepository


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "name": "get_incident_timeline",
        "description": "Returns a chronological, deterministic timeline of events and detections belonging to this incident.",
        "parameters": {
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "The unique ID of the incident being investigated."
                }
            },
            "required": ["incident_id"]
        }
    },
    {
        "type": "function",
        "name": "get_event_details",
        "description": "Retrieves normalized, sanitized security event details for a list of event IDs belonging to the incident.",
        "parameters": {
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "The unique ID of the incident."
                },
                "event_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of specific event IDs to inspect (max 20)."
                }
            },
            "required": ["incident_id", "event_ids"]
        }
    },
    {
        "type": "function",
        "name": "get_detection_details",
        "description": "Retrieves rule explanations, severity, and supporting event references for specific detections.",
        "parameters": {
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "The unique ID of the incident."
                },
                "detection_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of detection IDs to inspect."
                }
            },
            "required": ["incident_id", "detection_ids"]
        }
    },
    {
        "type": "function",
        "name": "query_entity_history",
        "description": "Queries historical events involving a specific entity (user, host, or IP) within the incident scope.",
        "parameters": {
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "The unique ID of the incident."
                },
                "entity_type": {
                    "type": "string",
                    "enum": ["user", "hostname", "source_ip", "destination_ip"],
                    "description": "Entity category."
                },
                "entity_value": {
                    "type": "string",
                    "description": "Exact value of the entity (e.g. 'svc_deploy' or '198.51.100.44')."
                },
                "start_time": {
                    "type": "string",
                    "description": "Optional ISO-8601 formatted start time to filter events (inclusive, e.g. '2026-11-01T08:00:00Z')."
                },
                "end_time": {
                    "type": "string",
                    "description": "Optional ISO-8601 formatted end time to filter events (inclusive, e.g. '2026-11-01T08:30:00Z')."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of events to return (max 20, default 10)."
                }
            },
            "required": ["incident_id", "entity_type", "entity_value"]
        }
    }
]


class InvestigationToolExecutor:
    """Executes allow-listed read-only investigation tools against authorized incident evidence."""

    def __init__(self, session: AsyncSession, authorized_incident_id: str):
        self.session = session
        self.authorized_incident_id = authorized_incident_id
        self.incident_repo = IncidentRepository(session)

    async def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch requested function call with boundary verification."""
        inc_id = arguments.get("incident_id")
        if inc_id != self.authorized_incident_id:
            return {
                "error": f"Access denied: tool requested incident '{inc_id}' outside authorized scope '{self.authorized_incident_id}'"
            }

        if tool_name == "get_incident_timeline":
            return await self._get_incident_timeline()
        elif tool_name == "get_event_details":
            return await self._get_event_details(arguments.get("event_ids", []))
        elif tool_name == "get_detection_details":
            return await self._get_detection_details(arguments.get("detection_ids", []))
        elif tool_name == "query_entity_history":
            raw_limit = arguments.get("limit", 10)
            try:
                limit_int = min(int(raw_limit), 20)
            except (ValueError, TypeError):
                limit_int = 10
            return await self._query_entity_history(
                entity_type=arguments.get("entity_type", ""),
                entity_value=arguments.get("entity_value", ""),
                start_time=arguments.get("start_time"),
                end_time=arguments.get("end_time"),
                limit=limit_int,
            )
        else:
            return {"error": f"Unknown or disallowed function name '{tool_name}'"}

    async def _get_incident_timeline(self) -> Dict[str, Any]:
        dossier = await self.incident_repo.get_incident_evidence(self.authorized_incident_id)
        if not dossier:
            return {"error": "Incident not found"}

        timeline_entries = []
        for e in dossier["events"]:
            timeline_entries.append({
                "type": "event",
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "category": e.category,
                "action": e.action,
                "user": e.username,
                "host": e.hostname,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "bytes_out": e.bytes_out,
                "process": e.process_name,
            })

        for d in dossier["detections"]:
            timeline_entries.append({
                "type": "detection",
                "id": d.id,
                "timestamp": d.detected_at.isoformat(),
                "rule_id": d.rule_id,
                "rule_name": d.rule_name,
                "severity": d.severity,
                "entity": f"{d.entity_type}:{d.entity_value}",
                "explanation": d.explanation,
                "triggering_event_ids": [ea.event_id for ea in d.event_associations],
            })

        timeline_entries.sort(key=lambda x: x["timestamp"])
        return {
            "incident_id": self.authorized_incident_id,
            "timeline_count": len(timeline_entries),
            "timeline": timeline_entries,
        }

    async def _get_event_details(self, event_ids: List[str]) -> Dict[str, Any]:
        dossier = await self.incident_repo.get_incident_evidence(self.authorized_incident_id)
        if not dossier:
            return {"error": "Incident not found"}

        # Restrict to events belonging to this incident
        incident_event_map = {e.id: e for e in dossier["events"]}
        bounded_ids = event_ids[:20]

        returned_events = []
        rejected_ids = []

        for eid in bounded_ids:
            if eid in incident_event_map:
                ev = incident_event_map[eid]
                returned_events.append({
                    "event_id": ev.id,
                    "timestamp": ev.timestamp.isoformat(),
                    "source_type": ev.source_type,
                    "category": ev.category,
                    "action": ev.action,
                    "severity": ev.severity,
                    "user_identity": ev.username,
                    "source_ip": ev.source_ip,
                    "destination_ip": ev.destination_ip,
                    "source_port": ev.source_port,
                    "destination_port": ev.destination_port,
                    "protocol": ev.protocol,
                    "bytes_sent": ev.bytes_out,
                    "hostname": ev.hostname,
                    "process_name": ev.process_name,
                    "process_command_line": ev.process_command_line,
                })
            else:
                rejected_ids.append(eid)

        return {
            "incident_id": self.authorized_incident_id,
            "requested_count": len(event_ids),
            "returned_count": len(returned_events),
            "events": returned_events,
            "rejected_or_unauthorized_ids": rejected_ids,
        }

    async def _get_detection_details(self, detection_ids: List[str]) -> Dict[str, Any]:
        dossier = await self.incident_repo.get_incident_evidence(self.authorized_incident_id)
        if not dossier:
            return {"error": "Incident not found"}

        det_map = {d.id: d for d in dossier["detections"]}
        results = []

        for did in detection_ids[:10]:
            if did in det_map:
                d = det_map[did]
                results.append({
                    "detection_id": d.id,
                    "rule_id": d.rule_id,
                    "rule_name": d.rule_name,
                    "severity": d.severity,
                    "entity_type": d.entity_type,
                    "entity_value": d.entity_value,
                    "detected_at": d.detected_at.isoformat(),
                    "explanation": d.explanation,
                    "triggering_event_ids": [ea.event_id for ea in d.event_associations],
                    "metadata": d.metadata_json,
                })

        return {
            "incident_id": self.authorized_incident_id,
            "detections": results,
        }

    @staticmethod
    def _parse_iso_timestamp(ts_str: str, field_name: str) -> Tuple[Optional[datetime], Optional[str]]:
        clean_ts = ts_str.strip()
        if clean_ts.endswith("Z"):
            clean_ts = clean_ts[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt, None
        except Exception:
            return None, f"Invalid {field_name} format: '{ts_str}'. Expected ISO-8601 (e.g., '2026-11-01T08:00:00Z')."

    async def _query_entity_history(
        self,
        entity_type: str,
        entity_value: str,
        limit: int,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        dossier = await self.incident_repo.get_incident_evidence(self.authorized_incident_id)
        if not dossier:
            return {"error": "Incident not found"}

        start_dt: Optional[datetime] = None
        end_dt: Optional[datetime] = None

        if start_time:
            start_dt, err = self._parse_iso_timestamp(start_time, "start_time")
            if err:
                return {"error": err}

        if end_time:
            end_dt, err = self._parse_iso_timestamp(end_time, "end_time")
            if err:
                return {"error": err}

        if start_dt and end_dt and start_dt > end_dt:
            return {"error": "start_time cannot be later than end_time"}

        clean_val = entity_value.lower().strip()
        matched = []

        for e in dossier["events"]:
            match = False
            if entity_type == "user" and e.username and e.username.lower() == clean_val:
                match = True
            elif entity_type == "hostname" and e.hostname and e.hostname.lower() == clean_val:
                match = True
            elif entity_type == "source_ip" and e.source_ip == entity_value.strip():
                match = True
            elif entity_type == "destination_ip" and e.destination_ip == entity_value.strip():
                match = True

            if not match:
                continue

            # Temporal filtering (inclusive)
            ev_ts = e.timestamp
            if ev_ts.tzinfo is None:
                ev_ts = ev_ts.replace(tzinfo=timezone.utc)
            else:
                ev_ts = ev_ts.astimezone(timezone.utc)

            if start_dt and ev_ts < start_dt:
                continue
            if end_dt and ev_ts > end_dt:
                continue

            matched.append({
                "event_id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "category": e.category,
                "user": e.username,
                "hostname": e.hostname,
                "source_ip": e.source_ip,
                "destination_ip": e.destination_ip,
                "bytes_out": e.bytes_out,
            })
            if len(matched) >= limit:
                break

        return {
            "incident_id": self.authorized_incident_id,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "start_time": start_time,
            "end_time": end_time,
            "matched_count": len(matched),
            "events": matched,
        }

