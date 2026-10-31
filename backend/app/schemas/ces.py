"""
CyberTrace Common Event Schema (CES)
Standardized data contracts for normalizing heterogeneous security logs.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field, field_validator, model_validator


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    PRIVILEGE_CHANGE = "privilege_change"
    PROCESS_EXECUTION = "process_execution"
    NETWORK_CONNECTION = "network_connection"
    FILE_OPERATION = "file_operation"
    SYSTEM_LOG = "system_log"


class EventAction(str, Enum):
    LOGON_SUCCESS = "logon_success"
    LOGON_FAILURE = "logon_failure"
    LOGOFF = "logoff"
    ELEVATION_ATTEMPT = "elevation_attempt"
    ELEVATION_SUCCESS = "elevation_success"
    PROCESS_START = "process_start"
    PROCESS_TERMINATE = "process_terminate"
    NETWORK_CONNECT = "network_connect"
    NETWORK_LISTEN = "network_listen"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class EventSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def generate_event_id(prefix: str = "evt", seed_str: Optional[str] = None) -> str:
    """Generate a clean deterministic or random event ID."""
    if seed_str:
        h = hashlib.sha256(seed_str.encode("utf-8")).hexdigest()[:12]
        return f"{prefix}_{h}"
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class CommonEvent(BaseModel):
    """
    Normalized Security Event Schema (CES).
    All ingested log formats (Windows Event, Linux Auth, Zeek, etc.) are converted to this contract.
    """
    event_id: str = Field(default_factory=generate_event_id, description="Unique event identifier")
    timestamp: datetime = Field(..., description="Normalized UTC timestamp")
    category: EventCategory = Field(..., description="High-level security telemetry category")
    action: EventAction = Field(..., description="Specific observed action")
    severity: EventSeverity = Field(default=EventSeverity.INFORMATIONAL, description="Base severity level")
    
    # Entity Attribution
    user_identity: Optional[str] = Field(None, description="Normalized username, account name, or UPN")
    source_ip: Optional[str] = Field(None, description="Source IP address (IPv4 or IPv6)")
    destination_ip: Optional[str] = Field(None, description="Destination IP address (IPv4 or IPv6)")
    source_port: Optional[int] = Field(None, ge=0, le=65535, description="Source transport port")
    destination_port: Optional[int] = Field(None, ge=0, le=65535, description="Destination transport port")
    hostname: Optional[str] = Field(None, description="Host, asset ID, or endpoint machine name")
    
    # Process & Execution Context
    process_name: Optional[str] = Field(None, description="Executed binary or script name")
    process_command_line: Optional[str] = Field(None, description="Command line invocation with arguments")
    parent_process_name: Optional[str] = Field(None, description="Parent process binary name")
    
    # Network & Egress Metrics
    bytes_sent: int = Field(default=0, ge=0, description="Outbound bytes sent")
    bytes_received: int = Field(default=0, ge=0, description="Inbound bytes received")
    protocol: Optional[str] = Field(None, description="Transport/Application protocol (e.g., TCP, UDP, HTTPS)")
    
    # Provenance
    source_format: str = Field(..., description="Original log format (e.g. windows_event, linux_auth, zeek_conn)")
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Preserved original raw log data")

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, str):
            # Parse ISO-8601 or common log date formats
            try:
                dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                # Try common formats
                for fmt in (
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d %H:%M:%S%z",
                    "%Y %b %d %H:%M:%S",
                    "%Y %b  %d %H:%M:%S",
                    "%b %d %H:%M:%S",
                    "%b  %d %H:%M:%S",
                    "%Y/%m/%d %H:%M:%S",
                ):
                    try:
                        dt = datetime.strptime(v, fmt)
                        if dt.year == 1900:
                            dt = dt.replace(year=datetime.now(timezone.utc).year)
                        break
                    except ValueError:
                        continue
                else:
                    raise ValueError(f"Unable to parse timestamp: {v}")
        elif isinstance(v, datetime):
            dt = v
        elif isinstance(v, (int, float)):
            dt = datetime.fromtimestamp(v, tz=timezone.utc)
        else:
            raise ValueError(f"Invalid timestamp type: {type(v)}")

        # Ensure UTC timezone
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def clean_ip(cls, v: Any) -> Optional[str]:
        if not v:
            return None
        v_str = str(v).strip()
        # Remove common wrapper characters e.g. brackets or port tails if present
        v_str = v_str.strip("[]")
        if v_str in ("-", "null", "none", "N/A", ""):
            return None
        return v_str

    @field_validator("user_identity", "hostname", "process_name", mode="before")
    @classmethod
    def clean_string_entities(cls, v: Any) -> Optional[str]:
        if not v:
            return None
        v_str = str(v).strip()
        if v_str in ("-", "null", "none", "N/A", ""):
            return None
        return v_str

    def get_primary_entities(self) -> Dict[str, str]:
        """Extract populated entity key-value pairs for correlation."""
        entities = {}
        if self.user_identity:
            entities["user"] = self.user_identity.lower()
        if self.source_ip:
            entities["src_ip"] = self.source_ip
        if self.destination_ip:
            entities["dst_ip"] = self.destination_ip
        if self.hostname:
            entities["host"] = self.hostname.lower()
        return entities
