"""
Pydantic response schemas for Phase 6.1 Asset & Identity Inventory.

All fields reflect observed telemetry only. No fabricated metadata.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class TriggeredRule(BaseModel):
    rule_id: str
    rule_name: str
    severity: str


class AssetSummary(BaseModel):
    """Summary of a single observed asset (hostname or IP)."""
    asset_type: str                         # "hostname" or "ip"
    asset_value: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    event_count: int = 0
    # IP-only fields (omitted for hostnames)
    source_event_count: Optional[int] = None
    destination_event_count: Optional[int] = None
    detection_count: int = 0
    incident_count: int = 0
    provenance: str = "observed_telemetry"


class AssetDetail(AssetSummary):
    """Full detail for a single observed asset."""
    triggered_rules: List[TriggeredRule] = []
    incident_ids: List[str] = []


class AssetListResponse(BaseModel):
    assets: List[AssetSummary]
    total: int
    provenance: str = "observed_telemetry"


class IdentitySummary(BaseModel):
    """Summary of a single observed user identity."""
    username: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    event_count: int = 0
    detection_count: int = 0
    incident_count: int = 0
    provenance: str = "observed_telemetry"


class IdentityDetail(IdentitySummary):
    """Full detail for a single observed identity."""
    triggered_rules: List[TriggeredRule] = []
    incident_ids: List[str] = []


class IdentityListResponse(BaseModel):
    identities: List[IdentitySummary]
    total: int
    provenance: str = "observed_telemetry"
