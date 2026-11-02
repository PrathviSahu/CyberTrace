"""
Asset & Identity Repository for CyberTrace.

Derives observed asset and identity inventories from persisted security telemetry.
No external integrations, no fabricated metadata. All data is derived from ingested events.

Canonical Entity Normalization Rules:
  - Hostnames: Stored/grouped canonically in UPPERCASE (e.g. 'SRV-APP-01')
    consistent with NetBIOS/FQDN conventions and incident entity records.
  - Usernames: Stored/grouped canonically in LOWERCASE (e.g. 'svc_deploy')
    consistent with POSIX/CES user identity conventions.
  - IP addresses: Stored as trimmed IPv4/IPv6 address strings.
  - Whitespace-only or null values are strictly excluded.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, literal, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    DetectionModel,
    IncidentEntityModel,
    SecurityEventModel,
)


def _format_datetime(dt: Optional[datetime]) -> Optional[str]:
    """Format datetime as ISO 8601 string with explicit UTC timezone."""
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Asset aggregation (Hostnames + IPs)
# ---------------------------------------------------------------------------

class AssetRepository:
    """
    Observed asset inventory derived from persisted security events.

    Assets = hostnames + IP addresses (source and destination) seen in telemetry.
    Global sort order:
      1. last_seen DESC
      2. asset_value ASC (stable tie-breaker)
      3. asset_type ASC (guarantees determinism)
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def _get_hostname_candidate_query(self):
        """
        Query generating (asset_type, asset_value, first_seen, last_seen) for hostnames.
        Groups canonically by UPPERCASE hostname so case variants (e.g. 'srv-app-01',
        'SRV-APP-01', 'Srv-App-01') collapse into a single unified inventory record.
        """
        return (
            select(
                literal("hostname").label("asset_type"),
                func.upper(func.trim(SecurityEventModel.hostname)).label("asset_value"),
                func.min(SecurityEventModel.timestamp).label("first_seen"),
                func.max(SecurityEventModel.timestamp).label("last_seen"),
            )
            .where(SecurityEventModel.hostname.isnot(None))
            .where(func.trim(SecurityEventModel.hostname) != "")
            .group_by(func.upper(func.trim(SecurityEventModel.hostname)))
        )

    def _get_ip_candidate_query(self):
        """Query generating (asset_type, asset_value, first_seen, last_seen) for distinct IPs across src and dst."""
        src_ip = (
            select(
                func.trim(SecurityEventModel.source_ip).label("ip"),
                SecurityEventModel.timestamp.label("timestamp"),
            )
            .where(SecurityEventModel.source_ip.isnot(None))
            .where(func.trim(SecurityEventModel.source_ip) != "")
        )
        dst_ip = (
            select(
                func.trim(SecurityEventModel.destination_ip).label("ip"),
                SecurityEventModel.timestamp.label("timestamp"),
            )
            .where(SecurityEventModel.destination_ip.isnot(None))
            .where(func.trim(SecurityEventModel.destination_ip) != "")
        )
        ip_events = union_all(src_ip, dst_ip).subquery("ip_events")
        return (
            select(
                literal("ip").label("asset_type"),
                ip_events.c.ip.label("asset_value"),
                func.min(ip_events.c.timestamp).label("first_seen"),
                func.max(ip_events.c.timestamp).label("last_seen"),
            )
            .group_by(ip_events.c.ip)
        )

    async def list_assets(
        self,
        asset_type: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        List observed assets with unified database-level global ordering and pagination.
        Global sort order:
          1. last_seen DESC
          2. asset_value ASC (stable tie-breaker)
          3. asset_type ASC (guarantees determinism)
        """
        limit = min(limit, 200)

        if asset_type == "hostname":
            candidate_base = self._get_hostname_candidate_query()
        elif asset_type == "ip":
            candidate_base = self._get_ip_candidate_query()
        else:
            host_q = self._get_hostname_candidate_query()
            ip_q = self._get_ip_candidate_query()
            candidate_base = union_all(host_q, ip_q)

        candidates = candidate_base.subquery("asset_candidates")

        # Base count and pagination queries
        count_stmt = select(func.count()).select_from(candidates)
        page_stmt = select(
            candidates.c.asset_type,
            candidates.c.asset_value,
            candidates.c.first_seen,
            candidates.c.last_seen,
        )

        if search:
            search_pattern = f"%{search.strip().lower()}%"
            count_stmt = count_stmt.where(func.lower(candidates.c.asset_value).like(search_pattern))
            page_stmt = page_stmt.where(func.lower(candidates.c.asset_value).like(search_pattern))

        total: int = (await self.session.execute(count_stmt)).scalar() or 0

        # Apply strict global ordering before LIMIT and OFFSET
        page_stmt = (
            page_stmt
            .order_by(
                candidates.c.last_seen.desc(),
                candidates.c.asset_value.asc(),
                candidates.c.asset_type.asc(),
            )
            .offset(offset)
            .limit(limit)
        )
        page_rows = (await self.session.execute(page_stmt)).all()

        results: List[Dict[str, Any]] = []
        for row in page_rows:
            if row.asset_type == "hostname":
                summary = await self._resolve_hostname_metrics(
                    row.asset_value, row.first_seen, row.last_seen
                )
            else:
                summary = await self._resolve_ip_metrics(
                    row.asset_value, row.first_seen, row.last_seen
                )
            results.append(summary)

        return results, total

    async def list_hostnames(
        self,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        return await self.list_assets(
            asset_type="hostname", search=search, limit=limit, offset=offset
        )

    async def list_ips(
        self,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        return await self.list_assets(
            asset_type="ip", search=search, limit=limit, offset=offset
        )

    async def _resolve_hostname_metrics(
        self, hostname: str, first_seen: Optional[datetime], last_seen: Optional[datetime]
    ) -> Dict[str, Any]:
        canonical_hostname = hostname.strip().upper()
        count_stmt = select(func.count(SecurityEventModel.id.distinct())).where(
            func.upper(func.trim(SecurityEventModel.hostname)) == canonical_hostname
        )
        event_count: int = (await self.session.execute(count_stmt)).scalar() or 0

        det_count, inc_count = await self._hostname_assoc_counts(canonical_hostname)
        return {
            "asset_type": "hostname",
            "asset_value": canonical_hostname,
            "first_seen": _format_datetime(first_seen),
            "last_seen": _format_datetime(last_seen),
            "event_count": event_count,
            "source_event_count": None,
            "destination_event_count": None,
            "detection_count": det_count,
            "incident_count": inc_count,
            "provenance": "observed_telemetry",
        }

    async def _resolve_ip_metrics(
        self, ip: str, first_seen: Optional[datetime], last_seen: Optional[datetime]
    ) -> Dict[str, Any]:
        ip_clean = ip.strip()
        src_stmt = select(func.count(SecurityEventModel.id.distinct())).where(
            SecurityEventModel.source_ip == ip_clean
        )
        src_count: int = (await self.session.execute(src_stmt)).scalar() or 0

        dst_stmt = select(func.count(SecurityEventModel.id.distinct())).where(
            SecurityEventModel.destination_ip == ip_clean
        )
        dst_count: int = (await self.session.execute(dst_stmt)).scalar() or 0

        total_stmt = select(func.count(SecurityEventModel.id.distinct())).where(
            (SecurityEventModel.source_ip == ip_clean) | (SecurityEventModel.destination_ip == ip_clean)
        )
        event_count: int = (await self.session.execute(total_stmt)).scalar() or 0

        det_count, inc_count = await self._ip_assoc_counts(ip_clean)
        return {
            "asset_type": "ip",
            "asset_value": ip_clean,
            "first_seen": _format_datetime(first_seen),
            "last_seen": _format_datetime(last_seen),
            "event_count": event_count,
            "source_event_count": src_count,
            "destination_event_count": dst_count,
            "detection_count": det_count,
            "incident_count": inc_count,
            "provenance": "observed_telemetry",
        }

    async def _hostname_assoc_counts(self, hostname: str) -> Tuple[int, int]:
        """
        Return (detection_count, incident_count) for a canonical hostname.
        Checked case-insensitively using canonical uppercase comparison.
        """
        canonical = hostname.strip().upper()
        det_stmt = select(func.count(DetectionModel.id.distinct())).where(
            DetectionModel.entity_type.in_(["host", "hostname"]),
            func.upper(func.trim(DetectionModel.entity_value)) == canonical,
        )
        det_count: int = (await self.session.execute(det_stmt)).scalar() or 0

        inc_stmt = select(func.count(IncidentEntityModel.incident_id.distinct())).where(
            IncidentEntityModel.entity_type.in_(["host", "hostname"]),
            func.upper(func.trim(IncidentEntityModel.entity_value)) == canonical,
        )
        inc_count: int = (await self.session.execute(inc_stmt)).scalar() or 0

        return det_count, inc_count

    async def _ip_assoc_counts(self, ip: str) -> Tuple[int, int]:
        """
        Return (detection_count, incident_count) for an IP address.
        Detections table uses entity_type="ip" (or "source_ip", "destination_ip").
        Incident entities table uses entity_type in ("source_ip", "destination_ip", "ip").
        Uses exact string equality.
        """
        ip_clean = ip.strip()
        det_stmt = select(func.count(DetectionModel.id.distinct())).where(
            DetectionModel.entity_type.in_(["ip", "source_ip", "destination_ip"]),
            DetectionModel.entity_value == ip_clean,
        )
        det_count: int = (await self.session.execute(det_stmt)).scalar() or 0

        inc_stmt = select(func.count(IncidentEntityModel.incident_id.distinct())).where(
            IncidentEntityModel.entity_type.in_(["source_ip", "destination_ip", "ip"]),
            IncidentEntityModel.entity_value == ip_clean,
        )
        inc_count: int = (await self.session.execute(inc_stmt)).scalar() or 0

        return det_count, inc_count

    async def get_hostname_detail(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Return full observed detail for a single hostname.
        Resolves case variants canonically to UPPERCASE. Returns None if not found.
        """
        if not hostname or not hostname.strip():
            return None
        canonical_hostname = hostname.strip().upper()

        stmt = (
            select(
                func.min(SecurityEventModel.timestamp).label("first_seen"),
                func.max(SecurityEventModel.timestamp).label("last_seen"),
                func.count(SecurityEventModel.id.distinct()).label("event_count"),
            )
            .where(
                SecurityEventModel.hostname.isnot(None),
                func.trim(SecurityEventModel.hostname) != "",
                func.upper(func.trim(SecurityEventModel.hostname)) == canonical_hostname,
            )
        )
        row = (await self.session.execute(stmt)).one()
        if not row.event_count:
            return None

        det_count, inc_count = await self._hostname_assoc_counts(canonical_hostname)

        det_rules_stmt = (
            select(DetectionModel.rule_id, DetectionModel.rule_name, DetectionModel.severity)
            .where(
                DetectionModel.entity_type.in_(["host", "hostname"]),
                func.upper(func.trim(DetectionModel.entity_value)) == canonical_hostname,
            )
            .distinct()
            .limit(20)
        )
        det_rules = (await self.session.execute(det_rules_stmt)).all()

        inc_ids_stmt = (
            select(IncidentEntityModel.incident_id)
            .where(
                IncidentEntityModel.entity_type.in_(["host", "hostname"]),
                func.upper(func.trim(IncidentEntityModel.entity_value)) == canonical_hostname,
            )
            .distinct()
            .limit(20)
        )
        inc_ids = (await self.session.execute(inc_ids_stmt)).scalars().all()

        return {
            "asset_type": "hostname",
            "asset_value": canonical_hostname,
            "first_seen": _format_datetime(row.first_seen),
            "last_seen": _format_datetime(row.last_seen),
            "event_count": row.event_count,
            "source_event_count": None,
            "destination_event_count": None,
            "detection_count": det_count,
            "incident_count": inc_count,
            "triggered_rules": [
                {"rule_id": r.rule_id, "rule_name": r.rule_name, "severity": r.severity}
                for r in det_rules
            ],
            "incident_ids": list(inc_ids),
            "provenance": "observed_telemetry",
        }

    async def get_ip_detail(self, ip: str) -> Optional[Dict[str, Any]]:
        """Return full observed detail for a single IP. None if not found."""
        if not ip or not ip.strip():
            return None
        ip_clean = ip.strip()

        time_stmt = select(
            func.min(SecurityEventModel.timestamp).label("first_seen"),
            func.max(SecurityEventModel.timestamp).label("last_seen"),
        ).where(
            (SecurityEventModel.source_ip == ip_clean) | (SecurityEventModel.destination_ip == ip_clean)
        )
        time_row = (await self.session.execute(time_stmt)).one()
        if time_row.first_seen is None and time_row.last_seen is None:
            return None

        summary = await self._resolve_ip_metrics(ip_clean, time_row.first_seen, time_row.last_seen)
        if summary["event_count"] == 0:
            return None

        det_rules_stmt = (
            select(DetectionModel.rule_id, DetectionModel.rule_name, DetectionModel.severity)
            .where(
                DetectionModel.entity_type.in_(["ip", "source_ip", "destination_ip"]),
                DetectionModel.entity_value == ip_clean,
            )
            .distinct()
            .limit(20)
        )
        det_rules = (await self.session.execute(det_rules_stmt)).all()

        inc_ids_stmt = (
            select(IncidentEntityModel.incident_id)
            .where(
                IncidentEntityModel.entity_type.in_(["source_ip", "destination_ip", "ip"]),
                IncidentEntityModel.entity_value == ip_clean,
            )
            .distinct()
            .limit(20)
        )
        inc_ids = (await self.session.execute(inc_ids_stmt)).scalars().all()

        return {
            **summary,
            "triggered_rules": [
                {"rule_id": r.rule_id, "rule_name": r.rule_name, "severity": r.severity}
                for r in det_rules
            ],
            "incident_ids": list(inc_ids),
        }


# ---------------------------------------------------------------------------
# Identity aggregation (Usernames)
# ---------------------------------------------------------------------------

class IdentityRepository:
    """
    Observed identity inventory derived from the username column in security_events.
    Groups canonically by LOWERCASE username so case variants (e.g. 'svc_deploy',
    'SVC_DEPLOY') collapse into a single unified identity record.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_identities(
        self,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Return distinct observed usernames with aggregated activity metrics.
        Null, empty, and whitespace-only values are excluded.
        Ordered by:
          1. last_seen DESC
          2. username ASC (stable tie-breaker)
        """
        limit = min(limit, 200)

        base = (
            select(
                func.lower(func.trim(SecurityEventModel.username)).label("username"),
                func.min(SecurityEventModel.timestamp).label("first_seen"),
                func.max(SecurityEventModel.timestamp).label("last_seen"),
                func.count(SecurityEventModel.id.distinct()).label("event_count"),
            )
            .where(SecurityEventModel.username.isnot(None))
            .where(func.trim(SecurityEventModel.username) != "")
            .group_by(func.lower(func.trim(SecurityEventModel.username)))
        )

        if search:
            search_pattern = f"%{search.strip().lower()}%"
            base = base.where(func.lower(SecurityEventModel.username).like(search_pattern))

        count_subq = base.subquery()
        total: int = (
            await self.session.execute(select(func.count()).select_from(count_subq))
        ).scalar() or 0

        paginated = (
            base.order_by(
                func.max(SecurityEventModel.timestamp).desc(),
                func.lower(func.trim(SecurityEventModel.username)).asc(),
            )
            .offset(offset)
            .limit(limit)
        )
        rows = (await self.session.execute(paginated)).all()

        results = []
        for row in rows:
            det_count, inc_count = await self._identity_assoc_counts(row.username)
            results.append({
                "username": row.username,
                "first_seen": _format_datetime(row.first_seen),
                "last_seen": _format_datetime(row.last_seen),
                "event_count": row.event_count,
                "detection_count": det_count,
                "incident_count": inc_count,
                "provenance": "observed_telemetry",
            })
        return results, total

    async def _identity_assoc_counts(self, username: str) -> Tuple[int, int]:
        """
        Return (detection_count, incident_count) for a canonical username.
        Checked case-insensitively using lowercase equality.
        """
        canonical = username.strip().lower()
        det_stmt = select(func.count(DetectionModel.id.distinct())).where(
            DetectionModel.entity_type == "user",
            func.lower(func.trim(DetectionModel.entity_value)) == canonical,
        )
        det_count: int = (await self.session.execute(det_stmt)).scalar() or 0

        inc_stmt = select(func.count(IncidentEntityModel.incident_id.distinct())).where(
            IncidentEntityModel.entity_type == "user",
            func.lower(func.trim(IncidentEntityModel.entity_value)) == canonical,
        )
        inc_count: int = (await self.session.execute(inc_stmt)).scalar() or 0

        return det_count, inc_count

    async def get_identity_detail(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Return full observed detail for a single username.
        Resolves case variants canonically to LOWERCASE. Returns None if not found.
        """
        if not username or not username.strip():
            return None
        canonical_username = username.strip().lower()

        stmt = (
            select(
                func.min(SecurityEventModel.timestamp).label("first_seen"),
                func.max(SecurityEventModel.timestamp).label("last_seen"),
                func.count(SecurityEventModel.id.distinct()).label("event_count"),
            )
            .where(
                SecurityEventModel.username.isnot(None),
                func.trim(SecurityEventModel.username) != "",
                func.lower(func.trim(SecurityEventModel.username)) == canonical_username,
            )
        )
        row = (await self.session.execute(stmt)).one()
        if not row.event_count:
            return None

        det_count, inc_count = await self._identity_assoc_counts(canonical_username)

        det_rules_stmt = (
            select(DetectionModel.rule_id, DetectionModel.rule_name, DetectionModel.severity)
            .where(
                DetectionModel.entity_type == "user",
                func.lower(func.trim(DetectionModel.entity_value)) == canonical_username,
            )
            .distinct()
            .limit(20)
        )
        det_rules = (await self.session.execute(det_rules_stmt)).all()

        inc_ids_stmt = (
            select(IncidentEntityModel.incident_id)
            .where(
                IncidentEntityModel.entity_type == "user",
                func.lower(func.trim(IncidentEntityModel.entity_value)) == canonical_username,
            )
            .distinct()
            .limit(20)
        )
        inc_ids = (await self.session.execute(inc_ids_stmt)).scalars().all()

        return {
            "username": canonical_username,
            "first_seen": _format_datetime(row.first_seen),
            "last_seen": _format_datetime(row.last_seen),
            "event_count": row.event_count,
            "detection_count": det_count,
            "incident_count": inc_count,
            "triggered_rules": [
                {"rule_id": r.rule_id, "rule_name": r.rule_name, "severity": r.severity}
                for r in det_rules
            ],
            "incident_ids": list(inc_ids),
            "provenance": "observed_telemetry",
        }
