"""
Unit tests for CyberTrace Common Event Schema (CES).
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
from app.schemas.ces import (
    CommonEvent,
    EventAction,
    EventCategory,
    EventSeverity,
    generate_event_id,
)


def test_ces_valid_event_creation():
    evt = CommonEvent(
        timestamp="2026-11-01T08:00:00Z",
        category=EventCategory.AUTHENTICATION,
        action=EventAction.LOGON_FAILURE,
        severity=EventSeverity.MEDIUM,
        user_identity="svc_deploy",
        source_ip="198.51.100.44",
        source_port=41201,
        hostname="SRV-APP-01",
        source_format="test_log"
    )

    assert evt.event_id.startswith("evt_")
    assert evt.timestamp.tzinfo == timezone.utc
    assert evt.user_identity == "svc_deploy"
    assert evt.source_ip == "198.51.100.44"
    assert evt.source_port == 41201
    assert evt.hostname == "SRV-APP-01"


def test_ces_timestamp_normalization():
    # ISO with space
    evt1 = CommonEvent(
        timestamp="2026-11-01 08:00:00",
        category=EventCategory.SYSTEM_LOG,
        action=EventAction.UNKNOWN,
        source_format="test"
    )
    assert evt1.timestamp == datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)

    # Epoch timestamp
    evt2 = CommonEvent(
        timestamp=1730448000,
        category=EventCategory.SYSTEM_LOG,
        action=EventAction.UNKNOWN,
        source_format="test"
    )
    assert evt2.timestamp.tzinfo == timezone.utc


def test_ces_entity_extraction():
    evt = CommonEvent(
        timestamp="2026-11-01T08:00:00Z",
        category=EventCategory.AUTHENTICATION,
        action=EventAction.LOGON_SUCCESS,
        user_identity="Alice",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        hostname="DC-01",
        source_format="test"
    )
    entities = evt.get_primary_entities()
    assert entities["user"] == "alice"
    assert entities["src_ip"] == "192.168.1.50"
    assert entities["dst_ip"] == "10.0.0.1"
    assert entities["host"] == "dc-01"


def test_ces_invalid_port_raises_error():
    with pytest.raises(ValidationError):
        CommonEvent(
            timestamp="2026-11-01T08:00:00Z",
            category=EventCategory.NETWORK_CONNECTION,
            action=EventAction.NETWORK_CONNECT,
            source_port=70000,  # Invalid port > 65535
            source_format="test"
        )


def test_deterministic_event_id_generation():
    id1 = generate_event_id("evt", "unique_seed_123")
    id2 = generate_event_id("evt", "unique_seed_123")
    id3 = generate_event_id("evt", "different_seed")

    assert id1 == id2
    assert id1 != id3
