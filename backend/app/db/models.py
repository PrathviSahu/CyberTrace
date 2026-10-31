"""
SQLAlchemy 2.0 Declarative Models for CyberTrace.
Defines schemas for Security Events, Detections, Incidents, and Entity Associations.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship as sa_relationship
from app.db.session import Base


class SecurityEventModel(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    
    # Entity attribution
    username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    
    # Network metrics
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    bytes_in: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    
    # Process & command line
    process_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    process_command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Provenance
    raw_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    source_file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Relationships
    detection_associations: Mapped[List["DetectionEventModel"]] = sa_relationship(
        "DetectionEventModel", back_populates="event", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_events_user_time", "username", "timestamp"),
        Index("idx_events_ip_time", "source_ip", "timestamp"),
    )


class DetectionModel(Base):
    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)  # user, ip, host
    entity_value: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    event_associations: Mapped[List["DetectionEventModel"]] = sa_relationship(
        "DetectionEventModel", back_populates="detection", cascade="all, delete-orphan"
    )
    incident_associations: Mapped[List["IncidentDetectionModel"]] = sa_relationship(
        "IncidentDetectionModel", back_populates="detection", cascade="all, delete-orphan"
    )


class DetectionEventModel(Base):
    __tablename__ = "detection_events"

    detection_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("detections.id", ondelete="CASCADE"),
        primary_key=True,
    )
    event_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("security_events.id", ondelete="CASCADE"),
        primary_key=True,
    )

    detection: Mapped["DetectionModel"] = sa_relationship("DetectionModel", back_populates="event_associations")
    event: Mapped["SecurityEventModel"] = sa_relationship("SecurityEventModel", back_populates="detection_associations")


class IncidentModel(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    correlation_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # low, medium, high, critical
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    detection_associations: Mapped[List["IncidentDetectionModel"]] = sa_relationship(
        "IncidentDetectionModel", back_populates="incident", cascade="all, delete-orphan"
    )
    entities: Mapped[List["IncidentEntityModel"]] = sa_relationship(
        "IncidentEntityModel", back_populates="incident", cascade="all, delete-orphan"
    )
    investigations: Mapped[List["AIInvestigationModel"]] = sa_relationship(
        "AIInvestigationModel", back_populates="incident", cascade="all, delete-orphan"
    )


class IncidentDetectionModel(Base):
    __tablename__ = "incident_detections"

    incident_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
    )
    detection_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("detections.id", ondelete="CASCADE"),
        primary_key=True,
    )
    correlation_reason: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    incident: Mapped["IncidentModel"] = sa_relationship("IncidentModel", back_populates="detection_associations")
    detection: Mapped["DetectionModel"] = sa_relationship("DetectionModel", back_populates="incident_associations")


class IncidentEntityModel(Base):
    __tablename__ = "incident_entities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)  # user, source_ip, destination_ip, hostname, process
    entity_value: Mapped[str] = mapped_column(String(128), nullable=False)
    relationship: Mapped[str] = mapped_column(String(128), nullable=False)  # e.g., compromised_account, attacker_ip
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    evidence_references: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    incident: Mapped["IncidentModel"] = sa_relationship("IncidentModel", back_populates="entities")

    __table_args__ = (
        UniqueConstraint("incident_id", "entity_type", "entity_value", name="uq_incident_entity"),
    )


class AIInvestigationModel(Base):
    __tablename__ = "ai_investigations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    model_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # completed, fallback, failed, in_progress
    executive_summary: Mapped[str] = mapped_column(Text, nullable=False)
    structured_result: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    event_citations: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    tool_call_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    request_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    incident: Mapped["IncidentModel"] = sa_relationship("IncidentModel", back_populates="investigations")
