"""SQLAlchemy ORM models: alerts, incidents, action executions and the audit chain."""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, String, Text, TypeDecorator
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Stores timezone-aware UTC datetimes on every backend (SQLite drops tzinfo)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    type_annotation_map: ClassVar[dict[Any, Any]] = {dict[str, Any]: JSON, list[Any]: JSON}


class IncidentStatus(enum.StrEnum):
    TRIGGERED = "triggered"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    AUTO_APPROVED = "auto_approved"
    DENIED = "denied"
    EXPIRED = "expired"
    EXECUTING = "executing"
    CONTAINED = "contained"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


OPEN_STATUSES = (
    IncidentStatus.TRIGGERED,
    IncidentStatus.AWAITING_APPROVAL,
    IncidentStatus.APPROVED,
    IncidentStatus.AUTO_APPROVED,
    IncidentStatus.EXECUTING,
)


class ExecutionStatus(enum.StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    rule_id: Mapped[int] = mapped_column(Integer, index=True)
    rule_level: Mapped[int] = mapped_column(Integer)
    rule_groups: Mapped[list[Any]] = mapped_column(default=list)
    description: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(16))
    agent_name: Mapped[str] = mapped_column(String(255))
    event_timestamp: Mapped[datetime] = mapped_column(UTCDateTime)
    raw_log: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: f"INC-{uuid.uuid4().hex[:12].upper()}"
    )
    playbook_id: Mapped[str] = mapped_column(String(128), index=True)
    playbook_name: Mapped[str] = mapped_column(String(255))
    threat_type: Mapped[str] = mapped_column(String(255))
    severity: Mapped[int] = mapped_column(Integer)
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, native_enum=False, length=32), index=True
    )
    status_reason: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(16))
    agent_name: Mapped[str] = mapped_column(String(255))
    parsed_vars: Mapped[dict[str, Any]] = mapped_column(default=dict)
    trigger_payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    alert_count: Mapped[int] = mapped_column(Integer, default=1)
    correlated_events: Mapped[int] = mapped_column(Integer, default=0)

    # Lifecycle timeline
    alert_received_at: Mapped[datetime] = mapped_column(UTCDateTime)
    playbook_triggered_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    hitl_sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    hitl_deadline: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    hitl_channels: Mapped[list[Any]] = mapped_column(default=list)
    decision: Mapped[str | None] = mapped_column(String(32))
    decision_by: Mapped[str | None] = mapped_column(String(255))
    decision_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    execution_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    execution_completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    executions: Mapped[list[ActionExecution]] = relationship(
        back_populates="incident", order_by="ActionExecution.id", lazy="selectin"
    )


class ActionExecution(Base):
    __tablename__ = "action_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    action_name: Mapped[str] = mapped_column(String(128))
    responder: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255))
    params: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[ExecutionStatus] = mapped_column(
        Enum(ExecutionStatus, native_enum=False, length=16)
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    status_code: Mapped[int | None] = mapped_column(Integer)
    response: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    incident: Mapped[Incident] = relationship(back_populates="executions")


class AuditEntry(Base):
    """Append-only, hash-chained audit record. ``prev_hash`` is unique to prevent forks."""

    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    incident_id: Mapped[str | None] = mapped_column(String(36), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(255))
    data: Mapped[dict[str, Any]] = mapped_column(default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hash: Mapped[str] = mapped_column(String(64), unique=True)
