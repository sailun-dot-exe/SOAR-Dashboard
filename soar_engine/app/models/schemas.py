"""Pydantic schemas for API payloads."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.orm import ExecutionStatus, IncidentStatus


def _dig(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


class AlertIn(BaseModel):
    """Normalized SIEM alert.

    Accepts either the flat schema emitted by the ``custom-soar`` Wazuh integration or a raw
    Wazuh ``alerts.json`` document, which is flattened automatically.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    rule_id: int = Field(..., ge=0)
    rule_level: int = Field(..., ge=0, le=16)
    description: str = Field(..., max_length=4096)
    source_ip: IPv4Address | IPv6Address | None = None
    agent_id: str = Field("000", max_length=16, pattern=r"^[0-9]{3,8}$")
    agent_name: str = Field("wazuh-manager", max_length=255)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_log: str = Field("", max_length=65536)
    rule_groups: list[str] = Field(default_factory=list)
    raw: dict[str, Any] | None = Field(default=None, description="Original SIEM document.")

    @model_validator(mode="before")
    @classmethod
    def _flatten_wazuh_alert(cls, data: Any) -> Any:
        if not isinstance(data, dict) or not isinstance(data.get("rule"), dict):
            return data
        return {
            "rule_id": _dig(data, "rule.id"),
            "rule_level": _dig(data, "rule.level"),
            "description": _dig(data, "rule.description") or "",
            "rule_groups": _dig(data, "rule.groups") or [],
            "source_ip": _dig(data, "data.srcip"),
            "agent_id": _dig(data, "agent.id") or "000",
            "agent_name": _dig(data, "agent.name") or "wazuh-manager",
            "timestamp": data.get("timestamp") or datetime.now(UTC),
            "raw_log": data.get("full_log") or "",
            "raw": data,
        }

    @field_validator("source_ip", mode="before")
    @classmethod
    def _empty_ip_is_none(cls, value: Any) -> Any:
        return None if value in ("", "-", "unknown") else value

    @field_validator("timestamp")
    @classmethod
    def _ensure_tz(cls, value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def to_context(self) -> dict[str, Any]:
        """Flat variable namespace used by playbook conditions and templates."""
        return {
            "rule_id": self.rule_id,
            "rule_level": self.rule_level,
            "description": self.description,
            "source_ip": str(self.source_ip) if self.source_ip else None,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "timestamp": self.timestamp.isoformat(),
            "raw_log": self.raw_log,
            "rule_groups": list(self.rule_groups),
            "raw": self.raw or {},
        }


class IngestResponse(BaseModel):
    alert_id: int
    matched_playbooks: list[str]
    incident_ids: list[str]
    processing_ms: float


class ExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action_name: str
    responder: str
    target: str
    params: dict[str, Any]
    status: ExecutionStatus
    attempts: int
    status_code: int | None
    response: dict[str, Any]
    error: str | None
    started_at: datetime
    finished_at: datetime | None


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    playbook_id: str
    playbook_name: str
    threat_type: str
    severity: int
    status: IncidentStatus
    status_reason: str | None
    source_ip: str | None
    agent_id: str
    agent_name: str
    parsed_vars: dict[str, Any]
    alert_count: int
    correlated_events: int
    alert_received_at: datetime
    playbook_triggered_at: datetime
    hitl_sent_at: datetime | None
    hitl_deadline: datetime | None
    hitl_channels: list[str]
    decision: str | None
    decision_by: str | None
    decision_at: datetime | None
    execution_started_at: datetime | None
    execution_completed_at: datetime | None


class IncidentDetail(IncidentOut):
    trigger_payload: dict[str, Any]
    executions: list[ExecutionOut]


class TimelineEvent(BaseModel):
    stage: str
    timestamp: datetime | None
    elapsed_ms: float | None = Field(None, description="Milliseconds since alert received.")


class IncidentTimeline(BaseModel):
    incident_id: str
    status: IncidentStatus
    events: list[TimelineEvent]
    ingest_to_hitl_ms: float | None


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    timestamp: datetime
    incident_id: str | None
    event_type: str
    actor: str
    data: dict[str, Any]
    prev_hash: str
    hash: str


class AuditVerification(BaseModel):
    valid: bool
    entries_checked: int
    head_hash: str | None
    first_invalid_seq: int | None = None
    reason: str | None = None


class DecisionResult(BaseModel):
    incident_id: str
    decision: str
    status: IncidentStatus
    message: str
