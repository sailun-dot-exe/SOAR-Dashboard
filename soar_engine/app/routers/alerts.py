"""Module A: webhook ingestion engine."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select

from app.dependencies import (
    ContainerDep,
    SessionDep,
    require_admin_token,
    require_siem_token,
)
from app.models.orm import Alert
from app.models.schemas import AlertIn, IngestResponse

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED,
             dependencies=[Depends(require_siem_token)])
async def ingest_alert(alert: AlertIn, container: ContainerDep) -> IngestResponse:
    """Receive an alert pushed by the Wazuh ``custom-soar`` integration."""
    return await container.incidents.ingest(alert)


@router.get("", dependencies=[Depends(require_admin_token)])
async def list_alerts(
    session: SessionDep,
    source_ip: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[dict[str, object]]:
    query = select(Alert).order_by(Alert.id.desc()).limit(limit)
    if source_ip:
        query = query.where(Alert.source_ip == source_ip)
    rows = await session.scalars(query)
    return [{"id": a.id, "received_at": a.received_at, "rule_id": a.rule_id,
             "rule_level": a.rule_level, "description": a.description,
             "source_ip": a.source_ip, "agent_id": a.agent_id, "agent_name": a.agent_name,
             "incident_id": a.incident_id} for a in rows]
