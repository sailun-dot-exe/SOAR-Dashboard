"""Module E: incident records and lifecycle timeline."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from app.dependencies import SessionDep, require_admin_token
from app.models.orm import Incident, IncidentStatus
from app.models.schemas import IncidentDetail, IncidentOut, IncidentTimeline, TimelineEvent

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"],
                   dependencies=[Depends(require_admin_token)])


@router.get("", response_model=list[IncidentOut])
async def list_incidents(
    session: SessionDep,
    status_filter: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    source_ip: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> list[Incident]:
    query = select(Incident).order_by(Incident.playbook_triggered_at.desc()).limit(limit)
    if status_filter:
        query = query.where(Incident.status == status_filter)
    if source_ip:
        query = query.where(Incident.source_ip == source_ip)
    return list(await session.scalars(query))


async def _get(session: SessionDep, incident_id: str) -> Incident:
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    return incident


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: str, session: SessionDep) -> Incident:
    return await _get(session, incident_id)


@router.get("/{incident_id}/timeline", response_model=IncidentTimeline)
async def get_timeline(incident_id: str, session: SessionDep) -> IncidentTimeline:
    inc = await _get(session, incident_id)
    start = inc.alert_received_at
    stages = [
        ("alert_received", inc.alert_received_at),
        ("playbook_triggered", inc.playbook_triggered_at),
        ("hitl_notification_sent", inc.hitl_sent_at),
        (f"admin_decision:{inc.decision}" if inc.decision else "admin_decision", inc.decision_at),
        ("execution_started", inc.execution_started_at),
        ("execution_completed", inc.execution_completed_at),
    ]
    events = [TimelineEvent(stage=name, timestamp=ts,
                            elapsed_ms=round((ts - start).total_seconds() * 1000, 2)
                            if ts else None) for name, ts in stages]
    hitl_ms = (round((inc.hitl_sent_at - start).total_seconds() * 1000, 2)
               if inc.hitl_sent_at else None)
    return IncidentTimeline(incident_id=inc.id, status=inc.status, events=events,
                            ingest_to_hitl_ms=hitl_ms)
