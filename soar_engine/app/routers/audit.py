"""Hash-chained audit trail access and verification."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.dependencies import ContainerDep, SessionDep, require_admin_token
from app.models.orm import AuditEntry
from app.models.schemas import AuditEntryOut, AuditVerification

router = APIRouter(prefix="/api/v1/audit", tags=["audit"],
                   dependencies=[Depends(require_admin_token)])


@router.get("", response_model=list[AuditEntryOut])
async def list_audit(
    session: SessionDep,
    incident_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
) -> list[AuditEntry]:
    query = select(AuditEntry).order_by(AuditEntry.seq).limit(limit)
    if incident_id:
        query = query.where(AuditEntry.incident_id == incident_id)
    return list(await session.scalars(query))


@router.get("/verify", response_model=AuditVerification)
async def verify_chain(session: SessionDep, container: ContainerDep) -> AuditVerification:
    return await container.audit.verify(session)
