"""Module C: HITL approve / deny callbacks (signed GET links for Slack / e-mail)."""

from __future__ import annotations

import html
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.dependencies import ContainerDep
from app.models.schemas import DecisionResult
from app.services.security import constant_time_equals

router = APIRouter(prefix="/api/v1/actions", tags=["hitl"])


def _render(result: DecisionResult, request: Request) -> Response:
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(result.model_dump(mode="json"))
    color = {"approve": "#2e7d32", "deny": "#c62828"}.get(result.decision, "#555")
    body = f"""<!doctype html><html><head><title>SOAR {html.escape(result.incident_id)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:sans-serif;max-width:640px;margin:3em auto">
<h2 style="color:{color}">{html.escape(result.message)}</h2>
<p>Incident <code>{html.escape(result.incident_id)}</code> is now
<b>{html.escape(result.status.value)}</b>.</p></body></html>"""
    return HTMLResponse(body)


async def _decide(incident_id: str, decision: str, request: Request, container: ContainerDep,
                  exp: int | None, sig: str | None, admin_token: str | None) -> Response:
    settings = container.settings
    if constant_time_equals(admin_token, settings.admin_token.get_secret_value()):
        actor = "admin-api"
    elif exp is not None and sig and container.incidents.signer.verify(
            incident_id, decision, exp, sig):
        actor = f"hitl-link@{request.client.host if request.client else 'unknown'}"
    else:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid or expired approval link")

    try:
        applied, incident = await container.incidents.decide(
            incident_id, approve=decision == "approve", actor=actor)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc

    if applied:
        message = ("Mitigation approved - containment is executing"
                   if decision == "approve" else "Mitigation denied - no action will be taken")
    else:
        message = f"No change: incident already {incident.status.value}"
    result = DecisionResult(incident_id=incident_id, decision=decision,
                            status=incident.status, message=message)
    response = _render(result, request)
    if not applied:
        response.status_code = status.HTTP_409_CONFLICT
    return response


@router.get("/approve/{incident_id}", response_model=DecisionResult)
async def approve(
    incident_id: str, request: Request, container: ContainerDep,
    exp: Annotated[int | None, Query()] = None,
    sig: Annotated[str | None, Query(max_length=128)] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
) -> Response:
    return await _decide(incident_id, "approve", request, container, exp, sig, x_admin_token)


@router.get("/deny/{incident_id}", response_model=DecisionResult)
async def deny(
    incident_id: str, request: Request, container: ContainerDep,
    exp: Annotated[int | None, Query()] = None,
    sig: Annotated[str | None, Query(max_length=128)] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
) -> Response:
    return await _decide(incident_id, "deny", request, container, exp, sig, x_admin_token)
