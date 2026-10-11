"""Health, readiness, playbook management and dependency checks."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies import ContainerDep, require_admin_token
from app.playbooks.loader import PlaybookLoadError

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
async def ready(container: ContainerDep) -> dict[str, Any]:
    try:
        await container.db.ping()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"database: {exc}") from exc
    return {"status": "ready", "playbooks": [p.id for p in container.engine.playbooks]}


@router.get("/api/v1/playbooks", dependencies=[Depends(require_admin_token)])
async def list_playbooks(container: ContainerDep) -> list[dict[str, Any]]:
    return [p.model_dump(mode="json", by_alias=True) for p in container.engine.playbooks]


@router.post("/api/v1/playbooks/reload", dependencies=[Depends(require_admin_token)])
async def reload_playbooks(container: ContainerDep) -> dict[str, Any]:
    try:
        loaded = container.engine.reload()
    except PlaybookLoadError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    await container.audit.append("playbooks.reloaded", actor="admin-api",
                                 data={"playbooks": [p.id for p in loaded]})
    return {"loaded": [p.id for p in loaded]}


@router.get("/api/v1/system/dependencies", dependencies=[Depends(require_admin_token)])
async def dependencies(container: ContainerDep) -> dict[str, Any]:
    """Probe external integrations (used by the e2e script and operators)."""
    result: dict[str, Any] = {
        "notification_channels": [c.name for c in container.incidents.notifier.channels]}
    try:
        response = await container.wazuh.request("GET", "/agents",
                                                 params={"select": "id,name,status,ip"})
        result["wazuh"] = {"ok": True,
                           "agents": response.json()["data"]["affected_items"]}
    except Exception as exc:
        result["wazuh"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    try:
        response = await container.docker_http.get("/_ping")
        result["docker"] = {"ok": response.status_code == 200}
    except Exception as exc:
        result["docker"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return result
