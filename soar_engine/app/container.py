"""Application service container (wired once at startup)."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.config import Settings
from app.db import Database
from app.services.audit import AuditService
from app.services.executor import ActionExecutor
from app.services.incident_service import IncidentService
from app.services.notifier import Notifier
from app.services.playbook_engine import PlaybookEngine
from app.services.responders.base import Responder
from app.services.responders.docker_isolation import DockerIsolationResponder
from app.services.responders.ssh_iptables import SshIptablesResponder
from app.services.responders.wazuh import WazuhActiveResponder, WazuhApiClient
from app.services.security import LinkSigner


@dataclass(slots=True)
class Container:
    settings: Settings
    db: Database
    audit: AuditService
    engine: PlaybookEngine
    incidents: IncidentService
    http: httpx.AsyncClient
    docker_http: httpx.AsyncClient
    wazuh: WazuhApiClient

    async def aclose(self) -> None:
        await self.incidents.drain(max_wait=5)
        await self.http.aclose()
        await self.docker_http.aclose()
        await self.wazuh.aclose()
        await self.db.dispose()


def build_container(
    settings: Settings, responders: dict[str, Responder] | None = None
) -> Container:
    db = Database(settings.database_url)
    audit = AuditService(db.session_factory)
    engine = PlaybookEngine(settings.playbook_dir)
    http = httpx.AsyncClient(timeout=settings.notification_timeout_seconds)
    docker_http = httpx.AsyncClient(base_url=settings.docker_api_url,
                                    timeout=settings.docker_request_timeout)
    wazuh = WazuhApiClient(settings)
    if responders is None:
        built: list[Responder] = [
            WazuhActiveResponder(wazuh),
            SshIptablesResponder(settings),
            DockerIsolationResponder(docker_http),
        ]
        responders = {r.name: r for r in built}
    executor = ActionExecutor(responders, settings.retry_max_retries,
                              settings.retry_backoff_seconds)
    incidents = IncidentService(settings, db.session_factory, audit, engine,
                                Notifier(settings, http), executor,
                                LinkSigner(settings.hitl_signing_key.get_secret_value()))
    return Container(settings, db, audit, engine, incidents, http, docker_http, wazuh)
