from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.config import Settings
from app.container import Container, build_container
from app.main import create_app
from app.services.notifier import ApprovalRequest
from app.services.responders.base import ResponderResult
from app.services.retry import PermanentError, RetryableError

PLAYBOOK_DIR = Path(__file__).resolve().parent.parent / "playbooks"
API_TOKEN = "siem-token"
ADMIN_TOKEN = "admin-token"


class CapturingNotifier:
    def __init__(self) -> None:
        self.requests: list[ApprovalRequest] = []
        self.channels: list[Any] = []

    async def dispatch(self, request: ApprovalRequest) -> dict[str, str | None]:
        self.requests.append(request)
        return {"capture": None}


class FakeResponder:
    """Scriptable responder: ``script`` is a list of 'ok' | 'retry' | 'fail' per attempt."""

    def __init__(self, name: str, script: list[str] | None = None) -> None:
        self.name = name
        self.script = list(script or ["ok"])
        self.calls: list[dict[str, Any]] = []

    async def execute(self, params: dict[str, Any]) -> ResponderResult:
        self.calls.append(params)
        step = self.script.pop(0) if self.script else "ok"
        if step == "retry":
            raise RetryableError("transient")
        if step == "fail":
            raise PermanentError("agent offline", 409)
        return ResponderResult(target=f"fake:{params.get('srcip')}", status_code=200,
                               response={"ok": True})


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        api_token=API_TOKEN,
        admin_token=ADMIN_TOKEN,
        hitl_signing_key="signing-key",
        database_url=f"sqlite+aiosqlite:///{tmp_path}/soar.db",
        playbook_dir=PLAYBOOK_DIR,
        retry_backoff_seconds=0.001,
        protected_cidrs=["127.0.0.0/8", "10.99.0.0/16"],
        public_base_url="http://soar.test",
    )


@pytest.fixture
def responders() -> dict[str, FakeResponder]:
    return {
        "wazuh_active_response": FakeResponder("wazuh_active_response"),
        "ssh_iptables": FakeResponder("ssh_iptables"),
        "docker_network_disconnect": FakeResponder("docker_network_disconnect"),
    }


@pytest.fixture
async def container(settings: Settings,
                    responders: dict[str, FakeResponder]) -> AsyncIterator[Container]:
    c = build_container(settings, responders=dict(responders))  # type: ignore[arg-type]
    c.incidents.notifier = CapturingNotifier()  # type: ignore[assignment]
    await c.db.create_schema()
    c.engine.reload()
    yield c
    await c.aclose()


@pytest.fixture
async def client(settings: Settings, container: Container) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings, container)
    app.state.container = container
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://soar.test") as c:
        yield c


def ssh_alert(rule_id: int = 5710, level: int = 5, ip: str = "203.0.113.50",
              description: str = "sshd: Attempt to login using a non-existent user",
              groups: list[str] | None = None) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_level": level,
        "description": description,
        "source_ip": ip,
        "agent_id": "001",
        "agent_name": "target-victim",
        "timestamp": "2026-10-11T04:00:00.000+0000",
        "raw_log": f"sshd[123]: Invalid user admin from {ip} port 4242",
        "rule_groups": groups if groups is not None else ["syslog", "sshd", "invalid_login",
                                                          "authentication_failed"],
    }
