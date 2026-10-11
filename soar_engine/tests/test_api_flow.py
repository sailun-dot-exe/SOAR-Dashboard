from __future__ import annotations

import asyncio
from datetime import timedelta
from urllib.parse import urlparse

import httpx
import pytest
from sqlalchemy import text, update
from sqlalchemy.exc import DBAPIError

from app.container import Container
from app.models.orm import Incident, utcnow
from tests.conftest import ADMIN_TOKEN, API_TOKEN, FakeResponder, ssh_alert

SIEM = {"X-SOAR-Token": API_TOKEN}
ADMIN = {"X-Admin-Token": ADMIN_TOKEN}


async def brute_force(client: httpx.AsyncClient, ip: str = "203.0.113.50",
                      level: int = 10) -> str:
    for _ in range(5):
        r = await client.post("/api/v1/alerts/ingest", json=ssh_alert(ip=ip), headers=SIEM)
        assert r.status_code == 202, r.text
        assert r.json()["incident_ids"] == []
    r = await client.post(
        "/api/v1/alerts/ingest", headers=SIEM,
        json=ssh_alert(rule_id=5712, level=level, ip=ip,
                       description="sshd: brute force trying to get access to the system."))
    body = r.json()
    assert body["matched_playbooks"] == ["ssh-bruteforce-containment"]
    assert len(body["incident_ids"]) == 1
    return str(body["incident_ids"][0])


def path_of(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.path}?{parsed.query}"


async def test_ingest_requires_token(client: httpx.AsyncClient) -> None:
    r = await client.post("/api/v1/alerts/ingest", json=ssh_alert())
    assert r.status_code == 401
    r = await client.post("/api/v1/alerts/ingest", json=ssh_alert(),
                          headers={"X-SOAR-Token": "wrong"})
    assert r.status_code == 401


async def test_ingest_rejects_malformed_payload(client: httpx.AsyncClient) -> None:
    bad = ssh_alert()
    bad["source_ip"] = "not-an-ip"
    r = await client.post("/api/v1/alerts/ingest", json=bad, headers=SIEM)
    assert r.status_code == 422


async def test_full_approve_flow(client: httpx.AsyncClient, container: Container,
                                 responders: dict[str, FakeResponder]) -> None:
    incident_id = await brute_force(client)
    await container.incidents.drain()

    notifier = container.incidents.notifier
    [request] = notifier.requests  # type: ignore[attr-defined]
    assert request.attacker_ip == "203.0.113.50"
    assert request.target_host == "target-victim"
    assert request.incident_id == incident_id

    r = await client.get(f"/api/v1/incidents/{incident_id}", headers=ADMIN)
    assert r.json()["status"] == "awaiting_approval"

    r = await client.get(path_of(request.approve_url), headers={"accept": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved"
    await container.incidents.drain()

    detail = (await client.get(f"/api/v1/incidents/{incident_id}", headers=ADMIN)).json()
    assert detail["status"] == "contained"
    assert detail["decision"] == "approve"
    [execution] = detail["executions"]
    assert execution["responder"] == "wazuh_active_response"
    assert execution["status"] == "success"
    assert responders["wazuh_active_response"].calls[0] == {
        "command": "!firewall-drop", "agent_id": "001", "srcip": "203.0.113.50",
        "host": "target-victim", "chain": "INPUT"}

    timeline = (await client.get(f"/api/v1/incidents/{incident_id}/timeline",
                                 headers=ADMIN)).json()
    stages = [e["stage"] for e in timeline["events"]]
    assert stages == ["alert_received", "playbook_triggered", "hitl_notification_sent",
                      "admin_decision:approve", "execution_started", "execution_completed"]
    assert all(e["timestamp"] for e in timeline["events"])
    assert timeline["ingest_to_hitl_ms"] < 2000

    # Second click is idempotent
    r = await client.get(path_of(request.approve_url), headers={"accept": "application/json"})
    assert r.status_code == 409

    audit = (await client.get("/api/v1/audit/verify", headers=ADMIN)).json()
    assert audit["valid"] is True
    events = [e["event_type"] for e in (await client.get(
        f"/api/v1/audit?incident_id={incident_id}", headers=ADMIN)).json()]
    assert events == ["playbook.triggered", "hitl.notification_sent", "hitl.decision",
                      "execution.started", "execution.action", "execution.completed"]


async def test_follow_up_alerts_attach_to_open_incident(client: httpx.AsyncClient,
                                                        container: Container) -> None:
    incident_id = await brute_force(client)
    r = await client.post("/api/v1/alerts/ingest", headers=SIEM,
                          json=ssh_alert(rule_id=5712, level=10))
    assert r.json()["incident_ids"] == [incident_id]
    incidents = (await client.get("/api/v1/incidents", headers=ADMIN)).json()
    assert len(incidents) == 1
    assert incidents[0]["alert_count"] == 2


async def test_deny_flow(client: httpx.AsyncClient, container: Container,
                         responders: dict[str, FakeResponder]) -> None:
    incident_id = await brute_force(client)
    await container.incidents.drain()
    [request] = container.incidents.notifier.requests  # type: ignore[attr-defined]
    r = await client.get(path_of(request.deny_url))
    assert r.status_code == 200
    assert "denied" in r.text
    await container.incidents.drain()
    detail = (await client.get(f"/api/v1/incidents/{incident_id}", headers=ADMIN)).json()
    assert detail["status"] == "denied"
    assert detail["executions"] == []
    assert responders["wazuh_active_response"].calls == []


async def test_forged_or_cross_used_signature_rejected(client: httpx.AsyncClient,
                                                       container: Container) -> None:
    incident_id = await brute_force(client)
    await container.incidents.drain()
    [request] = container.incidents.notifier.requests  # type: ignore[attr-defined]
    deny_query = urlparse(request.deny_url).query
    r = await client.get(f"/api/v1/actions/approve/{incident_id}?{deny_query}")
    assert r.status_code == 403
    r = await client.get(f"/api/v1/actions/approve/{incident_id}?exp=9999999999&sig=00")
    assert r.status_code == 403


async def test_timeout_defaults_to_safe_posture(client: httpx.AsyncClient,
                                                container: Container,
                                                responders: dict[str, FakeResponder]) -> None:
    incident_id = await brute_force(client, level=10)
    await container.incidents.drain()
    await _expire(container, incident_id)
    assert await container.incidents.sweep_timeouts() == 1
    await container.incidents.drain()
    detail = (await client.get(f"/api/v1/incidents/{incident_id}", headers=ADMIN)).json()
    assert detail["status"] == "expired"
    assert detail["decision"] == "timeout_safe_posture"
    assert responders["wazuh_active_response"].calls == []


async def test_timeout_auto_executes_above_level_12(client: httpx.AsyncClient,
                                                    container: Container) -> None:
    incident_id = await brute_force(client, level=13)
    await container.incidents.drain()
    await _expire(container, incident_id)
    await container.incidents.sweep_timeouts()
    await container.incidents.drain()
    detail = (await client.get(f"/api/v1/incidents/{incident_id}", headers=ADMIN)).json()
    assert detail["status"] == "contained"
    assert detail["decision"] == "timeout_auto_execute"


async def test_fallback_responder_when_agent_offline(
        client: httpx.AsyncClient, container: Container,
        responders: dict[str, FakeResponder]) -> None:
    responders["wazuh_active_response"].script = ["fail"]
    incident_id = await brute_force(client)
    await container.incidents.drain()
    r = await client.get(f"/api/v1/actions/approve/{incident_id}", headers=ADMIN)
    assert r.status_code == 200
    await container.incidents.drain()
    detail = (await client.get(f"/api/v1/incidents/{incident_id}", headers=ADMIN)).json()
    assert detail["status"] == "contained"
    assert [(e["responder"], e["status"], e["status_code"]) for e in detail["executions"]] == [
        ("wazuh_active_response", "failed", 409), ("ssh_iptables", "success", 200)]


async def test_retry_then_fail_marks_incident_failed(
        client: httpx.AsyncClient, container: Container,
        responders: dict[str, FakeResponder]) -> None:
    responders["wazuh_active_response"].script = ["retry"] * 10
    responders["ssh_iptables"].script = ["retry", "retry", "ok"]
    incident_id = await brute_force(client)
    await container.incidents.drain()
    await client.get(f"/api/v1/actions/approve/{incident_id}", headers=ADMIN)
    await container.incidents.drain()
    detail = (await client.get(f"/api/v1/incidents/{incident_id}", headers=ADMIN)).json()
    wazuh, ssh = detail["executions"]
    assert wazuh["attempts"] == 4  # initial + 3 retries
    assert wazuh["status"] == "failed"
    assert ssh["attempts"] == 3
    assert detail["status"] == "contained"

    responders["wazuh_active_response"].script = ["fail"]
    responders["ssh_iptables"].script = ["fail"]
    incident_id = await brute_force(client, ip="203.0.113.77")
    await container.incidents.drain()
    await client.get(f"/api/v1/actions/approve/{incident_id}", headers=ADMIN)
    await container.incidents.drain()
    detail = (await client.get(f"/api/v1/incidents/{incident_id}", headers=ADMIN)).json()
    assert detail["status"] == "failed"
    assert "failed on all responders" in detail["status_reason"]


async def test_protected_ip_is_never_blocked(client: httpx.AsyncClient,
                                             container: Container) -> None:
    incident_id = await brute_force(client, ip="10.99.1.1")
    await container.incidents.drain()
    detail = (await client.get(f"/api/v1/incidents/{incident_id}", headers=ADMIN)).json()
    assert detail["status"] == "suppressed"
    assert container.incidents.notifier.requests == []  # type: ignore[attr-defined]


async def test_audit_log_is_append_only(client: httpx.AsyncClient,
                                        container: Container) -> None:
    await brute_force(client)
    await container.incidents.drain()
    async with container.db.session_factory() as session:
        with pytest.raises(DBAPIError, match="append-only"):
            await session.execute(text("UPDATE audit_log SET actor='mallory' WHERE seq=1"))
        await session.rollback()
        # Bypass the trigger to simulate tampering at the storage layer.
        await session.execute(text("DROP TRIGGER audit_log_no_update"))
        await session.execute(text("UPDATE audit_log SET actor='mallory' WHERE seq=2"))
        await session.commit()
    result = (await client.get("/api/v1/audit/verify", headers=ADMIN)).json()
    assert result == {**result, "valid": False, "first_invalid_seq": 2}


async def test_concurrent_ingest_creates_single_incident(client: httpx.AsyncClient,
                                                         container: Container) -> None:
    alerts = [ssh_alert() for _ in range(5)] + [
        ssh_alert(rule_id=5712, level=10, description="sshd: brute force") for _ in range(5)]
    responses = await asyncio.gather(*(
        client.post("/api/v1/alerts/ingest", json=a, headers=SIEM) for a in alerts))
    ids = {i for r in responses for i in r.json()["incident_ids"]}
    assert len(ids) == 1


async def _expire(container: Container, incident_id: str) -> None:
    async with container.db.session_factory() as session:
        await session.execute(update(Incident).where(Incident.id == incident_id)
                              .values(hitl_deadline=utcnow() - timedelta(seconds=1)))
        await session.commit()
