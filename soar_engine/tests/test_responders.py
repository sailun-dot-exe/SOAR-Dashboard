from __future__ import annotations

import httpx
import pytest
import respx

from app.config import Settings
from app.services.notifier import ApprovalRequest, build_email, build_slack_payload
from app.services.responders.docker_isolation import DockerIsolationResponder
from app.services.responders.wazuh import WazuhActiveResponder, WazuhApiClient
from app.services.retry import PermanentError, RetryableError, retry_async

WAZUH = "https://wazuh.test:55000"
PARAMS = {"agent_id": "001", "srcip": "172.28.0.66", "command": "!firewall-drop"}


def wazuh_settings(settings: Settings) -> Settings:
    return settings.model_copy(update={"wazuh_api_url": WAZUH})


def mock_auth(router: respx.MockRouter) -> respx.Route:
    return router.post(f"{WAZUH}/security/user/authenticate").respond(
        200, json={"data": {"token": "jwt-1"}})


def mock_agent(router: respx.MockRouter, status: str = "active") -> None:
    router.get(f"{WAZUH}/agents").respond(
        200, json={"data": {"affected_items": [{"id": "001", "status": status}]}})


@respx.mock
async def test_wazuh_active_response_success(settings: Settings) -> None:
    mock_auth(respx.mock)
    mock_agent(respx.mock)
    ar = respx.put(f"{WAZUH}/active-response").respond(
        200, json={"data": {"affected_items": ["001"], "total_affected_items": 1,
                            "failed_items": []}, "error": 0})
    client = WazuhApiClient(wazuh_settings(settings))
    result = await WazuhActiveResponder(client).execute(PARAMS)
    await client.aclose()
    assert result.status_code == 200
    request = ar.calls.last.request
    assert request.headers["Authorization"] == "Bearer jwt-1"
    assert request.url.params["agents_list"] == "001"
    assert b'"srcip":"172.28.0.66"' in request.content.replace(b" ", b"")


@respx.mock
async def test_wazuh_agent_offline_is_permanent(settings: Settings) -> None:
    mock_auth(respx.mock)
    mock_agent(respx.mock, status="disconnected")
    client = WazuhApiClient(wazuh_settings(settings))
    with pytest.raises(PermanentError, match="not active"):
        await WazuhActiveResponder(client).execute(PARAMS)
    await client.aclose()


@respx.mock
async def test_wazuh_bad_credentials_is_permanent(settings: Settings) -> None:
    respx.post(f"{WAZUH}/security/user/authenticate").respond(401)
    client = WazuhApiClient(wazuh_settings(settings))
    with pytest.raises(PermanentError, match="authentication failed"):
        await WazuhActiveResponder(client).execute(PARAMS)
    await client.aclose()


@respx.mock
async def test_wazuh_expired_jwt_reauthenticates_on_retry(settings: Settings) -> None:
    auth = mock_auth(respx.mock)
    respx.get(f"{WAZUH}/agents").mock(side_effect=[
        httpx.Response(401),
        httpx.Response(200, json={"data": {"affected_items": [{"status": "active"}]}})])
    respx.put(f"{WAZUH}/active-response").respond(
        200, json={"data": {"total_affected_items": 1, "failed_items": []}})
    client = WazuhApiClient(wazuh_settings(settings))
    responder = WazuhActiveResponder(client)
    outcome = await retry_async(lambda: responder.execute(PARAMS), backoff_seconds=0)
    await client.aclose()
    assert outcome.attempts == 2
    assert auth.call_count == 2


async def test_wazuh_rejects_injection_attempts(settings: Settings) -> None:
    client = WazuhApiClient(wazuh_settings(settings))
    responder = WazuhActiveResponder(client)
    with pytest.raises(PermanentError):
        await responder.execute({**PARAMS, "srcip": "1.2.3.4; rm -rf /"})
    with pytest.raises(PermanentError):
        await responder.execute({**PARAMS, "agent_id": "../001"})
    await client.aclose()


@respx.mock
async def test_docker_network_disconnect() -> None:
    respx.get("http://docker.test/containers/target-victim/json").respond(
        200, json={"NetworkSettings": {"Networks": {"soar-lab": {}, "bridge": {}}}})
    d1 = respx.post("http://docker.test/networks/soar-lab/disconnect").respond(200)
    d2 = respx.post("http://docker.test/networks/bridge/disconnect").respond(200)
    async with httpx.AsyncClient(base_url="http://docker.test") as http:
        result = await DockerIsolationResponder(http).execute({"container": "target-victim"})
    assert result.response["disconnected"] == {"soar-lab": 200, "bridge": 200}
    assert d1.called and d2.called


@respx.mock
async def test_docker_missing_container_is_permanent() -> None:
    respx.get("http://docker.test/containers/ghost/json").respond(404)
    async with httpx.AsyncClient(base_url="http://docker.test") as http:
        with pytest.raises(PermanentError):
            await DockerIsolationResponder(http).execute({"container": "ghost"})


async def test_retry_gives_up_after_three_retries() -> None:
    calls = 0

    async def flaky() -> None:
        nonlocal calls
        calls += 1
        raise RetryableError("boom")

    with pytest.raises(RetryableError):
        await retry_async(flaky, max_retries=3, backoff_seconds=0)
    assert calls == 4


def _request() -> ApprovalRequest:
    return ApprovalRequest(
        incident_id="INC-1", threat_type="SSH Brute Force", playbook_name="pb",
        target_host="target-victim", agent_id="001", attacker_ip="172.28.0.66", severity=10,
        correlated_events=8, planned_actions=["block-attacker-ip"],
        approve_url="http://soar/approve", deny_url="http://soar/deny", timeout_seconds=300,
        timeout_policy="DENY")


def test_slack_payload_contains_required_fields() -> None:
    payload = build_slack_payload(_request())
    flat = str(payload)
    for needle in ("INC-1", "SSH Brute Force", "target-victim", "172.28.0.66",
                   "http://soar/approve", "http://soar/deny", "Approve Mitigation"):
        assert needle in flat


def test_email_contains_links() -> None:
    msg = build_email(_request(), "soar@lab", ["secops@lab"])
    body = msg.get_body(preferencelist=("plain",))
    assert body is not None
    assert "http://soar/approve" in body.get_content()
