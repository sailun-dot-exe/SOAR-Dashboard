"""Option A: Wazuh Manager REST API Active Response (JWT authenticated)."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

import httpx

from app.config import Settings
from app.services.responders.base import ResponderResult, validated_ip
from app.services.retry import PermanentError, RetryableError

logger = logging.getLogger(__name__)

_AGENT_ID = re.compile(r"^[0-9]{3,8}$")
_TOKEN_TTL_SECONDS = 800  # Wazuh default JWT lifetime is 900s


class WazuhApiClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.wazuh_api_url,
            verify=settings.wazuh_verify_ssl,
            timeout=settings.wazuh_request_timeout,
        )
        self._token: str | None = None
        self._token_expiry = 0.0
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _authenticate(self) -> str:
        async with self._lock:
            if self._token and time.monotonic() < self._token_expiry:
                return self._token
            response = await self._client.post(
                "/security/user/authenticate",
                auth=(self._settings.wazuh_api_user,
                      self._settings.wazuh_api_password.get_secret_value()),
            )
            if response.status_code == 401:
                raise PermanentError("Wazuh API authentication failed (bad credentials)", 401)
            if response.status_code >= 400:
                raise RetryableError(f"Wazuh API auth returned {response.status_code}")
            self._token = str(response.json()["data"]["token"])
            self._token_expiry = time.monotonic() + _TOKEN_TTL_SECONDS
            return self._token

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        token = await self._authenticate()
        response = await self._client.request(
            method, url, headers={"Authorization": f"Bearer {token}"}, **kwargs
        )
        if response.status_code == 401:
            self._token = None  # expired/revoked JWT: force re-auth on retry
            raise RetryableError("Wazuh API JWT rejected; re-authenticating")
        if response.status_code >= 500 or response.status_code == 429:
            raise RetryableError(f"Wazuh API {method} {url} returned {response.status_code}")
        return response

    async def agent_status(self, agent_id: str) -> str | None:
        response = await self.request("GET", "/agents",
                                      params={"agents_list": agent_id, "select": "status"})
        items = response.json().get("data", {}).get("affected_items", [])
        return str(items[0].get("status")) if items else None


class WazuhActiveResponder:
    name = "wazuh_active_response"

    def __init__(self, client: WazuhApiClient) -> None:
        self._client = client

    async def execute(self, params: dict[str, Any]) -> ResponderResult:
        agent_id = str(params.get("agent_id", ""))
        if not _AGENT_ID.match(agent_id):
            raise PermanentError(f"invalid agent_id: {agent_id!r}")
        srcip = validated_ip(params.get("srcip"))
        command = str(params.get("command", "!firewall-drop"))

        status = await self._client.agent_status(agent_id)
        if status != "active":
            raise PermanentError(f"agent {agent_id} is not active (status={status})", 409)

        body = {
            "command": command,
            "arguments": [str(a) for a in params.get("arguments", [])],
            "alert": {"data": {"srcip": srcip}},
        }
        response = await self._client.request(
            "PUT", "/active-response", params={"agents_list": agent_id}, json=body
        )
        payload: dict[str, Any] = response.json()
        if response.status_code >= 400:
            raise PermanentError(f"active response rejected: {payload}", response.status_code)
        data = payload.get("data", {})
        if data.get("failed_items") or not data.get("total_affected_items"):
            raise PermanentError(f"active response failed: {data.get('failed_items')}",
                                 response.status_code)
        return ResponderResult(target=f"agent:{agent_id}/{srcip}",
                               status_code=response.status_code, response=payload)
