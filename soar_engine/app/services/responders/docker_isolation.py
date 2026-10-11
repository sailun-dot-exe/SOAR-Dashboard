"""Option B (container): isolate a container by disconnecting it from a Docker network."""

from __future__ import annotations

import re
from typing import Any

import httpx

from app.services.responders.base import ResponderResult
from app.services.retry import PermanentError, RetryableError

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")


class DockerIsolationResponder:
    name = "docker_network_disconnect"

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def execute(self, params: dict[str, Any]) -> ResponderResult:
        container = str(params.get("container", ""))
        if not _NAME.match(container):
            raise PermanentError(f"invalid container name: {container!r}")

        inspect = await self._client.get(f"/containers/{container}/json")
        if inspect.status_code == 404:
            raise PermanentError(f"container {container} not found", 404)
        if inspect.status_code >= 400:
            raise RetryableError(f"docker inspect returned {inspect.status_code}")
        attached = list(inspect.json().get("NetworkSettings", {}).get("Networks", {}).keys())

        requested = params.get("networks") or attached
        networks = [requested] if isinstance(requested, str) else list(requested)
        results: dict[str, int] = {}
        for network in networks:
            if not _NAME.match(str(network)):
                raise PermanentError(f"invalid network name: {network!r}")
            if network not in attached:
                results[str(network)] = 304
                continue
            response = await self._client.post(
                f"/networks/{network}/disconnect", json={"Container": container, "Force": True}
            )
            if response.status_code >= 500:
                raise RetryableError(f"docker disconnect returned {response.status_code}")
            if response.status_code >= 400:
                raise PermanentError(f"docker disconnect failed: {response.text}",
                                     response.status_code)
            results[str(network)] = response.status_code
        return ResponderResult(target=f"container:{container}", status_code=200,
                               response={"disconnected": results, "previously_attached": attached})
