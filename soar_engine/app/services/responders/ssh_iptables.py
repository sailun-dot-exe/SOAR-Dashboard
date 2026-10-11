"""Option B (direct agent): drop a source IP via iptables over SSH."""

from __future__ import annotations

import re
from typing import Any

import asyncssh

from app.config import Settings
from app.services.responders.base import ResponderResult, validated_ip
from app.services.retry import PermanentError, RetryableError

_HOST = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


class SshIptablesResponder:
    name = "ssh_iptables"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def execute(self, params: dict[str, Any]) -> ResponderResult:
        host = str(params.get("host", ""))
        if not _HOST.match(host):
            raise PermanentError(f"invalid SSH host: {host!r}")
        ip = validated_ip(params.get("srcip"))
        chain = str(params.get("chain", "INPUT"))
        if chain not in {"INPUT", "FORWARD", "DOCKER-USER"}:
            raise PermanentError(f"unsupported chain: {chain}")
        binary = "ip6tables" if ":" in ip else "iptables"
        sudo = "" if self._settings.ssh_username == "root" else "sudo -n "
        rule = f"{chain} -s {ip} -j DROP -m comment --comment soar-block"
        command = f"{sudo}{binary} -C {rule} 2>/dev/null || {sudo}{binary} -I {rule}"

        s = self._settings
        try:
            async with asyncssh.connect(
                host,
                port=int(params.get("port", s.ssh_port)),
                username=s.ssh_username,
                client_keys=[str(s.ssh_key_path)] if s.ssh_key_path else None,
                password=s.ssh_password.get_secret_value() if s.ssh_password else None,
                known_hosts=str(s.ssh_known_hosts) if s.ssh_known_hosts else None,
                connect_timeout=s.ssh_connect_timeout,
            ) as conn:
                result = await conn.run(command, check=False, timeout=15)
        except asyncssh.PermissionDenied as exc:
            raise PermanentError(f"SSH authentication failed for {host}: {exc}", 401) from exc
        except (asyncssh.Error, OSError, TimeoutError) as exc:
            raise RetryableError(f"SSH connection to {host} failed: {exc}") from exc

        exit_status = result.exit_status if result.exit_status is not None else -1
        output = {"exit_status": exit_status, "command": command,
                  "stdout": str(result.stdout or "")[-2000:],
                  "stderr": str(result.stderr or "")[-2000:]}
        if exit_status != 0:
            raise PermanentError(f"iptables failed on {host}: {output['stderr']}", exit_status)
        return ResponderResult(target=f"{host}/{ip}", status_code=exit_status, response=output)
