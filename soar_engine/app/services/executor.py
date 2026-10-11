"""Action executor: renders playbook params and runs responders with retry + fallback."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.orm import ExecutionStatus, utcnow
from app.playbooks.models import Action
from app.services.responders.base import Responder
from app.services.retry import PermanentError, retry_async

logger = logging.getLogger(__name__)

_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def render(value: Any, variables: dict[str, Any]) -> Any:
    """Substitute ``{var}`` placeholders; a lone placeholder keeps the variable's type."""
    if isinstance(value, dict):
        return {k: render(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, variables) for v in value]
    if not isinstance(value, str):
        return value

    def lookup(name: str) -> Any:
        if name not in variables or variables[name] is None:
            raise PermanentError(f"template variable '{name}' is not available")
        return variables[name]

    whole = _PLACEHOLDER.fullmatch(value)
    if whole:
        return lookup(whole.group(1))
    return _PLACEHOLDER.sub(lambda m: str(lookup(m.group(1))), value)


@dataclass(slots=True)
class ExecutionRecord:
    action_name: str
    responder: str
    target: str
    params: dict[str, Any]
    status: ExecutionStatus
    attempts: int
    status_code: int | None
    response: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None


class ActionExecutor:
    def __init__(self, responders: dict[str, Responder], max_retries: int,
                 backoff_seconds: float) -> None:
        self.responders = responders
        self._max_retries = max_retries
        self._backoff = backoff_seconds

    async def run_action(self, action: Action, variables: dict[str, Any]) -> list[ExecutionRecord]:
        """Try each responder in order until one succeeds. Returns one record per responder."""
        records: list[ExecutionRecord] = []
        try:
            params = render(action.params, variables)
        except PermanentError as exc:
            return [ExecutionRecord(action.name, "-", "-", dict(action.params),
                                    ExecutionStatus.FAILED, 0, None, error=str(exc),
                                    finished_at=utcnow())]

        for name in action.responders:
            responder = self.responders.get(name)
            started = utcnow()
            if responder is None:
                records.append(ExecutionRecord(action.name, name, "-", params,
                                               ExecutionStatus.SKIPPED, 0, None,
                                               error="responder not configured",
                                               started_at=started, finished_at=utcnow()))
                continue

            attempts = 0

            async def attempt(r: Responder = responder) -> Any:
                nonlocal attempts
                attempts += 1
                return await r.execute(params)

            try:
                outcome = await retry_async(attempt, max_retries=self._max_retries,
                                            backoff_seconds=self._backoff,
                                            label=f"{action.name}:{name}")
            except PermanentError as exc:
                records.append(ExecutionRecord(action.name, name, _target(params), params,
                                               ExecutionStatus.FAILED, attempts, exc.status_code,
                                               error=str(exc), started_at=started,
                                               finished_at=utcnow()))
                logger.warning("responder %s failed permanently: %s", name, exc)
                continue
            except Exception as exc:
                records.append(ExecutionRecord(action.name, name, _target(params), params,
                                               ExecutionStatus.FAILED, attempts, None,
                                               error=f"{type(exc).__name__}: {exc}",
                                               started_at=started, finished_at=utcnow()))
                logger.warning("responder %s exhausted retries: %s", name, exc)
                continue

            result = outcome.value
            records.append(ExecutionRecord(action.name, name, result.target, params,
                                           ExecutionStatus.SUCCESS, outcome.attempts,
                                           result.status_code, response=result.response,
                                           started_at=started, finished_at=utcnow()))
            break
        return records


def _target(params: dict[str, Any]) -> str:
    for key in ("agent_id", "host", "container"):
        if params.get(key):
            return f"{key}:{params[key]}"
    return "-"
