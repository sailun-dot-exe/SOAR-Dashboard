"""Playbook engine: trigger evaluation, sliding-window correlation and variable extraction."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.playbooks.conditions import _MISSING, evaluate, resolve_field
from app.playbooks.loader import load_playbooks
from app.playbooks.models import Playbook

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PlaybookMatch:
    playbook: Playbook
    variables: dict[str, Any]
    correlated_events: int


@dataclass(slots=True)
class SlidingWindowCounter:
    """In-memory per-key sliding window of event times (monotonic clock)."""

    _events: dict[tuple[str, str], deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )

    def add(self, key: tuple[str, str], window: float, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        bucket = self._events[key]
        bucket.append(now)
        return self._prune(bucket, window, now)

    def count(self, key: tuple[str, str], window: float, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        bucket = self._events.get(key)
        return self._prune(bucket, window, now) if bucket is not None else 0

    def reset(self, key: tuple[str, str]) -> None:
        self._events.pop(key, None)

    @staticmethod
    def _prune(bucket: deque[float], window: float, now: float) -> int:
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        return len(bucket)


class PlaybookEngine:
    def __init__(self, playbook_dir: Path) -> None:
        self._playbook_dir = playbook_dir
        self._playbooks: list[Playbook] = []
        self._counter = SlidingWindowCounter()
        self._lock = asyncio.Lock()

    @property
    def playbooks(self) -> list[Playbook]:
        return list(self._playbooks)

    def get(self, playbook_id: str) -> Playbook | None:
        return next((p for p in self._playbooks if p.id == playbook_id), None)

    def reload(self) -> list[Playbook]:
        self._playbooks = load_playbooks(self._playbook_dir)
        return self.playbooks

    def set_playbooks(self, playbooks: list[Playbook]) -> None:
        self._playbooks = list(playbooks)

    async def evaluate(
        self, context: dict[str, Any], now: float | None = None
    ) -> list[PlaybookMatch]:
        matches: list[PlaybookMatch] = []
        async with self._lock:
            for playbook in self._playbooks:
                if not playbook.enabled:
                    continue
                match = self._evaluate_one(playbook, context, now)
                if match is not None:
                    matches.append(match)
        return matches

    def _evaluate_one(
        self, playbook: Playbook, context: dict[str, Any], now: float | None
    ) -> PlaybookMatch | None:
        correlated = 0
        threshold = playbook.threshold
        if threshold is not None:
            group_value = resolve_field(context, threshold.group_by)
            if group_value is _MISSING or group_value is None:
                return None
            key = (playbook.id, str(group_value))
            if evaluate(threshold.count_when, context):
                correlated = self._counter.add(key, threshold.window_seconds, now)
            else:
                correlated = self._counter.count(key, threshold.window_seconds, now)

        if not evaluate(playbook.trigger, context):
            return None
        if threshold is not None and correlated <= threshold.gt:
            logger.info("playbook %s trigger matched but threshold not met (%d <= %d)",
                        playbook.id, correlated, threshold.gt)
            return None

        variables: dict[str, Any] = {}
        for name, path in playbook.extract.items():
            value = resolve_field(context, path)
            variables[name] = None if value is _MISSING else value
        missing = [f for f in playbook.required_fields
                   if resolve_field(context, f) in (_MISSING, None, "")]
        if missing:
            logger.warning("playbook %s matched but required fields missing: %s",
                           playbook.id, missing)
            return None
        return PlaybookMatch(playbook=playbook, variables=variables, correlated_events=correlated)
