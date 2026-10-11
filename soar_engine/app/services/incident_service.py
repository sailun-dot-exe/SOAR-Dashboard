"""Incident lifecycle orchestration: ingest -> playbook -> HITL gate -> execution."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Coroutine
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.models.orm import (
    OPEN_STATUSES,
    ActionExecution,
    Alert,
    ExecutionStatus,
    Incident,
    IncidentStatus,
    utcnow,
)
from app.models.schemas import AlertIn, IngestResponse
from app.playbooks.models import OnTimeout, Playbook
from app.services.audit import AuditService
from app.services.executor import ActionExecutor
from app.services.notifier import ApprovalRequest, Notifier
from app.services.playbook_engine import PlaybookEngine, PlaybookMatch
from app.services.security import LinkSigner

logger = logging.getLogger(__name__)


def _ms_between(start: datetime, end: datetime) -> float:
    return round((end - start).total_seconds() * 1000, 2)


class IncidentService:
    def __init__(
        self,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        audit: AuditService,
        engine: PlaybookEngine,
        notifier: Notifier,
        executor: ActionExecutor,
        signer: LinkSigner,
    ) -> None:
        self.settings = settings
        self._sessions = session_factory
        self.audit = audit
        self.engine = engine
        self.notifier = notifier
        self.executor = executor
        self.signer = signer
        self._tasks: set[asyncio.Task[Any]] = set()
        self._open_lock = asyncio.Lock()

    # ------------------------------------------------------------------ utils
    def spawn(self, coro: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task[Any]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logger.error("background task failed", exc_info=task.exception())

    async def drain(self, max_wait: float = 10.0) -> None:
        """Wait for in-flight background work (used by tests and graceful shutdown)."""
        deadline = time.monotonic() + max_wait
        while self._tasks and time.monotonic() < deadline:
            await asyncio.wait(set(self._tasks), timeout=max(0.0, deadline - time.monotonic()))

    def decision_links(self, incident: Incident) -> tuple[str, str]:
        base = self.settings.public_base_url.rstrip("/")
        deadline = incident.hitl_deadline or utcnow()
        expires = int(deadline.timestamp()) + 60
        links = []
        for decision in ("approve", "deny"):
            query = urlencode({"exp": expires,
                               "sig": self.signer.sign(incident.id, decision, expires)})
            links.append(f"{base}/api/v1/actions/{decision}/{incident.id}?{query}")
        return links[0], links[1]

    def _timeout_seconds(self, playbook: Playbook) -> int:
        return playbook.hitl.timeout_seconds or self.settings.hitl_timeout_seconds

    def _auto_level(self, playbook: Playbook | None) -> int:
        if playbook and playbook.hitl.auto_execute_above_level is not None:
            return playbook.hitl.auto_execute_above_level
        return self.settings.hitl_auto_execute_level

    # ----------------------------------------------------------------- ingest
    async def ingest(self, alert: AlertIn) -> IngestResponse:
        started = time.perf_counter()
        received_at = utcnow()
        context = alert.to_context()

        async with self._sessions() as session:
            row = Alert(
                received_at=received_at,
                rule_id=alert.rule_id,
                rule_level=alert.rule_level,
                rule_groups=alert.rule_groups,
                description=alert.description,
                source_ip=context["source_ip"],
                agent_id=alert.agent_id,
                agent_name=alert.agent_name,
                event_timestamp=alert.timestamp,
                raw_log=alert.raw_log,
                payload=alert.model_dump(mode="json"),
            )
            session.add(row)
            await session.commit()
            alert_id = row.id

        await self.audit.append(
            "alert.received",
            actor="siem",
            data={"alert_id": alert_id, "rule_id": alert.rule_id, "rule_level": alert.rule_level,
                  "source_ip": context["source_ip"], "agent_id": alert.agent_id,
                  "agent_name": alert.agent_name, "description": alert.description},
        )

        matches = await self.engine.evaluate(context)
        incident_ids: list[str] = []
        for match in matches:
            incident_id = await self._open_or_attach(match, alert, alert_id, received_at)
            if incident_id:
                incident_ids.append(incident_id)

        return IngestResponse(
            alert_id=alert_id,
            matched_playbooks=[m.playbook.id for m in matches],
            incident_ids=incident_ids,
            processing_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    async def _open_or_attach(
        self, match: PlaybookMatch, alert: AlertIn, alert_id: int, received_at: datetime
    ) -> str | None:
        playbook = match.playbook
        source_ip = str(alert.source_ip) if alert.source_ip else None
        async with self._open_lock, self._sessions() as session:
            window_start = received_at - timedelta(seconds=playbook.suppression_seconds)
            existing = await session.scalar(
                select(Incident)
                .where(Incident.playbook_id == playbook.id,
                       Incident.source_ip == source_ip,
                       Incident.agent_id == alert.agent_id,
                       or_(Incident.status.in_(OPEN_STATUSES),
                           Incident.playbook_triggered_at >= window_start))
                .order_by(Incident.playbook_triggered_at.desc())
                .limit(1)
            )
            if existing is not None:
                existing.alert_count += 1
                existing.correlated_events = max(existing.correlated_events,
                                                 match.correlated_events)
                await session.execute(update(Alert).where(Alert.id == alert_id)
                                      .values(incident_id=existing.id))
                await session.commit()
                logger.info("alert %s attached to existing incident %s", alert_id, existing.id)
                return existing.id

            incident = Incident(
                playbook_id=playbook.id,
                playbook_name=playbook.name,
                threat_type=playbook.threat_type,
                severity=alert.rule_level,
                status=IncidentStatus.TRIGGERED,
                source_ip=source_ip,
                agent_id=alert.agent_id,
                agent_name=alert.agent_name,
                parsed_vars=match.variables,
                trigger_payload=alert.model_dump(mode="json"),
                correlated_events=match.correlated_events,
                alert_received_at=received_at,
                playbook_triggered_at=utcnow(),
            )
            session.add(incident)
            await session.flush()
            await session.execute(update(Alert).where(Alert.id == alert_id)
                                  .values(incident_id=incident.id))

            protected = source_ip is not None and self.settings.is_protected_ip(source_ip)
            if protected:
                incident.status = IncidentStatus.SUPPRESSED
                incident.status_reason = f"source IP {source_ip} is in a protected network"
            elif playbook.hitl.enabled:
                incident.status = IncidentStatus.AWAITING_APPROVAL
                incident.hitl_deadline = utcnow() + timedelta(
                    seconds=self._timeout_seconds(playbook))
            else:
                incident.status = IncidentStatus.AUTO_APPROVED
                incident.decision = "auto"
                incident.decision_by = "playbook-policy"
                incident.decision_at = utcnow()
            await session.commit()

        await self.audit.append(
            "playbook.triggered",
            incident_id=incident.id,
            data={"playbook_id": playbook.id, "alert_id": alert_id,
                  "parsed_vars": match.variables, "correlated_events": match.correlated_events,
                  "status": incident.status.value},
        )
        if incident.status is IncidentStatus.SUPPRESSED:
            await self.audit.append("playbook.suppressed", incident_id=incident.id,
                                    data={"reason": incident.status_reason})
        elif incident.status is IncidentStatus.AWAITING_APPROVAL:
            self.spawn(self.dispatch_hitl(incident.id))
        else:
            self.spawn(self.execute(incident.id))
        return incident.id

    # ------------------------------------------------------------------- HITL
    async def dispatch_hitl(self, incident_id: str) -> None:
        async with self._sessions() as session:
            incident = await session.get(Incident, incident_id)
            if incident is None:
                return
            playbook = self.engine.get(incident.playbook_id)
            approve_url, deny_url = self.decision_links(incident)
            timeout = self._timeout_seconds(playbook) if playbook else \
                self.settings.hitl_timeout_seconds
            auto = incident.severity > self._auto_level(playbook) or (
                playbook is not None and playbook.hitl.on_timeout is OnTimeout.EXECUTE)
            request = ApprovalRequest(
                incident_id=incident.id,
                threat_type=incident.threat_type,
                playbook_name=incident.playbook_name,
                target_host=incident.agent_name,
                agent_id=incident.agent_id,
                attacker_ip=incident.source_ip,
                severity=incident.severity,
                correlated_events=incident.correlated_events,
                planned_actions=[a.name for a in playbook.actions] if playbook else [],
                approve_url=approve_url,
                deny_url=deny_url,
                timeout_seconds=timeout,
                timeout_policy="AUTO-EXECUTE" if auto else "DENY (safe posture)",
            )

        results = await self.notifier.dispatch(request)
        sent_at = utcnow()
        delivered = [name for name, error in results.items() if error is None]
        async with self._sessions() as session:
            incident = await session.get(Incident, incident_id)
            if incident is None:
                return
            incident.hitl_sent_at = sent_at
            incident.hitl_channels = delivered
            await session.commit()
            latency = _ms_between(incident.alert_received_at, sent_at)

        event = "hitl.notification_sent" if delivered else "hitl.notification_failed"
        await self.audit.append(event, incident_id=incident_id,
                                data={"channels": results, "ingest_to_hitl_ms": latency})
        log = logger.info if latency < 2000 else logger.warning
        log("HITL for %s dispatched via %s in %.1f ms", incident_id, delivered, latency)

    async def decide(self, incident_id: str, approve: bool, actor: str) -> tuple[bool, Incident]:
        """Atomically record an admin decision. Returns (applied, incident)."""
        new_status = IncidentStatus.APPROVED if approve else IncidentStatus.DENIED
        now = utcnow()
        async with self._sessions() as session:
            result = await session.execute(
                update(Incident)
                .where(Incident.id == incident_id,
                       Incident.status == IncidentStatus.AWAITING_APPROVAL)
                .values(status=new_status, decision="approve" if approve else "deny",
                        decision_by=actor, decision_at=now, updated_at=now)
            )
            await session.commit()
            applied = bool(getattr(result, "rowcount", 0))
            incident = await session.get(Incident, incident_id, populate_existing=True)
        if incident is None:
            raise LookupError(incident_id)
        if applied:
            await self.audit.append("hitl.decision", incident_id=incident_id, actor=actor,
                                    data={"decision": incident.decision,
                                          "status": new_status.value})
            if approve:
                self.spawn(self.execute(incident_id))
        return applied, incident

    async def sweep_timeouts(self) -> int:
        now = utcnow()
        async with self._sessions() as session:
            expired = list(await session.scalars(
                select(Incident).where(Incident.status == IncidentStatus.AWAITING_APPROVAL,
                                       Incident.hitl_deadline <= now)))
        handled = 0
        for incident in expired:
            playbook = self.engine.get(incident.playbook_id)
            auto = incident.severity > self._auto_level(playbook) or (
                playbook is not None and playbook.hitl.on_timeout is OnTimeout.EXECUTE)
            status = IncidentStatus.AUTO_APPROVED if auto else IncidentStatus.EXPIRED
            decision = "timeout_auto_execute" if auto else "timeout_safe_posture"
            async with self._sessions() as session:
                result = await session.execute(
                    update(Incident)
                    .where(Incident.id == incident.id,
                           Incident.status == IncidentStatus.AWAITING_APPROVAL)
                    .values(status=status, decision=decision, decision_by="hitl-timeout",
                            decision_at=now, updated_at=now,
                            status_reason=None if auto else
                            "no decision within HITL window; no action taken")
                )
                await session.commit()
            if not getattr(result, "rowcount", 0):
                continue
            handled += 1
            await self.audit.append("hitl.timeout", incident_id=incident.id,
                                    actor="hitl-timeout",
                                    data={"decision": decision, "severity": incident.severity,
                                          "auto_execute_above_level":
                                              self._auto_level(playbook)})
            if auto:
                self.spawn(self.execute(incident.id))
        return handled

    # -------------------------------------------------------------- execution
    async def execute(self, incident_id: str) -> None:
        now = utcnow()
        async with self._sessions() as session:
            result = await session.execute(
                update(Incident)
                .where(Incident.id == incident_id,
                       Incident.status.in_([IncidentStatus.APPROVED,
                                            IncidentStatus.AUTO_APPROVED]))
                .values(status=IncidentStatus.EXECUTING, execution_started_at=now,
                        updated_at=now)
            )
            await session.commit()
            if not getattr(result, "rowcount", 0):
                logger.info("incident %s not in an executable state; skipping", incident_id)
                return
            incident = await session.get(Incident, incident_id, populate_existing=True)
        assert incident is not None
        await self.audit.append("execution.started", incident_id=incident_id)

        playbook = self.engine.get(incident.playbook_id)
        variables = dict(incident.parsed_vars)
        success = playbook is not None
        reason: str | None = None if playbook else "playbook no longer loaded"

        for action in playbook.actions if playbook else []:
            records = await self.executor.run_action(action, variables)
            async with self._sessions() as session:
                for rec in records:
                    session.add(ActionExecution(
                        incident_id=incident_id, action_name=rec.action_name,
                        responder=rec.responder, target=rec.target, params=rec.params,
                        status=rec.status, attempts=rec.attempts, status_code=rec.status_code,
                        response=rec.response, error=rec.error, started_at=rec.started_at,
                        finished_at=rec.finished_at))
                await session.commit()
            for rec in records:
                await self.audit.append(
                    "execution.action", incident_id=incident_id,
                    data={"action": rec.action_name, "responder": rec.responder,
                          "target": rec.target, "status": rec.status.value,
                          "status_code": rec.status_code, "attempts": rec.attempts,
                          "error": rec.error})
            succeeded = any(r.status is ExecutionStatus.SUCCESS for r in records)
            if not succeeded and not action.continue_on_failure:
                success = False
                reason = f"action '{action.name}' failed on all responders"
                break

        completed = utcnow()
        final = IncidentStatus.CONTAINED if success else IncidentStatus.FAILED
        async with self._sessions() as session:
            await session.execute(
                update(Incident).where(Incident.id == incident_id)
                .values(status=final, status_reason=reason, execution_completed_at=completed,
                        updated_at=completed))
            await session.commit()
        await self.audit.append("execution.completed", incident_id=incident_id,
                                data={"status": final.value, "reason": reason})
        logger.info("incident %s execution finished: %s", incident_id, final.value)
