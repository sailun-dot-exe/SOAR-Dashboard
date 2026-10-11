"""HITL notification channels: Slack incoming webhook and SMTP e-mail."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

import aiosmtplib
import httpx

from app.config import Settings
from app.services.retry import RetryableError, retry_async

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class ApprovalRequest:
    incident_id: str
    threat_type: str
    playbook_name: str
    target_host: str
    agent_id: str
    attacker_ip: str | None
    severity: int
    correlated_events: int
    planned_actions: list[str]
    approve_url: str
    deny_url: str
    timeout_seconds: int
    timeout_policy: str


class NotificationChannel(Protocol):
    name: str

    async def send(self, request: ApprovalRequest) -> None: ...


def build_slack_payload(req: ApprovalRequest) -> dict[str, object]:
    fields = [
        ("Incident ID", req.incident_id),
        ("Threat Type", req.threat_type),
        ("Target Host", f"{req.target_host} (agent {req.agent_id})"),
        ("Attacker IP", req.attacker_ip or "n/a"),
        ("Severity", f"rule level {req.severity}"),
        ("Correlated events", str(req.correlated_events)),
    ]
    return {
        "text": f":rotating_light: SOAR approval required: {req.threat_type} "
                f"from {req.attacker_ip} on {req.target_host} ({req.incident_id})",
        "blocks": [
            {"type": "header",
             "text": {"type": "plain_text", "text": f"Approval required: {req.threat_type}"}},
            {"type": "section",
             "fields": [{"type": "mrkdwn", "text": f"*{k}:*\n{v}"} for k, v in fields]},
            {"type": "section",
             "text": {"type": "mrkdwn",
                      "text": f"*Planned actions:* {', '.join(req.planned_actions)}\n"
                              f"*Timeout:* {req.timeout_seconds}s, then `{req.timeout_policy}`"}},
            {"type": "actions",
             "elements": [
                 {"type": "button", "style": "primary", "url": req.approve_url,
                  "text": {"type": "plain_text", "text": "Approve Mitigation"}},
                 {"type": "button", "style": "danger", "url": req.deny_url,
                  "text": {"type": "plain_text", "text": "Deny Mitigation"}},
             ]},
        ],
    }


def build_email(req: ApprovalRequest, sender: str, recipients: list[str]) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"[SOAR] Approval required: {req.threat_type} - {req.incident_id}"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["X-SOAR-Incident"] = req.incident_id
    text = (
        f"Incident ID: {req.incident_id}\nThreat Type: {req.threat_type}\n"
        f"Target Host: {req.target_host} (agent {req.agent_id})\n"
        f"Attacker IP: {req.attacker_ip}\nSeverity: {req.severity}\n"
        f"Correlated events: {req.correlated_events}\n"
        f"Planned actions: {', '.join(req.planned_actions)}\n\n"
        f"Approve Mitigation: {req.approve_url}\nDeny Mitigation: {req.deny_url}\n\n"
        f"If no decision is made within {req.timeout_seconds}s the policy is: "
        f"{req.timeout_policy}.\n"
    )
    msg.set_content(text)
    msg.add_alternative(
        f"""<h2>SOAR approval required: {req.threat_type}</h2>
<table cellpadding="4">
<tr><td><b>Incident ID</b></td><td>{req.incident_id}</td></tr>
<tr><td><b>Threat Type</b></td><td>{req.threat_type}</td></tr>
<tr><td><b>Target Host</b></td><td>{req.target_host} (agent {req.agent_id})</td></tr>
<tr><td><b>Attacker IP</b></td><td>{req.attacker_ip}</td></tr>
<tr><td><b>Severity</b></td><td>rule level {req.severity}</td></tr>
<tr><td><b>Planned actions</b></td><td>{', '.join(req.planned_actions)}</td></tr>
</table>
<p><a href="{req.approve_url}" style="background:#2e7d32;color:#fff;padding:8px 14px;
text-decoration:none">Approve Mitigation</a>&nbsp;
<a href="{req.deny_url}" style="background:#c62828;color:#fff;padding:8px 14px;
text-decoration:none">Deny Mitigation</a></p>
<p>Timeout: {req.timeout_seconds}s, then <b>{req.timeout_policy}</b>.</p>""",
        subtype="html",
    )
    return msg


class SlackChannel:
    name = "slack"

    def __init__(self, webhook_url: str, client: httpx.AsyncClient) -> None:
        self._url = webhook_url
        self._client = client

    async def send(self, request: ApprovalRequest) -> None:
        response = await self._client.post(self._url, json=build_slack_payload(request))
        if response.status_code >= 500 or response.status_code == 429:
            raise RetryableError(f"slack returned {response.status_code}")
        response.raise_for_status()


class EmailChannel:
    name = "email"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def send(self, request: ApprovalRequest) -> None:
        s = self._settings
        assert s.smtp_host is not None
        message = build_email(request, s.smtp_from, s.smtp_to)
        try:
            await aiosmtplib.send(
                message,
                hostname=s.smtp_host,
                port=s.smtp_port,
                username=s.smtp_username,
                password=s.smtp_password.get_secret_value() if s.smtp_password else None,
                start_tls=s.smtp_starttls,
                timeout=s.notification_timeout_seconds,
            )
        except aiosmtplib.SMTPException as exc:
            raise RetryableError(f"smtp error: {exc}") from exc


class LogChannel:
    """Fallback when no channel is configured: approval links are written to the log."""

    name = "log"

    async def send(self, request: ApprovalRequest) -> None:
        logger.warning("HITL approval required for %s: approve=%s deny=%s",
                       request.incident_id, request.approve_url, request.deny_url)


class Notifier:
    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self._settings = settings
        self.channels: list[NotificationChannel] = []
        if settings.slack_webhook_url:
            self.channels.append(SlackChannel(settings.slack_webhook_url.get_secret_value(),
                                              client))
        if settings.smtp_host and settings.smtp_to:
            self.channels.append(EmailChannel(settings))
        if not self.channels:
            self.channels.append(LogChannel())

    async def dispatch(self, request: ApprovalRequest) -> dict[str, str | None]:
        """Send to every channel concurrently. Returns channel -> error (None on success)."""

        async def _one(channel: NotificationChannel) -> tuple[str, str | None]:
            try:
                await retry_async(
                    lambda: asyncio.wait_for(channel.send(request),
                                             self._settings.notification_timeout_seconds),
                    max_retries=self._settings.retry_max_retries,
                    backoff_seconds=self._settings.retry_backoff_seconds / 5,
                    label=f"notify:{channel.name}",
                )
                return channel.name, None
            except Exception as exc:
                logger.exception("notification via %s failed", channel.name)
                return channel.name, f"{type(exc).__name__}: {exc}"

        results = await asyncio.gather(*(_one(c) for c in self.channels))
        return dict(results)
