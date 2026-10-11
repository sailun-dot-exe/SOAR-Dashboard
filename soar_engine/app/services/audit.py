"""Hash-chained, append-only audit trail.

Each entry stores ``hash = sha256(canonical_json(prev_hash, timestamp, event, ...))`` so any
tampering with a historical row breaks verification of every subsequent row.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.orm import AuditEntry, utcnow
from app.models.schemas import AuditVerification

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def compute_hash(
    prev_hash: str,
    timestamp: datetime,
    event_type: str,
    incident_id: str | None,
    actor: str,
    data: dict[str, Any],
) -> str:
    canonical = json.dumps(
        {
            "prev_hash": prev_hash,
            "timestamp": timestamp.isoformat(),
            "event_type": event_type,
            "incident_id": incident_id,
            "actor": actor,
            "data": data,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._lock = asyncio.Lock()

    async def append(
        self,
        event_type: str,
        *,
        incident_id: str | None = None,
        actor: str = "soar-engine",
        data: dict[str, Any] | None = None,
    ) -> AuditEntry:
        payload = json.loads(json.dumps(data or {}, default=_json_default))
        async with self._lock:
            for attempt in range(5):
                async with self._session_factory() as session:
                    head = await session.scalar(
                        select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)
                    )
                    prev_hash = head.hash if head else GENESIS_HASH
                    timestamp = utcnow()
                    entry = AuditEntry(
                        timestamp=timestamp,
                        incident_id=incident_id,
                        event_type=event_type,
                        actor=actor,
                        data=payload,
                        prev_hash=prev_hash,
                        hash=compute_hash(
                            prev_hash, timestamp, event_type, incident_id, actor, payload
                        ),
                    )
                    session.add(entry)
                    try:
                        await session.commit()
                    except IntegrityError:
                        # Another writer (e.g. a second worker) extended the chain first.
                        await session.rollback()
                        logger.warning("audit chain contention, retry %d", attempt + 1)
                        continue
                    return entry
        raise RuntimeError("unable to append audit entry after 5 attempts")

    async def verify(self, session: AsyncSession) -> AuditVerification:
        prev_hash = GENESIS_HASH
        checked = 0
        result = await session.stream_scalars(select(AuditEntry).order_by(AuditEntry.seq))
        async for entry in result:
            checked += 1
            if entry.prev_hash != prev_hash:
                return AuditVerification(valid=False, entries_checked=checked,
                                         head_hash=prev_hash, first_invalid_seq=entry.seq,
                                         reason="prev_hash does not link to previous entry")
            expected = compute_hash(entry.prev_hash, entry.timestamp, entry.event_type,
                                    entry.incident_id, entry.actor, entry.data)
            if expected != entry.hash:
                return AuditVerification(valid=False, entries_checked=checked,
                                         head_hash=prev_hash, first_invalid_seq=entry.seq,
                                         reason="entry content does not match its hash")
            prev_hash = entry.hash
        return AuditVerification(valid=True, entries_checked=checked,
                                 head_hash=None if checked == 0 else prev_hash)
