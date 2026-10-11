"""FastAPI application entry point."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import Settings, get_settings
from app.container import Container, build_container
from app.routers import actions, alerts, audit, dashboard, incidents, system

logger = logging.getLogger("soar")


async def _sweeper(container: Container) -> None:
    interval = container.settings.sweeper_interval_seconds
    while True:
        try:
            await container.incidents.sweep_timeouts()
        except Exception:
            logger.exception("HITL timeout sweeper iteration failed")
        await asyncio.sleep(interval)


def create_app(settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        c = container or build_container(settings)
        await c.db.create_schema()
        playbooks = c.engine.reload() if not c.engine.playbooks else c.engine.playbooks
        app.state.container = c
        await c.audit.append("system.startup",
                             data={"playbooks": [p.id for p in playbooks]})
        sweeper = asyncio.create_task(_sweeper(c))
        try:
            yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            await c.aclose()

    app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
    for router in (system.router, alerts.router, actions.router, incidents.router,
                   audit.router, dashboard.router):
        app.include_router(router)
    return app


def app_factory() -> FastAPI:
    return create_app()
