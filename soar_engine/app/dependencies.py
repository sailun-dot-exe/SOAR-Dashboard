from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.container import Container
from app.services.security import constant_time_equals


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


ContainerDep = Annotated[Container, Depends(get_container)]


async def get_session(container: ContainerDep) -> AsyncIterator[AsyncSession]:
    async with container.db.session_factory() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def require_siem_token(
    container: ContainerDep, x_soar_token: Annotated[str | None, Header()] = None
) -> None:
    expected = container.settings.api_token.get_secret_value()
    if not constant_time_equals(x_soar_token, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing X-SOAR-Token")


async def require_admin_token(
    container: ContainerDep, x_admin_token: Annotated[str | None, Header()] = None
) -> None:
    expected = container.settings.admin_token.get_secret_value()
    if not constant_time_equals(x_admin_token, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing X-Admin-Token")
