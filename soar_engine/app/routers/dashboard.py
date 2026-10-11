"""Operator dashboard (static single-page app backed by the admin APIs)."""

from __future__ import annotations

from functools import cache
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter(tags=["dashboard"], include_in_schema=False)

_PAGE = Path(__file__).resolve().parent.parent / "static" / "dashboard.html"


@cache
def _page() -> str:
    return _PAGE.read_text(encoding="utf-8")


@router.get("/")
async def root() -> RedirectResponse:
    return RedirectResponse("/dashboard")


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    return HTMLResponse(_page(), headers={
        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; "
                                   "style-src 'unsafe-inline'; connect-src 'self'",
        "Cache-Control": "no-store",
    })
