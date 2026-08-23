"""FastAPI application for Aegis Shield."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .routers import events, recovery, status as status_router

WEB_DIR = Path(__file__).parent.parent.parent / "web"


def create_app(
    engine=None,
    public_key_path: Optional[Path] = None,
) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Aegis Shield",
        description=(
            "Hardware-grade ransomware isolation — software reference deployment. "
            "This is a reference/demonstration API; review docs/ARCHITECTURE.md "
            "for capability boundaries."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.state.engine = engine
    app.state.public_key_path = public_key_path
    app.state.challenges = {}

    # The dashboard is self-contained (no CDNs, no inline event handlers), so a
    # strict policy costs nothing and gives defence in depth behind the DOM-based
    # rendering in dashboard.js.
    _CSP = (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    app.include_router(status_router.router, prefix="/v1", tags=["status"])
    app.include_router(events.router, prefix="/v1", tags=["events"])
    app.include_router(recovery.router, prefix="/v1", tags=["recovery"])

    @app.get("/v1/health", tags=["status"])
    async def health() -> dict:
        """Unauthenticated health probe."""
        if app.state.engine is not None:
            return {"status": "ok", "state": app.state.engine.state.value}
        return {"status": "no_engine"}

    if WEB_DIR.exists():
        app.mount("/ui", StaticFiles(directory=str(WEB_DIR), html=True), name="dashboard")

        @app.get("/", include_in_schema=False)
        async def dashboard_root() -> RedirectResponse:
            """Send the bare host to the dashboard rather than a bare 404."""
            return RedirectResponse(url="/ui/")

    return app
