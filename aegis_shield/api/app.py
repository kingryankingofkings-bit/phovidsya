"""FastAPI application for Aegis Shield."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI
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

    return app
