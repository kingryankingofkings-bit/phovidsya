"""Audit event route handlers."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query, Request

from ..auth import require_api_key

router = APIRouter()


@router.get("/events")
async def get_events(
    request: Request,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    _key: str = Depends(require_api_key),
) -> dict:
    """Return paginated signed events from the audit log, starting after the given index."""
    engine = request.app.state.engine
    audit_path = engine.audit.path

    all_events: list[dict] = []
    with audit_path.open("rb") as handle:
        for raw in handle:
            if raw.strip():
                all_events.append(json.loads(raw))

    page = all_events[after : after + limit]
    return {
        "total": len(all_events),
        "after": after,
        "count": len(page),
        "events": page,
    }
