"""Audit event route handlers."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request

from ..auth import require_api_key

router = APIRouter()


def _read_log_file(path: Path) -> list[dict]:
    """Read all valid JSON lines from a single log file."""
    events: list[dict] = []
    try:
        with path.open("rb") as handle:
            for raw in handle:
                if raw.strip():
                    events.append(json.loads(raw))
    except FileNotFoundError:
        pass
    return events


def _collect_all_events(audit_path: Path) -> list[dict]:
    """Collect events from all archive files (oldest first) then the active file.

    After rotation, audit events are split across numbered archives
    (``audit.1.jsonl``, ``audit.2.jsonl``, …) and the active
    ``audit.jsonl``.  Returning only the active file silently drops all
    rotated events, so we reconstruct the full ordered sequence here.
    """
    parent = audit_path.parent

    # Gather all numbered archives, e.g. audit.1.jsonl, audit.2.jsonl, …
    stem = audit_path.stem  # "audit"
    suffix = audit_path.suffix  # ".jsonl"
    archives: list[tuple[int, Path]] = []
    for candidate in parent.iterdir():
        if candidate == audit_path:
            continue
        # Expect names like "audit.N.jsonl"
        name = candidate.name
        if not name.startswith(stem + ".") or not name.endswith(suffix):
            continue
        middle = name[len(stem) + 1 : -len(suffix)]  # extract "N"
        if middle.isdigit():
            archives.append((int(middle), candidate))

    archives.sort(key=lambda pair: pair[0])

    all_events: list[dict] = []
    for _, archive_path in archives:
        all_events.extend(_read_log_file(archive_path))
    all_events.extend(_read_log_file(audit_path))
    return all_events


@router.get("/events")
async def get_events(
    request: Request,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    _key: str = Depends(require_api_key),
) -> dict:
    """Return paginated signed events from the audit log, starting after the given index.

    Events are returned in chronological order across all log files, including
    any archives produced by size-based rotation (``audit.1.jsonl``, etc.).
    """
    engine = request.app.state.engine
    audit_path = engine.audit.path

    all_events = _collect_all_events(audit_path)

    page = all_events[after : after + limit]
    return {
        "total": len(all_events),
        "after": after,
        "count": len(page),
        "events": page,
    }
