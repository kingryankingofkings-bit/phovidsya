"""Status and sizing route handlers."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ...core import AegisEngine
from ..auth import require_api_key

router = APIRouter()


@router.get("/status")
async def get_status(request: Request, _key: str = Depends(require_api_key)) -> dict:
    """Return device identity, state, health, and journal capacity."""
    engine: AegisEngine = request.app.state.engine
    status = engine.status()
    status["journal_capacity_blocks"] = engine.journal.blocks
    status["journal_block_size"] = engine.journal.block_size
    return status


@router.get("/sizing")
async def get_sizing(request: Request, _key: str = Depends(require_api_key)) -> dict:
    """Return storage sizing calculations for this journal."""
    from ...core.sizing import size_gen2_design

    engine: AegisEngine = request.app.state.engine
    result = size_gen2_design(
        lanes=4,
        logical_block_bytes=engine.journal.block_size,
        journal_bytes=engine.journal.blocks * engine.journal.block_size,
        sustained_unique_write_bytes_s=500 * 1024 * 1024,
        map_entry_bytes=32,
    )
    return result.to_dict()
