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
    """Return storage sizing figures for the *hardware* design, not this host.

    These are static calculations for the FPGA/PCIe design described in
    docs/ARCHITECTURE.md (Gen 2, 4 lanes). They do not describe the throughput
    of this software deployment and must not be read as live device metrics.
    """
    from ...core.sizing import size_gen2_design

    engine: AegisEngine = request.app.state.engine
    result = size_gen2_design(  # PCIe Gen 2 x4 reference design
        lanes=4,
        logical_block_bytes=engine.journal.block_size,
        journal_bytes=engine.journal.blocks * engine.journal.block_size,
        sustained_unique_write_bytes_s=500 * 1024 * 1024,
        map_entry_bytes=32,
    )
    payload = result.to_dict()
    payload["model"] = "pcie-gen2-x4-hardware-design"
    payload["applies_to"] = (
        "hypothetical FPGA interposer described in docs/ARCHITECTURE.md; "
        "not a measurement of this software deployment"
    )
    return payload
