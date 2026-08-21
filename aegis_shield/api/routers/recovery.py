"""Recovery and authorization route handlers."""

from __future__ import annotations

import secrets
import time
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from ..auth import require_api_key

router = APIRouter()

_challenges: dict[str, dict] = {}
_CHALLENGE_TTL_SECONDS = 120


class ChallengeRequest(BaseModel):
    action: str


class AuthorizeRequest(BaseModel):
    challenge_id: str
    token: str
    physical_presence: bool = False


class ExportRequest(BaseModel):
    target_sequence: int | None = None


@router.post("/challenge")
async def create_challenge(
    request: Request,
    body: ChallengeRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Issue a one-time challenge nonce for a named action."""
    challenge_id = secrets.token_hex(16)
    _challenges[challenge_id] = {
        "action": body.action,
        "issued_at": int(time.time()),
        "device_id": request.app.state.engine.journal.device_id,
    }
    now = int(time.time())
    expired = [k for k, v in _challenges.items() if now - v["issued_at"] > _CHALLENGE_TTL_SECONDS]
    for k in expired:
        del _challenges[k]
    return {
        "challenge_id": challenge_id,
        "action": body.action,
        "device_id": request.app.state.engine.journal.device_id,
        "expires_at": int(time.time()) + _CHALLENGE_TTL_SECONDS,
    }


@router.post("/authorize")
async def authorize_action(
    request: Request,
    body: AuthorizeRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Submit a signed authorization token for a previously issued challenge."""
    challenge = _challenges.pop(body.challenge_id, None)
    if challenge is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found or expired")

    engine = request.app.state.engine
    public_pem_path = request.app.state.public_key_path
    if not public_pem_path or not public_pem_path.exists():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No public key configured for token verification",
        )

    from ...core.tokens import TokenVerifier
    try:
        verifier = TokenVerifier(public_pem_path.read_bytes())
        engine.authorize_recovery(
            body.token,
            verifier,
            physical_presence=body.physical_presence,
        )
    except (RuntimeError, PermissionError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))

    return {"authorized": True, "state": engine.state.value}


@router.post("/recovery/export")
async def recovery_export(
    request: Request,
    body: ExportRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Create a read-only recovery export snapshot."""
    engine = request.app.state.engine
    journal = engine.journal
    target_seq = body.target_sequence if body.target_sequence is not None else journal.last_sequence

    if not 0 <= target_seq <= journal.last_sequence:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid target_sequence")

    snapshot_name = f"export-{int(time.time())}-seq{target_seq}"
    try:
        snapshot_path = journal.snapshot(snapshot_name)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    return {
        "snapshot_name": snapshot_name,
        "snapshot_path": str(snapshot_path),
        "target_sequence": target_seq,
        "device_id": journal.device_id,
    }
