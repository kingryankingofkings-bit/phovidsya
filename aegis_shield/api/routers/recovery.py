"""Recovery and authorization route handlers."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from ..auth import require_api_key

router = APIRouter()
log = logging.getLogger("aegis.api.recovery")

_CHALLENGE_TTL_SECONDS = 120
# Bounded so an authenticated caller cannot grow the store without limit inside
# the TTL window.  Oldest entries are evicted first.
_MAX_CHALLENGES = 256
# Snapshots are full copies of the base image; without a cap a caller could fill
# the volume the journal itself depends on.
_MAX_SNAPSHOTS = 32
# Actions a challenge may be issued for.
_ALLOWED_ACTIONS = frozenset({"enter_recovery_read_only", "enter_maintenance"})


def _challenge_store(request: Request) -> dict:
    """Per-application challenge store (never a module global)."""
    store = getattr(request.app.state, "challenges", None)
    if store is None:
        store = {}
        request.app.state.challenges = store
    return store


class ChallengeRequest(BaseModel):
    action: str


class AuthorizeRequest(BaseModel):
    challenge_id: str
    token: str
    # `physical_presence` is intentionally absent from the HTTP body.
    #
    # A network-supplied boolean cannot represent a physical security property.
    # Physical presence must be asserted by running:
    #
    #   echo "authorize <token>" | nc -U /run/aegis-shield/aegis.sock
    #
    # The Unix socket is only reachable by a local shell — that is the access
    # barrier that stands in for hardware physical-presence detection in this
    # software reference implementation.


class ExportRequest(BaseModel):
    target_sequence: int | None = None


@router.post("/challenge")
async def create_challenge(
    request: Request,
    body: ChallengeRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Issue a one-time challenge nonce for a named action."""
    if body.action not in _ALLOWED_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported action; expected one of {sorted(_ALLOWED_ACTIONS)}",
        )
    challenges = _challenge_store(request)
    now = int(time.time())
    for key in [
        k for k, v in challenges.items() if now - v["issued_at"] > _CHALLENGE_TTL_SECONDS
    ]:
        del challenges[key]
    while len(challenges) >= _MAX_CHALLENGES:
        challenges.pop(next(iter(challenges)))

    challenge_id = secrets.token_hex(16)
    challenges[challenge_id] = {
        "action": body.action,
        "issued_at": now,
        "device_id": request.app.state.engine.journal.device_id,
    }
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
    """Verify a signed token.

    This endpoint validates the token's signature and binding (device ID,
    action, state version, expiry) but does **not** complete recovery
    authorization by itself — physical presence must be separately asserted
    via the local Unix socket (``aegis.sock``).

    Returns ``{"token_valid": true}`` when the token passes all checks,
    ``{"token_valid": false, "detail": "..."}`` on any failure.
    """
    challenge = _challenge_store(request).pop(body.challenge_id, None)
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
        # Verify signature and claims only; do not transition state.
        verifier.verify(
            body.token,
            device_id=engine.journal.device_id,
            action="enter_recovery_read_only",
            state_version=engine.state_version,
        )
    except (RuntimeError, ValueError) as exc:
        return {"token_valid": False, "detail": str(exc)}

    return {
        "token_valid": True,
        "detail": (
            "Token verified. To complete recovery, assert physical presence via "
            "the local Unix socket: "
            "echo 'authorize <token>' | nc -U /run/aegis-shield/aegis.sock"
        ),
    }


@router.post("/recovery/export")
async def recovery_export(
    request: Request,
    body: ExportRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Create a read-only recovery export snapshot.

    Takes a point-in-time snapshot of the journal at *target_sequence* (defaults
    to the current head).  The snapshot directory contains the base image and
    journal log up to that sequence — enough to reconstruct the namespace state
    at that moment via ``DurableJournal.read(..., at_sequence=target_sequence)``.
    """
    engine = request.app.state.engine
    journal = engine.journal
    target_seq = body.target_sequence if body.target_sequence is not None else journal.last_sequence

    if not 0 <= target_seq <= journal.last_sequence:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid target_sequence")

    snapshot_root = journal.root / "snapshots"
    existing = sorted(p for p in snapshot_root.iterdir() if p.is_dir()) if snapshot_root.exists() else []
    if len(existing) >= _MAX_SNAPSHOTS:
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail=(
                f"snapshot limit reached ({_MAX_SNAPSHOTS}); remove old snapshots "
                "under the namespace's snapshots/ directory before exporting again"
            ),
        )

    # Nanosecond stamp plus random suffix: two exports in the same second, of the
    # same sequence, must both succeed rather than collide.
    snapshot_name = f"export-{time.time_ns()}-seq{target_seq}-{secrets.token_hex(3)}"
    try:
        snapshot_path = journal.snapshot(snapshot_name, at_sequence=target_seq)
    except FileExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="snapshot already exists"
        )
    except (OSError, ValueError) as exc:
        # Never return raw exception text: it leaks absolute filesystem paths.
        log.error("recovery export failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="snapshot could not be created",
        )

    # Build a per-file SHA-256 manifest so the recipient can verify the bundle
    # hasn't been tampered with in transit or at rest.
    file_hashes: dict[str, str] = {}
    for file in sorted(snapshot_path.iterdir()):
        if file.is_file():
            file_hashes[file.name] = hashlib.sha256(file.read_bytes()).hexdigest()

    manifest: dict = {
        "device_id": journal.device_id,
        "exported_at_ns": time.time_ns(),
        "files": file_hashes,
        "snapshot_name": snapshot_name,
        "target_sequence": target_seq,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
    (snapshot_path / "manifest.json").write_bytes(manifest_bytes)
    integrity_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

    engine.audit.append(
        "recovery_export",
        {
            "integrity_sha256": integrity_sha256,
            "snapshot_name": snapshot_name,
            "target_sequence": target_seq,
        },
    )

    return {
        "device_id": journal.device_id,
        "integrity_sha256": integrity_sha256,
        "note": (
"Snapshot contains base.img and journal.jsonl truncated at target_sequence. "
            "Open with DurableJournal(snapshot_path) and read(block, at_sequence=target_sequence). "
            "Verify integrity: re-hash snapshot files and compare against manifest.json."
        ),
        "snapshot_name": snapshot_name,
        "snapshot_path": str(snapshot_path),
        "target_sequence": target_seq,
    }
