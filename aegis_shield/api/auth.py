"""API key authentication middleware for Aegis Shield."""

from __future__ import annotations

import hashlib
import os
import secrets
from typing import Optional

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_ACTIVE_KEY: Optional[str] = None


def get_active_key() -> str:
    global _ACTIVE_KEY
    if _ACTIVE_KEY is None:
        env_key = os.environ.get("AEGIS_API_KEY")
        if env_key:
            _ACTIVE_KEY = env_key
        else:
            _ACTIVE_KEY = secrets.token_hex(32)
            # Never log the key itself: stdout reaches journald/docker logs,
            # which are readable by more principals than the key should be.
            print(
                "[aegis-shield] No AEGIS_API_KEY set. Generated an ephemeral key "
                f"(sha256:{key_fingerprint(_ACTIVE_KEY)}). It changes on every "
                "restart — set AEGIS_API_KEY for a stable key."
            )
    return _ACTIVE_KEY


def key_fingerprint(key: str) -> str:
    """Return a short, non-reversible identifier for an API key."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


async def require_api_key(api_key: Optional[str] = Security(_API_KEY_HEADER)) -> str:
    """FastAPI dependency: validates X-API-Key header."""
    active = get_active_key()
    # compare_digest raises TypeError on non-ASCII str.  Starlette decodes header
    # bytes as latin-1, so any byte >= 0x80 would reach it and turn a failed auth
    # into an unauthenticated 500.  Compare bytes instead.
    supplied = None if api_key is None else api_key.encode("utf-8", "surrogateescape")
    if supplied is None or not secrets.compare_digest(supplied, active.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key
