"""API key authentication middleware for Aegis Shield."""

from __future__ import annotations

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
            print(f"[aegis-shield] No AEGIS_API_KEY set. Generated ephemeral key: {_ACTIVE_KEY}")
    return _ACTIVE_KEY


async def require_api_key(api_key: Optional[str] = Security(_API_KEY_HEADER)) -> str:
    """FastAPI dependency: validates X-API-Key header."""
    active = get_active_key()
    if api_key is None or not secrets.compare_digest(api_key, active):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key
