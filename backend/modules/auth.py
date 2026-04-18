"""
auth.py — Lightweight API-key authentication for agent endpoints.

Design
------
The web UI is deliberately **unauthenticated** so the graduation demo and live
Render deployment remain easy to showcase. Only endpoints intended for the
remote CLI agent require an API key.

The key is validated against the ``AGENT_API_KEY`` environment variable using a
constant-time comparison (hmac.compare_digest) to defeat timing attacks.

Usage in FastAPI
----------------
    from modules.auth import require_agent_api_key

    @app.post("/api/agent/upload")
    async def agent_upload(
        ...,
        _: None = Depends(require_agent_api_key),
    ):
        ...

If ``AGENT_API_KEY`` is not set, the dependency rejects every call to agent
endpoints with a 503 — this is safer than silently allowing anonymous access.

Multiple keys
-------------
For teams you can set AGENT_API_KEY to a comma-separated list
("key1,key2,key3"); any one of them will authenticate.
"""

from __future__ import annotations

import hmac
import os
from typing import List

from fastapi import Header, HTTPException, status


def _load_valid_keys() -> List[str]:
    """Read the env var at request-time so rotations without restart work."""
    raw = os.getenv("AGENT_API_KEY", "").strip()
    if not raw:
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


async def require_agent_api_key(
    x_api_key: str = Header(
        default="",
        alias="X-API-Key",
        description="API key issued to the forensic agent CLI.",
    ),
) -> None:
    """
    FastAPI dependency. Raises HTTPException on invalid or missing key;
    returns None otherwise (so the route sees it only as a gate).
    """
    valid_keys = _load_valid_keys()

    if not valid_keys:
        # Fail closed — don't allow agent traffic if the server was started
        # without any configured keys.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Agent endpoint disabled: no AGENT_API_KEY configured on the "
                "server. Set it in backend/.env and restart."
            ),
        )

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
        )

    # Constant-time compare against every allowed key.
    for k in valid_keys:
        if hmac.compare_digest(k, x_api_key):
            return None

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid API key.",
    )
