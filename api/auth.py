"""API key authentication and RLS user context injection."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import bcrypt
from fastapi import Depends, HTTPException, Request

from database import get_pool


@dataclass
class UserContext:
    """Authenticated user context, injected into route handlers."""

    id: str
    org_id: str
    display_name: str
    role: str  # admin | editor | commenter | viewer
    department: str | None
    source: str  # web_ui | agent | api
    key_type: str  # interactive | agent | api_integration | service


# Map key_type to source
_KEY_TYPE_TO_SOURCE = {
    "interactive": "web_ui",
    "agent": "agent",
    "api_integration": "api",
    # 'service' keys always act on behalf of a user via X-Act-As-User; the
    # effective source is therefore the target user's downstream context.
    # The fallback mapping below only applies when the service key is used
    # without an X-Act-As-User header (service-identity calls, rare).
    "service": "api",
}

# Cache for verified tokens: token -> (expires_at_timestamp, user_data_tuple)
# user_data_tuple: (key_id, key_type, user_id, org_id, display_name, role, department)
_TOKEN_AUTH_CACHE: dict[str, tuple[float, tuple[str, str, str, str, str, str, str | None]]] = {}
_LAST_USED_THROTTLE: dict[str, float] = {}
_AUTH_CACHE_TTL = 300.0  # 5 minutes


def _extract_bearer_token(request: Request) -> str:
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    return parts[1]


async def _throttle_last_used_update(key_id: str) -> None:
    """Update last_used_at at most once every 60s per key_id to eliminate row-lock contention."""
    now = time.time()
    last_updated = _LAST_USED_THROTTLE.get(key_id, 0.0)
    if now - last_updated >= 60.0:
        _LAST_USED_THROTTLE[key_id] = now
        try:
            pool = get_pool()
            async with pool.connection() as conn:
                await conn.execute(
                    "UPDATE api_keys SET last_used_at = %s WHERE id = %s",
                    (datetime.now(timezone.utc), key_id),
                )
        except Exception:
            pass


async def get_current_user(request: Request) -> UserContext:
    """FastAPI dependency that authenticates via API key and returns UserContext.

    Auth flow:
    1. Extract Bearer token from Authorization header
    2. Check in-memory verified token cache
    3. If cache miss:
         - Lookup api_keys by key_prefix (first 9 chars)
         - bcrypt verify full token in worker thread (non-blocking)
         - Populate in-memory cache
    4. Throttled update of last_used_at (max 1x per 60s per key)
    5. If X-Act-As-User header is present:
         - key_type must be 'service' (else 403)
         - load the target user row and return UserContext for *that* user
    6. Map key_type to source
    7. Return UserContext
    """
    token = _extract_bearer_token(request)

    if len(token) < 9:
        raise HTTPException(status_code=401, detail="Invalid API key")

    now = time.time()
    cached = _TOKEN_AUTH_CACHE.get(token)
    if cached and cached[0] > now:
        (
            key_id,
            key_type,
            user_id,
            org_id,
            display_name,
            role,
            department,
        ) = cached[1]
    else:
        # Cache miss or expired — query DB and verify bcrypt in worker thread
        key_prefix = token[:9]
        pool = get_pool()
        async with pool.connection() as conn:
            row = await conn.execute(
                """
                SELECT
                    ak.id AS key_id,
                    ak.key_hash,
                    ak.key_type,
                    ak.user_id,
                    u.org_id,
                    u.display_name,
                    u.role,
                    u.department
                FROM api_keys ak
                JOIN users u ON u.id = ak.user_id
                WHERE ak.key_prefix = %s
                  AND ak.is_revoked = FALSE
                  AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
                """,
                (key_prefix,),
            )
            result = await row.fetchone()

            if result is None:
                raise HTTPException(status_code=401, detail="Invalid or expired API key")

            (
                key_id,
                key_hash,
                key_type,
                user_id,
                org_id,
                display_name,
                role,
                department,
            ) = result

            # bcrypt verify in background thread so event loop never blocks
            is_valid = await asyncio.to_thread(
                bcrypt.checkpw,
                token.encode("utf-8"),
                key_hash.encode("utf-8"),
            )
            if not is_valid:
                raise HTTPException(status_code=401, detail="Invalid API key")

            # Store in cache
            if len(_TOKEN_AUTH_CACHE) > 2000:
                _TOKEN_AUTH_CACHE.clear()
            _TOKEN_AUTH_CACHE[token] = (
                now + _AUTH_CACHE_TTL,
                (
                    str(key_id),
                    key_type,
                    str(user_id),
                    str(org_id),
                    display_name,
                    role,
                    department,
                ),
            )

    # Throttled update of last_used_at in background task
    asyncio.create_task(_throttle_last_used_update(key_id))

    # ------------------------------------------------------------------
    # X-Act-As-User handling (service-role gate)
    # ------------------------------------------------------------------
    act_as_user_id = request.headers.get("X-Act-As-User")
    if act_as_user_id is not None:
        act_as_user_id = act_as_user_id.strip()
        if not act_as_user_id:
            raise HTTPException(
                status_code=400,
                detail="X-Act-As-User header present but empty",
            )

        if key_type != "service":
            raise HTTPException(
                status_code=403,
                detail=(
                    "X-Act-As-User header is only honored on service-role "
                    "API keys"
                ),
            )

        pool = get_pool()
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                SELECT id, org_id, display_name, role, department
                FROM users
                WHERE id = %s
                  AND is_active = TRUE
                """,
                (act_as_user_id,),
            )
            target = await cur.fetchone()
            if target is None:
                raise HTTPException(
                    status_code=404,
                    detail="X-Act-As-User target user not found or inactive",
                )

            (
                target_id,
                target_org_id,
                target_display_name,
                target_role,
                target_department,
            ) = target

            if str(target_org_id) != str(org_id):
                raise HTTPException(
                    status_code=403,
                    detail="X-Act-As-User target belongs to a different org",
                )

            request.state.user_org_id = str(target_org_id)
            request.state.user_id = str(target_id)

            return UserContext(
                id=str(target_id),
                org_id=str(target_org_id),
                display_name=target_display_name,
                role=target_role,
                department=target_department,
                source="api",
                key_type="service",
            )

    # ------------------------------------------------------------------
    # No X-Act-As-User header → normal self-auth path.
    # ------------------------------------------------------------------
    source = _KEY_TYPE_TO_SOURCE.get(key_type, "api")

    request.state.user_org_id = str(org_id)
    request.state.user_id = str(user_id)

    return UserContext(
        id=str(user_id),
        org_id=str(org_id),
        display_name=display_name,
        role=role,
        department=department,
        source=source,
        key_type=key_type,
    )
