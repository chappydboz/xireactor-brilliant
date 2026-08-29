"""Buffered background request logging middleware.

For every request (except /health and /static/*), records:
    endpoint (path template), method, status, response_bytes, approx_tokens,
    duration_ms, org_id, actor_id

Buffers entries into an asyncio.Queue and batches inserts into request_log
via a single background worker task, ensuring zero DB connection contention
with user requests. All logging failures are swallowed safely.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route
from starlette.types import ASGIApp

from database import get_pool

logger = logging.getLogger(__name__)

# Safe identifier pattern for SET LOCAL values (matches database._SAFE_VALUE)
_SAFE_VALUE = re.compile(r"^[\w\-\.]+$")

_MAX_ENDPOINT_LEN = 256
_MAX_QUEUE_SIZE = 10000
_BATCH_SIZE = 100

_log_queue: asyncio.Queue | None = None
_worker_task: asyncio.Task | None = None


def get_log_queue() -> asyncio.Queue:
    global _log_queue
    if _log_queue is None:
        _log_queue = asyncio.Queue(maxsize=_MAX_QUEUE_SIZE)
    return _log_queue


async def start_log_worker() -> None:
    """Start the background request log batch consumer task."""
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(_request_log_worker())


async def stop_log_worker() -> None:
    """Stop the background request log worker and flush remaining entries."""
    global _worker_task
    if _worker_task is not None:
        _worker_task.cancel()
        try:
            await _worker_task
        except (asyncio.CancelledError, Exception):
            pass
        _worker_task = None


async def _flush_log_batch(batch: list[dict[str, Any]]) -> None:
    """Write a batch of request logs to Postgres using a single connection grouped by org_id."""
    if not batch:
        return
    by_org: dict[str | None, list[tuple]] = {}
    for item in batch:
        org_id = item.get("org_id")
        row = (
            org_id,
            item.get("actor_id"),
            item.get("endpoint"),
            item.get("method"),
            item.get("status"),
            item.get("response_bytes"),
            item.get("approx_tokens"),
            item.get("duration_ms"),
        )
        by_org.setdefault(org_id, []).append(row)

    try:
        pool = get_pool()
        async with pool.connection() as conn:
            for org_id, rows in by_org.items():
                async with conn.transaction():
                    await conn.execute("SET LOCAL ROLE kb_admin")
                    if org_id is not None and _SAFE_VALUE.match(str(org_id)):
                        await conn.execute(f"SET LOCAL app.org_id = '{org_id}'")
                    async with conn.cursor() as cur:
                        await cur.executemany(
                            """
                            INSERT INTO request_log
                                (org_id, actor_id, endpoint, method, status,
                                 response_bytes, approx_tokens, duration_ms)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            rows,
                        )
    except Exception as exc:
        logger.warning("request_log batch insert failed (%d items): %s", len(batch), exc)


async def _request_log_worker() -> None:
    """Background task consuming log entries from queue and inserting in batches."""
    queue = get_log_queue()
    while True:
        try:
            # Wait for the first log entry
            item = await queue.get()
            batch = [item]
            queue.task_done()

            # Collect additional pending entries up to _BATCH_SIZE
            while len(batch) < _BATCH_SIZE and not queue.empty():
                try:
                    batch.append(queue.get_nowait())
                    queue.task_done()
                except asyncio.QueueEmpty:
                    break

            await _flush_log_batch(batch)
            await asyncio.sleep(0.01)

        except asyncio.CancelledError:
            # Drain remaining on shutdown
            remaining = []
            while not queue.empty():
                try:
                    remaining.append(queue.get_nowait())
                    queue.task_done()
                except asyncio.QueueEmpty:
                    break
            if remaining:
                try:
                    await _flush_log_batch(remaining)
                except Exception:
                    pass
            break
        except Exception as exc:
            logger.warning("request_log worker error: %s", exc)
            await asyncio.sleep(0.5)


def _resolve_endpoint(request: Request) -> str:
    """Return the matched route's path template, or raw path as fallback."""
    override = getattr(request.state, "log_endpoint", None)
    if isinstance(override, str) and override:
        path = override
    else:
        route = request.scope.get("route")
        if isinstance(route, Route):
            path = route.path
        else:
            path = request.url.path
    if len(path) > _MAX_ENDPOINT_LEN:
        path = path[:_MAX_ENDPOINT_LEN]
    return path


def _should_skip(path: str) -> bool:
    """Return True if this path should not be logged."""
    if path == "/health":
        return True
    if path.startswith("/static"):
        return True
    return False


class RequestLogMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that queues request metadata for batch DB logging."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Any):
        # Ensure the log worker is active
        if _worker_task is None or _worker_task.done():
            await start_log_worker()

        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = int((time.perf_counter() - start) * 1000)

        endpoint = _resolve_endpoint(request)
        if _should_skip(endpoint):
            return response

        content_length = response.headers.get("content-length")
        try:
            response_bytes = int(content_length) if content_length else None
        except (TypeError, ValueError):
            response_bytes = None
        approx_tokens = response_bytes // 4 if response_bytes else None

        org_id = getattr(request.state, "user_org_id", None)
        actor_id = getattr(request.state, "user_id", None)

        queue = get_log_queue()
        try:
            queue.put_nowait(
                {
                    "org_id": org_id,
                    "actor_id": actor_id,
                    "endpoint": endpoint,
                    "method": request.method,
                    "status": response.status_code,
                    "response_bytes": response_bytes,
                    "approx_tokens": approx_tokens,
                    "duration_ms": duration_ms,
                }
            )
        except asyncio.QueueFull:
            logger.warning("request_log queue is full, dropping entry")
        except Exception as exc:
            logger.warning("request_log enqueue failed: %s", exc)

        return response
