"""SSE stream (§6 ``GET /stream``) — how the dashboard stays live.

Plain SSE (native ``EventSource``), not websockets. Event names and payloads come
straight from the pydantic event models, so ``alert.*`` carries an
``AlertSummary`` — never an ``AlertDetail``.

Two operational details that are easy to skip and fatal in a demo:

* A heartbeat comment every 15s. Render's proxy reaps idle connections and the
  dashboard would silently go dead with no error anywhere.
* Unsubscribe in a ``finally``. Without it every browser refresh leaks a queue and
  memory climbs for the whole demo.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import orjson
from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse, ServerSentEvent

from app.core.logging import get_logger
from app.deps import BusDep
from app.schemas import FlareEvent

log = get_logger(__name__)

router = APIRouter(tags=["stream"])

HEARTBEAT_SECONDS = 15
RETRY_MS = 3000


def _encode(event: FlareEvent) -> ServerSentEvent:
    """Serialize a typed event via orjson — never hand-built JSON strings."""
    payload = orjson.dumps(event.data.model_dump(mode="json")).decode()
    return ServerSentEvent(data=payload, event=event.event)


async def _events(bus: BusDep) -> AsyncIterator[ServerSentEvent]:
    """Yield events until the client goes away.

    Disconnect handling is deliberately NOT done with ``request.is_disconnected()``:
    ``EventSourceResponse`` already runs its own ``receive()`` listener for
    ``http.disconnect``, and a second concurrent consumer of the same ASGI receive
    channel violates the spec and can swallow the disconnect message outright.
    Instead we let sse-starlette cancel this generator, and unsubscribe in the
    ``finally`` — which covers clean exit, disconnect, and CancelledError alike.
    """
    subscription = bus.subscribe()
    log.info("stream.connected", subscribers=bus.subscriber_count)
    try:
        # Pin the client's reconnect backoff so EventSource behaves predictably.
        yield ServerSentEvent(comment="flare stream connected", retry=RETRY_MS)
        async for event in subscription:
            yield _encode(event)
    finally:
        subscription.close()
        log.info("stream.disconnected", subscribers=bus.subscriber_count)


@router.get("/stream")
async def stream(bus: BusDep) -> EventSourceResponse:
    return EventSourceResponse(
        _events(bus),
        ping=HEARTBEAT_SECONDS,
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


__all__ = ["router"]
