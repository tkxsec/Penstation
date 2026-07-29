"""A tiny in-process pub/sub bus.

The pipeline publishes status transitions and log lines; the server's SSE
endpoint subscribes and forwards them to the browser. Keeping this separate
means the pipeline doesn't know about HTTP and the server doesn't know about
docker.
"""
from __future__ import annotations

import asyncio
from typing import Any


class Bus:
    def __init__(self, maxsize: int = 1000) -> None:
        self.maxsize = maxsize
        self._subs: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self.maxsize)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, event: str, data: Any) -> None:
        msg = {"event": event, "data": data}
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass  # a slow consumer must not stall the build


# Process-wide bus.
bus = Bus()
