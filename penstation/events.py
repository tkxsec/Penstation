"""A tiny in-process pub/sub bus.

The pipeline publishes status transitions and log lines; the server's SSE
endpoint subscribes and forwards them to the browser. Keeping this separate
means the pipeline doesn't know about HTTP and the server doesn't know how tools
get installed.
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

    # Events that carry state rather than output. Losing one leaves the browser
    # showing something that is no longer true, with no way to notice.
    CRITICAL = frozenset({"status", "removed", "run_start", "run_done"})

    def publish(self, event: str, data: Any) -> None:
        msg = {"event": event, "data": data}
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                # A build emits thousands of log lines — far faster than a
                # browser drains them — so the queue fills and everything after
                # it was dropped, including the next tool's status. The UI then
                # froze on a stale card until a manual refresh.
                #
                # Log lines are cosmetic and refetchable from /tools/{id}/log,
                # so discard those to make room. State transitions are not.
                if event not in self.CRITICAL:
                    continue
                self._drop_lossy(q)
                try:
                    q.put_nowait(msg)
                except asyncio.QueueFull:
                    pass   # nothing droppable left; a reconnect will resync

    @staticmethod
    def _drop_lossy(q: asyncio.Queue) -> None:
        """Free a slot by discarding the oldest non-critical messages."""
        rescued: list[Any] = []
        freed = False
        while not q.empty():
            item = q.get_nowait()
            if not freed and item.get("event") not in Bus.CRITICAL:
                freed = True          # dropped: this is the slot we needed
                continue
            rescued.append(item)
        for item in rescued:
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                break


# Process-wide bus.
bus = Bus()
