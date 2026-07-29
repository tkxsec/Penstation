"""Job queue + status machine.

Setup takes minutes (compiles), so `POST /tools` must never block: it creates a
record, enqueues a job, and returns immediately. This module owns the background
worker that advances a record through the pipeline.

Builds run SERIALLY — docker builds are heavy and interleaved logs are
unreadable. Tools waiting behind an active build carry `queue_position > 0` so
the UI can say "queued (position 2)" instead of showing an empty log.

Stage functions are injected (see `Pipeline`), so this module stays about
*orchestration* — the real gather/build/verify land in later steps.
"""
from __future__ import annotations

import asyncio
import traceback
from typing import Awaitable, Callable, Protocol

from penstation.events import bus
from penstation.store import ToolRecord

# A pipeline stage: given the record, do work (may append to its log).
Stage = Callable[[ToolRecord], Awaitable[None]]


class Pipeline(Protocol):
    """The stages the worker drives, in order."""

    async def inspect(self, rec: ToolRecord) -> None: ...
    async def acquire(self, rec: ToolRecord) -> None: ...
    async def verify(self, rec: ToolRecord) -> None: ...


class SetupFailed(Exception):
    """Raised by a stage to fail the tool with a readable reason."""


class JobQueue:
    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._pending: list[str] = []      # ids waiting, in order
        self._active: str | None = None    # id currently being set up
        self._worker: asyncio.Task | None = None

    def _emit(self, event: str, rec: ToolRecord) -> None:
        """Status transitions go on the shared bus; the server streams them."""
        bus.publish(event, rec.to_dict())

    # -- enqueue -------------------------------------------------------
    def start(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._run())

    def submit(self, rec: ToolRecord) -> ToolRecord:
        self._pending.append(rec.id)
        # queue_position = how many jobs are ahead of this one. 0 means next up
        # (status disambiguates: queued+0 = about to start, building = running).
        rec.queue_position = len(self._pending) - 1
        rec.set_status("queued", f"waiting behind {rec.queue_position}"
                       if rec.queue_position else "starting")
        self._emit("status", rec)
        self._queue.put_nowait(rec.id)
        self.start()
        return rec

    @property
    def depth(self) -> int:
        return len(self._pending)

    # -- worker --------------------------------------------------------
    async def _run(self) -> None:
        while True:
            tool_id = await self._queue.get()
            self._active = tool_id
            if tool_id in self._pending:
                self._pending.remove(tool_id)
            self._renumber()
            try:
                await self._setup(tool_id)
            except Exception:
                pass  # _setup already recorded the failure
            finally:
                self._active = None
                self._queue.task_done()

    def _renumber(self) -> None:
        """Keep queue_position honest for everyone still waiting (0 = next up)."""
        from penstation import store
        for i, tid in enumerate(self._pending):
            rec = store.load(tid)
            if rec and rec.queue_position != i:
                rec.queue_position = i
                rec.detail = f"waiting behind {i}" if i else "starting"
                rec.save()
                self._emit("status", rec)

    async def _setup(self, tool_id: str) -> None:
        from penstation import store
        rec = store.load(tool_id)
        if rec is None:
            return
        rec.queue_position = 0

        stages = (
            ("inspecting", self.pipeline.inspect),
            ("building", self.pipeline.acquire),
            ("verifying", self.pipeline.verify),
        )
        try:
            for status, stage in stages:
                rec.set_status(status)
                self._emit("status", rec)
                await stage(rec)
                rec = store.load(tool_id) or rec  # stage may have written fields
            rec.set_status("ready", "installed and verified")
            self._emit("status", rec)
        except SetupFailed as exc:
            rec.append_log(f"\n[failed] {exc}\n")
            rec.set_status("failed", str(exc))
            self._emit("status", rec)
        except asyncio.CancelledError:
            rec.set_status("failed", "cancelled")
            self._emit("status", rec)
            raise
        except Exception as exc:
            rec.append_log("\n[error]\n" + traceback.format_exc())
            rec.set_status("failed", f"unexpected error: {exc}")
            self._emit("status", rec)
