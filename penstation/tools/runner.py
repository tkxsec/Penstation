"""Run a command inside an installed tool's container.

You type the real command; this assembles the `docker run` around it. Output is
streamed line-by-line through `on_line` so it appears while the tool works.

Two details that matter:
  * Containers are **named**, so Stop can `docker kill` the container. Killing the
    `docker run` client alone would leave the work running.
  * If the image has an ENTRYPOINT (most do), the binary is already baked in, so
    typing `bbot -t x` would pass "bbot" as an argument. The first token is
    stripped **only when it matches that entrypoint**, so `bbot -t x` and `-t x`
    both work.

Nothing goes through a shell: the command is split with shlex and passed as argv.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import tempfile
import time
from pathlib import Path
from typing import Callable

from penstation.addtool import dockerops as D
from penstation.addtool.store import ToolRecord
from penstation.addtool.validate import validate_command

OnLine = Callable[[str], None]

DEFAULT_TIMEOUT = 1800.0     # 30 min — scanners legitimately run long
CONTAINER_OUTDIR = "/out"
LIMITS = ["--rm", "--memory=2g", "--cpus=2", "--pids-limit=1024"]

# tool id -> container name, for Stop
_active: dict[str, str] = {}


class RunError(Exception):
    pass


def is_running(tool_id: str) -> bool:
    return tool_id in _active


def _container_name(tool_id: str) -> str:
    return f"penstation-run-{tool_id}-{int(time.time() * 1000)}"


def _strip_entrypoint(rec: ToolRecord, parts: list[str]) -> list[str]:
    if not parts:
        return parts
    first = os.path.basename(parts[0]).lower()
    known = {os.path.basename(rec.entrypoint or "").lower(), rec.id.lower()}
    known.discard("")
    if rec.argv_mode == "entrypoint" and first in known:
        return parts[1:]
    return parts


def build_argv(rec: ToolRecord, command: str, name: str,
               outdir_host: Path | None = None) -> list[str]:
    filled = command.replace("{{outdir}}", CONTAINER_OUTDIR)
    try:
        parts = shlex.split(filled)
    except ValueError as exc:
        raise RunError(f"couldn't parse the command: {exc}") from exc
    if not parts:
        raise RunError("empty command")

    args = _strip_entrypoint(rec, parts)
    argv = ["docker", "run", *LIMITS, "--name", name,
            # A per-tool named volume for the container's home dir. Without it,
            # --rm wipes config every run: bbot re-creates its config and
            # re-downloads Ansible collections each time (and API keys written
            # to ~/.config could never persist). Docker seeds a named volume
            # from the image's own contents, so this is safe for any image.
            "-v", f"penstation-home-{rec.id}:/root"]
    if outdir_host is not None:
        # The one intentional mount: an empty per-run scratch dir so tools that
        # write files have somewhere real to put them. Never the host FS.
        argv += ["-v", f"{outdir_host}:{CONTAINER_OUTDIR}"]
    argv += [rec.image, *args]
    return argv


async def run_command(rec: ToolRecord, command: str, on_line: OnLine,
                      timeout: float = DEFAULT_TIMEOUT) -> dict:
    if rec.status != "ready":
        raise RunError(f"tool is not ready (status: {rec.status})")
    if is_running(rec.id):
        raise RunError("a run is already in progress for this tool")
    check = validate_command(command)
    if not check:
        raise RunError(check.reason)

    scratch: tempfile.TemporaryDirectory | None = None
    outdir: Path | None = None
    if "{{outdir}}" in command:
        scratch = tempfile.TemporaryDirectory(prefix="penstation-run-")
        outdir = Path(scratch.name)

    name = _container_name(rec.id)
    argv = build_argv(rec, command, name, outdir)
    _active[rec.id] = name
    on_line("$ " + " ".join(shlex.quote(a) for a in argv) + "\n")

    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,   # closed: never hang on input
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError:
            raise RunError("`docker` not found on PATH") from None
        except OSError as exc:
            raise RunError(f"couldn't start docker: {exc}") from exc

        async def pump() -> int:
            assert proc.stdout is not None
            buf = ""
            while True:
                chunk = await proc.stdout.read(4096)
                if not chunk:
                    break
                buf += chunk.decode(errors="replace")
                buf = buf.replace("\r\n", "\n").replace("\r", "\n")
                *lines, buf = buf.split("\n")
                for line in lines:
                    on_line(line + "\n")
            if buf:
                on_line(buf + "\n")
            return await proc.wait()

        try:
            code = await asyncio.wait_for(pump(), timeout=timeout)
        except asyncio.TimeoutError:
            await D.kill_container(name)
            proc.kill()
            on_line(f"[timed out after {int(timeout)}s]\n")
            code = -1

        files: list[dict] = []
        if outdir is not None:
            for p in sorted(outdir.rglob("*")):
                if p.is_file():
                    files.append({"name": p.name, "bytes": p.stat().st_size})
        return {"command": " ".join(shlex.quote(a) for a in argv),
                "code": code, "files": files}
    finally:
        _active.pop(rec.id, None)
        if scratch is not None:
            scratch.cleanup()


async def stop(tool_id: str) -> bool:
    name = _active.get(tool_id)
    if not name:
        return False
    return await D.kill_container(name)
