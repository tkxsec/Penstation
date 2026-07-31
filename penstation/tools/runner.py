"""Run an installed tool as a subprocess.

You type the real command; this resolves it to the binary that was installed and
runs it. Output is streamed line-by-line through `on_line` so it appears while
the tool works.

Two details that matter:
  * The tool leads its **own process group**, so Stop can take the whole tree.
    nmap and bbot spawn helpers, and killing only the immediate child leaves a
    "stopped" scan still sending packets.
  * It runs as an **unprivileged account**, not as penstation. A package that
    behaves during install and misbehaves when invoked would otherwise hold the
    access penstation has to the map, the evidence and the network.

Nothing goes through a shell: the command is split with shlex and passed as argv.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import signal
import tempfile
from pathlib import Path
from typing import Callable

from penstation.tools import nativeops as N
from penstation.tools.store import ToolRecord
from penstation.tools.validate import validate_command

OnLine = Callable[[str], None]

DEFAULT_TIMEOUT = 1800.0     # 30 min — scanners legitimately run long
INPUT_NAME = "input.txt"

# The unprivileged account tools run as. Installing under one account and
# running under another is the point: a package that behaves during install and
# misbehaves when invoked would otherwise hold penstation's own access to the
# map, the evidence and the network position.
#
# Resolved per call rather than at import, so a run picks up an account created
# after the server started.
def _run_user() -> str:
    return N.account("run")

# tool id -> pid of the running process group leader, for Stop
_active: dict[str, int] = {}


class RunError(Exception):
    pass


def is_running(tool_id: str) -> bool:
    return tool_id in _active


def build_argv(rec: ToolRecord, command: str,
               outdir_host: Path | None = None,
               has_input: bool = False) -> list[str]:
    """Assemble the argv to execute.

    `{{outdir}}` is where a tool writes; `{{input}}` is a file we wrote for it
    to read. Nearly every tool in this space takes a list — httpx -l, nmap -iL,
    nuclei -l, dnsx -l — so without an input path the output of one step cannot
    become the input of the next.

    There is no mount and no path translation: the tool sees the same directory
    the server does, which is the run's own scratch dir.

    The first token is replaced with the binary's resolved absolute path when we
    have one. The server and the tool may run as different accounts with
    different PATHs, so naming the file rather than trusting a lookup is what
    makes the run reproducible — and what stops a same-named binary earlier on
    someone's PATH being the thing that actually ran.
    """
    # Split first, substitute second. shlex reads a backslash as an escape, so a
    # Windows path would lose its separators outright, and a path containing a
    # space would split into two arguments on any platform. Substituting
    # per-token means the path is never parsed at all.
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise RunError(f"couldn't parse the command: {exc}") from exc
    if not parts:
        raise RunError("empty command")

    outdir = str(outdir_host) if outdir_host is not None else ""
    inpath = str(Path(outdir) / INPUT_NAME) if (has_input and outdir) else ""
    parts = [p.replace("{{outdir}}", outdir) for p in parts]
    if inpath:
        parts = [p.replace("{{input}}", inpath) for p in parts]

    if rec.binary_path:
        parts[0] = rec.binary_path
    return N.as_user(_run_user(), parts)


async def run_command(rec: ToolRecord, command: str, on_line: OnLine,
                      timeout: float = DEFAULT_TIMEOUT,
                      outdir_keep: Path | None = None,
                      input_text: str = "") -> dict:
    """Run an installed tool as a subprocess.

    `outdir_keep` is where files the tool writes to {{outdir}} should land. Pass
    the run's own directory and they survive; omit it and a temp dir is used and
    discarded — which is what used to happen unconditionally, so a run reported
    files that had already been deleted by the time you could ask for them.
    """
    if rec.status != "ready":
        raise RunError(f"tool is not ready (status: {rec.status})")
    if is_running(rec.id):
        raise RunError("a run is already in progress for this tool")
    check = validate_command(command)
    if not check:
        raise RunError(check.reason)

    # {{input}} lives in the same directory {{outdir}} names, so asking for
    # either one gets you the directory.
    wants_dir = "{{outdir}}" in command or "{{input}}" in command
    scratch: tempfile.TemporaryDirectory | None = None
    outdir: Path | None = None
    if wants_dir:
        if outdir_keep is not None:
            outdir_keep.mkdir(parents=True, exist_ok=True)
            outdir = outdir_keep
        else:
            scratch = tempfile.TemporaryDirectory(prefix="penstation-run-")
            outdir = Path(scratch.name)

    has_input = bool(input_text) and "{{input}}" in command
    if has_input and outdir is not None:
        (outdir / INPUT_NAME).write_text(
            input_text if input_text.endswith("\n") else input_text + "\n")

    argv = build_argv(rec, command, outdir, has_input)
    on_line("$ " + " ".join(shlex.quote(a) for a in argv) + "\n")

    # Never inherit penstation's own CWD. It is normally the checkout — on an
    # engagement box /root/Penstation, mode 0700 — and the unprivileged account
    # a tool runs as cannot chdir into it. The run's own directory is both
    # reachable and where a tool writing relative paths should land anyway.
    cwd = str(outdir) if outdir is not None else N.workdir(_run_user())

    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                # Its own process group, so Stop can take the whole tree. Killing
                # only the immediate child leaves nmap's and bbot's helpers
                # running, which is how a "stopped" scan keeps sending packets.
                start_new_session=True,
                stdin=asyncio.subprocess.DEVNULL,   # closed: never hang on input
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=cwd,
            )
        except FileNotFoundError:
            raise RunError(f"`{argv[0]}` not found — is the tool still installed?") from None
        except OSError as exc:
            raise RunError(f"couldn't start {argv[0]}: {exc}") from exc
        # Registered only once it is actually running, so Stop never holds a pid
        # for a process that failed to start.
        _active[rec.id] = proc.pid

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
            _kill_tree(proc.pid)
            on_line(f"[timed out after {int(timeout)}s]\n")
            code = -1

        files: list[dict] = []
        if outdir is not None:
            for p in sorted(outdir.rglob("*")):
                if p.is_file():
                    # Path relative to the run dir, so a screenshot in a
                    # subfolder is still addressable later. as_posix() because
                    # the name becomes a URL path: str() on Windows yields
                    # "scan_dir\output.json", which encodes to one %5C-laden
                    # segment the file route cannot resolve.
                    files.append({"name": p.relative_to(outdir).as_posix(),
                                  "bytes": p.stat().st_size})
        return {"command": " ".join(shlex.quote(a) for a in argv),
                "code": code, "files": files}
    finally:
        _active.pop(rec.id, None)
        if scratch is not None:
            scratch.cleanup()


def _kill_tree(pid: int) -> bool:
    """Kill a tool and everything it spawned.

    The child leads its own process group (start_new_session at spawn), so one
    signal to the group reaches helpers the tool started. Without this, Stop
    ends the parent and leaves the scan running.
    """
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
        return True
    except (ProcessLookupError, PermissionError, AttributeError, OSError):
        return False


async def stop(tool_id: str) -> bool:
    pid = _active.get(tool_id)
    if not pid:
        return False
    return _kill_tree(pid)
