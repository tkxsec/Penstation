"""Docker operations — the real acquire step.

Every command is built as an **argv list and run without a shell**. The validator
(validate.py) is defense in depth; constructing argv ourselves means untrusted
text never reaches a shell in the first place.

All output is streamed line-by-line through an `on_line` callback so the UI can
watch a multi-minute build live instead of waiting for a blob at the end.
"""
from __future__ import annotations

import asyncio
from typing import Callable, Sequence

OnLine = Callable[[str], None]

BUILD_TIMEOUT = 1800.0   # 30 min — Rust compiles are genuinely slow
PULL_TIMEOUT = 600.0
QUICK_TIMEOUT = 20.0


class DockerError(Exception):
    """A docker command failed or the daemon is unreachable."""


async def _stream(argv: Sequence[str], on_line: OnLine, timeout: float,
                  stdin_data: str | None = None) -> int:
    """Run argv, streaming combined output. Returns the exit code."""
    on_line("$ " + " ".join(argv) + "\n")
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as exc:
        raise DockerError("`docker` not found on PATH") from exc
    except OSError as exc:
        raise DockerError(f"couldn't start docker: {exc}") from exc

    if stdin_data is not None and proc.stdin is not None:
        proc.stdin.write(stdin_data.encode())
        await proc.stdin.drain()
        proc.stdin.close()

    async def pump() -> int:
        """Chunk-read and split lines ourselves.

        Iterating a StreamReader by line raises once a single line exceeds its
        64 KiB limit — which build output can do. Reading fixed chunks avoids
        that entirely and still yields output promptly.
        """
        assert proc.stdout is not None
        buf = ""
        while True:
            chunk = await proc.stdout.read(8192)
            if not chunk:
                break
            buf += chunk.decode(errors="replace")
            # BuildKit's non-plain progress uses \r; treat it as a line break too.
            buf = buf.replace("\r\n", "\n").replace("\r", "\n")
            *lines, buf = buf.split("\n")
            for line in lines:
                on_line(line + "\n")
        if buf:
            on_line(buf + "\n")
        return await proc.wait()

    try:
        return await asyncio.wait_for(pump(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        on_line(f"[timed out after {int(timeout)}s]\n")
        raise DockerError(f"timed out after {int(timeout)}s") from None


# -- preflight ---------------------------------------------------------
async def preflight() -> str:
    """Confirm the daemon is reachable; return its version. Fail fast and clearly."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "version", "--format", "{{.Server.Version}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=QUICK_TIMEOUT)
    except FileNotFoundError:
        raise DockerError("`docker` not found on PATH — install Docker") from None
    except (asyncio.TimeoutError, OSError) as exc:
        raise DockerError(f"docker not responding: {exc}") from None
    text = out.decode(errors="replace").strip()
    if proc.returncode != 0:
        raise DockerError(f"Docker daemon unreachable — is Docker running? ({text[:160]})")
    return text


# -- acquire -----------------------------------------------------------
async def pull(image: str, on_line: OnLine) -> None:
    code = await _stream(["docker", "pull", image], on_line, PULL_TIMEOUT)
    if code != 0:
        raise DockerError(f"docker pull failed (exit {code})")


async def build_from_git(image: str, git_url: str, on_line: OnLine) -> None:
    code = await _stream(["docker", "build", "--progress=plain", "-t", image, git_url],
                         on_line, BUILD_TIMEOUT)
    if code != 0:
        raise DockerError(f"docker build failed (exit {code})")


async def build_from_dockerfile(image: str, dockerfile: str, on_line: OnLine) -> None:
    """Build with a generated Dockerfile piped in; '-' means no build context."""
    code = await _stream(["docker", "build", "--progress=plain", "-t", image, "-"],
                         on_line, BUILD_TIMEOUT, stdin_data=dockerfile)
    if code != 0:
        raise DockerError(f"docker build failed (exit {code})")


async def image_exists(image: str) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "image", "inspect", image,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(proc.wait(), timeout=QUICK_TIMEOUT)
        return proc.returncode == 0
    except (asyncio.TimeoutError, OSError):
        return False


async def entrypoint_of(image: str) -> list[str]:
    """The image's ENTRYPOINT — decides argv_mode at verify time."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "image", "inspect", "--format", "{{json .Config.Entrypoint}}", image,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=QUICK_TIMEOUT)
    except (asyncio.TimeoutError, OSError):
        return []
    import json
    try:
        val = json.loads(out.decode().strip() or "null")
    except ValueError:
        return []
    return list(val) if isinstance(val, list) else []


HELP_TIMEOUT = 30.0


async def capture_help(image: str) -> str:
    """Grab the tool's own --help text, for on-screen guidance.

    Tries `--help` then `-h`. Output is kept even on a non-zero exit — plenty of
    tools print usage to stderr and exit 1 or 2. No-argument invocation is
    deliberately NOT tried: for a scanner that could start doing work.
    """
    for flag in ("--help", "-h"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "run", "--rm", "--memory=512m", image, flag,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=HELP_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            continue
        text = out.decode(errors="replace").strip()
        if text:
            return f"$ {flag}\n\n{text}"
    return ""


async def kill_container(name: str) -> bool:
    """Stop a running container by name.

    Killing the `docker run` client would orphan the container, so runs are
    named and stopped here instead.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "kill", name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(proc.wait(), timeout=30)
        return proc.returncode == 0
    except (asyncio.TimeoutError, OSError):
        return False


async def remove_volume(name: str) -> None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "volume", "rm", "-f", name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(proc.wait(), timeout=30)
    except (asyncio.TimeoutError, OSError):
        pass


async def remove_image(image: str) -> None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "rmi", "-f", image,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(proc.wait(), timeout=60)
    except (asyncio.TimeoutError, OSError):
        pass
