"""Native install operations — the acquire step on a box with no container runtime.

Every command is built as an **argv list and run without a shell**, and all
output is streamed line-by-line through `on_line` so a slow install is watchable
rather than a blob at the end.

**The validator is not defence in depth — it is the defence.** An install runs on
the engagement box itself, as whoever runs penstation, so validate.py is the
barrier rather than a second one behind something else. Nothing reaches a shell.

There were two unprivileged accounts here once: one installed, another ran. The
idea was that downloaded code never held your access. It was removed, because on
an engagement box it bought less than it cost.

What it cost was concrete. A tool could not be executed by the account that had
to run it, because `useradd -m` makes a home 0700. Results could not be written,
because the data directory is the thing the separation existed to protect. bbot
could not install its own module dependencies into a venv owned by someone else,
and asked for a sudo password no one was there to type. nmap could not use the
capability its SYN scan needs. Every one of those is a real tool made worse.

What it bought was thinner than it looks: penstation already runs as root on the
same box, that box is provisioned for one engagement and destroyed after, and the
tools are pinned ones you chose. A malicious subfinder has the client network
either way. The honest trade was to drop it rather than keep machinery that
looked like a boundary without being one.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from typing import Callable, Sequence

OnLine = Callable[[str], None]

APT_TIMEOUT = 600.0
INSTALL_TIMEOUT = 900.0    # go builds and pip wheels are genuinely slow
QUICK_TIMEOUT = 20.0
HELP_TIMEOUT = 30.0


class InstallError(Exception):
    """An install command failed, or the tooling it needs is missing."""


def home_of() -> str:
    """Home directory of the account everything runs as — ours."""
    return os.path.expanduser("~")


# -- where installed tools live ----------------------------------------
# One predictable prefix rather than scattered per-ecosystem defaults.
#
# This is not about accounts — it survived their removal on its own merit. The
# distro ships its own `httpx` and `subfinder`, several versions behind the ones
# the baseline pins, and both land in /usr/bin. Resolving an installed tool by
# asking the shell found those instead: penstation recorded /usr/bin/subfinder
# v2.6.0 for a recipe that had just installed v2.14.0, and would have scanned
# with it. Putting our installs somewhere we control, and looking there first,
# is what stops a same-named binary elsewhere on PATH being what actually ran.
#
# setup.sh creates it; when it is absent, everything falls back to the home
# directory, which is what a dev box wants anyway.
SHARED_PREFIX = "/opt/penstation"


def prefix() -> str:
    """Root of the install tree."""
    return SHARED_PREFIX if os.path.isdir(SHARED_PREFIX) else home_of()


def bin_dir() -> str:
    """Where installed commands land — GOBIN and pipx's bin dir alike."""
    return f"{prefix()}/bin"


def pipx_home() -> str:
    """Where pipx keeps its venvs."""
    return f"{prefix()}/pipx"


def tools_dir() -> str:
    """Where clone+venv trees land, one directory per tool."""
    return f"{prefix()}/tools"


def workdir() -> str:
    """A directory to start a subprocess in, rather than inheriting ours.

    Never inherit penstation's own. It is normally the checkout — on an
    engagement box /root/Penstation — and what a tool does with the working
    directory is not ours to assume: bbot stats every target against it to
    decide whether the target names a file, and the Go toolchain chdirs in each
    `compile` it spawns. An incidental CWD is a source of failures that have
    nothing to do with the command being run.
    """
    home = home_of()
    return home if os.path.isdir(home) else tempfile.gettempdir()


async def _stream(argv: Sequence[str], on_line: OnLine, timeout: float,
                  env: dict | None = None, cwd: str | None = None) -> int:
    """Run argv, streaming combined output. Returns the exit code."""
    on_line("$ " + " ".join(argv) + "\n")
    full_env = {**os.environ, **(env or {})}
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,   # never let an install prompt hang
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=full_env,
            cwd=cwd,                            # see workdir(): never inherit ours
        )
    except FileNotFoundError as exc:
        raise InstallError(f"`{argv[0]}` not found on PATH") from exc
    except OSError as exc:
        raise InstallError(f"couldn't start {argv[0]}: {exc}") from exc

    async def pump() -> int:
        # Chunk-read rather than iterating lines: a StreamReader raises once a
        # single line passes its 64 KiB limit, and build output does that.
        assert proc.stdout is not None
        buf = ""
        while True:
            chunk = await proc.stdout.read(8192)
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
        return await asyncio.wait_for(pump(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        on_line(f"[timed out after {int(timeout)}s]\n")
        raise InstallError(f"timed out after {int(timeout)}s") from None


async def _capture(argv: Sequence[str], timeout: float = QUICK_TIMEOUT,
                   cwd: str | None = None) -> tuple[int, str]:
    """Run argv quietly and return (exit code, combined output)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            cwd=cwd)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError, FileNotFoundError):
        return -1, ""
    return proc.returncode or 0, out.decode(errors="replace")


# -- preflight ---------------------------------------------------------
async def preflight() -> str:
    """Which rungs this box can actually offer. Fail only if none of them can."""
    have = {name: bool(shutil.which(name))
            for name in ("apt-get", "pipx", "go", "git", "curl")}
    if not any(have[n] for n in ("apt-get", "pipx", "go")):
        raise InstallError(
            "no install method available — none of apt-get, pipx or go is on PATH")
    return ", ".join(n for n, ok in have.items() if ok)


# -- where a tool ended up ---------------------------------------------
# Resolved rather than assumed: apt lands in /usr/bin, go install and pipx in our
# own prefix. Storing the absolute path is what makes a run reproducible.
SEARCH_DIRS = ("/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/sbin")


async def binary_path(name: str) -> str:
    """Absolute path to an installed binary, or "" if it isn't there."""
    # Our prefix first, and by path rather than by lookup. `command -v` answers
    # from PATH, and PATH is how the distro's own `subfinder` (v2.6.0, in
    # /usr/bin) got recorded for a recipe that had just installed v2.14.0. What
    # we installed wins over what happens to be named the same.
    home = home_of()
    candidates = (
        f"{bin_dir()}/{name}",
        f"{home}/.local/bin/{name}",       # pre-prefix installs, still valid
        f"{home}/go/bin/{name}",
        *(f"{d}/{name}" for d in SEARCH_DIRS),
    )
    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    # Nothing where we put things — fall back to asking the shell.
    code, out = await _capture(["sh", "-c", f"command -v {name}"], cwd=workdir())
    if code == 0 and out.strip():
        return out.strip().splitlines()[0]
    return ""


# -- the rungs ---------------------------------------------------------
async def apt_available(pkg: str) -> str:
    """The candidate version apt would install, or "" when there is none."""
    code, out = await _capture(["apt-cache", "policy", pkg], cwd=workdir())
    if code != 0:
        return ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Candidate:"):
            ver = line.split(":", 1)[1].strip()
            return "" if ver in ("(none)", "") else ver
    return ""


async def apt_install(pkg: str, on_line: OnLine) -> None:
    """Install from the distro. Root, non-interactive, no recommends.

    The one rung that does not execute code from the repository being installed
    — apt runs maintainer scripts from a signed archive, which is a different
    trust question from a stranger's setup.py.
    """
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    code = await _stream(
        ["apt-get", "install", "-y", "--no-install-recommends", pkg],
        on_line, APT_TIMEOUT, env=env, cwd=workdir())
    if code != 0:
        raise InstallError(f"apt-get install {pkg} failed (exit {code})")


async def pipx_install(spec: str, on_line: OnLine) -> None:
    """Install a Python tool into its own venv.

    pipx rather than pip because each tool gets an isolated dependency tree,
    which is the part of per-tool images actually worth keeping.
    """
    env = {"PIPX_HOME": pipx_home(), "PIPX_BIN_DIR": bin_dir()}
    code = await _stream(["pipx", "install", spec],
                         on_line, INSTALL_TIMEOUT, env=env, cwd=workdir())
    if code != 0:
        raise InstallError(f"pipx install {spec} failed (exit {code})")


def venv_name(spec: str) -> str:
    """The venv pipx creates for a spec — `bbot==3.0.1` becomes `bbot`."""
    return re.split(r"[<>=!~\[]", (spec or "").strip(), 1)[0].strip()


async def pipx_inject(spec: str, packages: list, on_line: OnLine) -> None:
    """Install extra packages *into* an already-installed tool's venv.

    For dependencies a tool would otherwise resolve while running. bbot installs
    its own module dependencies mid-scan, which makes an engagement depend on
    PyPI being reachable at exactly the wrong moment. Declaring them here
    installs them at setup instead, recorded on the record and replayed on
    reinstall.

    Not fatal. A missing optional dependency costs one module; failing the whole
    install over it would cost the tool.
    """
    if not packages:
        return
    name = venv_name(spec)
    env = {"PIPX_HOME": pipx_home(), "PIPX_BIN_DIR": bin_dir()}
    try:
        code = await _stream(["pipx", "inject", name, *packages],
                             on_line, INSTALL_TIMEOUT, env=env, cwd=workdir())
        why = f"exit {code}" if code else ""
    except InstallError as exc:
        why = str(exc)          # pipx gone, or the call never started
    if why:
        on_line(f"[warn] pipx inject {name} {' '.join(packages)} failed "
                f"({why}) — modules needing those will be skipped\n")


async def go_install(pkg: str, on_line: OnLine) -> None:
    """Install a Go tool from its module path.

    The path comes from the repo's own documentation, never from the repo name —
    subfinder's is `github.com/projectdiscovery/subfinder/v2/cmd/subfinder`, and
    guessing `owner/repo` fails for most real tools. See gather.extract_install.
    """
    # GOPATH stays in the home directory — it is the module cache, wanted only
    # at build time. GOBIN is our prefix, because that is where we look first.
    home = home_of()
    env = {"GOPATH": f"{home}/go", "GOBIN": bin_dir(),
           "HOME": home, "GOFLAGS": "-modcacherw"}
    if not pkg.endswith("@latest") and "@" not in pkg.rsplit("/", 1)[-1]:
        pkg = f"{pkg}@latest"
    # cwd matters more here than anywhere else: the toolchain chdirs in every
    # `compile` it spawns, so an unreachable CWD fails once per package.
    code = await _stream(["go", "install", pkg],
                         on_line, INSTALL_TIMEOUT, env=env, cwd=workdir())
    if code != 0:
        raise InstallError(f"go install {pkg} failed (exit {code})")


async def clone_venv(git_url: str, dest: str, on_line: OnLine,
                     requirements: str = "requirements.txt") -> None:
    """Clone a repo and install its requirements into a venv beside it.

    The rung for tools with no packaging — and the only one that runs arbitrary
    code from the repository, so the pipeline asks before reaching it. The repo
    is kept rather than discarded because tools like cloud_enum ship data files
    (wordlists, mutation lists) that a bare binary would lose.
    """
    work = workdir()
    code = await _stream(["git", "clone", "--depth", "1", git_url, dest],
                         on_line, INSTALL_TIMEOUT, cwd=work)
    if code != 0:
        raise InstallError(f"git clone failed (exit {code})")
    code = await _stream(["python3", "-m", "venv", f"{dest}/.venv"],
                         on_line, INSTALL_TIMEOUT, cwd=work)
    if code != 0:
        raise InstallError(f"venv creation failed (exit {code})")
    req = f"{dest}/{requirements}"
    if os.path.isfile(req):
        code = await _stream(
            [f"{dest}/.venv/bin/pip", "install", "-r", req],
            on_line, INSTALL_TIMEOUT, cwd=work)
        if code != 0:
            raise InstallError(f"pip install -r {requirements} failed (exit {code})")


# -- verify ------------------------------------------------------------
# Help flags in the order worth trying. All three are unambiguously flags — a
# bare `help` subcommand is deliberately excluded, because a scanner would read
# it as a positional target and start working.
HELP_FLAGS = ("--help", "-h", "-help")
VERSION_FLAGS = ("--version", "-version", "-V", "version")

_HELPISH = re.compile(r"\busage\b|\boptions\b|\bflags\b|^\s*-{1,2}\w", re.I | re.M)


def _help_score(text: str) -> tuple[int, int]:
    """Rank a candidate: looking like help beats being long.

    Length alone is a bad signal — hakrawler uses `-h` for custom Headers, so
    `-h` returns a *longer* "flag needs an argument" error than the real usage.
    """
    return (1 if _HELPISH.search(text or "") else 0, len(text or ""))


async def capture_help(binary: str) -> str:
    """The tool's own help text, for on-screen guidance.

    Kept even on a non-zero exit: plenty of tools print usage to stderr and exit
    1 or 2. The test is **produced output**, never the exit code.
    """
    best, best_score = "", (0, 0)
    for flag in HELP_FLAGS:
        _, out = await _capture([binary, flag], HELP_TIMEOUT, cwd=workdir())
        score = _help_score(out)
        if score > best_score:
            best, best_score = out, score
        if best_score[0] and best_score[1] > 200:
            break            # convincingly help-shaped; stop paying for more
    return best.strip()


async def capture_version(binary: str) -> str:
    """What this box actually resolved.

    Replaces pinning. The version comes from the distro or the module proxy
    rather than from an image we built, so the run record has to say what ran —
    the same reason every map node records the tool and run that found it.
    """
    for flag in VERSION_FLAGS:
        _, out = await _capture([binary, flag], QUICK_TIMEOUT, cwd=workdir())
        line = (out or "").strip().splitlines()
        if line and any(ch.isdigit() for ch in line[0]):
            return line[0].strip()[:200]
    return ""


async def verify(binary: str) -> tuple[str, str]:
    """(help text, version). Raises if the binary produced nothing at all."""
    help_text = await capture_help(binary)
    version = await capture_version(binary)
    if not help_text and not version:
        raise InstallError(
            f"{binary} produced no output for --help or --version — "
            "installed, but it may not be the right binary")
    return help_text, version


# -- remove ------------------------------------------------------------
async def apt_remove(pkg: str, on_line: OnLine) -> None:
    await _stream(["apt-get", "remove", "-y", pkg], on_line, APT_TIMEOUT,
                  env={"DEBIAN_FRONTEND": "noninteractive"}, cwd=workdir())


async def pipx_uninstall(name: str, on_line: OnLine) -> None:
    await _stream(["pipx", "uninstall", name], on_line, APT_TIMEOUT,
                  env={"PIPX_HOME": pipx_home(), "PIPX_BIN_DIR": bin_dir()},
                  cwd=workdir())


async def remove_path(path: str, on_line: OnLine) -> None:
    """For go-install binaries and clone+venv trees."""
    if not path or path in ("/", "/usr", "/usr/bin", "/home"):
        raise InstallError(f"refusing to remove {path!r}")
    await _stream(["rm", "-rf", "--", path], on_line, QUICK_TIMEOUT, cwd=workdir())
