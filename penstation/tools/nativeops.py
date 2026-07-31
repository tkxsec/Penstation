"""Native install operations — the acquire step on a box with no container runtime.

Every command is built as an **argv list and run without a shell**, and all
output is streamed line-by-line through `on_line` so a slow install is watchable
rather than a blob at the end.

Two properties matter, and both follow from there being no sandbox.

**The validator is not defence in depth — it is the defence.** An install runs on
the engagement box itself, so validate.py is the barrier rather than a second one
behind something else. Nothing reaches a shell.

**Installs run as another user.** `install_user` is an unprivileged account that
cannot read the engagement data or your keys, so a package's setup.py never holds
your access. apt is the exception — it needs root by nature, and it is also the
one rung that does not execute a stranger's code to install itself.
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


# -- who runs what -----------------------------------------------------
# The unprivileged accounts setup.sh creates. Discovered rather than configured:
# they either exist on this box or they do not, so asking the passwd database is
# a better answer than an environment variable someone has to remember to set —
# and forgetting it silently drops the separation these accounts exist to buy.
INSTALL_ACCOUNT = "noprivuser-install"
RUN_ACCOUNT = "noprivuser-run"


def _exists(name: str) -> bool:
    try:
        import pwd                       # Unix only; absent on a dev box
        pwd.getpwnam(name)
        return True
    except (ImportError, KeyError):
        return False


def account(kind: str) -> str:
    """The account to install or run as: the env override, the standard account
    if setup.sh made it, else empty — meaning "this user"."""
    env = "PENSTATION_INSTALL_USER" if kind == "install" else "PENSTATION_RUN_USER"
    override = os.environ.get(env)
    if override is not None:            # set-but-empty deliberately means "me"
        return override.strip()
    standard = INSTALL_ACCOUNT if kind == "install" else RUN_ACCOUNT
    return standard if _exists(standard) else ""


def home_of(user: str = "") -> str:
    """Home directory of the account a command will run as."""
    return f"/home/{user}" if user else os.path.expanduser("~")


# -- where installed tools live ----------------------------------------
# Installs land under a shared prefix, not in the install account's home.
#
# The two accounts are the point: one installs, another runs. But `useradd -m`
# makes a home 0700, so a tool installed into ~noprivuser-install could not be
# *executed* by noprivuser-run — `runuser -u noprivuser-run -- ~/.local/bin/bbot`
# failed with "Permission denied" before the binary was ever reached. apt tools
# were fine only because they land in /usr/bin.
#
# The prefix is owned by the install account and mode 0755, which states the
# intended relationship directly: the installer writes, the runner executes, and
# the runner cannot modify what it runs. Relying on the two accounts' umasks
# happening to be 022 would buy the same thing on a good day and fail silently on
# a bad one.
#
# setup.sh creates it. When it is absent — a dev box with no accounts at all —
# everything falls back to the current user's home, where the question does not
# arise because there is only one account.
SHARED_PREFIX = "/opt/penstation"


def prefix(user: str = "") -> str:
    """Root of the install tree for `user`."""
    return SHARED_PREFIX if os.path.isdir(SHARED_PREFIX) else home_of(user)


def bin_dir(user: str = "") -> str:
    """Where installed commands land — GOBIN and pipx's bin dir alike."""
    return f"{prefix(user)}/bin"


def pipx_home(user: str = "") -> str:
    """Where pipx keeps its venvs. Must be readable by the run account too: a
    console script's shebang points straight into its venv's interpreter."""
    return f"{prefix(user)}/pipx"


def tools_dir(user: str = "") -> str:
    """Where clone+venv trees land, one directory per tool."""
    return f"{prefix(user)}/tools"


def workdir(user: str = "") -> str:
    """A directory `user` can actually enter, to start a subprocess in.

    A subprocess inherits penstation's own working directory, and penstation is
    normally started from its checkout — which on a Kali engagement box is
    /root/Penstation, mode 0700 and owned by root. Stepping down to an
    unprivileged account leaves the CWD pointing there, and the account cannot
    chdir into it.

    That surfaced as a build failure with nothing to do with the build: the Go
    toolchain chdirs in every `compile` it spawns, so a `go install` died with
    "chdir /root/Penstation: permission denied" once per package — hundreds of
    identical lines, and an exit 1 that looked like a broken recipe. apt was
    unaffected because it runs as root, which is why the distro rungs worked
    while every user-scoped rung failed on the same box.

    So: anything that runs as another account starts in that account's own home.
    """
    # Existence is all we can usefully check from here: we are typically root,
    # and root's os.access() says yes to directories the target account cannot
    # enter, so a permission probe would only give false confidence.
    home = home_of(user)
    return home if os.path.isdir(home) else tempfile.gettempdir()


# -- running things ----------------------------------------------------
def as_user(user: str, argv: Sequence[str]) -> list[str]:
    """Wrap argv so it runs as `user`, or unchanged when no user is set.

    Root can step down with runuser and never needs a password. Unprivileged,
    we go through sudo, which needs the drop-in described in the design doc —
    `-n` so a missing rule fails immediately rather than hanging on a prompt
    that nobody is there to answer.
    """
    if not user:
        return list(argv)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return ["runuser", "-u", user, "--", *argv]
    return ["sudo", "-n", "-u", user, *argv]


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
# Resolved rather than assumed: apt lands in /usr/bin, go install in the install
# user's GOPATH, pipx in its own bin dir. Storing the absolute path is what makes
# a run reproducible when the server and the tool run as different users with
# different PATHs.
SEARCH_DIRS = ("/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/sbin")


async def binary_path(name: str, user: str = "") -> str:
    """Absolute path to an installed binary, or "" if it isn't there."""
    # The shared prefix first, and by path rather than by lookup: `command -v`
    # answers from the *server's* PATH, which is a different account's. That is
    # how a same-named binary earlier on someone's PATH becomes the thing that
    # actually ran — the Python `httpx` console script shadowing ProjectDiscovery's
    # is the case that bites in this space.
    home = home_of(user)
    candidates = (
        f"{bin_dir(user)}/{name}",
        f"{home}/.local/bin/{name}",       # pre-prefix installs, still valid
        f"{home}/go/bin/{name}",
        *(f"{d}/{name}" for d in SEARCH_DIRS),
    )
    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    # Nothing where we put things — fall back to asking the shell.
    code, out = await _capture(as_user(user, ["sh", "-c", f"command -v {name}"]),
                               cwd=workdir(user))
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


async def pipx_install(spec: str, on_line: OnLine, user: str = "") -> None:
    """Install a Python tool into its own venv.

    pipx rather than pip because each tool gets an isolated dependency tree,
    which is the part of per-tool images actually worth keeping.
    """
    env = {"PIPX_HOME": pipx_home(user), "PIPX_BIN_DIR": bin_dir(user)}
    code = await _stream(as_user(user, ["pipx", "install", spec]),
                         on_line, INSTALL_TIMEOUT, env=env, cwd=workdir(user))
    if code != 0:
        raise InstallError(f"pipx install {spec} failed (exit {code})")


def venv_name(spec: str) -> str:
    """The venv pipx creates for a spec — `bbot==3.0.1` becomes `bbot`."""
    return re.split(r"[<>=!~\[]", (spec or "").strip(), 1)[0].strip()


async def pipx_inject(spec: str, packages: list, on_line: OnLine,
                      user: str = "") -> None:
    """Install extra packages *into* an already-installed tool's venv.

    For dependencies a tool would otherwise resolve while running. bbot installs
    its own module dependencies at scan time and asks for root to do it, which
    the run account has no way to answer — so the scan died on a password prompt
    before a module loaded. Declaring them here installs them at setup instead:
    unprivileged, recorded on the tool record, and replayed on reinstall.

    Not fatal. A missing optional dependency costs one module; failing the whole
    install over it would cost the tool.
    """
    if not packages:
        return
    name = venv_name(spec)
    env = {"PIPX_HOME": pipx_home(user), "PIPX_BIN_DIR": bin_dir(user)}
    try:
        code = await _stream(as_user(user, ["pipx", "inject", name, *packages]),
                             on_line, INSTALL_TIMEOUT, env=env, cwd=workdir(user))
        why = f"exit {code}" if code else ""
    except InstallError as exc:
        why = str(exc)          # pipx gone, or the call never started
    if why:
        on_line(f"[warn] pipx inject {name} {' '.join(packages)} failed "
                f"({why}) — modules needing those will be skipped\n")


async def go_install(pkg: str, on_line: OnLine, user: str = "") -> None:
    """Install a Go tool from its module path.

    The path comes from the repo's own documentation, never from the repo name —
    subfinder's is `github.com/projectdiscovery/subfinder/v2/cmd/subfinder`, and
    guessing `owner/repo` fails for most real tools. See gather.extract_install.
    """
    # GOPATH stays in the install account's home: it is the module cache, wanted
    # only at build time. GOBIN is the shared prefix, because the *binary* is
    # what another account has to execute.
    home = home_of(user)
    env = {"GOPATH": f"{home}/go", "GOBIN": bin_dir(user),
           "HOME": home, "GOFLAGS": "-modcacherw"}
    if not pkg.endswith("@latest") and "@" not in pkg.rsplit("/", 1)[-1]:
        pkg = f"{pkg}@latest"
    # cwd matters more here than anywhere else: the toolchain chdirs in every
    # `compile` it spawns, so an unreachable CWD fails once per package.
    code = await _stream(as_user(user, ["go", "install", pkg]),
                         on_line, INSTALL_TIMEOUT, env=env, cwd=workdir(user))
    if code != 0:
        raise InstallError(f"go install {pkg} failed (exit {code})")


async def clone_venv(git_url: str, dest: str, on_line: OnLine, user: str = "",
                     requirements: str = "requirements.txt") -> None:
    """Clone a repo and install its requirements into a venv beside it.

    The rung for tools with no packaging — and the only one that runs arbitrary
    code from the repository, so the pipeline asks before reaching it. The repo
    is kept rather than discarded because tools like cloud_enum ship data files
    (wordlists, mutation lists) that a bare binary would lose.
    """
    work = workdir(user)
    code = await _stream(as_user(user, ["git", "clone", "--depth", "1", git_url, dest]),
                         on_line, INSTALL_TIMEOUT, cwd=work)
    if code != 0:
        raise InstallError(f"git clone failed (exit {code})")
    code = await _stream(as_user(user, ["python3", "-m", "venv", f"{dest}/.venv"]),
                         on_line, INSTALL_TIMEOUT, cwd=work)
    if code != 0:
        raise InstallError(f"venv creation failed (exit {code})")
    req = f"{dest}/{requirements}"
    if os.path.isfile(req):
        code = await _stream(
            as_user(user, [f"{dest}/.venv/bin/pip", "install", "-r", req]),
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


async def capture_help(binary: str, user: str = "") -> str:
    """The tool's own help text, for on-screen guidance.

    Kept even on a non-zero exit: plenty of tools print usage to stderr and exit
    1 or 2. The test is **produced output**, never the exit code.
    """
    best, best_score = "", (0, 0)
    for flag in HELP_FLAGS:
        _, out = await _capture(as_user(user, [binary, flag]), HELP_TIMEOUT,
                                cwd=workdir(user))
        score = _help_score(out)
        if score > best_score:
            best, best_score = out, score
        if best_score[0] and best_score[1] > 200:
            break            # convincingly help-shaped; stop paying for more
    return best.strip()


async def capture_version(binary: str, user: str = "") -> str:
    """What this box actually resolved.

    Replaces pinning. The version comes from the distro or the module proxy
    rather than from an image we built, so the run record has to say what ran —
    the same reason every map node records the tool and run that found it.
    """
    for flag in VERSION_FLAGS:
        _, out = await _capture(as_user(user, [binary, flag]), QUICK_TIMEOUT,
                                cwd=workdir(user))
        line = (out or "").strip().splitlines()
        if line and any(ch.isdigit() for ch in line[0]):
            return line[0].strip()[:200]
    return ""


async def verify(binary: str, user: str = "") -> tuple[str, str]:
    """(help text, version). Raises if the binary produced nothing at all."""
    help_text = await capture_help(binary, user)
    version = await capture_version(binary, user)
    if not help_text and not version:
        raise InstallError(
            f"{binary} produced no output for --help or --version — "
            "installed, but it may not be the right binary")
    return help_text, version


# -- remove ------------------------------------------------------------
async def apt_remove(pkg: str, on_line: OnLine) -> None:
    await _stream(["apt-get", "remove", "-y", pkg], on_line, APT_TIMEOUT,
                  env={"DEBIAN_FRONTEND": "noninteractive"}, cwd=workdir())


async def pipx_uninstall(name: str, on_line: OnLine, user: str = "") -> None:
    await _stream(as_user(user, ["pipx", "uninstall", name]), on_line, APT_TIMEOUT,
                  env={"PIPX_HOME": pipx_home(user), "PIPX_BIN_DIR": bin_dir(user)},
                  cwd=workdir(user))


async def remove_path(path: str, on_line: OnLine, user: str = "") -> None:
    """For go-install binaries and clone+venv trees."""
    if not path or path in ("/", "/usr", "/usr/bin", "/home"):
        raise InstallError(f"refusing to remove {path!r}")
    await _stream(as_user(user, ["rm", "-rf", "--", path]), on_line, QUICK_TIMEOUT,
                  cwd=workdir(user))
