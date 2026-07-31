"""Hand a build failure to a capable model — via you, not an API.

penstation's install ladder is deterministic and has no LLM in it. When every
rung fails, the missing piece is usually a fact about one specific project: the
system package a C extension links against, the build step its README never
spells out. That is genuinely a job for a strong model, but wiring one in means
an API key, a network dependency, and a weak local model that measurably could
not do it.

So: compose the whole question here, you paste it wherever you already have a
good model, and paste its answer back into the manual-install box. No
integration, no key, no inference on this machine.

The prompt carries penstation's real constraints (one command, no shell, no
fetch-execute), so an answer that follows it will pass validate_install rather
than being rejected after a round trip.
"""
from __future__ import annotations

import re

MAX_ERROR_LINES = 60

# Interpreter and package-manager internals. A failing pip install emits dozens
# of frames from its own machinery, none of which is about the repo — they crowd
# out the one line that names the actual problem.
_NOISE = re.compile(
    r'^\s*(File "|  \^+|  ~+|\.{3}<\d+ lines>|\| |╰─>|│ |╭|╯)|'
    r'site-packages/(pip|setuptools|pyproject_hooks)/', re.I)
_SIGNAL = re.compile(
    r"error|failed|cannot|could not|no such|not found|no module|unable to|"
    r"denied|fatal|>>>|requires go|note: module", re.I)
_MAX_LINE = 400


def distill(log: str) -> str:
    """The lines of a build log that actually name the failure.

    Long lines are kept head-and-tail: pip's "from versions: …" list runs to
    thousands of characters and the useful, recent versions are at the end.
    """
    kept: list[str] = []
    for raw in (log or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or _NOISE.search(line) or not _SIGNAL.search(line):
            continue
        if len(line) > _MAX_LINE:
            line = f"{line[:_MAX_LINE // 2]} …… {line[-_MAX_LINE // 2:]}"
        kept.append(line)
    if not kept:
        kept = [l for l in (log or "").splitlines() if l.strip()]
    return "\n".join(kept[-MAX_ERROR_LINES:])


def prompt_for(rec, tried: list[str] | None = None) -> str:
    """A self-contained prompt describing this failure, ready to paste."""
    attempts = "\n".join(f"  - {t}" for t in (tried or [])) or "  - (none recorded)"
    errors = distill(rec.read_log(tail=400)) or "(no install output captured)"
    last = (rec.manual_install or rec.install_cmd or "").strip()
    last_block = f"\nThe last command it tried:\n```\n{last}\n```\n" if last else ""

    return f"""I'm installing a command-line security tool natively on a Debian-based \
box (Kali) and every approach has failed. Give me an install command that works.

Repository: {rec.source_url}

What was already tried, and failed:
{attempts}
{last_block}
The install errors:
```
{errors}
```

Constraints — these are properties of my installer, not preferences:
- The result must be a SINGLE command, run as argv with NO shell. Pipes,
  `&&`, `;`, redirection, backticks and `$(...)` are all rejected — if the fix
  needs several steps, tell me the system packages to install first in prose and
  give the one command separately.
- It must start with one of: apt-get install, pipx install, pip install,
  go install, git clone, cargo install, npm install, gem install, make.
- Never pipe a download into a shell (`curl ... | sh`). curl and wget are
  rejected outright in an install command.
- No sudo/su in the command itself — privilege is handled by the installer.
- It runs as an unprivileged account whose HOME is its own, so anything writing
  outside that home will fail.
- Afterwards a binary must be on PATH (or in ~/.local/bin or ~/go/bin), because
  the next step resolves the command's absolute path and fails without it.
- If the tool reads data files (wordlists, signatures, templates) that ship in
  the repo, prefer a `git clone` so those files stay beside it — an installed
  console script resolves those paths relative to the wrong directory.

Two things that often matter here:
- A Go tool's module path is usually NOT `owner/repo` (subfinder is really
  `github.com/projectdiscovery/subfinder/v2/cmd/subfinder`), and a recent tool
  may need a newer Go toolchain than the distro ships — if so, say which.
- A compile that fails on a missing header needs that library's -dev package,
  which the error usually names.

Reply with the single install command in a code block, any system packages I
need first, and one sentence on what was actually wrong.
"""
