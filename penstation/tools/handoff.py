"""Hand a build failure to a capable model — via you, not an API.

penstation's install ladder is deterministic and has no LLM in it. When every
rung fails, the missing piece is usually a fact about one specific project: the
system package a C extension links against, the build step its README never
spells out. That is genuinely a job for a strong model, but wiring one in means
an API key, a network dependency, and a weak local model that measurably could
not do it.

So: compose the whole question here, you paste it wherever you already have a
good model, and paste its answer back into the same box you'd type a Dockerfile
into. No integration, no key, no inference on this machine.

The prompt carries penstation's real constraints (no build context, official
base images, no fetch-execute), so an answer that follows it will pass
validate_dockerfile rather than being rejected after a round trip.
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
    r"denied|fatal|>>>|^Dockerfile:|^#\d+ \[", re.I)
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
    errors = distill(rec.read_log(tail=400)) or "(no build output captured)"
    last = (rec.dockerfile or "").strip()
    last_block = f"\nThe last Dockerfile it tried:\n```dockerfile\n{last}\n```\n" if last else ""

    return f"""I'm installing a command-line security tool into a Docker image and every \
approach has failed. Write me a Dockerfile that works.

Repository: {rec.source_url}

What was already tried, and failed:
{attempts}
{last_block}
The build errors:
```
{errors}
```

Constraints — these are properties of my build system, not preferences:
- The Dockerfile is piped to `docker build -`, so there is NO build context.
  COPY and ADD from the local filesystem cannot work. Fetch the source with
  `RUN git clone --depth 1 {rec.source_url} /src` and then set WORKDIR.
- It must start with FROM, using an official base image (golang, python, node,
  rust, alpine, debian, ubuntu).
- Never pipe a download into a shell (`curl ... | sh`).
- No `--mount=type=secret` or `--mount=type=ssh`.
- Keep it under 60 instructions.
- End with an ENTRYPOINT that runs the tool directly, so arguments passed to
  `docker run <image> <args>` reach it.
- If the tool reads data files (wordlists, signatures, templates) that ship in
  the repo, run it from the checkout rather than as an installed console
  script — otherwise it resolves those paths relative to the wrong directory.

Two things that often matter for older tools:
- An unpinned dependency set resolves against today's toolchain, which may have
  broken compatibility since. A base image contemporary with the project can be
  simpler than fighting it.
- A compile that fails on a missing header needs that library's -dev package,
  which the error usually names.

Reply with just the Dockerfile in a single code block, and one sentence on what
was actually wrong.
"""
