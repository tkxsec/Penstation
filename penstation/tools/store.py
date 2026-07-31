"""Tool record + file-per-tool store.

The ToolRecord is the contract every pipeline stage reads and writes (see
docs/external-design.md). Storage is one JSON file per tool plus a sibling
append-only log, so build output can grow without rewriting the record.

    data/tools/<id>.json     the record
    data/tools/<id>.log      build/setup log (append-only)
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from penstation.paths import TOOLS_DIR  # anchored to the project, not the CWD

# Status machine. queued -> ... -> ready | failed
STATUSES = (
    "queued", "inspecting", "building", "repairing", "verifying", "ready", "failed",
)
TERMINAL = ("ready", "failed")

# How the tool was acquired. Recorded because reinstall replays the same rung:
# a tool that shipped data files alongside its code — cloud_enum's mutation
# lists — must not come back as a bare binary that has lost them.
STRATEGIES = ("apt", "pipx", "go-install", "release-binary", "clone-venv")


def slug(text: str) -> str:
    """A filesystem-safe id."""
    s = re.sub(r"[^a-z0-9._-]+", "-", (text or "").strip().lower()).strip("-._")
    return s[:64] or "tool"


@dataclass
class ToolRecord:
    id: str
    source_url: str = ""
    section: str = ""
    strategy: str = ""
    resolved_ref: str = ""       # commit/tag actually installed
    install_cmd: str = ""
    # Where the tool actually landed, resolved with `command -v` rather than
    # assumed: apt writes to /usr/bin, go install to the install user's GOPATH,
    # pipx to its own bin dir, and the server may not share their PATH.
    binary_path: str = ""
    version: str = ""            # what this box resolved; replaces pinning
    install_kind: str = ""       # which rung: apt | pipx | go-install | clone-venv
    install_pkg: str = ""        # package / module path that rung installs
    install_binary: str = ""     # command it provides, when it differs from the
                                 # package name — dnsutils installs `dig`
    manual_install: str = ""     # install command you supplied when the ladder found none
    tried: list = field(default_factory=list)   # recipe notes, for the handoff prompt
    baseline: bool = False       # part of an engagement type's baseline toolset
    check: str = ""              # coverage kind this tool satisfies (portscan, resolve…)
    baseline_order: int = 0      # position in the baseline workflow
    consumes: list = field(default_factory=list)   # map node kinds it takes as input
    result_file: str = ""        # basename of the output file holding its results;
                                 # when set, promotion reads only that file rather
                                 # than sweeping every log the tool wrote
    output_files: list = field(default_factory=list)
                                 # basename globs worth listing after a run;
                                 # empty lists everything the run retained
    targets: list = field(default_factory=list)
                                 # node kinds this tool can be pointed at one
                                 # at a time, from the map. `consumes` is the
                                 # list form; this is the single-target form
    vhosts: bool = False         # the protocol routes on the hostname, so a port
                                 # is reachable as every name that resolves to
                                 # its host — and names under a wildcard are
                                 # separate targets rather than one
    run_template: str = ""       # extracted hint — shown as the input's placeholder
    last_command: str = ""       # what you last ran, for history only
    command_override: str = ""   # your edit, if you made one; clears back to
                                 # the generated default when emptied
    entrypoint: str = ""         # basename of the command it provides
    help_text: str = ""          # captured --help, shown beside the run box
    target_kind: str = "domain"
    output_format: str = "stdout"
    status: str = "queued"
    detail: str = ""             # short human-readable status/error line
    llm_attempts: int = 0   # legacy field, kept so old records still load
    queue_position: int = 0      # >0 while waiting behind another build
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # -- paths ---------------------------------------------------------
    @property
    def path(self) -> Path:
        return TOOLS_DIR / f"{self.id}.json"

    @property
    def log_path(self) -> Path:
        return TOOLS_DIR / f"{self.id}.log"

    # -- persistence ---------------------------------------------------
    def save(self) -> "ToolRecord":
        self.updated_at = time.time()
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2))
        tmp.replace(self.path)  # atomic: never leave a half-written record
        return self

    def set_status(self, status: str, detail: str = "") -> "ToolRecord":
        if status not in STATUSES:
            raise ValueError(f"unknown status: {status!r}")
        self.status = status
        self.detail = detail
        return self.save()

    def append_log(self, text: str) -> None:
        if not text:
            return
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(text)

    def read_log(self, tail: int | None = None) -> str:
        try:
            data = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        if tail is None:
            return data
        return "\n".join(data.splitlines()[-tail:])

    def to_dict(self) -> dict:
        return asdict(self)


# -- module-level store API -------------------------------------------
def load(tool_id: str) -> ToolRecord | None:
    try:
        data = json.loads((TOOLS_DIR / f"{tool_id}.json").read_text())
    except (OSError, ValueError):
        return None
    known = set(ToolRecord.__dataclass_fields__)
    return ToolRecord(**{k: v for k, v in data.items() if k in known})


def load_all() -> list[ToolRecord]:
    if not TOOLS_DIR.exists():
        return []
    out = []
    for p in sorted(TOOLS_DIR.glob("*.json")):
        rec = load(p.stem)
        if rec is not None:
            out.append(rec)
    return sorted(out, key=lambda r: r.created_at, reverse=True)


def exists(tool_id: str) -> bool:
    return (TOOLS_DIR / f"{tool_id}.json").exists()


def create(source_url: str, section: str, tool_id: str) -> ToolRecord:
    rec = ToolRecord(id=tool_id, source_url=source_url, section=section)
    rec.save()
    return rec


def reap_orphans() -> list[str]:
    """Fail any record left mid-setup by a crash or restart.

    A build lives in the server process, so if that process dies the record
    would otherwise sit in a non-terminal status forever — a spinner in the UI
    with nothing behind it. Called at startup; the tool can then be retried.
    """
    orphaned = []
    for rec in load_all():
        if rec.status not in TERMINAL:
            rec.append_log("\n[interrupted] the server stopped while this was "
                           f"'{rec.status}'. Press Retry to start over.\n")
            rec.queue_position = 0
            rec.set_status("failed", f"interrupted during {rec.status} "
                                     "(server restarted) — retry to resume")
            orphaned.append(rec.id)
    return orphaned


def delete(tool_id: str) -> bool:
    rec = load(tool_id)
    if rec is None:
        return False
    rec.path.unlink(missing_ok=True)
    rec.log_path.unlink(missing_ok=True)
    return True
