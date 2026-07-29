"""Recorded tool runs, filed under the engagement they belong to.

Output used to be transient — it lived in the browser until you navigated away.
That is fine for checking a command works and useless as evidence: a scan
against one client and a scan against another shared one pane, with nothing
tying either to an engagement.

A run is therefore stored under its project. Metadata is small and goes in JSON;
output can be megabytes and goes beside it in a plain log file, so listing runs
never reads the output.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from penstation.paths import DATA

RUNS_DIR = DATA / "runs"


def _dir(project: str) -> Path:
    d = RUNS_DIR / project
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class Run:
    id: str
    project: str
    tool: str
    section: str = ""
    command: str = ""
    exit_code: int | None = None
    error: str = ""
    files: list = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    @property
    def path(self) -> Path:
        return _dir(self.project) / f"{self.id}.json"

    @property
    def log_path(self) -> Path:
        return _dir(self.project) / f"{self.id}.log"

    def append(self, text: str) -> None:
        with self.log_path.open("a") as fh:
            fh.write(text)

    def output(self, limit: int = 200_000) -> str:
        try:
            data = self.log_path.read_text(errors="replace")
        except OSError:
            return ""
        # Newest content is what matters when a scan floods the log.
        return data if len(data) <= limit else data[-limit:]

    def save(self) -> "Run":
        self.path.write_text(json.dumps(asdict(self), indent=2))
        return self

    def to_dict(self) -> dict:
        d = asdict(self)
        d["duration"] = round((self.finished_at or time.time()) - self.started_at, 1)
        return d


def start(project: str, tool: str, section: str, command: str) -> Run:
    # Second-resolution ids would collide when a command fails instantly and you
    # immediately retry, silently overwriting the previous run.
    rid = f"{tool}-{int(time.time() * 1000)}"
    run = Run(id=rid, project=project, tool=tool, section=section, command=command)
    run.log_path.write_text("")
    return run.save()


def load(project: str, run_id: str) -> Run | None:
    try:
        raw = json.loads((_dir(project) / f"{run_id}.json").read_text())
    except (OSError, ValueError):
        return None
    known = {f for f in Run.__dataclass_fields__}
    return Run(**{k: v for k, v in raw.items() if k in known})


def for_tool(project: str, tool: str, limit: int | None = None) -> list[Run]:
    """Runs of one tool in one engagement, newest first.

    Nothing is ever pruned — a run is evidence, and evidence you deleted to save
    disk is evidence you cannot produce later. `limit` only bounds a listing.
    """
    out = []
    for f in _dir(project).glob(f"{tool}-*.json"):
        if r := load(project, f.stem):
            out.append(r)
    out.sort(key=lambda r: r.started_at, reverse=True)
    return out[:limit] if limit else out


def forget_project(project: str) -> None:
    d = RUNS_DIR / project
    if not d.exists():
        return
    for f in d.iterdir():
        f.unlink(missing_ok=True)
    d.rmdir()
