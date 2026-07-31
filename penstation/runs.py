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
import shutil
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
    input_lines: int = 0          # how many lines you fed it, for the history
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

    @property
    def files_dir(self) -> Path:
        """Where files this run wrote to {{outdir}} are kept.

        Beside the log rather than in a temp dir: a screenshot or a scan export
        is evidence, and evidence that is deleted when the process exits is not
        evidence at all.
        """
        return _dir(self.project) / self.id

    def file_path(self, name: str) -> Path | None:
        """Resolve a stored file, refusing anything outside the run's dir.

        The name arrives from a URL, so it uses "/". Runs recorded before that
        was normalised stored the Windows separator instead — "scan_dir\\out.json"
        — and those records have to stay readable, on Linux and macOS too, where
        that is one filename rather than a path. Hence the second attempt.
        """
        base = self.files_dir.resolve()
        for candidate in (name, name.replace("\\", "/")):
            try:
                target = (base / candidate).resolve()
                target.relative_to(base)     # rejects ../ traversal
            except (OSError, ValueError):
                continue                     # absolute or escaping — not ours
            if target.is_file():
                return target
        return None

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
    # The id arrives from a URL and is about to be joined onto a path. Run ids
    # are generated as `<tool>-<millis>`, so anything with a separator in it is
    # not one — and file_path() only guards files *inside* a run, not which run
    # directory gets opened.
    if not run_id or "/" in run_id or "\\" in run_id or ".." in run_id:
        return None
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


def count(project: str) -> int:
    """How many runs are on file for an engagement."""
    return len(list(_dir(project).glob("*.json")))


def forget_project(project: str) -> None:
    """Drop every run and every retained file for an engagement.

    A recursive delete, because runs now own directories of evidence — the
    earlier per-file unlink() raised as soon as a run had files.
    """
    shutil.rmtree(RUNS_DIR / project, ignore_errors=True)
