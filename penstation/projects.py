"""Engagements, and which tools each one uses.

A tool's Docker image is expensive to build and identical whichever client you
point it at, so images live in one library (addtool/store.py) and a project only
records *which* of them it uses, and in which section. The same nuclei image can
therefore serve every engagement without rebuilding, while each engagement shows
only the tooling that belongs to it.

Sections come from the engagement type: an external test and an internal one run
through different phases, so the section list is a property of the type rather
than a constant.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field

from penstation.paths import DATA

PROJECTS_DIR = DATA / "projects"

# Engagement types -> the sections they run through, in order.
TYPES: dict[str, list[tuple[str, str]]] = {
    "external": [
        ("reconnaissance",    "Reconnaissance"),
        ("active-scanning",   "Active Scanning"),
        ("web-analysis",      "Web Analysis"),
        ("password-spraying", "Password Spraying"),
        ("exploitation",      "Exploitation"),
    ],
}


def sections_for(kind: str) -> list[tuple[str, str]]:
    return TYPES.get(kind) or TYPES["external"]


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s or "project"


@dataclass
class Project:
    id: str
    client: str = ""
    scope: str = ""
    kind: str = "external"            # engagement type; drives the section list
    notes: str = ""
    # section key -> tool ids, in the order you added them. Membership lives
    # here rather than on the tool so one image can sit in different sections
    # for different clients.
    sections: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @property
    def label(self) -> str:
        return self.client or self.id

    def tools_in(self, section: str) -> list[str]:
        return list(self.sections.get(section) or [])

    def assign(self, section: str, tool_id: str) -> bool:
        ids = self.sections.setdefault(section, [])
        if tool_id in ids:
            return False
        ids.append(tool_id)
        return True

    def unassign(self, section: str, tool_id: str) -> bool:
        ids = self.sections.get(section) or []
        if tool_id not in ids:
            return False
        ids.remove(tool_id)
        return True

    def forget(self, tool_id: str) -> None:
        """Drop a tool from every section — used when its image is deleted."""
        for ids in self.sections.values():
            if tool_id in ids:
                ids.remove(tool_id)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["label"] = self.label
        d["section_list"] = [{"key": k, "label": l} for k, l in sections_for(self.kind)]
        return d

    def save(self) -> "Project":
        PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
        self.updated_at = time.time()
        (PROJECTS_DIR / f"{self.id}.json").write_text(json.dumps(asdict(self), indent=2))
        return self


def load(pid: str) -> Project | None:
    try:
        raw = json.loads((PROJECTS_DIR / f"{pid}.json").read_text())
    except (OSError, ValueError):
        return None
    known = {f for f in Project.__dataclass_fields__}
    return Project(**{k: v for k, v in raw.items() if k in known})


def load_all() -> list[Project]:
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    out = [p for f in sorted(PROJECTS_DIR.glob("*.json")) if (p := load(f.stem))]
    return sorted(out, key=lambda p: p.created_at)


def create(client: str, scope: str = "", kind: str = "external") -> Project:
    base = slug(client)
    pid, n = base, 2
    while (PROJECTS_DIR / f"{pid}.json").exists():
        pid, n = f"{base}-{n}", n + 1
    return Project(id=pid, client=client.strip(), scope=scope.strip(),
                   kind=kind if kind in TYPES else "external").save()


def delete(pid: str) -> bool:
    """Remove the engagement. Tool images are untouched — they are shared."""
    try:
        (PROJECTS_DIR / f"{pid}.json").unlink()
        return True
    except OSError:
        return False


def forget_tool(tool_id: str) -> None:
    """Unassign a tool from every project, after its image has been deleted."""
    for p in load_all():
        before = json.dumps(p.sections, sort_keys=True)
        p.forget(tool_id)
        if json.dumps(p.sections, sort_keys=True) != before:
            p.save()


def ensure_default() -> Project:
    """Guarantee at least one project, adopting any pre-project tools.

    Tools used to carry their own `section`, with no notion of an engagement.
    Rather than orphan them, fold them into a first project so nothing
    disappears the moment projects arrive.
    """
    existing = load_all()
    if existing:
        return existing[0]

    from penstation.addtool import store           # local: avoids a cycle
    proj = create("Unassigned")
    for rec in store.load_all():
        section = getattr(rec, "section", "") or "reconnaissance"
        proj.assign(section, rec.id)
    return proj.save()
