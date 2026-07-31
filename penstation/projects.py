"""Engagements, and which tools each one uses.

Installing a tool is expensive and the result is identical whichever client you
point it at, so tools live in one library (tools/store.py) and a project only
records *which* of them it uses, and in which section. The same nuclei install
can therefore serve every engagement without being redone, while each engagement
shows only the tooling that belongs to it.

Sections come from the engagement type: an external test and an internal one run
through different phases, so the section list is a property of the type rather
than a constant.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field

from penstation import engagements
from penstation.paths import DATA

PROJECTS_DIR = DATA / "projects"

# Methodology lives in penstation/engagements — a project only records which
# type it is, so adding an engagement type never touches this file.
TYPES = engagements.TYPES
sections_for = engagements.sections_for


# How hard this engagement may be tested.
#
# A property of the engagement, not of a command. The right pace is a client
# decision — a CDN-fronted marketing site and a self-hosted application on small
# hardware want very different answers — and encoding it per command meant
# baseline tools drifting apart with nothing recording what had actually been
# agreed. Baseline commands write placeholders; these decide what they become.
#
# Stored on the project, so a run's recorded command states the pace it ran at.
# "Did your test cause the outage?" is a question you answer from the run
# history or not at all.
#
# `careful` is the default on both dials deliberately. Scanning is authorised;
# degrading a service usually is not.
# Two dials, not one. The same word cannot mean the right thing for both: on a
# real engagement — several hundred names across a hundred addresses — the same
# "careful" costs the port scanner hours and the web probe about three minutes.
# One setting therefore either makes the scan unusable or makes the probe
# needlessly loud, and there is no value that avoids both.
PACE_KEYS = ("careful", "normal", "aggressive")
DEFAULT_PACE = "careful"

# Port scanning. Timing decides how long you wait; probe intensity decides how
# likely you are to upset something. They are separate flags because they are
# separate risks — what knocks a fragile service over is being sent an odd
# protocol probe, not being sent packets quickly. So the gentler settings reach
# for `--version-light` first and only slow the clock when asked.
#
# Measured against a scan of three hosts across the top 1000 ports, nearly all
# filtered — the worst case, since every filtered port waits out a timeout:
# `-T4` took 35 seconds. `-T3` is a small multiple of that. `-T2` puts 0.4s
# between probes and serialises them, which is 400 seconds per host before any
# timeout — hours on a real estate, so it is not offered here. Ask for it by
# hand on the run you need it for.
SCAN_PACES = {
    "careful":    {"timing": "-T3", "probes": "--version-light",
                   "label": "careful — nmap's own timing, fewest service probes"},
    "normal":     {"timing": "-T4", "probes": "--version-light",
                   "label": "normal — quicker timeouts, still the light probe set"},
    "aggressive": {"timing": "-T4", "probes": "",
                   "label": "aggressive — nmap's full service-probe set"},
}

# HTTP probing. One request per target, so the cost is concurrency against a
# single origin rather than volume: many hostnames routinely resolve to a
# handful of addresses, and the whole sweep lands on those.
#
# Cheap at every setting — around 1,500 probes takes ~3 minutes at `careful` —
# so the reason to move this dial is being noticed, not being slow. Hundreds of
# requests carrying hundreds of distinct Host headers from one source address is
# what enumeration detection is looking for.
WEB_PACES = {
    "careful":    {"threads": 5,  "rate": 10,
                   "label": "careful — 5 at a time, 10 requests a second"},
    "normal":     {"threads": 10, "rate": 20,
                   "label": "normal — 10 at a time, 20 requests a second"},
    "aggressive": {"threads": 50, "rate": 150,
                   "label": "aggressive — httpx's own defaults"},
}


def scan_pace(pace: str) -> dict:
    return SCAN_PACES.get(pace or DEFAULT_PACE, SCAN_PACES[DEFAULT_PACE])


def web_pace(pace: str) -> dict:
    return WEB_PACES.get(pace or DEFAULT_PACE, WEB_PACES[DEFAULT_PACE])


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s or "project"


@dataclass
class Project:
    id: str
    client: str = ""
    scope: str = ""
    kind: str = engagements.DEFAULT   # engagement type; drives the section list
    pace_scan: str = DEFAULT_PACE     # nmap, and anything that probes ports
    pace_web: str = DEFAULT_PACE      # httpx, and anything that speaks HTTP
    pace: str = ""                    # retired: one dial that drove both. Kept
                                      # so a record written before the split
                                      # still loads and carries its choice over
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

    @property
    def targets(self) -> list[str]:
        """Every domain in scope, in the order written.

        The engagement's scope is the basis for everything the baseline runs
        against, so a scope naming three domains has to reach all three — using
        only the first silently under-tested two of them.
        """
        from penstation import scope as scope_mod
        out = []
        for rule in scope_mod.parse(self.scope):
            if scope_mod.is_network(rule):        # a network, not a domain
                continue
            apex = rule.removeprefix("*.")
            if apex and not apex.replace(".", "").isdigit() and apex not in out:
                out.append(apex)
        return out

    @property
    def networks(self) -> list[str]:
        from penstation import scope as scope_mod
        return [r for r in scope_mod.parse(self.scope) if scope_mod.is_network(r)]

    @property
    def scope_all(self) -> list[str]:
        """Everything in scope — domains and networks, in the order written.

        For tools that accept both. bbot takes `-t acme.com 203.0.113.0/24` and
        expands the CIDR itself, so restricting it to domains silently left the
        network ranges untested.
        """
        from penstation import scope as scope_mod
        out = []
        for rule in scope_mod.parse(self.scope):
            v = rule.removeprefix("*.")
            if v and v not in out:
                out.append(v)
        return out

    @property
    def target(self) -> str:
        """The primary target, for commands that take exactly one."""
        t = self.targets
        return t[0] if t else ""

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
        d["kind_label"] = engagements.label_for(self.kind)
        d["target"] = self.target
        d["targets"] = self.targets
        d["networks"] = self.networks
        d["scope_all"] = self.scope_all
        # The numbers behind each pace, so the command box can show what will
        # actually run rather than a placeholder.
        d["pace_scan_values"] = scan_pace(self.pace_scan)
        d["pace_web_values"] = web_pace(self.pace_web)
        d["scan_pace_options"] = [{"key": k, "label": v["label"]}
                                  for k, v in SCAN_PACES.items()]
        d["web_pace_options"] = [{"key": k, "label": v["label"]}
                                 for k, v in WEB_PACES.items()]
        # Rules that cannot match anything, reported with the project so the UI
        # can say so where the scope is shown rather than silently finding less.
        from penstation import scope as scope_mod
        d["scope_problems"] = [{"rule": r, "why": w}
                               for r, w in scope_mod.problems(self.scope)]
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
    p = Project(**{k: v for k, v in raw.items() if k in known})
    # An engagement set before the split kept one word for both tools. Carry it
    # to each dial rather than silently resetting a decision that was made.
    if p.pace and "pace_scan" not in raw:
        carried = p.pace if p.pace in PACE_KEYS else DEFAULT_PACE
        p.pace_scan = p.pace_web = carried
    p.pace = ""
    return p


def load_all() -> list[Project]:
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    out = [p for f in sorted(PROJECTS_DIR.glob("*.json")) if (p := load(f.stem))]
    return sorted(out, key=lambda p: p.created_at)


def create(client: str, scope: str = "", kind: str = engagements.DEFAULT) -> Project:
    base = slug(client)
    pid, n = base, 2
    while (PROJECTS_DIR / f"{pid}.json").exists():
        pid, n = f"{base}-{n}", n + 1
    return Project(id=pid, client=client.strip(), scope=scope.strip(),
                   kind=kind if kind in TYPES else engagements.DEFAULT).save()


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

    from penstation.tools import store           # local: avoids a cycle
    proj = create("Unassigned")
    for rec in store.load_all():
        section = getattr(rec, "section", "") or sections_for(proj.kind)[0][0]
        proj.assign(section, rec.id)
    return proj.save()
