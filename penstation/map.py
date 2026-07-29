"""The engagement map — what you have found, and how it connects.

A directed graph, not a tree. One IP hosts many domains and one domain resolves
to many IPs; a `parent` field would force a choice that is not true. Trees are
how you *read* it, so the UI renders one — but storage keeps the real edges.

Five node kinds only: domain, host, port, webapp, finding. A service is attrs on
a port and a route is a list on a webapp; separate node kinds for those added
edges without adding information.

Nothing enters the map without you confirming it, and nothing is ever silently
overwritten — attributes keep every value with the tool that reported it, and
every node and edge records the run that found it. That provenance is what makes
undo, retest diffs and "which tool said what" possible at all.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from penstation.paths import DATA

MAP_DIR = DATA / "map"

KINDS = ("domain", "host", "port", "webapp", "finding")
RELATIONS = ("contains", "resolves_to", "has_port", "serves", "affects")

# One writer at a time. Two tools can run concurrently, and a read-modify-write
# over a whole JSON file would let the second silently discard the first's
# nodes. Every mutation goes through save(); this is what makes that safe.
_lock = asyncio.Lock()


# -- canonical identity ------------------------------------------------
# Everything downstream depends on two tools describing the same thing landing
# on the same id. Get this wrong and the map silently duplicates or, worse,
# merges things that are not the same.

def canon_domain(value: str) -> str:
    return (value or "").strip().lower().rstrip(".").removeprefix("*.")


def canon_host(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return (value or "").strip().lower()


def canon_url(value: str) -> str:
    """Scheme + host + port, dropping a bare trailing slash.

    `HTTP://ACME.COM` and `http://acme.com/` are the same web app; a path is
    kept only when it is not just "/".
    """
    raw = (value or "").strip()
    if "://" not in raw:
        raw = "http://" + raw
    u = urlsplit(raw)
    scheme = (u.scheme or "http").lower()
    host = canon_domain(u.hostname or "")
    default = {"http": 80, "https": 443}.get(scheme)
    port = u.port
    netloc = host if port in (None, default) else f"{host}:{port}"
    path = u.path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


def node_id(kind: str, value: str, **extra) -> str:
    if kind == "domain":
        return f"domain:{canon_domain(value)}"
    if kind == "host":
        return f"host:{canon_host(value)}"
    if kind == "port":
        return f"port:{canon_host(value)}:{int(extra['port'])}"
    if kind == "webapp":
        return f"webapp:{canon_url(value)}"
    if kind == "finding":
        # Content-addressed: the same check on the same target is one finding
        # whenever it is re-run, so a re-scan updates last_seen instead of
        # stacking duplicates — and the difference between runs is a retest.
        check = re.sub(r"[^a-z0-9.-]+", "-", (value or "").strip().lower()).strip("-")
        return f"finding:{check}@{extra.get('on','')}"
    raise ValueError(f"unknown kind {kind!r}")


# -- classification ----------------------------------------------------
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+\.?$", re.I)
_HOSTPORT = re.compile(r"^(?P<h>[^\s:/]+):(?P<p>\d{1,5})$")


def classify(line: str) -> tuple[str, dict] | None:
    """What kind of thing is this line? None when it isn't one.

    Deliberately conservative: a wrong node is worse than no node, because you
    have to notice it to fix it.
    """
    s = (line or "").strip()
    if not s or s.startswith("#"):
        return None
    if "://" in s:
        return ("webapp", {"value": s})
    try:
        ipaddress.ip_address(s)
        return ("host", {"value": s})
    except ValueError:
        pass
    if m := _HOSTPORT.match(s):
        port = int(m.group("p"))
        if 0 < port < 65536:
            return ("port", {"value": m.group("h"), "port": port})
    if _DOMAIN.match(s):
        return ("domain", {"value": s})
    return None


def classify_all(text: str) -> dict:
    """Classify every line, reporting how uniform the result is.

    Uniform output can be imported wholesale; mixed output needs looking at.
    """
    rows, kinds = [], set()
    for line in (text or "").splitlines():
        hit = classify(line)
        if hit:
            rows.append({"line": line.strip(), "kind": hit[0], **hit[1]})
            kinds.add(hit[0])
    return {"rows": rows, "kinds": sorted(kinds),
            "uniform": len(kinds) == 1, "total": len(rows)}


# -- records -----------------------------------------------------------
@dataclass
class Node:
    id: str
    kind: str
    value: str
    # Attribute values are kept with the tool that reported them rather than
    # overwritten. whatweb saying nginx 1.18 while httpx says 1.20 is usually a
    # load balancer or a stale banner — the disagreement is the interesting
    # part, and last-write-wins would hide it behind whichever ran last.
    attrs: dict = field(default_factory=dict)      # name -> [{value, source, at}]
    checks: dict = field(default_factory=dict)     # check kind -> run id
    sources: list = field(default_factory=list)    # [{run, tool, at}]
    tags: list = field(default_factory=list)
    note: str = ""
    dismissed: bool = False                        # you deleted it; re-discovery
                                                   # shows it as dismissed rather
                                                   # than silently reappearing
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def attr(self, name: str) -> str:
        """Most recent value, for display."""
        vals = self.attrs.get(name) or []
        return vals[-1]["value"] if vals else ""

    def conflicts(self) -> list[str]:
        """Attributes where sources disagree — worth surfacing in the UI."""
        return [k for k, v in self.attrs.items()
                if len({x["value"] for x in v}) > 1]


@dataclass
class Edge:
    frm: str
    rel: str
    to: str
    sources: list = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def key(self) -> str:
        return f"{self.frm}|{self.rel}|{self.to}"


@dataclass
class Map:
    project: str
    nodes: dict = field(default_factory=dict)      # id -> Node
    edges: dict = field(default_factory=dict)      # key -> Edge

    # -- mutation ------------------------------------------------------
    def add_node(self, kind: str, value: str, *, run: str = "", tool: str = "",
                 attrs: dict | None = None, **extra) -> Node:
        nid = node_id(kind, value, **extra)
        now = time.time()
        node = self.nodes.get(nid)
        if node is None:
            node = Node(id=nid, kind=kind, value=value.strip())
            self.nodes[nid] = node
        node.last_seen = now
        if run and not any(s.get("run") == run for s in node.sources):
            node.sources.append({"run": run, "tool": tool, "at": now})
        for name, val in (attrs or {}).items():
            if val in (None, "", []):
                continue
            bucket = node.attrs.setdefault(name, [])
            if not any(x["value"] == val and x["source"] == tool for x in bucket):
                bucket.append({"value": val, "source": tool or "manual", "at": now})
        return node

    def link(self, frm: str, rel: str, to: str, *, run: str = "", tool: str = "") -> Edge:
        now = time.time()
        e = Edge(frm=frm, rel=rel, to=to)
        edge = self.edges.get(e.key) or e
        self.edges[edge.key] = edge
        edge.last_seen = now
        if run and not any(s.get("run") == run for s in edge.sources):
            edge.sources.append({"run": run, "tool": tool, "at": now})
        return edge

    def mark_checked(self, node_id_: str, check: str, run: str) -> None:
        if node := self.nodes.get(node_id_):
            node.checks[check] = run

    def dismiss(self, nid: str) -> bool:
        """Soft delete. A hard delete would be undone by the next run that finds
        it again, and you would keep dismissing the same false positive."""
        if node := self.nodes.get(nid):
            node.dismissed = True
            return True
        return False

    def restore(self, nid: str) -> bool:
        if node := self.nodes.get(nid):
            node.dismissed = False
            return True
        return False

    def remove(self, nid: str) -> bool:
        """Hard delete, plus any edge touching it."""
        if self.nodes.pop(nid, None) is None:
            return False
        for k in [k for k, e in self.edges.items() if nid in (e.frm, e.to)]:
            self.edges.pop(k, None)
        return True

    def undo_run(self, run: str) -> int:
        """Drop everything a run contributed.

        Nodes another run also saw keep their other sources and stay; only the
        ones this run alone is responsible for go.
        """
        gone = 0
        for nid, node in list(self.nodes.items()):
            node.sources = [s for s in node.sources if s.get("run") != run]
            if not node.sources:
                self.remove(nid)
                gone += 1
        for k, edge in list(self.edges.items()):
            edge.sources = [s for s in edge.sources if s.get("run") != run]
            if not edge.sources:
                self.edges.pop(k, None)
        return gone

    # -- reading -------------------------------------------------------
    def out(self, nid: str, rel: str | None = None) -> list[Edge]:
        return [e for e in self.edges.values()
                if e.frm == nid and (rel is None or e.rel == rel)]

    def by_kind(self, kind: str, include_dismissed: bool = False) -> list[Node]:
        return [n for n in self.nodes.values()
                if n.kind == kind and (include_dismissed or not n.dismissed)]

    def coverage(self, check: str, kind: str) -> dict:
        nodes = self.by_kind(kind)
        done = [n for n in nodes if check in n.checks]
        return {"kind": kind, "check": check,
                "total": len(nodes), "done": len(done),
                "pending": len(nodes) - len(done)}

    def to_dict(self) -> dict:
        return {"project": self.project,
                "nodes": {k: asdict(v) for k, v in self.nodes.items()},
                "edges": {k: asdict(v) for k, v in self.edges.items()}}


# -- persistence -------------------------------------------------------
def _path(project: str):
    MAP_DIR.mkdir(parents=True, exist_ok=True)
    return MAP_DIR / f"{project}.json"


def load(project: str) -> Map:
    try:
        raw = json.loads(_path(project).read_text())
    except (OSError, ValueError):
        return Map(project=project)
    m = Map(project=project)
    for nid, n in (raw.get("nodes") or {}).items():
        m.nodes[nid] = Node(**{k: v for k, v in n.items()
                               if k in Node.__dataclass_fields__})
    for key, e in (raw.get("edges") or {}).items():
        m.edges[key] = Edge(**{k: v for k, v in e.items()
                               if k in Edge.__dataclass_fields__})
    return m


async def mutate(project: str, fn):
    """Read → change → write, serialised.

    The only supported way to change a map. `fn` receives the Map and whatever
    it returns is handed back to the caller.
    """
    async with _lock:
        m = load(project)
        result = fn(m)
        _path(project).write_text(json.dumps(m.to_dict(), indent=2))
        return result
