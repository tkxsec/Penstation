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

# Filenames look exactly like domains. A log line mentioning output.csv would
# otherwise be offered as a subdomain, which is the sweep's main false positive.
_NOT_TLD = {
    "csv", "json", "txt", "xml", "html", "htm", "log", "yml", "yaml", "md",
    "py", "js", "ts", "go", "rs", "sh", "rb", "php", "java", "c", "h", "cpp",
    "png", "jpg", "jpeg", "gif", "svg", "pdf", "zip", "tar", "gz", "tsv",
    "conf", "cfg", "ini", "toml", "lock", "bak", "tmp", "out", "err", "pem",
    "key", "crt", "db", "sqlite", "so", "dll", "exe", "bin", "dat",
}
_HOSTPORT = re.compile(r"^(?P<h>[^\s:/]+):(?P<p>\d{1,5})$")

# A domain that answers for every label under it. bbot reports the fact once, as
# `_wildcard.janktm.acme.com`, instead of the unbounded list of names that would
# all resolve to the same host; `*.acme.com` is the same claim written by hand.
#
# It is a fact about the parent, not a host. Swept up as a name it became
# `wildcard.janktm.acme.com` — a node for something that does not exist — while
# the names it was warning about still arrived one at a time from every other
# tool. A bare `wildcard.acme.com` is left alone: that is a legitimate hostname.
_WILDCARD = re.compile(r"^(?:[_*]wildcard|\*)\.(?P<parent>.+)$", re.I)


def wildcard_of(value: str) -> str:
    """The domain this wildcard marker is about, or "" when it is not one."""
    m = _WILDCARD.match((value or "").strip().rstrip("."))
    parent = canon_domain(m.group("parent")) if m else ""
    return parent if parent and _DOMAIN.match(parent) else ""


def wildcard_over(wildcards, value: str) -> str:
    """The nearest domain in `wildcards` that this value sits under, or "".

    Strict ancestors only, so a wildcard does not fold into itself, and never the
    TLD. `clay.janktm.acme.com` and `clay-saturn.janktm.acme.com` both fold into
    `janktm.acme.com`: they are one host, and carrying them separately inflates
    the attack surface in the report and scans the same machine once per name.
    """
    parts = canon_domain(value).split(".")
    for i in range(1, len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in wildcards:
            return cand
    return ""


def classify(line: str) -> tuple[str, dict] | None:
    """What kind of thing is this line? None when it isn't one.

    Deliberately conservative: a wrong node is worse than no node, because you
    have to notice it to fix it.
    """
    s = (line or "").strip()
    if not s or s.startswith("#"):
        return None
    if parent := wildcard_of(s):
        return ("domain", {"value": parent, "wildcard": True})
    if "://" in s:
        # urlsplit raises on malformed brackets, and log lines contain anything.
        try:
            u = urlsplit(s if s.startswith(("http://", "https://")) else "http://" + s)
            host = u.hostname or ""
        except ValueError:
            return None
        # A log line containing a URL is not itself a URL; the sweep finds the
        # URL inside it. Only accept a line that *is* one.
        if u.scheme in ("http", "https") and host and " " not in s and _DOMAIN.match(host):
            return ("webapp", {"value": s})
        try:
            ipaddress.ip_address(host)
            if " " not in s:
                return ("webapp", {"value": s})
        except ValueError:
            pass
        return None
    try:
        ipaddress.ip_address(s)
        return ("host", {"value": s})
    except ValueError:
        pass
    if m := _HOSTPORT.match(s):
        port = int(m.group("p"))
        if 0 < port < 65536:
            return ("port", {"value": m.group("h"), "port": port})
    if _DOMAIN.match(s) and s.rsplit(".", 1)[-1].lower() not in _NOT_TLD:
        return ("domain", {"value": s})
    return None


# Tokens embedded in a line rather than being the whole line. bbot logs
# `[DNS_NAME] www.acme.com  TARGET`, and its result files are structured events —
# whole-line matching finds nothing in either, which is why a real bbot run
# reported "nothing recognisable to promote".
_TOKEN = re.compile(
    # Wildcard markers first, and as whole tokens: the domain alternative cannot
    # start on "_" or "*", so the scan skipped the marker and matched the name
    # inside it — which is exactly how the phantom `wildcard.…` node was born.
    r"[_*]wildcard\.(?:[a-z0-9-]+\.)+[a-z]{2,63}"
    r"|\*\.(?:[a-z0-9-]+\.)+[a-z]{2,63}"
    r"|https?://[^\s\"'<>,;)\]}]+"                        # urls
    r"|(?:\d{1,3}\.){3}\d{1,3}"                          # ipv4
    r"|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",  # domains
    re.I)


def sweep(text: str) -> list[tuple[str, dict]]:
    """Pull recognisable things out of arbitrary text.

    Deliberately greedy. Precision is provided by you confirming the list and by
    scope flagging — a sweep that misses a subdomain is worse than one that
    offers a few extras you untick.
    """
    seen, out = set(), []
    for tok in _TOKEN.findall(text or ""):
        tok = tok.rstrip(".,;:)\"'")
        hit = classify(tok)
        if hit and tok.lower() not in seen:
            seen.add(tok.lower())
            out.append(hit)
    return out


# -- bbot's own event stream -------------------------------------------
# bbot --json emits one event per line, already typed and already attributed.
# Reading it replaces guessing at strings: sweeping the same log offered
# `python-dateutil-2.9.0.post` (pip output), `output.subdomains` (bbot's own
# filename) and `dnsresolve.handle` (a traceback fragment) as subdomains, because
# to a regex they are indistinguishable from one. None of them is an event, so
# none of them survives here.
#
# This is bbot's taxonomy, not a guess about text shape — that is the whole point.
_BBOT_KIND = {
    "DNS_NAME": "domain",
    "DNS_NAME_UNRESOLVED": "domain",
    "IP_ADDRESS": "host",
    "OPEN_TCP_PORT": "port",
    "URL": "webapp",
    "URL_UNVERIFIED": "webapp",
    "FINDING": "finding",
    "VULNERABILITY": "finding",
}


def _events(text: str) -> list[dict]:
    """The JSON events in this output, ignoring everything else.

    bbot's log interleaves its banner, INFO lines and tracebacks with the event
    stream, so this is a filter rather than a whole-file parse.
    """
    return [e for e in _json_lines(text) if "type" in e]


def _json_lines(text: str) -> list[dict]:
    """Every JSON object on a line of its own, whatever tool wrote it.

    Split out from _events because that one keeps only bbot's typed events, and
    httpx's records carry no `type` — reading them through it found nothing and
    dropped the output to the sweep, which then offered the DNS resolvers listed
    in each record as hosts.
    """
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


def parse_events(text: str) -> dict:
    """Nodes and edges from a structured event stream. Empty when there isn't one.

    Edges are the real gain: `resolved_hosts` says which host a name resolves to,
    which no amount of text scraping recovers — a bare list of names and a bare
    list of addresses cannot be reconnected afterwards.
    """
    rows, edges, seen = [], [], set()

    def take(kind: str, value: str, line: str = "", **extra) -> str | None:
        if not value:
            return None
        try:
            nid = node_id(kind, value, **extra)
        except (ValueError, KeyError, TypeError):
            return None
        if nid not in seen:
            seen.add(nid)
            rows.append({"line": line or value, "kind": kind,
                         "value": value, "id": nid, **extra})
        return nid

    for e in _events(text):
        kind = _BBOT_KIND.get(e.get("type"))
        if not kind:
            continue                      # SCAN, ORG_STUB, TECHNOLOGY, …
        data = e.get("data")

        if kind == "finding":
            # data is an object here, not a string.
            if not isinstance(data, dict):
                continue
            desc = data.get("description") or e.get("type")
            on = canon_host(data.get("host") or e.get("host") or "")
            take("finding", desc, desc, on=on)
            continue

        if not isinstance(data, str):
            continue

        if kind == "port":
            host, _, port = data.rpartition(":")
            if not (host and port.isdigit()):
                continue
            take("port", host.strip("[]"), data, port=int(port))
            continue

        # A DNS_NAME whose data is an address is a host, whatever the label says.
        if kind == "domain":
            try:
                ipaddress.ip_address(data.strip())
                kind = "host"
            except ValueError:
                pass

        # bbot emits the wildcard as a DNS_NAME too. Recorded against the parent,
        # which is what it is actually telling us about.
        # What the scan worked out about whose infrastructure this is. bbot's
        # cloudcheck already told us `216.198.79.1` is Amazon and the CNAME
        # target is an affiliate; dropping that left you identifying CDN edges
        # by eye from an address.
        marks = [t for t in (e.get("tags") or []) if t in KEEP_TAGS]
        extra = {"tags": marks} if marks else {}
        if kind == "domain" and (parent := wildcard_of(data)):
            nid = take("domain", parent, data, wildcard=True, **extra)
        else:
            nid = take(kind, data, data, **extra)

        # resolved_hosts is bbot telling us the resolution it performed. It holds
        # CNAME targets as well as addresses, so the entry decides its own kind —
        # typing a CNAME as a host would put a name in the Hosts column and hand
        # it to tools that expect addresses.
        if nid:
            for addr in (e.get("resolved_hosts") or []):
                if not isinstance(addr, str):
                    continue
                try:
                    ipaddress.ip_address(addr.strip())
                    akind = "host"
                except ValueError:
                    akind = "domain"
                if hid := take(akind, addr, addr):
                    if hid != nid:
                        edges.append({"frm": nid, "rel": "resolves_to", "to": hid})

    kinds = {r["kind"] for r in rows}
    return {"rows": rows, "edges": edges, "kinds": sorted(kinds),
            "swept": False, "uniform": len(kinds) == 1, "total": len(rows)}


# -- DNS answer records ------------------------------------------------
# `dig +noall +answer` prints one record per line in a fixed shape:
#
#   blacklanternsecurity.github.io.  4502  IN  A      185.199.108.153
#   www.blacklanternsecurity.com.    4502  IN  CNAME  blacklanternsecurity.github.io.
#
# Strict enough to parse, which matters because the alternative was sweeping the
# whole output — and dig writes its failures to the same stream:
#
#   ;; communications error to 192.168.65.7#53: timed out
#
# The sweep read that address as a discovered host, and nmap then port-scanned the
# machine penstation was running on. A record parser cannot make that mistake:
# a comment line is not a record.
_DNS_ANSWER = re.compile(
    r"^(?P<name>\S+)\s+\d+\s+IN\s+(?P<type>A|AAAA|CNAME)\s+(?P<value>\S+)\s*$",
    re.I | re.M)


def parse_dns_answers(text: str) -> dict:
    """Nodes and resolution edges from DNS answer records. Empty when there are none."""
    rows, edges, seen = [], [], set()

    def take(kind: str, value: str) -> str | None:
        value = (value or "").rstrip(".")
        if not value:
            return None
        try:
            nid = node_id(kind, value)
        except (ValueError, KeyError, TypeError):
            return None
        if nid not in seen:
            seen.add(nid)
            rows.append({"line": value, "kind": kind, "value": value, "id": nid})
        return nid

    for m in _DNS_ANSWER.finditer(text or ""):
        rtype = m.group("type").upper()
        frm = take("domain", m.group("name"))
        # A/AAAA point at an address; CNAME points at another name.
        to = take("host" if rtype in ("A", "AAAA") else "domain", m.group("value"))
        if frm and to and frm != to:
            edges.append({"frm": frm, "rel": "resolves_to", "to": to})

    kinds = {r["kind"] for r in rows}
    return {"rows": rows, "edges": edges, "kinds": sorted(kinds),
            "swept": False, "uniform": len(kinds) == 1, "total": len(rows)}


def parse_httpx(text: str) -> dict:
    """Nodes and edges from httpx's JSONL. Empty when it isn't that.

    One record per target, already typed: the URL that answered, the name it
    answered for, the addresses behind it. Sweeping this instead would offer the
    same three facts as a bag of strings and invent a node for every technology
    name in `tech`.
    """
    rows, edges, seen = [], [], set()

    def take(kind: str, value: str, line: str, **extra) -> str | None:
        value = (value or "").strip()
        if not value:
            return None
        try:
            nid = node_id(kind, value, **extra)
        except (ValueError, KeyError, TypeError):
            return None
        if nid not in seen:
            seen.add(nid)
            rows.append({"line": line, "kind": kind, "value": value,
                         "id": nid, **extra})
        return nid

    for e in _json_lines(text):
        url = e.get("url")
        if not isinstance(url, str) or "status_code" not in e:
            continue                      # some other tool's json
        code = e.get("status_code")
        title = (e.get("title") or "").strip()
        tech = [t for t in (e.get("tech") or []) if isinstance(t, str)]
        # The label is what you read in the list, so it carries the verdict:
        # a bare URL says nothing a port node did not already say.
        label = " ".join(str(x) for x in [url, code, title and f'"{title}"',
                                          tech and "· " + ", ".join(tech)] if x)
        app = take("webapp", url, label)
        host = e.get("host") or e.get("input")
        name = take("domain", host, label) if isinstance(host, str) else None
        if name and app:
            edges.append({"frm": name, "rel": "serves", "to": app})
        for addr in (e.get("a") or []):
            if not isinstance(addr, str):
                continue
            ip = take("host", addr, label)
            if name and ip:
                edges.append({"frm": name, "rel": "resolves_to", "to": ip})

    kinds = {r["kind"] for r in rows}
    return {"rows": rows, "edges": edges, "kinds": sorted(kinds),
            "swept": False, "uniform": len(kinds) == 1, "total": len(rows)}


def classify_all(text: str) -> dict:
    """Everything recognisable in this text.

    A structured event stream wins outright when there is one: it is typed at the
    source, so it neither invents nodes nor needs a deny-list to avoid them. DNS
    answer records are the same deal in a text format. Sweeping is the fallback for
    tools that only print prose.

    Otherwise both text passes run and are merged: a line-per-value list
    (assetfinder, a plain subdomain list) classifies exactly, while log-shaped
    output only yields anything to the sweep. Deduped by node id, so a value found
    both ways appears once.
    """
    if (structured := parse_events(text))["rows"]:
        return structured
    if (probed := parse_httpx(text))["rows"]:
        return probed
    if (answers := parse_dns_answers(text))["rows"]:
        return answers

    rows, kinds, seen = [], set(), set()
    exact = 0

    def take(kind: str, extra: dict, line: str):
        nonlocal exact
        val = extra.get("value", "")
        try:
            nid = node_id(kind, val, **{k: v for k, v in extra.items() if k == "port"})
        except (ValueError, KeyError):
            return
        if nid in seen:
            return
        seen.add(nid)
        rows.append({"line": line, "kind": kind, "id": nid, **extra})
        kinds.add(kind)

    for line in (text or "").splitlines():
        if hit := classify(line):
            exact += 1
            take(hit[0], hit[1], line.strip())
    for kind, extra in sweep(text):
        take(kind, extra, extra.get("value", ""))

    return {"rows": rows, "edges": [], "kinds": sorted(kinds),
            "swept": len(rows) > exact, "uniform": len(kinds) == 1,
            "total": len(rows)}


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
    dismissed: bool = False    # retired: the map had a soft delete, and removing
                               # a node only hid it while it still counted as
                               # known, so a row you had removed was never
                               # offered again. Delete is a delete now. The field
                               # stays so records written before that still load;
                               # anything still carrying it is dropped on load.
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

    def by_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

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


# Tag marking a node you put on the map yourself. The engagement scope text says
# what you were given; this says what you accepted. Both count as in scope, and
# this one is the record of a decision, so it survives a scope edit.
ACCEPTED = "accepted"

# Tag marking a domain that answers for any label under it. Set from the marker a
# scan reports; everything found beneath it folds in rather than becoming nodes.
WILDCARD = "wildcard"

# Tag marking a name that sits under one. It is recorded like any other name —
# a passive source reporting it means something published it, and a wildcard
# only means DNS cannot confirm that, not that the name is invented. What the
# tag buys is the scanning layer: every name under a wildcard answers with the
# same address, so port-scanning each of them is scanning one host N times.
UNDER_WILDCARD = "under-wildcard"

# Your call on one node, overriding what the scope text works out to. The rules
# cover the engagement; these cover the exceptions the rules cannot express — an
# address that is the client's even though the scope only named domains, or a
# host inside their range that the client has told you to leave alone.
SCOPE_IN = "scope-in"
SCOPE_OUT = "scope-out"


def in_scope(tags, by_rules: bool) -> bool:
    """Scope for one node: your override if there is one, else the rules."""
    if SCOPE_IN in (tags or []):
        return True
    if SCOPE_OUT in (tags or []):
        return False
    return by_rules


# Relations along which scope carries. All of them mean "this is the same target
# reached another way": a name and the address it answers with, a host and its
# open port, a name and the app it serves.
_INHERIT = ("resolves_to", "has_port", "serves")


# Markers a scan attaches to something that is not the client's: bbot knows a
# CDN edge or a cloud front from its own cloudcheck, and says so on the event.
# Kept through promotion because a host you inherit into scope being Amazon's is
# the single most useful thing anyone can tell you about it.
THIRD_PARTY = ("cloud", "cdn", "affiliate")
# Provider names worth keeping alongside, so a row can say whose it is.
PROVIDERS = ("amazon", "aws", "azure", "google", "cloudflare", "akamai",
             "fastly", "vercel", "netlify", "heroku", "digitalocean")
KEEP_TAGS = THIRD_PARTY + PROVIDERS


def is_third_party(tags) -> bool:
    return any(t in THIRD_PARTY for t in (tags or []))


def derive_scope(m: Map, matches) -> dict:
    """Which nodes are in scope: your overrides, the rules, then inheritance.

    Scope is written about names and address ranges, because that is what a
    statement of work gives you. Everything else on the map is one of those
    reached by another route — the address a name answers with, the port on that
    address — so it takes the scope of what it hangs off rather than needing a
    rule of its own that could never match it: no domain rule matches an IP, and
    no CIDR matches a hostname.

    It runs both ways for the same reason. A domain-scoped engagement seeds from
    the names and the addresses follow; an IP-scoped one seeds from the range and
    the names pointing into it follow.

    Only "in scope" propagates. An out-of-scope name resolving to an address says
    nothing about that address — another name that *is* in scope may point at it
    too. And an override is never overwritten, which is what marks a CDN address
    off-limits even though your own name resolves to it.

    Returns {node id: {"in_scope": bool, "why": str}} — the verdict and the
    reason for it, because "in scope" and "in scope because *.acme.com covers
    it" are different claims and only the second one can be defended.

    `matches` takes a value and returns the rule that covers it, or "".
    """
    out, forced, seed = {}, set(), set()

    def put(nid, ok, why):
        out[nid] = {"in_scope": bool(ok), "why": why}

    for nid, n in m.nodes.items():
        if SCOPE_IN in n.tags:
            put(nid, True, "you moved it in")
            forced.add(nid); seed.add(nid)
        elif SCOPE_OUT in n.tags:
            put(nid, False, "you moved it out")
            forced.add(nid)
        else:
            rule = matches(n.value)
            put(nid, bool(rule), f"the scope rule {rule}" if rule else
                "no scope rule covers it")
            if rule:
                seed.add(nid)

    # Resolution carries scope exactly one hop, and only away from something a
    # rule matched or you moved in. Letting it run further is a closure, and a
    # closure is wrong here: an in-scope name resolves to a shared address, and
    # every other customer's hostname on that address would come with it. Tested
    # with `shop.other.net` sharing an IP with `www.acme.com` — it must stay out.
    #
    # And never into infrastructure a scan identified as someone else's. Your
    # name resolving to a CDN edge does not make that edge yours to scan; it can
    # still be moved in by hand, which is a decision with your name on it rather
    # than one the tool made for you.
    for e in m.edges.values():
        if e.rel != "resolves_to":
            continue
        for src, dst in ((e.frm, e.to), (e.to, e.frm)):
            node = m.nodes.get(dst)
            if src not in seed or node is None or dst in forced:
                continue
            if out[dst]["in_scope"]:
                continue
            if is_third_party(node.tags):
                out[dst]["why"] = (f"{m.nodes[src].value} resolves here, but a scan "
                                   f"identified this as third-party infrastructure")
                continue
            put(dst, True, f"{m.nodes[src].value} resolves here")

    # Ports and web apps are not independent targets — they are a way of
    # addressing whatever they hang off — so they follow it however it got its
    # verdict, seed or inherited.
    for _ in range(2):
        for e in m.edges.values():
            if e.rel in ("has_port", "serves") and e.to in out \
                    and e.to not in forced and out.get(e.frm, {}).get("in_scope") \
                    and not out[e.to]["in_scope"]:
                put(e.to, True, f"it belongs to {m.nodes[e.frm].value}")
    return out


def scope_apexes(scope_text: str) -> list[str]:
    """The domains in a scope, canonical, in the order written.

    Only domains. A CIDR describes a range rather than a host, and inventing 256
    host nodes for a /24 would bury the ones you actually found.
    """
    from penstation import scope as scope_mod
    out = []
    for rule in scope_mod.parse(scope_text):
        if scope_mod.is_network(rule):     # a network, not a host
            continue
        apex = canon_domain(rule)          # canon_domain drops a leading *.
        if apex and not apex.replace(".", "").isdigit() and apex not in out:
            out.append(apex)
    return out


def seed_from_scope(m: Map, scope_text: str) -> int:
    """Put the engagement's scope on the map as its base.

    The scope is what you were given, so it is the root everything else hangs
    off — and it is the one part of the map that exists before you have run
    anything. Without it the map opens empty and there is nowhere to start.

    Idempotent: a scope root is on the map by definition, so re-seeding is also
    how a deleted one comes back.
    """
    added = 0
    for apex in scope_apexes(scope_text):
        node = m.add_node("domain", apex, tool="scope")
        if "scope" not in node.tags:
            node.tags.append("scope")
        added += 1
    return added


def scope_missing(m: Map, scope_text: str) -> bool:
    """Is any scope root absent from the map?"""
    return any(node_id("domain", apex) not in m.nodes
               for apex in scope_apexes(scope_text))


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
        node = Node(**{k: v for k, v in n.items()
                       if k in Node.__dataclass_fields__})
        if node.dismissed:
            continue        # written by the retired soft delete: you removed it,
        m.nodes[nid] = node # so it is removed, not hidden and still counted
    for key, e in (raw.get("edges") or {}).items():
        edge = Edge(**{k: v for k, v in e.items()
                       if k in Edge.__dataclass_fields__})
        if edge.frm in m.nodes and edge.to in m.nodes:
            m.edges[key] = edge      # never a link to something that is gone
    return m


def forget(project: str) -> None:
    """Drop an engagement's map.

    Deleting a project removed its record and its runs but left this behind, and
    project ids are slugs of the client name — so a second engagement for the
    same client opened onto the first one's map: its hosts, its findings, its
    scope decisions. Evidence from one client must not appear under another.
    """
    try:
        _path(project).unlink()
    except OSError:
        pass


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
