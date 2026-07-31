"""nmap's XML output, read as the record it is.

nmap writes three formats from one scan and only this one is typed. `.nmap` is a
column-aligned report for a human, `.gnmap` packs a host onto one line for grep,
and `.xml` separates state, reason, service, product and version into fields
that mean the same thing on every host. Promotion used to read all three at
once, concatenated, and fall through to the generic sweep — which re-offered the
three addresses it already knew, invented `nmap.org` from the "report incorrect
results at" footer and `nmap.xsl` from the stylesheet reference, and reported
not one open port, because no sweep pattern matches `443/tcp open  https`. A
port scanner contributed no ports.

Nothing here knows about the map. This module reads nmap's XML into plain
dicts; `map.parse_nmap` decides what becomes a node. That keeps canonical
identity in the one module that owns it, and lets the CSV route reuse the parse
without dragging the graph in behind it.

Read per `<host>` block rather than as one document. A scan you interrupt, or
that the runner kills on a timeout, leaves `</nmaprun>` unwritten, and a
whole-document parse of that yields nothing at all from a scan that found
plenty. A host block also carries no DOCTYPE, so an entity reference in a
hostname or a banner has nothing to resolve against.
"""
from __future__ import annotations

import csv
import io
import re
import xml.etree.ElementTree as ET

# `<host ` and `<host>` only. `\b` is what keeps this off `<hostnames>`,
# `<hostname>` and `<hosthint>` — nmap 7.95 writes all three, and -vv writes a
# `<hosthint>` per target before the scan proper. The closing tag is matched in
# full for the same reason: `</hostscript>` starts with `</host`.
_HOST = re.compile(r"<host\b.*?</host>", re.S)
_SCANINFO = re.compile(r"<scaninfo\b[^>]*>")

# Ports individually reported per host. A scan of every port would list 65535 of
# them, and nmap does not aggregate when you ask for -v enough, so the block is
# bounded rather than trusted.
_MAX_PORTS = 65536


def is_nmap(text: str) -> bool:
    """Cheap enough to run before anything else claims this output."""
    return "<nmaprun" in (text or "")


def _attr(el, name: str, default: str = "") -> str:
    if el is None:
        return default
    return (el.get(name) or default).strip()


def ranges(spec: str) -> list[tuple[int, int]]:
    """`"1,3-4,6-7"` → `[(1,1), (3,4), (6,7)]`.

    Kept as ranges rather than expanded because the map only ever asks whether
    one known port falls inside them. Expanding first is what the CSV does, and
    on a `-p-` scan that is 65535 integers per host for a question answered by a
    comparison.
    """
    out: list[tuple[int, int]] = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        try:
            a = int(lo)
            b = int(hi) if hi.strip() else a
        except ValueError:
            continue
        if a > b:
            a, b = b, a
        a, b = max(a, 0), min(b, 65535)
        if a <= b:
            out.append((a, b))
    return out


def in_ranges(spans: list[tuple[int, int]], port: int) -> bool:
    return any(lo <= port <= hi for lo, hi in spans)


def expand(spans: list[tuple[int, int]]) -> list[int]:
    return [n for lo, hi in spans for n in range(lo, hi + 1)]


def _port(el) -> dict | None:
    try:
        portid = int(el.get("portid") or "")
    except ValueError:
        return None
    if not 0 < portid <= 65535:
        return None
    state, svc = el.find("state"), el.find("service")
    cpes = [(c.text or "").strip()
            for c in (svc.findall("cpe") if svc is not None else [])]
    return {
        "port": portid,
        "proto": (el.get("protocol") or "tcp").strip(),
        "state": _attr(state, "state"),
        "reason": _attr(state, "reason"),
        "service": _attr(svc, "name"),
        "product": _attr(svc, "product"),
        "version": _attr(svc, "version"),
        "extrainfo": _attr(svc, "extrainfo"),
        "tunnel": _attr(svc, "tunnel"),
        "cpe": ", ".join(c for c in cpes if c),
    }


def _host(block: str) -> dict | None:
    """One `<host>` element. Returns None when there is no address to key on."""
    el = ET.fromstring(block)      # caller catches ParseError

    address = ""
    for a in el.findall("address"):
        # `mac` is also an address element, and it is not what a host node is
        # keyed on. ipv4 first, ipv6 accepted, everything else ignored.
        if (a.get("addrtype") or "").startswith("ipv"):
            address = (a.get("addr") or "").strip()
            if address:
                break
    if not address:
        return None

    status = el.find("status")
    ports, aggregate = [], {}
    ports_el = el.find("ports")
    if ports_el is not None:
        for p in ports_el.findall("port")[:_MAX_PORTS]:
            if (parsed := _port(p)) is not None:
                ports.append(parsed)
        # nmap collapses the boring majority into a count and a range string —
        # 998 filtered ports are one element, not 998. This is what keeps a map
        # of "things you can act on" from being drowned by a scan's own
        # negative space.
        for ex in ports_el.findall("extraports"):
            state = (ex.get("state") or "unknown").strip()
            try:
                count = int(ex.get("count") or 0)
            except ValueError:
                count = 0
            bucket = aggregate.setdefault(
                state, {"count": 0, "spec": "", "reason": "", "proto": "tcp"})
            bucket["count"] += count
            for reason in ex.findall("extrareasons"):
                spec = (reason.get("ports") or "").strip()
                if spec:
                    bucket["spec"] = f"{bucket['spec']},{spec}".strip(",")
                if reason.get("reason") and not bucket["reason"]:
                    bucket["reason"] = reason.get("reason").strip()
                if reason.get("proto"):
                    bucket["proto"] = reason.get("proto").strip()

    hostnames = [((h.get("name") or "").strip(), (h.get("type") or "").strip())
                 for h in el.findall("hostnames/hostname")]

    return {
        "address": address,
        "state": _attr(status, "state"),
        "reason": _attr(status, "reason"),
        "ports": ports,
        "aggregate": aggregate,
        "hostnames": [h for h in hostnames if h[0]],
    }


def _probed(text: str) -> str:
    """What the scan actually covered, from `<scaninfo>`.

    This sits at `<nmaprun>` level, outside every host block, so it is read
    separately from the host loop. It is also the attribute that makes the rest
    defensible: "no open ports" and "no open ports among the top 1000 of 65535"
    are different claims, and only the second one survives a report review.
    """
    bits = []
    for m in _SCANINFO.finditer(text or ""):
        try:
            el = ET.fromstring(m.group())
        except ET.ParseError:
            continue
        count = el.get("numservices") or "?"
        proto = el.get("protocol") or "?"
        kind = (el.get("type") or "").strip()
        bits.append(f"{count} {proto} ports ({kind})" if kind
                    else f"{count} {proto} ports")
    return " · ".join(bits)


def scan(text: str) -> dict:
    """`{"probed": str, "hosts": [host, …]}`, or `{}` when this isn't nmap XML.

    A host block that will not parse is skipped rather than fatal — that is the
    whole point of slicing per host, so a truncated final block costs you the
    one host it was describing and nothing else.
    """
    if not is_nmap(text):
        return {}
    hosts = []
    for m in _HOST.finditer(text):
        try:
            host = _host(m.group())
        except (ET.ParseError, ValueError, TypeError):
            continue
        if host:
            hosts.append(host)
    return {"probed": _probed(text), "hosts": hosts}


# -- the port table ----------------------------------------------------
# Every port nmap reported, in every state, one row each — the detail that is
# deliberately not on the map. Generated on request from the run's retained
# scan.xml rather than written to disk: nothing to drift from the XML, and it
# works for scans taken before this existed.

CSV_HEADER = ("host", "port", "protocol", "state", "reason",
              "service", "product", "version")

# A `-p-` sweep of a /24 is 16.7 million rows, and this server builds a response
# body in memory and serves one request at a time — so an uncapped table stalls
# every live scan log behind it. The XML is still there, complete, as evidence.
CSV_LIMIT = 200_000

# Excel, LibreOffice and Sheets execute a cell that begins with any of these.
# `product`, `version` and `extrainfo` are banner text written by the target, so
# without this the port table is a remote-code-execution path into the analyst's
# spreadsheet — and opening it in a spreadsheet is the entire point of the file.
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _cell(value) -> str:
    text = "" if value is None else str(value)
    text = "".join(ch for ch in text if ch.isprintable() or ch in "\t")
    return "'" + text if text[:1] in _FORMULA else text


def csv_text(text: str, limit: int = CSV_LIMIT) -> str:
    data = scan(text)
    buf = io.StringIO()
    out = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_ALL)
    out.writerow(CSV_HEADER)

    written = dropped = 0
    for host in (data.get("hosts") or []):
        rows = [(host["address"], p["port"], p["proto"], p["state"], p["reason"],
                 p["service"], " ".join(x for x in (p["product"], p["extrainfo"]) if x),
                 p["version"])
                for p in host["ports"]]
        for state, agg in (host.get("aggregate") or {}).items():
            rows += [(host["address"], n, agg["proto"], state, agg["reason"],
                      "", "", "")
                     for n in expand(ranges(agg["spec"]))]
        for row in sorted(rows, key=lambda r: (r[2], r[1])):
            if written >= limit:
                dropped += 1
                continue
            out.writerow([_cell(x) for x in row])
            written += 1

    if dropped:
        out.writerow([f"# truncated at {limit} rows — {dropped} more ports were "
                      f"scanned; the complete record is this run's scan.xml"])
    return buf.getvalue()
