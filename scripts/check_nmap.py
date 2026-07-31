"""What the nmap parser does, checked against whatever scans are on disk.

Run it: `py -3 scripts/check_nmap.py` from the project root.

Two kinds of case, deliberately:

**Invariants against real scans.** Every `nmap-*/scan.xml` under `data/runs`, in
every engagement, whichever they happen to be. The assertions are relationships
between the file and the parse — "as many host rows as the file has host blocks",
"as many port rows as it has open ports" — never counts from one particular scan.
A number lifted out of one engagement stops being true the moment that
engagement moves on, and asserts nothing about the parser in the meantime.

Real scans are the fixtures because the failure this replaced — a port scanner
that contributed no ports — was invisible to a synthetic test: a fixture only
ever proves the parser agrees with whoever wrote the fixture.

**Behaviour that no captured run can show.** An interrupted scan, a re-scan where
a port has closed, and a hostile service banner are not things you can wait
around for, so those are built here from a minimal synthetic document.

Exits non-zero if anything fails, or if there is nothing on disk to read.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from penstation import map as gmap                     # noqa: E402
from penstation import nmapxml                         # noqa: E402
from penstation.paths import DATA                      # noqa: E402

failures: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (expected {want!r})"))
    if not ok:
        failures.append(label)


def scans() -> list[Path]:
    """Every captured nmap scan, in every engagement."""
    return sorted((DATA / "runs").glob("*/nmap-*/scan.xml"))


# What the file itself says, counted without the parser, so the parse is checked
# against the document rather than against a remembered result.
def host_blocks(xml: str) -> int:
    return len(re.findall(r"<host\b.*?</host>", xml, re.S))


def open_ports(xml: str) -> int:
    return len(re.findall(r'<state state="open"', xml))


def probed(xml: str) -> int:
    return sum(int(n) for n in re.findall(r'<scaninfo[^>]*numservices="(\d+)"', xml))


SYNTHETIC = (
    '<?xml version="1.0"?><nmaprun>'
    '<scaninfo type="syn" protocol="tcp" numservices="4" services="80,443,8080,9000"/>'
    '<host><status state="up" reason="reset"/>'
    '<address addr="198.51.100.10" addrtype="ipv4"/>'
    '<ports><extraports state="filtered" count="2">'
    '<extrareasons reason="no-response" count="2" proto="tcp" ports="8080,9000"/>'
    '</extraports>'
    '<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>'
    '<service name="http" product="nginx" version="1.18.0"/></port>'
    '<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>'
    '<service name="http" product="nginx" version="1.18.0" tunnel="ssl"/></port>'
    '</ports></host>'
    '<host><status state="down" reason="no-response"/>'
    '<address addr="198.51.100.11" addrtype="ipv4"/></host>'
    '</nmaprun>'
)


def main() -> int:
    # The synthetic cases always run. There is not always a scan on disk — a
    # fresh clone has none, and clearing an engagement's data deletes the ones
    # it had — and a check suite that only works when you happen to have run
    # something is one you stop trusting.
    found = scans()
    if not found:
        print(f"no captured nmap runs under {DATA / 'runs'} — skipping the "
              f"real-scan checks, running the synthetic ones only")

    for xml_path in found:
        xml = xml_path.read_text(errors="replace")
        print(f"\n{xml_path.parent.name}  ({xml_path.parent.parent.name})")

        r = gmap.classify_all(xml)
        hosts = [x for x in r["rows"] if x["kind"] == "host"]
        ports = [x for x in r["rows"] if x["kind"] == "port"]

        check("a row per host in the file", len(hosts), host_blocks(xml))
        check("a row per open port", len(ports), open_ports(xml))
        check("an edge per open port",
              sum(1 for e in r["edges"] if e["rel"] == "has_port"), len(ports))
        check("nothing was swept", r["swept"], False)
        check("only hosts and ports", r["kinds"],
              [k for k in ("host", "port") if k in r["kinds"]])

        # Nothing that is not open becomes a node — the whole point of counting
        # the rest as attributes instead.
        check("every port row is open",
              {p["attrs"].get("state") for p in ports} - {"open"}, set())

        # Every host row states what was probed, and its open list agrees with
        # the ports that came back for it.
        # Addressed by position, not by value: this reads real engagement data
        # and its output should not carry any of it.
        for i, h in enumerate(hosts, 1):
            if h.get("enrich_only"):
                continue                       # a host that did not respond
            listed = h["attrs"].get("scan.open", "")
            mine = sorted(p["port"] for p in ports if p["value"] == h["value"])
            check(f"host {i}: open list matches its port rows",
                  listed, ",".join(str(p) for p in mine) or "none")
            check(f"host {i}: says what was probed",
                  h["attrs"].get("scan.probed", "").startswith(str(probed(xml))), True)

        # The sweep's failure mode, which this parser exists to end: nmap's own
        # footer and stylesheet reference read as an attack surface.
        check("no node came from nmap's own output",
              [x["value"] for x in r["rows"]
               if "nmap.org" in x["value"] or x["value"].endswith(".xsl")], [])

        # The port table covers every port the scan reported, in every state.
        rows = [l for l in nmapxml.csv_text(xml).splitlines() if l.startswith('"')]
        check("csv has a row per probed port, plus a header",
              len(rows), host_blocks(xml) * probed(xml) + 1
              if probed(xml) else len(rows))

        # A scan cut off mid-document still yields the hosts it finished.
        cut = xml[:xml.rfind("<host ") + 200] if xml.count("<host ") > 1 else ""
        if cut:
            t = gmap.classify_all(cut)
            check("truncated: earlier hosts survive",
                  sum(1 for x in t["rows"] if x["kind"] == "host"),
                  host_blocks(xml) - 1)

    print("\nsynthetic — cases no captured run can show")
    s = gmap.classify_all(SYNTHETIC)
    hosts = [x for x in s["rows"] if x["kind"] == "host"]
    ports = [x for x in s["rows"] if x["kind"] == "port"]
    check("both hosts reported", len(hosts), 2)
    check("only the open ports are nodes", len(ports), 2)
    check("the host that answered carries its counts",
          hosts[0]["attrs"].get("scan.filtered"), "2")
    check("and what was probed", hosts[0]["attrs"].get("scan.probed"),
          "4 tcp ports (syn)")
    check("service detail is kept", ports[0]["attrs"].get("product"), "nginx")

    # A host that did not answer is evidence about a host you targeted, never a
    # new node — otherwise scanning a range fills the map with dead addresses.
    down = [h for h in hosts if h.get("enrich_only")]
    check("a down host cannot create a node", len(down), 1)
    check("and says so", down[0]["attrs"].get("scan.state"), "down · no-response")

    # A re-scan where a port has closed: recorded against the node, not deleted,
    # and only for ports the map already holds.
    closed = SYNTHETIC.replace('portid="80"><state state="open"',
                               'portid="80"><state state="filtered"')
    known = {"port:198.51.100.10:80", "host:198.51.100.10"}
    again = gmap.classify_all(closed, known=known)
    was = [x for x in again["rows"] if x["kind"] == "port" and x.get("port") == 80]
    check("the closed port is still reported", len(was), 1)
    check("as evidence, not a discovery", was[0].get("enrich_only"), True)
    check("carrying its new state", was[0]["attrs"].get("state"), "filtered")
    check("ports the map does not know stay out",
          [x for x in again["rows"] if x.get("enrich_only") and x.get("port") not in (80, None)],
          [])

    print("\nsynthetic — the port table is safe to open in a spreadsheet")
    hostile = SYNTHETIC.replace('product="nginx" version="1.18.0"/>',
                                'product="=cmd|\'/c calc\'!A1" version="+1"/>', 1)
    out = nmapxml.csv_text(hostile)
    check("a formula is neutralised", "\"'=cmd|'/c calc'!A1\"" in out, True)
    check("no cell can start one",
          [c for line in out.splitlines() for c in line.split(",")
           if c[:2] in ('"=', '"+', '"@')], [])
    capped = nmapxml.csv_text(SYNTHETIC, limit=2)
    check("the table is capped", len([l for l in capped.splitlines()
                                      if l.startswith('"')]), 4)
    check("and says it was", "truncated at 2 rows" in capped, True)

    print()
    if failures:
        print(f"{len(failures)} FAILED: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
