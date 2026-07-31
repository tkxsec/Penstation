"""What the httpx parser does, against captured runs and synthetic records.

Run it: `py -3 scripts/check_httpx.py` from the project root.

Same split as check_nmap.py. Invariants run against every `httpx-*/httpx.jsonl`
under `data/runs` — assertions about the relationship between the file and the
parse, never counts lifted from one engagement. The cases a captured run cannot
be relied on to contain — an application answering on a bare address, a
certificate naming other hosts — are built here.

The distinction this exists to protect: **asking for a name and dialling an
address are different questions.** A name's answer is that site's behaviour,
whatever the status. An address's answer, with no Host header, is whatever the
server does for nobody in particular — a redirect to the platform it is hosted
on, or a reverse proxy's default 404. Those are facts about the listener, so
they belong on the port. Recorded as web apps they were half the list, each one
restating a host sitting beside it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from penstation import map as gmap                     # noqa: E402
from penstation.paths import DATA                      # noqa: E402

failures: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (expected {want!r})"))
    if not ok:
        failures.append(label)


def rec(**kw) -> str:
    """One httpx JSONL record, with the fields the parser reads."""
    base = {"url": kw.get("url", "https://example.com"), "status_code": 200,
            "input": "example.com:443", "failed": False}
    base.update(kw)
    return json.dumps(base)


def parse(*records: str) -> dict:
    return gmap.classify_all("\n".join(records))


def kinds(out: dict, kind: str) -> list:
    return [r for r in out["rows"] if r["kind"] == kind]


NAME_CERT = {"subject_cn": "app.example.com", "issuer_cn": "Example CA",
             "not_after": "2027-01-01T00:00:00Z", "tls_version": "tls13",
             "subject_an": ["app.example.com", "*.internal.example.com"]}
DEFAULT_CERT = {"subject_cn": "PROXY DEFAULT CERT", "issuer_cn": "PROXY DEFAULT CERT",
                "self_signed": True, "mismatched": True,
                "subject_an": ["not-yours.someone-else.test"]}


def main() -> int:
    print("synthetic — a name is asked for, an address is dialled")

    # A name that answers: an application, however it answers.
    out = parse(rec(input="app.example.com:443", url="https://app.example.com:443",
                    status_code=200, title="Panel", webserver="nginx",
                    tech=["nginx"], tls=NAME_CERT, a=["198.51.100.10"]))
    apps = kinds(out, "webapp")
    check("a name that answers is an application", len(apps), 1)
    check("stored canonically, without the default port",
          apps[0]["value"], "https://app.example.com")
    check("carrying what it said", apps[0]["attrs"].get("title"), "Panel")
    check("and the certificate", apps[0]["attrs"].get("tls.subject"), "app.example.com")
    check("served by the name that was asked for",
          [(e["frm"], e["to"]) for e in out["edges"] if e["rel"] == "serves"],
          [("domain:app.example.com", "webapp:https://app.example.com")])
    check("the address behind it is a host, not a domain",
          [r["kind"] for r in out["rows"] if r["value"] == "198.51.100.10"], ["host"])

    # A name with a valid certificate that serves nothing at the root is still a
    # web app: a configured vhost with an empty root is worth seeing.
    out = parse(rec(input="empty.example.com:443", url="https://empty.example.com:443",
                    status_code=404, tls={"subject_cn": "empty.example.com"}))
    check("a name that 404s is still an application", len(kinds(out, "webapp")), 1)

    # An address that only redirects: a fact about the listener.
    out = parse(rec(input="198.51.100.10:443", url="https://198.51.100.10:443",
                    status_code=308, webserver="Platform", tls=DEFAULT_CERT))
    check("an address that redirects is not an application",
          len(kinds(out, "webapp")), 0)
    ports = kinds(out, "port")
    check("its answer lands on the port", len(ports), 1)
    check("recorded as evidence, never creating a port",
          ports[0].get("enrich_only"), True)
    check("with the status", ports[0]["attrs"].get("http.status"), "308")
    check("the server", ports[0]["attrs"].get("http.server"), "Platform")
    check("and the certificate it presented",
          ports[0]["attrs"].get("tls.subject"), "PROXY DEFAULT CERT")
    check("no serves edge for a port answering the door",
          [e for e in out["edges"] if e["rel"] == "serves"], [])

    # An address that answers like an application is kept — an app on a bare
    # address with no vhost is real and must not disappear.
    out = parse(rec(input="198.51.100.10:8443", url="https://198.51.100.10:8443",
                    status_code=200, title="Admin"))
    check("an address that answers 2xx is an application",
          [a["value"] for a in kinds(out, "webapp")], ["https://198.51.100.10:8443"])

    print("\nsynthetic — certificate names")
    out = parse(rec(input="app.example.com:443", url="https://app.example.com:443",
                    tls=NAME_CERT))
    names = sorted(r["value"] for r in kinds(out, "domain"))
    check("a name probe offers the certificate's other names",
          names, ["app.example.com", "internal.example.com"])
    check("a wildcard SAN is recorded as the wildcard it is",
          [r.get("wildcard") for r in kinds(out, "domain")
           if r["value"] == "internal.example.com"], [True])

    out = parse(rec(input="198.51.100.10:443", url="https://198.51.100.10:443",
                    status_code=308, tls=DEFAULT_CERT))
    check("an address probe offers none of them",
          [r["value"] for r in kinds(out, "domain")], [])

    print("\nsynthetic — several ways in to one application")
    out = parse(
        rec(input="example.com:80", url="http://example.com:80",
            final_url="https://example.com/", status_code=200, title="Home"),
        rec(input="example.com:443", url="https://example.com:443",
            status_code=200, title="Home"))
    check("a redirect and its destination are one node",
          [a["value"] for a in kinds(out, "webapp")], ["https://example.com"])

    print("\nsynthetic — nothing answered")
    out = parse(rec(input="198.51.100.11:443", url="https://198.51.100.11:443",
                    failed=True, status_code=0))
    check("a failed probe records nothing", out["rows"], [])

    # -- captured runs, if any ----------------------------------------
    found = sorted((DATA / "runs").glob("*/httpx-*/httpx.jsonl"))
    if not found:
        print(f"\nno captured httpx runs under {DATA / 'runs'} — skipping those")
    for path in found:
        text = path.read_text(errors="replace")
        records = [json.loads(l) for l in text.splitlines() if l.strip()]
        answered = [r for r in records if not r.get("failed")]
        print(f"\n{path.parent.name}  ({path.parent.parent.name})")
        out = gmap.classify_all(text)

        by_name = [r for r in answered
                   if not (gmap.classify(r.get("input", "")) or ("", {}))[1]
                   .get("value", "").replace(".", "").isdigit()]
        check("no address became a domain node",
              [r["value"] for r in kinds(out, "domain")
               if r["value"].replace(".", "").isdigit()], [])
        check("every web app is one a name serves, or a 2xx",
              all(a["attrs"].get("probed", "") in
                  [r.get("input") for r in by_name]
                  or a["attrs"].get("status", "").startswith("2")
                  for a in kinds(out, "webapp")), True)
        check("no web app value carries a default port",
              [a["value"] for a in kinds(out, "webapp")
               if a["value"].endswith(":80") or a["value"].endswith(":443")], [])
        check("port rows are evidence only",
              {p.get("enrich_only") for p in kinds(out, "port")} - {True}, set())

    print()
    if failures:
        print(f"{len(failures)} FAILED: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
