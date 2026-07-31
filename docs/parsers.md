# Reading tool output — why each tool has a parser

Everything a tool finds reaches the map through one function, `map.classify_all`.
It picks a reader for the output and falls back to a generic text sweep when
nothing else claims it. This document is about why the fallback keeps losing.

## The sweep is a fallback, not a strategy

`sweep()` pulls anything that *looks like* a domain, an address or a URL out of
arbitrary text. It has to be greedy, because a subdomain it misses is a
subdomain you never scan. Greedy over a tool's own log means it also finds:

| what it offered | where it came from |
|---|---|
| `python-dateutil-2.9.0.post` | pip output while bbot installed module deps |
| `output.subdomains` | bbot's own filename |
| `dnsresolve.handle` | a traceback fragment |
| `192.168.65.7` | `;; communications error to 192.168.65.7#53` — dig's *resolver* |
| `nmap.org`, `nmap.xsl` | nmap's "report incorrect results at" footer and its stylesheet |

The fourth one is the instructive one: nmap then port-scanned the machine
penstation was running on. A regex cannot tell a discovered host from the
infrastructure that reported it, because in text they are the same shape.

So: **when a tool can say what it found, read that instead.** The parsers are
ordered in `classify_all`, first match wins, sweep last.

| parser | reads | why it exists |
|---|---|---|
| `parse_nmap` | nmap XML | the sweep found no ports at all — see below |
| `parse_events` | bbot's `--json` event stream | typed at the source: `DNS_NAME`, `OPEN_TCP_PORT`, `FINDING` |
| `parse_httpx` | httpx JSONL | one record per target; sweeping it invented a node per entry in `tech` |
| `parse_dns_answers` | `dig +noall +answer` | a comment line is not a record, which is what stopped the resolver-scanning |

A tool that declares `result_file` is read *only* there, so a scanner's debug log
never reaches any of this. Declared means declared, including when the file is
missing — the box says which file was expected rather than silently sweeping.

## nmap

### The failure

nmap writes three formats from one scan and none of them was being parsed. With
all three concatenated and handed to the sweep, a real scan of three hosts
produced:

```
webapp  https://nmap.org          ← the "report incorrect results at" footer
webapp  https://nmap.org/submit/  ← the same line
domain  nmap.xsl                  ← the XML stylesheet reference
host    198.51.100.10             ← already on the map, from the resolver
host    198.51.100.12             ← already on the map
host    203.0.113.20              ← already on the map
```

Three false nodes, three the resolver had already found, and **zero ports**. No
sweep pattern matches `443/tcp open  https`, and `classify()` only recognises
`1.2.3.4:443` on a line of its own, which nmap never prints. The port scanner
contributed nothing a port scanner is for.

### The format

`.nmap` is a column-aligned report for a human and `.gnmap` packs a host onto one
line for grep. Only `.xml` separates state, reason, service, product and version
into fields that mean the same thing on every host, so that is what
`result_file` names. All three are still retained and listed — they are evidence,
and this only narrows what promotion reads.

It is parsed **per `<host>` block**, sliced out with a regex and handed to
ElementTree one at a time. A scan you interrupt, or that the runner kills on a
timeout, leaves `</nmaprun>` unwritten, and a whole-document parse of that
returns nothing at all from a scan that found plenty. A host block also carries
no DOCTYPE, so an entity reference in a hostname has nothing to resolve against.

### What becomes a node

Nodes are things you can act on.

- **An open port is a node**, with service, product, version, CPE and tunnel as
  attributes, and a `has_port` edge from its host. That edge is what lets httpx —
  which `consumes: ["port"]` — find anything at all.
- **Everything else is an attribute.** A three-host scan of the top 1000 ports
  has 2,994 filtered ports. As nodes that is a map you cannot read, and it
  buries the six that matter.
- **PTR hostnames are skipped.** Reverse DNS is mostly cloud boilerplate, and
  name discovery is bbot's and subfinder's job.
- **No web apps.** `-sV` will say `443/tcp open https`, and synthesising
  `https://host:443` from that is tempting — but httpx probes rather than
  assumes, and a URL nobody connected to is a node you have to disprove.

The host carries what was probed and what came back:

```
scan.state     up · reset          (or down · no-response)
scan.probed    1000 tcp ports (syn)
scan.open      80,443              (or "none" — never empty, see below)
scan.filtered  998
```

`scan.probed` is the one that makes the rest defensible. "No open ports" and "no
open ports among the top 1000 of 65535" are different claims, and only the
second survives a report review.

`scan.open` is written as the string `none` rather than left empty, because
`add_node` drops an empty attribute value — and a host that is up with nothing
listening would then carry no evidence at all, indistinguishable from one the
parser never read. That is precisely the distinction these attributes exist to
make. There are three states a bare port count cannot tell apart:

| shows as | means |
|---|---|
| `not scanned` | no `portscan` coverage mark — nothing has looked |
| `did not respond` | the host was scanned and is not there |
| `nothing listening` | it answered, and had nothing open, out of *n* probed |

### The port table

Every port in every state, one row each, at

```
GET /projects/{project}/runs/{run}/ports.csv
```

Generated from the run's retained `scan.xml` on request rather than written to
disk: nothing to drift from the XML, and it works for scans taken before the
route existed. The host node links to it through `checks["portscan"]`, which
holds the run id — which is what the coverage mark is for.

Two things about that file are load-bearing:

- **Cells are neutralised.** `product`, `version` and `extrainfo` are banner text
  written by the target. A service answering `=cmd|'/c calc'!A1` becomes a cell
  that executes when the file is opened, and opening it in a spreadsheet is the
  entire point. Anything starting `=`, `+`, `-`, `@`, tab or CR is prefixed with
  an apostrophe.
- **It is capped at 200,000 rows.** A `-p-` sweep of a /24 expands to 16.7
  million, this server builds a response body in memory and serves one request
  at a time, so an uncapped table would stall every live scan log behind it. The
  cap says so in the last row, and the XML remains the complete record.

### Re-scanning

A port that was open and is now filtered vanishes into nmap's aggregated
`<extraports>`, so nothing would mark it stale. It is **kept and greyed, not
deleted** — deliberately unlike the stale-resolution rule, where a superseded
`resolves_to` edge is dropped. A resolution changing is a correction to a fact
about now; a port closing between two scans is a result, and deleting the node
destroys the evidence it was ever open.

Making that work needs two things:

1. `classify_all(text, known=…)` gets the map's node ids, so the parser can emit
   the new state for ports the map already holds. Bounded by what is known, so a
   65535-port scan does not emit 65535 rows — the aggregate ranges are tested
   against the handful of known ports rather than expanded.
2. **A known row carrying attributes is applied, not dropped.** Promotion only
   ever offered rows the map did not have, so on a re-scan every row was
   `known` and every `scan.*` attribute went on the floor. These are applied
   without being offered: they are not a decision, they are what the scan saw.

Two guards on that, both of which cost a test to find:

- an **enrich-only** row never creates a node. `nmap 10.0.0.0/24` reports every
  dead address in the range, and 250 nodes for addresses that answered nothing
  is not a map of an attack surface. A down host is recorded where the node
  already exists, and nowhere else.
- an auto-applied row never adds the `accepted` tag. That tag means *you* put
  this on the map, and it puts the node in scope from then on — so without the
  guard, re-scanning would quietly accept a host you had deliberately left out.

## httpx, and why a port is not one target

### Probing addresses finds the wrong application

A web server picks which application to serve from the **Host header**. Dialling
`198.51.100.10:443` sends no meaningful one, so you get whatever that server
answers by default — which, measured against a real engagement, was never the
target's application. Ports on a hosting platform's edge addresses redirected to
that platform's own marketing site; ports behind a reverse proxy returned 404
with the proxy's default certificate.

That 404 is the proof rather than a dead end: the application is there, it is
chosen by name, and only a request naming it arrives.

So `vhosts: true` on a tool means *this protocol routes on the hostname*, and a
port expands to every way of reaching it:

```
198.51.100.10:443            the address, for an application with no vhost
app.internal.example.com:443     each name that resolves to that host
app-two.internal.example.com:443
```

Built from the `resolves_to` and `has_port` edges. This is the first thing in the
system that needs the map to be a **graph** — a list of names and a list of ports
cannot be recombined afterwards.

Two consequences worth stating:

- **Names dedupe across addresses.** One name behind two edge addresses is one
  application, and `name:443` is the same probe whichever answers.
- **The under-wildcard fold is turned off.** That fold is right for a port
  scanner, where thirteen names on one address are one machine scanned thirteen
  times. At the HTTP layer they are routinely thirteen applications, so folding
  them is how you miss twelve.

A tool without the flag — a port scanner, an SMB or SSH auditor — gets the same
connection whichever name it dials, so it keeps the plain address list.

### What the parser reads

`url` is what was dialled and `final_url` is where it landed. The **webapp node
is the final URL**, because that is the application that exists, and the `serves`
edge comes from what was asked for, so the redirect stays on the map:

```
198.51.100.10:443 → https://elsewhere.example/  200 "…"
```

Several names landing on one application become one node with several `serves`
edges — which is a finding in itself, not a probe that went missing.

Attributes: `status`, `title`, `webserver`, `tech`, `probed`, and from the
certificate `tls.subject`, `tls.issuer`, `tls.expires`, `tls.version`,
`tls.self_signed`, `tls.mismatched`.

Two things it must not do, both found by reading a real response:

- **`host` is whatever was probed**, so probing by address makes it an address.
  Filing that as a domain grew `domain:198.51.100.10` on the map — a name that is
  not a name — with a `resolves_to` edge pointing at itself. The shape is checked,
  exactly as `parse_events` does for a `DNS_NAME` whose data is an address.
- **Certificate names are taken only from a name probe.** A cert presented to a
  hostname is about that hostname; one collected by dialling an address belongs
  to whoever answers there by default, so taking names from it offers a hosting
  platform's wildcard and a proxy's placeholder as things to go and test.
  Wildcard SANs go through the same wildcard machinery bbot's markers do, and
  the per-record count is capped.

`tls.mismatched` is only meaningful against a name probe — dialling an address
and getting a certificate that does not name it is the normal case.

## Pace belongs to the engagement

Scanning tools ship tuned for speed. httpx's defaults are **50 threads at 150
requests a second**; nmap's `-T4` plus `-sV` sends protocol probes as fast as the
target will take them. Neither is a sensible default against a client you have
not agreed a pace with, and `-sV` against embedded or industrial kit is the
classic way to knock something over.

Vhost probing makes the concentration worse, not better: many names resolve to
*one* host, so concurrency that used to spread across an estate now lands on a
single machine.

So pace is a property of the **project**, like scope — *careful* (the default),
*normal*, *aggressive* — stored on the engagement, so a run's recorded command
states the pace it ran at. "Did your test cause the outage?" is a question you
answer from the run history or not at all.

**Two dials, not one**, because the same word costs the two tools wildly
different amounts. On a real engagement — several hundred names across a hundred
addresses — `careful` is about three minutes for the web probe and hours for the
port scan. A single setting therefore either makes the scan unusable or makes the
probe louder than it needs to be.

| | placeholders | careful | normal | aggressive |
|---|---|---|---|---|
| **scan** (nmap) | `{{scan_timing}}` `{{scan_probes}}` | `-T3 --version-light` | `-T4 --version-light` | `-T4` |
| **web** (httpx) | `{{web_threads}}` `{{web_rate}}` | `-t 5 -rl 10` | `-t 10 -rl 20` | `-t 50 -rl 150` |

The placeholder name says which dial it reads, so no tool needs classifying.

Timing and probe intensity are separate flags on the scan side because they are
separate risks: what upsets a fragile service is being sent an odd protocol
probe, not being sent packets quickly. The gentler settings reach for
`--version-light` first. `-T2` is not offered — it puts 0.4 s between probes and
serialises them, which is 400 seconds per host before any timeout, so it is hours
on a real estate. Ask for it by hand on the run that needs it.

Substituted **server-side, at the moment of running**. The browser fills the same
values in so the box shows what will actually run, but a limit you can edit out
of a text field is not a limit.

Related: httpx follows redirects with `-fhr`, not `-fr` — only while they stay on
the same host. You still learn that a target redirects away, without sending a
request to a third party the engagement never authorised.

## A phase sweeps the tools that can sweep

`consumes` means "reads the map"; `targets` means "aim me at one node". A tool
declaring only `targets` is a microscope, and running it as part of a phase ran
it against the project's apex domain every time, whatever the phase had actually
found — so a Web Analysis run re-fetched the front page while the tool that reads
the map did the work. Tools declaring neither start from the scope itself and do
belong in the sweep.

## Coverage is recorded when a run finishes

Not when you promote its output. `mark_checked` used to fire only for a run
aimed at a single map node, so a list-driven baseline scan marked nothing, and a
row you left unticked was scanned but recorded as never scanned. Coverage is a
fact about what ran, it is knowable the moment the run ends, and it comes from
the input list the run was handed — matched back through `classify()`, so
`host:port` resolves to the port node it came from.

## Scope is derived in one place

A classify row for a node the map already holds takes its verdict from
`derive_scope` — the same function the map view uses. Re-deriving a weaker one
from the scope rules alone is what made every port arrive "outside scope": no
domain rule matches an IP, so a host that is in scope on the map by inheritance
was not a seed, and the `has_port` pass had nothing to carry from. Forty ports on
hosts you are authorised to scan, all unticked.

## Known debt

- **Port node ids carry no protocol.** `node_id("port", ip, port=53)` is
  `port:1.2.3.4:53` whether that is TCP or UDP, so a `-sU` scan would merge the
  two and report "sources disagree" about the protocol instead of showing two
  services. Ids are stored on disk, so fixing it is a migration. The baseline is
  TCP-only, so nothing triggers it today.
- **Attributes dedupe on (value, source)**, so a re-scan returning the *same*
  result appends nothing and there is no "confirmed again on the 2nd" in the
  history. Node `last_seen` moves, so it is recoverable, but not from the
  attribute list.
- **NSE script output is not read.** The baseline runs no `-sC`, and
  `<script>`/`<hostscript>` elements are tolerated and ignored. They are the
  natural source of `finding` nodes when that arrives.

## Checking it

```
py -3 scripts/check_nmap.py
```

Runs against the captured scans under `data/runs/`, not synthetic fixtures. A
fixture only proves the parser agrees with whoever wrote the fixture, and the
failure this replaced — a port scanner contributing no ports — was invisible to
exactly that kind of test. Every assertion is a number you can read out of
`scan.nmap` by eye. The two cases with no captured run, interruption and
re-scanning, are derived from the real XML by cutting it and by replaying it
against a map that already holds a port.
