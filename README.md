# penstation

A workbench for an external penetration test. It holds the engagement — scope,
what you have found, what has been run against it — and drives a toolset that
fills that picture in.

Two halves that meet at the map:

- **the engagement** — a scope, a graph of what you have found, phases that run
  a baseline toolset against it, and a record of every run as evidence
- **the tool library** — paste a GitHub link and it works out how to install the
  tool in Docker, verifies it, and makes it runnable alongside the baseline

Design notes: [`docs/architecture.md`](docs/architecture.md) for the system,
[`docs/parsers.md`](docs/parsers.md) for how tool output becomes map nodes.

## Run

```bash
python3 serve.py                 # http://127.0.0.1:8787
```

Needs Docker running — every tool is a Docker image.

**A GitHub token is required to add tools.** Unauthenticated GitHub allows ~60
API requests an hour and trips abuse detection, which can get your whole IP
dropped, so adding is refused rather than burning it. A fine-grained PAT with
**no scopes** is enough for public repositories (github.com → Settings →
Developer settings → Personal access tokens):

```bash
export PENSTATION_GITHUB_TOKEN=github_pat_...   # or GITHUB_TOKEN / GH_TOKEN
python3 serve.py
```

It can also be saved in Settings, where it is written `0600` and never echoed
back. The baseline toolset needs no token — those are declared Dockerfiles, not
repositories.

| variable | what it does |
|---|---|
| `PENSTATION_GITHUB_TOKEN` / `GITHUB_TOKEN` / `GH_TOKEN` | raises the API limit to 5,000/hr |
| `PENSTATION_DATA` | where state lives (default: `data/` beside the code) |
| `PENSTATION_EXTRA_INSTALL_VERBS` | extend the install-command allowlist without editing code |

## The engagement

An engagement has a **scope** — the domains and ranges you were given — and a
**map**, which is everything you have found and how it connects.

Four node kinds, and a directed graph rather than a tree, because one address
hosts many names and one name resolves to many addresses:

```
domain  ──resolves_to──▶  host  ──has_port──▶  port
   │                                             │
   └──────────────serves───────▶ webapp ◀────────┘
```

Nothing is guessed. Every node records the run and tool that found it, every
attribute keeps its value alongside the tool that reported it — so two tools
disagreeing about a version is visible rather than resolved by whichever ran
last — and scope is derived in one place, with a reason you can read on each
node.

## Phases

An external test runs through these phases. The **baseline** is what each is run
with, installed into every engagement; the ones with no baseline tool are places
to put what you add. Passive Recon, Active Recon, Cloud Resources and GitHub
Resources share one **Reconnaissance** entry in the sidebar:

| phase | tools | what it adds to the map |
|---|---|---|
| Passive Recon | bbot, subfinder, dig | names, and the addresses they resolve to |
| Active Recon | nmap | open ports, service detail |
| Cloud Resources | — | |
| GitHub Resources | — | |
| Active Scanning | — | *(vulnerability scanners)* |
| Web Analysis | httpx, curl, openssl | web applications, TLS facts |
| Password Spraying | — | |
| Exploitation | — | |

Each phase reads the map and writes back to it: nmap takes the hosts the
resolver found, httpx takes the ports nmap found *crossed with the names that
reach them*, because a web server picks its application from the Host header and
probing an address alone reaches whatever answers for nobody in particular.

`curl` and `openssl` take one target at a time — you aim them at a node from its
own pane rather than running them across the phase.

A phase is **done** when nothing it takes as input has appeared since it ran.
Ports appearing does not date reconnaissance; a name nothing has resolved does.

## Scope and pace

**Scope** is written as domains and CIDRs and carries one hop along resolution —
an in-scope name brings the address it answers with, but not every other name on
that address, and never into infrastructure a scan identified as a third party's.
Anything a tool would send traffic to is checked against it, including a command
you edited by hand.

**Pace** is a property of the engagement, on two dials, because the same word
costs the two kinds of tool wildly different amounts:

| | careful *(default)* | normal | aggressive |
|---|---|---|---|
| scan (nmap) | `-T3 --version-light` | `-T4 --version-light` | `-T4` |
| web (httpx) | `-t 5 -rl 10` | `-t 10 -rl 20` | `-t 50 -rl 150` |

Substituted server-side at the moment of running, so a limit cannot be edited out
of the command box — and recorded with the run, so the history can state the pace
you tested at.

## Adding a tool

Paste a GitHub link. First rung that works wins:

| # | when | how | speed |
|---|---|---|---|
| 0 | the README documents a published image | `docker pull` | seconds |
| 1 | the repo ships a Dockerfile | `docker build` | minutes |
| 2 | an install command is extractable from the README or `go.mod` | generated Dockerfile | minutes |
| 3 | the same recipe on a base image contemporary with the dependencies | generated Dockerfile | minutes |
| 4 | none of the above | fail with a readable reason | — |

**Fully deterministic — there is no model in it.** An LLM stage that wrote and
repaired Dockerfiles was removed: every tool that installed did so through a
deterministic rung, while the model produced broken recipes and repair loops that
thrashed. Fixing the *environment* — era-matched base images, C-extension headers
— solved what it could not, in milliseconds rather than minutes.

When every rung fails, `Hand off` composes the whole question — the errors, what
was tried, the constraints of this build system — for you to paste into whatever
model you already use. Paste the Dockerfile back and it is validated like any
other. No API key, no network dependency, no inference here.

## Security posture

Install commands and pasted Dockerfiles derive from untrusted text, so both pass
allowlist validators (`tools/validate.py`) before execution: permitted verbs
only, no pipes, substitution, redirection or privilege escalation, must reference
the repo being installed, official base images only. Nothing reaches a shell —
commands are built as argv.

Runs are capped: `--rm`, 2 GB memory, 2 CPUs, 1024 pids, a wall-clock timeout and
stdin closed, with no host mounts except a per-run scratch directory for
`{{outdir}}`. Service banners and certificate fields are attacker-controlled, so
they are bounded and stripped of control characters before reaching the map, and
the port-table CSV neutralises cells that a spreadsheet would execute.

Docker isolates the host, but a build runs arbitrary `RUN` lines with network,
and the Docker socket is root-equivalent: **local use, not shared infrastructure.**

## Files

```
serve.py                     launcher
penstation/
  server.py          HTTP + SSE, routes, terminal mirror
  map.py             the engagement graph: identity, parsers, scope, persistence
  nmapxml.py         nmap's XML, read per <host>; also the port-table CSV
  projects.py        engagements, scope roots, pace
  runs.py            recorded runs and their retained files
  scope.py           scope rules — warns, never blocks
  engagements/
    external.py      the phases and the baseline toolset for an external test
  paths.py           where state lives (anchored to the package, not the CWD)
  settings.py        persisted config — GitHub token (0600, never echoed)
  events.py          pub/sub bus: pipeline and runs → UI + terminal
  web/index.html     single-page UI
  tools/             the tool library
    store.py         ToolRecord + file-per-tool store
    jobs.py          serial job queue + status machine
    pipeline.py      Inspect → Acquire → Verify
    gather.py        repo signals, command extraction, Dockerfile templates
    validate.py      install / command / Dockerfile validators
    dockerops.py     docker pull/build/inspect/kill with streamed output
    runner.py        docker run assembly (argv_mode, limits, {{outdir}})
    handoff.py       compose a build failure for you to paste into a model
scripts/
  check_nmap.py      what the nmap parser does — synthetic cases + real scans
  check_httpx.py     the same for httpx
data/                        state (gitignored)
  settings.json  projects/  map/  runs/  tools/  cache/
```

`tools/` depends on the app shell; never the reverse.

## Checking it

```bash
py -3 scripts/check_nmap.py
py -3 scripts/check_httpx.py
```

Both run synthetic cases plus invariants against whatever scans are on disk —
relationships between a file and its parse, never counts lifted from one
engagement. They pass on a fresh clone with no data.

## Known gaps

Password spraying and exploitation have no tools. No findings kind — the map
records what exists, not what is wrong with it. Screenshots are not taken. No
version pinning beyond the recorded commit, no image GC, serial builds only, and
tools needing API keys or wordlists are not configurable yet.

Port node ids carry no protocol, so a UDP scan would merge `udp/53` into
`tcp/53`; nothing in the baseline triggers it. The `contains` edge for a name
under a wildcard is not written reliably at promote time — the UI derives the
relationship from the names instead, so nothing is broken, but the stored graph
is missing it.
