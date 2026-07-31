# penstation

A workbench for an external penetration test. It holds the engagement — scope,
what you have found, what has been run against it — and drives a toolset that
fills that picture in.

Two halves that meet at the map:

- **the engagement** — a scope, a graph of what you have found, phases that run
  a baseline toolset against it, and a record of every run as evidence
- **the tool library** — paste a GitHub link and it works out how to install the
  tool, verifies it, and makes it runnable alongside the baseline

Design notes: [`docs/external-design.md`](docs/external-design.md) for how it is
deployed and run, [`docs/parsers.md`](docs/parsers.md) for how tool output
becomes map nodes.

## Run

penstation runs **on the engagement box** — the VM provisioned for the job, which
has the address the client whitelisted and holds the evidence.

```bash
sudo ./setup.sh                  # once per box — installs everything below
.venv/bin/penstation             # or: python3 serve.py
```

Reach the UI over the SSH session you already have:

```
Host engagement
  HostName <the VM's hostname>
  Port <ssh port>
  User <your account>
  LocalForward 8787 127.0.0.1:8787
  ExitOnForwardFailure yes
  ServerAliveInterval 30
```

`ssh engagement`, then `http://127.0.0.1:8787`.

**Nothing is published.** penstation has no authentication — one route accepts a
repository URL and installs it, another executes a command — so binding anywhere
but loopback puts a root-capable web interface on a public address. The CLI
refuses to do it without an explicit override, and the SSH key is what gates
access instead.

A run is a subprocess of the server, so closing the SSH session ends both — there
is no container left holding the work, and nothing reattaches on restart. For a
scan you cannot afford to lose, start it detached:
`nohup .venv/bin/penstation &`.

**A GitHub token is required to add tools.** Unauthenticated GitHub allows ~60
API requests an hour and trips abuse detection, which can get the whole IP
dropped, so adding is refused rather than burning it. A fine-grained PAT with
**no scopes** is enough for public repositories:

```bash
export PENSTATION_GITHUB_TOKEN=github_pat_...   # or GITHUB_TOKEN / GH_TOKEN
```

It can also be saved in Settings, where it is written `0600` and never echoed
back. The baseline toolset needs no token — those are declared package names, not
repositories.

| variable | what it does |
|---|---|
| `PENSTATION_GITHUB_TOKEN` / `GITHUB_TOKEN` / `GH_TOKEN` | raises the API limit to 5,000/hr |
| `PENSTATION_DATA` | where state lives (default: `data/` beside the code) |
| `PENSTATION_INSTALL_USER` | override the account installs run as *(found automatically)* |
| `PENSTATION_RUN_USER` | override the account tools run as *(found automatically)* |
| `PENSTATION_RUNGS` | restrict the install ladder, e.g. `apt` |
| `PENSTATION_EXTRA_INSTALL_VERBS` | extend the install-command allowlist |

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

The **baseline** is what each phase is run with, installed into every
engagement. Passive Recon, Active Recon, Cloud Resources and GitHub Resources
share one **Reconnaissance** entry in the sidebar; the phases with no baseline
tool are places to put what you add.

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

Paste a GitHub link. Tools are installed natively and run as subprocesses; there
is no container runtime on an engagement box. First rung that works wins:

| # | when | how | notes |
|---|---|---|---|
| 0 | in the distro's repos | `apt install` | signed packages, seconds |
| 1 | a Python package | `pipx install` | own venv per tool |
| 2 | a Go repo | `go install …@latest` | path from README / `go.mod` |
| 3 | publishes release assets | download + `chmod +x` | |
| 4 | anything else | clone + venv | explicit approval |
| 5 | none of the above | fail, with what each rung tried | |

Ordered by how much of a stranger's code has to run to install it — a distro
package runs maintainer scripts from a signed archive, a clone runs whatever is
in the repository.

**Extract, never synthesise.** `go install github.com/owner/repo@latest` fails
for most real Go tools: subfinder's actual path is
`github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` — note both the
`/v2` and the `/cmd/`. Repo name is not install path, so the job is reading the
repo's own documented command.

**Fully deterministic — there is no model in it.** An LLM stage that wrote and
repaired install recipes was removed: every tool that installed did so through a
deterministic rung, while the model produced broken recipes and repair loops that
thrashed. When every rung fails, `Hand off` composes the whole question — the
errors, what was tried, this system's constraints — for you to paste into
whatever model you already use. Paste a recipe back and it is validated like any
other. No API key, no network dependency, no inference here.

Which rungs are allowed is a **per-deployment policy**: everything on a box you
provision and destroy, `PENSTATION_RUNGS=apt` on hardware you do not own, where
add-a-tool then resolves against the distro and never fetches from the internet.

Version pins survive: the baseline declares `bbot==3.0.1` and
`subfinder@v2.14.0`, which pipx and go install honour. Only apt-sourced tools
take whatever the distro ships, so every run records the tool's `--version`.

## Security posture

Install commands derive from untrusted repository text, so they pass allowlist
validators (`tools/validate.py`) before execution: permitted verbs only, no
pipes, substitution, redirection or privilege escalation, must reference the repo
being installed, bounded length, no control characters. Nothing reaches a shell —
commands are built as argv.

Without a container those rules are the barrier rather than a second one.

Tools run with penstation's own privileges — root on a provisioned engagement
box, which is what nmap's SYN scan and masscan's raw sockets require. The
isolation boundary is the box itself, destroyed at the end of the engagement, not
an account on it; if you need more than that, use a separate VM.

Tools are spawned in their own process group so Stop takes the whole tree —
killing the immediate child leaves nmap's and bbot's helpers running — and always
with an explicit working directory, never penstation's own.

Service banners and certificate fields are attacker-controlled, so they are
bounded and stripped of control characters before reaching the map, and the
port-table CSV neutralises cells a spreadsheet would execute.

The UI is unauthenticated by design and reached over SSH. That only holds while
it stays on loopback: **local use behind a tunnel, not shared infrastructure.**

## Files

```
serve.py                     front door for a clone
pyproject.toml               packaging; zero dependencies, deliberately
penstation/
  cli.py             the command, and the bind guard
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
    pipeline.py      Inspect → Acquire → Verify, and the rung policy
    gather.py        repo signals, install-command extraction
    validate.py      install / command validators
    nativeops.py     apt / pipx / go / clone, run as the install user
    runner.py        argv assembly, process-group kill, {{outdir}}
    handoff.py       compose a failure for you to paste into a model
setup.sh                     prepare an engagement box — one command, idempotent
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

Password spraying, exploitation, cloud and GitHub resources have no baseline
tools. No findings kind — the map records what exists, not what is wrong with it.
Screenshots are not taken. Tools needing API keys or wordlists are not
configurable yet; `{{wordlist:…}}` and `{{key:…}}` are designed but unbuilt.

**Runs do not survive a restart.** Tools are subprocesses of the server, so
killing it kills them — where containers would have outlived it. Nothing
reattaches on startup.

Port node ids carry no protocol, so a UDP scan would merge `udp/53` into
`tcp/53`; nothing in the baseline triggers it. The `contains` edge for a name
under a wildcard is not written reliably at promote time — the UI derives the
relationship from the names instead, so nothing is broken, but the stored graph
is missing it.
