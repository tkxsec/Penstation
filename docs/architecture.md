# penstation — architecture

Two halves that meet at the map.

**The engagement** holds what you were given and what you have found: a scope, a
graph of names, addresses, ports and applications, and a record of every run as
evidence. **The tool library** turns a GitHub link into a runnable Docker image.
Phases are where they meet — a phase reads the map, runs tools against it, and
writes back what they found.

`docs/parsers.md` is the companion: how a tool's output becomes map nodes, and
why each tool needs a reader rather than a regex.

---

# Part 1 — the engagement

## The map is a graph

```
domain  ──resolves_to──▶  host  ──has_port──▶  port
   │                                             │
   └──────────────serves───────▶ webapp ◀────────┘
   └──contains──▶ domain        (a name under a wildcard)
```

Four node kinds: `domain`, `host`, `port`, `webapp`. A service is attributes on a
port and a route is a list on a webapp; separate kinds for those added edges
without adding information.

**A graph, not a tree.** One address hosts many names and one name resolves to
many addresses; a `parent` field would force a choice that is not true. Trees are
how you *read* it, so the UI draws one, but storage keeps the real edges.

A fifth kind, `finding`, was removed. It was fed only by bbot's FINDING events,
and the baseline reads bbot's declared result file rather than its event stream,
so nothing ever reached it. Findings are a deliberate piece of design — severity,
evidence, retest — and that was not it.

### Identity is the load-bearing decision

Everything downstream depends on two tools describing the same thing landing on
the same id.

```
domain:<canonical name>          lowercased, trailing dot and leading *. stripped
host:<canonical address>
port:<canonical address>:<n>
webapp:<scheme>://<host>[:port][/path]    default ports dropped, bare / dropped
```

Get it wrong and the map silently duplicates or, worse, merges things that are
not the same. Two consequences worth knowing:

- a **port is keyed on its host**, so its `value` is that address alone. The port
  number lives only in the id, and anything addressing or displaying a port has
  to put it back — including the list a tool is handed.
- port ids carry **no protocol**, so `udp/53` and `tcp/53` would collide. Nothing
  in the baseline triggers it; fixing it is a stored-id migration.

### Provenance, not overwriting

Every node and edge records the run and tool that found it. Every attribute keeps
each value *with* the tool that reported it, rather than overwriting:

```
webserver: [ {value: "nginx 1.18", source: "whatweb"},
             {value: "nginx 1.20", source: "httpx"} ]
```

Two tools disagreeing is usually a load balancer or a stale banner — the
disagreement is the interesting part, and last-write-wins would hide it behind
whichever ran last. It is also what makes undo, retest diffs and "which tool said
what" possible at all.

## Scope

Written as domains and CIDRs, because that is what a statement of work gives you.
Everything else on the map is one of those reached another way, so scope is
**inherited** rather than matched: no domain rule matches an address, and no CIDR
matches a hostname.

- one hop along `resolves_to`, never a closure — an in-scope name brings the
  address it answers with, but not the other tenants on that address
- freely along `has_port` and `serves`, which mean "the same target, addressed
  another way"
- never into infrastructure a scan identified as a third party's; your name
  resolving to a CDN edge does not make that edge yours to scan
- your explicit call on one node always wins

Derived in **one place** and shipped with the map, so the map view and the
promote box cannot disagree, and each node carries *why* — "in scope" and "in
scope because `*.acme.com` covers it" are different claims and only the second
can be defended.

Anything that would send traffic is checked against it, including a command you
edited by hand. Passive steps are exempt: asking a public resolver about a third
party's name sends them nothing, and is how you learn whose it is.

## Phases

An engagement type declares its phases and the baseline that runs them.
`engagements/external.py` is the whole of what makes an external test different —
adding a type is writing a module, not editing conditionals.

| phase | tools | consumes | produces |
|---|---|---|---|
| Reconnaissance | bbot, subfinder | — *(starts from the scope)* | names |
| | dig | domain | addresses, resolution edges |
| Active Scanning | nmap | host, domain | open ports, service detail |
| Web Analysis | httpx | port, host, domain | web applications, TLS facts |
| | curl, openssl | — *(one target at a time)* | evidence on one node |

`consumes` means "reads the map"; `targets` means "aim me at one node". A tool
declaring only `targets` is a microscope and is not swept — running it as part of
a phase pointed it at the project's apex domain every time, whatever the phase
had actually found.

### The pipeline is the point

Each phase consumes what the last produced, and the crossing matters:

```
scope ──▶ bbot, subfinder ──▶ names
names ──▶ dig ──▶ addresses
addresses ──▶ nmap ──▶ open ports
ports × the names that reach them ──▶ httpx ──▶ applications
```

That last line is the one that needs the graph. A web server picks its
application from the Host header, so probing an address alone reaches whatever
answers for nobody in particular — measured against a real engagement, probing
every open port by address returned a hosting platform's marketing site or a
reverse proxy's 404, and not one of the target's applications. Crossing ports
with the names that resolve to their host is the only way to reach them, and a
list of names and a list of ports cannot be recombined after the fact.

### When a phase is done

A phase is stale when something it **takes as input** appears after it ran —
a name nothing has resolved, a host nothing has scanned. Its own output does not
date it, and neither does a later phase's: ports appearing says nothing about
whether subdomain enumeration is current. Counting any new node made every phase
stale the moment it succeeded, and finishing the engagement undid the checklist
behind you.

Coverage is recorded **when a run finishes**, from the list it was handed — not
when you promote its output. A host that answered nothing was still scanned, and
so was a row you left unticked.

## Pace

Two dials on the project, because the same word costs the two kinds of tool
wildly different amounts. Across a few hundred names, "careful" is about three
minutes for the web probe and hours for the port scan.

| | careful *(default)* | normal | aggressive |
|---|---|---|---|
| **scan** `{{scan_timing}}` `{{scan_probes}}` | `-T3 --version-light` | `-T4 --version-light` | `-T4` |
| **web** `{{web_threads}}` `{{web_rate}}` | `-t 5 -rl 10` | `-t 10 -rl 20` | `-t 50 -rl 150` |

The placeholder name says which dial it reads, so no tool needs classifying.
Timing and probe intensity are separate on the scan side because they are
separate risks: what upsets a fragile service is being sent an odd protocol
probe, not being sent packets quickly.

Substituted **server-side at the moment of running** — a limit you can edit out of
a text field is not a limit — and recorded with the run, so the history states
the pace you tested at. `-T2` is not offered: 0.4 s between serialised probes is
400 seconds per host before any timeout, hours on a real estate. Ask for it by
hand on the run that needs it.

## Runs are evidence

A run is filed under its engagement. Metadata is small and goes in JSON; output
can be megabytes and goes beside it in a plain log, so listing runs never reads
the output. Files a tool writes to `{{outdir}}` are kept beside the log —
evidence deleted when the process exits is not evidence.

Nothing is ever pruned. A tool that declares `result_file` is read **only** there;
sweeping every log a scanner writes is how a scan that correctly found no
subdomains came back offering a mail provider's hosts and a pip version string.

---

# Part 2 — the tool library

Paste a GitHub link → the platform works out how to install the tool, installs it
in Docker, verifies it, and makes it runnable.

## Pipeline

```
1 Ingest       parse URL → owner/repo, slug id, reject dupes
2 Inspect      gather signals · derive every recipe we know, best first
3 Acquire      try each in turn: docker pull | docker build | generated Dockerfile
4 Verify       run with timeout, stdin closed; detect ENTRYPOINT vs argv; capture --help
5 Register     status ready; runnable under its section
```

## Strategy ladder — a list, not a choice

```
0. a published image the repo's own README documents      → docker pull   ~sec
1. the repo's own Dockerfile                              → docker build  ~min
2. the install command extracted from README / go.mod     → generated Dockerfile
3. the ecosystem's convention                             → generated Dockerfile
4. the same recipe on a base image contemporary with the
   dependencies                                           → generated Dockerfile
5. nothing usable                                         → fail, readable reason
```

A *list*, not a single choice. Committing to one strategy at inspect time was the
root cause of tools dying on their first setback: each new repo tripped over a
different missing escalation edge. Anything that fails hands off to the next.

The era-matched rung is last because old images carry old CVEs — but an old
repo's dependencies were resolved against an old toolchain, and today's
manufactures failures the authors never had.

## Extract, never synthesise

`go install github.com/owner/repo@latest` fails for most real Go tools.
subfinder's actual path is
`github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` — note the `/v2`
*and* the `/cmd/subfinder`. Repo name ≠ install path is the norm, and the same
holds for npm and pip. The README almost always contains the real command
verbatim, so the job is **reading the repo's own instructions**.

The same applies to published images: rather than guessing `docker.io/owner/repo`
and trying to corroborate it, read the image name out of the README's own
`docker pull` line. A repo that documents no image yields no image.

## There is no model in it

An LLM stage that wrote and repaired Dockerfiles was removed. Measured across
every tool added in development: each one that installed did so through a
deterministic rung, while the model produced broken recipes — a Dockerfile that
never cloned the repo — and repair loops that deleted their own earlier fixes,
invented package versions that had never existed, and looped on identical
answers. Fixing the *environment* solved what it could not, in milliseconds
rather than minutes.

Diagnosing a build failure is a far harder job than writing a recipe from
documentation, and it is the one the model was worst at. Falling through to the
next recipe is faster and more honest.

**When every rung fails**, `handoff.py` composes the whole question — the
distilled errors, what was tried, the constraints of this build system — for you
to paste into whatever model you already have. Paste the Dockerfile back and it
is validated like any other. No API key, no network dependency, no inference
here.

## Prompt injection is not the threat it was

With no model reading the README, the injection path is gone. What remains is
that **install commands still derive from untrusted repo text**, and a pasted
Dockerfile is whatever you pasted. Both are gated.

`install_cmd` must pass all of:

- an allowed leading verb (`go install`, `pip install`, `npm install`,
  `cargo install`, `docker build`, `git clone`, `make`, …). This list *will* go
  stale — `uv` broke it once — so it is a sanity check, extensible via
  `PENSTATION_EXTRA_INSTALL_VERBS`. **The shell-hygiene rules are what actually
  stop fetch-and-execute.**
- no fetch-execute chaining: no `|`, `curl … | sh`, `eval`, backticks, `$(…)`
- no redirection or privilege escalation: no `>`, `>>`, `sudo`, `su`
- must reference the repo being installed
- bounded length, no control characters

A Dockerfile must start with `FROM`, use only official bases (golang, python,
node, rust, alpine, debian, ubuntu, busybox, distroless), never pipe a download
into a shell or `ADD` from a URL, never `COPY` from a build context — there is
none, so the source is cloned inside a `RUN` — and carry no secret or ssh mounts.

## Verifying carefully

Many tools exit non-zero on `--help`, print to stderr, or hang on stdin. The test
is **"produced output within the timeout"**, never a bare exit code.

A baseline tool's run template is never derived from `--help`. Its command is
declared because it encodes how the methodology uses the tool — inference
replaced nmap's `-iL {{input}}` with `-iR {{target}}`, which scans *random
internet hosts*.

## Guardrails

- Docker daemon reachable before an add is accepted
- runs capped: `--rm`, 2 GB memory, 2 CPUs, 1024 pids, wall-clock timeout, stdin
  closed, no host mounts except a per-run scratch dir for `{{outdir}}`
- attacker-controlled text — service banners, certificate fields — is bounded and
  stripped of control characters at the one place it enters the map, and the
  port-table CSV neutralises cells a spreadsheet would execute
- responses are `no-store`: the UI is one file served off disk, and a cached page
  serving yesterday's code against today's data reads as a bug in the application
- honest posture: the Docker socket is root-equivalent. Local use. Safer, not safe.

## GitHub API budget

Unauthenticated GitHub allows ~60 requests/hour per IP and trips abuse detection,
so **adding without a token is refused** rather than burning it. A fine-grained
PAT with no scopes raises it to 5,000/hr. Two things keep adds cheap: the README
comes from `raw.githubusercontent.com`, which is not rate-limited, and repo
signals are cached for an hour, so a retry spends nothing.

## Accepted debt

Version pinning beyond `resolved_ref` · image and disk GC · parallel builds ·
tools needing interactive config, API keys or wordlists · ETag requests.
