# penstation on an engagement box — external design

How penstation is deployed and run for an external penetration test, and why it
is shaped this way.

The short version: penstation runs **on the engagement box**, tools are installed
**natively** and run as **subprocesses**, and the UI is reached over the SSH
session you already have. There is no Docker on these boxes, so there is none in
this design.

---

## The box

An external engagement gets a provisioned Kali VM. Measured on a real one:

```
docker      command not found
memory      100 GB total, 51 GB available
disk        4.1 TB free
python3     3.13.9
egress      <the VM's public address>
```

Two things follow. **There is no container runtime**, so tools cannot be images —
that is a measurement, not a preference. And **resources are not a constraint**,
so nothing here needs to be designed around memory or disk pressure.

```
YOUR LAPTOP                        ENGAGEMENT VM
┌────────────┐                     ┌──────────────────────────────────┐
│ browser    │ ssh -L 8787 ──────▶ │ penstation  127.0.0.1:8787       │
└────────────┘                     │   ├─ subprocess: nmap, httpx, …  │
                                   │   └─ data/  map · runs · evidence│
                                   │                                   │
                                   │ egress ──▶ the client's perimeter │
                                   └──────────────────────────────────┘
```

The box is where the engagement lives. It has the address the client whitelisted,
it holds the map and the evidence, and it is destroyed at the end. `data/` is
pulled home before that happens — it is the only thing that does not survive
teardown, and it is the engagement.

---

## Access

The UI binds loopback and is reached through a local port forward:

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

**No port is published.** penstation has no authentication — every route is open,
one of them accepts a repository URL and builds it, another executes a command —
so a publicly routable port would be a remote code execution endpoint with a web
interface, on a host that holds client data and has an address the client trusts.
An unusual high port on a public IP is found and fingerprinted within hours.

The SSH key is the authentication. Everyone who needs the UI already has shell
access to that box, so exposing a port buys nothing that is not already there.

`ExitOnForwardFailure` is not decoration: without it, a local port collision
prints a warning that scrolls past and the session connects anyway, leaving you
to work out why the page will not load.

A run is a subprocess of the server, so a dropped connection ends both — there is
no container left holding the work, and nothing reattaches on restart. Start it
detached for a scan you cannot afford to lose.

---

## Installing tools

Adding tools is the point of penstation, and it works here — the install ladder
changes rungs, not shape. First hit wins:

| # | when | how | notes |
|---|---|---|---|
| 0 | in Kali's repos | `apt install` | signed packages, seconds |
| 1 | a Python package | `pipx install` | own venv per tool |
| 2 | a Go repo | `go install …@latest` | path extracted from README / `go.mod` |
| 3 | publishes release assets | download + `chmod +x` | |
| 4 | anything else | clone + venv | **explicit approval** |
| 5 | none of the above | fail, with what each rung tried | |

`apt` leads because on Kali it is both the highest-quality answer and instant, and
because a distro package does not execute a stranger's code to install itself.
`pipx` before raw `pip` because it isolates each tool's dependency tree, which is
what per-tool images used to provide.

Rung 2 matters more than it looks. `go install github.com/owner/repo@latest`
fails for most real Go tools — subfinder's actual path is
`github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`, note both the
`/v2` and the `/cmd/`. Repo name is not install path, and reading the repo's own
documented command is the only reliable answer. `gather.py` already does this.

### Which rungs are allowed is a per-deployment policy

| deployment | allowed |
|---|---|
| an engagement VM you own | all rungs |
| a managed, client-site box | `apt` only |

Same binary, different policy. On hardware you do not own, add-a-tool resolves
against the distro and fails with *"not available from an approved source"*
rather than falling through to cloning a repository. On a box you provision and
destroy, the full ladder is available because that is where new tools are
actually needed.

### When every rung fails

Rung 5 does not report "failed". It reports what each rung tried:

```
apt          no package 'gitgot' in the configured repos
pipx         not on PyPI
go install   no go.mod
release      no release assets for linux/amd64
clone+venv   requirements.txt present — needs approval
```

The last line is the useful one: it says the tool *is* installable and what it
wants. Where that still is not enough, the card carries a box for supplying the
recipe yourself — one command, validated by the same rules — and `handoff.py`
composes the whole question, with the distilled errors and this system's
constraints, for pasting into whatever model you use.

A supplied recipe is stored on the tool record, so **reinstall replays it**. You
solve a difficult tool once and every later box gets it without you remembering
what you did.

---

## Running tools

Tools run as subprocesses of the server, as whoever runs penstation — root on a
provisioned engagement box.

### Privilege

There is no privilege separation between penstation and the tools it runs. A
scanner gets the same access penstation has, which on a provisioned box is root.

That is what the tools need. nmap's SYN scan wants `CAP_NET_RAW`, masscan wants
raw sockets, and bbot writes into its own installation. It is also all the
separation would have been worth here: penstation runs as root on the same host,
the box is provisioned for one engagement and destroyed after, and the tools are
pinned ones you chose. A malicious `subfinder` has the client network regardless
of which uid invoked it.

The isolation boundary is the box, not a second account on it. If an engagement
needs more than that, it needs its own VM.

`validate.py` is therefore the only barrier between a repository's README and a
command that runs with your access, which is why its rules are strict and why
nothing reaches a shell.

---

## What is unchanged

Everything above the execution layer:

- the **map** — identity, parsers, provenance, scope derivation
- **phases** and the baseline toolset, and how each consumes what the last produced
- **pace**, substituted server-side at the moment of running
- **run records and evidence**, including retained output files
- the entire **UI**
- `gather.py` — repo signals and install-command extraction
- `validate.py` — the allowlist and shell-hygiene rules

`validate.py` matters more here than it did. Behind a container it was
defence-in-depth; on this box it is the barrier between a repository's README and
a process running with your access. Its rules are unchanged: an allowed
leading verb, no pipes or command substitution or redirection or privilege
escalation, must reference the repository being installed, bounded length, no
control characters.

---

## The execution layer

`nativeops.py` installs, verifies, removes and streams. `build_argv()` returns a
bare command. `ToolRecord` stores a resolved binary path and the `--version`
string the box produced, which is what a run record reports rather than a pin.
`validate_install()` is the only gate an install command passes.

Three details carry more weight than their size suggests.

**Where tools live.** A naming question, not an isolation one. Our install path
competes with the distro's, and the distro's is older: Kali ships its own `httpx`
and `subfinder` in `/usr/bin`, several versions behind the pins. Installs go to
`/opt/penstation/{bin,pipx,tools}`, and that is the first place looked, so what
penstation installed is what runs. `GOBIN` and `PIPX_BIN_DIR` point there;
`GOPATH` stays in the home directory because the module cache is wanted only at
build time.

**Working directory.** Every spawn sets `cwd` explicitly rather than inheriting
penstation's, which is the checkout. What a tool does with the working directory
is not ours to assume: bbot stats every target against it to decide whether the
target names a file, and the Go toolchain chdirs in each `compile` it spawns. A
run gets its own directory, which is also where a tool writing relative paths
belongs.

**Dependencies at scan time.** bbot resolves its own module dependencies when a
scan starts — pip packages and apt packages both — which makes an engagement
depend on PyPI and the Debian mirrors answering at the worst possible moment. It
runs with `--no-deps`; its Python packages are declared in the tool spec's
`inject` list and installed into its venv at setup, and its one system package
comes from `setup.sh`.

The verification step keeps its rule: **"produced output within the timeout"**,
never a bare exit code. Many tools exit non-zero on `--help`, print to stderr, or
hang on stdin.

Recording `--version` replaces pinning. The box resolves the version, so the run
record has to say what actually ran — the same reason every node records the tool
and run that found it.

### Wordlists and keys

Kali carries `/usr/share/wordlists`, and `apt install seclists` adds the rest, so
these are packages rather than problems. What is missing is a managed setting, so
a path is not retyped per tool and per engagement:

```
{{wordlist:subdomains}}   {{wordlist:dirs}}   {{wordlist:vhosts}}
{{key:shodan}}
```

Named rather than a single path, because "the wordlist" means something different
for subdomain brute-forcing than for content discovery. These belong with pace for
the same reasons: they are properties of how you tested, they are recorded with
the run, and they are not something to be quietly swapped for something enormous
mid-engagement. A key resolved this way is never written into the command string,
so it does not reach the run record or the terminal mirror.

Some tools ship their own data — cloud_enum's mutation lists live in its
repository — so the rung that installed a tool is recorded, and reinstall uses the
same one rather than dropping a bare binary that has lost its data files.

---

## Build order

1. **Native installer** — the one genuinely new module
2. **`build_argv` returns the bare command**
3. **Tool record: resolved path + `--version`**
4. **Reinstall all**
5. **Wordlist and key substitution**

Then the hardening that holds regardless of how tools are run: atomic writes in
`map.py`, `projects.py` and `runs.py`; run artifacts served as inert downloads;
`_read()` keeping headers so Host and Origin can be validated; and credentials
redacted from run records, since password spraying is an external phase.
