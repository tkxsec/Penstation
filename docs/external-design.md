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
recipe yourself — a shell command rather than a Dockerfile, validated by the same
rules — and `handoff.py` composes the whole question, with the distilled errors
and this system's constraints, for pasting into whatever model you use.

A supplied recipe is stored on the tool record, so **reinstall replays it**. You
solve a difficult tool once and every later box gets it without you remembering
what you did.

---

## Running tools

Tools run as subprocesses of the server. Three users, so code downloaded from the
internet never holds your access — at install time or at run time:

| user | runs | can read |
|---|---|---|
| `root` / your account | penstation itself | everything; owns `data/` at `700` |
| `noprivuser-install` | install commands | not `data/`, not `~/.ssh` |
| `noprivuser-run` | the tools themselves | only the run's scratch directory |

```bash
useradd -m -s /usr/sbin/nologin noprivuser-install
useradd -m -s /usr/sbin/nologin noprivuser-run
chmod 700 data/
```

Where penstation runs unprivileged, a sudoers drop-in lets it step down without a
prompt:

```
<your account> ALL=(noprivuser-install) NOPASSWD: /usr/bin/pipx, /usr/bin/go, /usr/bin/git
<your account> ALL=(noprivuser-run)     NOPASSWD: ALL
```

Validate with `visudo -c` before logging out. A malformed sudoers file is the one
change here that can lock you out of a box you cannot walk to.

`apt` stays as root, by nature — and it is the rung that does not execute
repository code.

### Why two users rather than one

`noprivuser-install` protects installation. It does not protect execution: a
package that behaves during `pip install` and misbehaves when invoked would
otherwise run with penstation's own access to the map, the evidence and the
network position. `noprivuser-run` closes that, and costs the same to build.

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
a process running as `noprivuser-install`. Its rules are unchanged: an allowed
leading verb, no pipes or command substitution or redirection or privilege
escalation, must reference the repository being installed, bounded length, no
control characters.

---

## What changes in code

| | |
|---|---|
| `dockerops.py` | **removed.** `nativeops.py` carries the same interface: install, verify, remove, stream |
| `build_argv()` | returns the bare command; there is no `docker run` to wrap it in |
| `ToolRecord` | stores a resolved binary path and `--version` output; the image and Dockerfile fields are gone |
| `validate.py` | `validate_dockerfile()` removed — with nothing sandboxed, `validate_install()` is the only barrier |
| new | **reinstall all**, replaying every tool record onto a fresh box |
| new | `{{wordlist:…}}` and `{{key:…}}`, resolved server-side like pace |

### Two accounts, and what that costs

The separation — one account installs, another runs — has two consequences a
container had handled for free, and both showed up as permission errors that
looked like something else.

**Where tools live.** `useradd -m` makes a home `0700`, so a tool installed into
`~noprivuser-install` cannot be *executed* by `noprivuser-run`: the failure is
`Permission denied` on the binary, before the tool does anything. Installs
therefore go to `/opt/penstation/{bin,pipx,tools}`, owned by the install account
and mode `0755` — the installer writes, the runner executes, and the runner
cannot modify what it runs. `GOBIN` and `PIPX_BIN_DIR` both point there; `GOPATH`
stays in the install account's home because the module cache is wanted only at
build time.

**Where output lands.** `data/` is `0700` and penstation-owned, which is the
point — tool code must not reach the map, the scope or the evidence. So a tool
cannot write into a run's directory either. It writes to a scratch directory it
owns, and penstation moves the results in afterwards. Opening `data/` to the run
account would have been one chmod and would have given away the whole property.

**Working directory.** A subprocess inherits penstation's, which on an engagement
box is `/root/Penstation` — mode `0700`, unreachable by either account. Every
spawn sets `cwd` explicitly. The Go toolchain chdirs in each `compile` it spawns,
so this surfaced as hundreds of `chdir: permission denied` lines and an exit 1
that read like a broken recipe.

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
