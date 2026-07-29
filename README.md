# penstation — add a tool, auto-set-up

Paste a GitHub link. It works out how to install the tool, installs it in Docker,
verifies it, and lets you run it against a target. Design: `docs/architecture.md`.

## Run

```bash
python3 serve.py                 # http://127.0.0.1:8787
```

Needs Docker running (tools install as Docker images).

**Recommended — a GitHub token.** Unauthenticated GitHub allows only ~60 API
requests/hour (about 20 tool adds); a token raises that to **5,000**. A
fine-grained PAT with **no scopes** is enough for public repositories
(github.com → Settings → Developer settings → Personal access tokens):

```bash
export PENSTATION_GITHUB_TOKEN=github_pat_...   # or GITHUB_TOKEN / GH_TOKEN
python3 serve.py
```

The startup line reports which mode you're in, and each add logs remaining quota.

Optional local LLM:

```bash
PENSTATION_LLM=ollama PENSTATION_LLM_MODEL=qwen2.5-coder python3 serve.py
```

## How it works

```
paste link  →  Inspect   read the repo, pick an install strategy, validate the command
            →  Acquire   docker pull / docker build   (log streams live to the UI)
            →  Repair    on failure: fall back to a generated Dockerfile, then LLM-fix (≤3)
            →  Verify    image present, detect ENTRYPOINT vs argv
            →  Run       docker run --rm … against your target
```

Strategy ladder, first hit wins:

| # | When | How | Speed |
|---|---|---|---|
| 0 | the repo's README documents a published image | `docker pull` | seconds |
| 1 | the repo ships a Dockerfile | `docker build` | minutes |
| 2 | an install command is extractable | generated Dockerfile + build | minutes |
| 3 | none of the above | fail with a readable reason | — |

## The LLM is optional

Deterministic extraction runs first and carries most tools on its own. The model
is consulted only to (a) infer an install/run command the repo doesn't document,
and (b) repair a failed build. **It proposes; deterministic code verifies** — every
suggestion is gated by the validators before anything executes, so a weak local
model means more retry rounds, not a broken tool.

## Security posture

Install commands and LLM-written Dockerfiles derive from untrusted repo text, so
both pass allowlist validators (see `validate.py`) before execution: permitted
verbs only, no pipes/substitution/redirection/privesc, must reference the repo
being installed, and official base images only. Nothing reaches a shell — commands
are built as argv. Runs are capped (`--rm`, memory, cpus, pids, timeout, stdin
closed) with no host mounts except an opt-in per-run scratch dir for `{{outdir}}`.

Docker isolates the host, but a build still runs arbitrary `RUN` lines with
network and Docker socket access is root-equivalent: **local use, not shared infra.**

## Files

```
serve.py                 launcher
penstation/
  server.py      HTTP + SSE; tool API
  store.py       ToolRecord + file-per-tool store (data/tools/<id>.json + .log)
  jobs.py        serial job queue + status machine
  pipeline.py    Inspect → Acquire (+Repair) → Verify
  gather.py      repo signals, command extraction, Dockerfile templates
  validate.py    install / run / Dockerfile validators
  dockerops.py   docker pull/build/inspect with streamed output
  runner.py      docker run assembly (argv_mode, limits, {{outdir}})
  llm.py         provider interface + Ollama; reason & repair prompts
  events.py      pub/sub bus
  web/index.html single-page UI
```

## Status

Working end to end. Verified with real tools and **no LLM**: `hakrawler`
(published image, 18s) and `assetfinder` (compiled from a pre-modules Go repo,
25s) — both then ran and returned real output.

Known gaps: no version pinning beyond recording the commit, no image GC, serial
builds only, GitHub API unauthenticated (~15 adds/hour), tools needing API keys
or wordlists aren't configurable yet. The real Ollama path is implemented but
untested here (no local model available) — the repair loop was verified with a
provider double against real failing/succeeding Docker builds.
