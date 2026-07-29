"""Gather — deterministic repo signals, no LLM.

Fetches what a repo tells us about itself and extracts install/run commands from
its own documentation. Per docs/architecture.md we EXTRACT rather than synthesize:
`go install github.com/owner/repo@latest` fails for most real Go tools (subfinder
is really `.../subfinder/v2/cmd/subfinder@latest`), but the README states the true
command verbatim.

Budget: 4 unauthenticated GitHub API calls per repo (~15 adds/hour per IP).
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

_API = "https://api.github.com"
_RAW = "https://raw.githubusercontent.com"

# Unauthenticated GitHub allows ~60 requests/hour per IP; a token raises that to
# 5,000. A fine-grained PAT with NO scopes is enough for public repositories.
_TOKEN_VARS = ("PENSTATION_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")  # kept for docs

# Signals are cached so a Retry doesn't re-spend quota on the same repo.
from penstation.paths import CACHE_DIR  # anchored to the project, not the CWD
CACHE_TTL = 3600.0

# Last seen rate-limit headers, so the UI/CLI can report quota honestly.
rate_limit: dict[str, int] = {}


def token() -> str:
    """Effective GitHub token — env var, else the one saved in Settings."""
    from penstation import settings          # local import avoids a cycle
    return settings.github_token()


def _headers() -> dict[str, str]:
    h = {"User-Agent": "penstation", "Accept": "application/vnd.github+json"}
    tok = token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def check_token(candidate: str) -> dict:
    """Test a token against GitHub. Blocking — call via asyncio.to_thread.

    Returns {ok, detail, limit}. Distinguishes a bad token (401) from GitHub
    being unreachable, so we don't discard a good token over a network blip.
    """
    tok = (candidate or "").strip()
    if not tok:
        return {"ok": False, "detail": "no token given", "limit": 0}
    req = urllib.request.Request(
        _API + "/rate_limit",
        headers={"User-Agent": "penstation",
                 "Accept": "application/vnd.github+json",
                 "Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read())
        core = (data.get("resources") or {}).get("core") or {}
        limit = int(core.get("limit") or 0)
        if limit >= 1000:
            return {"ok": True, "limit": limit,
                    "detail": f"valid — {limit} requests/hour"}
        return {"ok": False, "limit": limit,
                "detail": f"authenticated but limit is only {limit}/hour"}
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {"ok": False, "detail": "GitHub rejected this token (401)", "limit": 0}
        return {"ok": False, "detail": f"GitHub returned {exc.code}", "limit": 0}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "unreachable": True, "limit": 0,
                "detail": f"couldn't reach GitHub to verify ({exc}) — saved anyway"}


def quota_note() -> str:
    """Human-readable quota state for logs."""
    if not rate_limit:
        return "github: quota unknown"
    remaining, limit = rate_limit.get("remaining", 0), rate_limit.get("limit", 0)
    mins = max(0, int((rate_limit.get("reset", 0) - time.time()) / 60))
    auth = "token" if token() else "unauthenticated"
    return f"github: {remaining}/{limit} requests left ({auth}, resets in {mins}m)"

# Ecosystem detection: marker file -> (ecosystem, docker base image)
ECOSYSTEMS = {
    "go.mod": ("go", "golang:alpine"),
    "pyproject.toml": ("pip", "python:3.13-slim"),
    "setup.py": ("pip", "python:3.13-slim"),
    "requirements.txt": ("pip", "python:3.13-slim"),
    "package.json": ("npm", "node:alpine"),
    "cargo.toml": ("cargo", "rust:slim"),
}

# Fallback when no marker file is present — plenty of older repos predate them
# (e.g. pre-modules Go tools with no go.mod). GitHub still tells us the language.
LANGUAGES = {
    "go": ("go", "golang:alpine"),
    "python": ("pip", "python:3.13-slim"),
    "javascript": ("npm", "node:alpine"),
    "typescript": ("npm", "node:alpine"),
    "rust": ("cargo", "rust:slim"),
}

# Install verbs we recognize when reading a README.
_INSTALL_VERBS = (
    "go install", "go get", "pip install", "pip3 install", "pipx install",
    "npm install", "npm i", "cargo install", "docker pull", "docker build",
)


class GatherError(Exception):
    """Repo signals couldn't be collected."""


@dataclass
class Signals:
    owner: str
    repo: str
    description: str = ""
    language: str = ""
    default_branch: str = "main"
    commit: str = ""                       # resolved ref, for provenance
    files: set[str] = field(default_factory=set)
    readme: str = ""

    @property
    def repo_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"

    @property
    def has_dockerfile(self) -> bool:
        return "dockerfile" in self.files

    def ecosystem(self) -> tuple[str, str] | tuple[None, None]:
        for marker, (eco, base) in ECOSYSTEMS.items():
            if marker in self.files:
                return eco, base
        return LANGUAGES.get((self.language or "").lower(), (None, None))

    @property
    def go_modules(self) -> bool:
        """A modern module-aware Go repo (vs a pre-modules one needing go mod init)."""
        return "go.mod" in self.files


# -- github -----------------------------------------------------------
def parse_url(url: str) -> tuple[str, str]:
    m = re.search(r"github\.com[/:]([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)", (url or "").strip())
    if not m:
        raise GatherError("not a GitHub repository URL")
    return m.group(1), m.group(2).removesuffix(".git")


def _note_limits(headers) -> None:
    for key, name in (("X-RateLimit-Remaining", "remaining"),
                      ("X-RateLimit-Limit", "limit"),
                      ("X-RateLimit-Reset", "reset")):
        val = headers.get(key)
        if val is not None:
            try:
                rate_limit[name] = int(val)
            except ValueError:
                pass


def _get(path: str, host: str = _API):
    try:
        req = urllib.request.Request(host + path, headers=_headers())
        with urllib.request.urlopen(req, timeout=12) as resp:
            _note_limits(resp.headers)
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        _note_limits(exc.headers or {})
        # 403/429 with no quota left is the rate limit; say when it resets and
        # how to raise it, rather than a vague "try again later".
        if exc.code in (403, 429) and rate_limit.get("remaining", 1) == 0:
            mins = max(1, int((rate_limit.get("reset", 0) - time.time()) / 60))
            hint = ("" if token() else
                    " Set a GitHub token (PENSTATION_GITHUB_TOKEN) to raise the "
                    "limit from 60 to 5,000 requests/hour.")
            raise GatherError(
                f"GitHub API rate limit reached — resets in ~{mins} minute(s)."
                + hint)
        return None
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _raw(owner: str, repo: str, branch: str, filename: str) -> str | None:
    """Fetch a file from raw.githubusercontent.com.

    The raw CDN does NOT count against the API rate limit, so pulling the README
    this way saves the single largest API call per add.
    """
    url = f"{_RAW}/{owner}/{repo}/{branch}/{filename}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "penstation"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            return resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError):
        return None


def _cache_path(owner: str, repo: str) -> Path:
    return CACHE_DIR / f"{owner}--{repo}.json".lower()


def _cache_read(owner: str, repo: str) -> Signals | None:
    p = _cache_path(owner, repo)
    try:
        raw = json.loads(p.read_text())
        if time.time() - raw.get("_cached_at", 0) > CACHE_TTL:
            return None
    except (OSError, ValueError):
        return None
    sig = Signals(owner=owner, repo=repo,
                  description=raw.get("description", ""),
                  language=raw.get("language", ""),
                  default_branch=raw.get("default_branch", "main"),
                  commit=raw.get("commit", ""),
                  readme=raw.get("readme", ""))
    sig.files = set(raw.get("files", []))
    return sig


def _cache_write(sig: Signals) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(sig.owner, sig.repo).write_text(json.dumps({
            "_cached_at": time.time(), "description": sig.description,
            "language": sig.language, "default_branch": sig.default_branch,
            "commit": sig.commit, "readme": sig.readme, "files": sorted(sig.files),
        }))
    except OSError:
        pass


def gather(url: str, use_cache: bool = True) -> Signals:
    """Collect repo signals. Blocking — call via asyncio.to_thread.

    Costs 2–3 GitHub API calls (the README comes from the raw CDN, which is not
    rate-limited). Results are cached for an hour so a Retry is free.
    """
    owner, repo = parse_url(url)
    if use_cache:
        cached = _cache_read(owner, repo)
        if cached is not None:
            return cached

    info = _get(f"/repos/{owner}/{repo}")          # API call 1
    if info is None:
        raise GatherError(f"couldn't reach GitHub or repo not found: {owner}/{repo}")

    sig = Signals(
        owner=owner,
        repo=repo,
        description=info.get("description") or "",
        language=info.get("language") or "",
        default_branch=info.get("default_branch") or "main",
    )

    contents = _get(f"/repos/{owner}/{repo}/contents") or []   # API call 2
    sig.files = {c["name"].lower() for c in contents if isinstance(c, dict)}

    # README from the raw CDN — free. Fall back to the API only if that misses.
    readme_names = [c["name"] for c in contents
                    if isinstance(c, dict) and c["name"].lower().startswith("readme")]
    for name in readme_names or ["README.md"]:
        text = _raw(owner, repo, sig.default_branch, name)
        if text:
            sig.readme = text
            break
    if not sig.readme:
        rd = _get(f"/repos/{owner}/{repo}/readme")
        if rd and rd.get("content"):
            try:
                sig.readme = base64.b64decode(rd["content"]).decode("utf-8", "replace")
            except (ValueError, TypeError):
                sig.readme = ""

    # Provenance only — best effort, and skipped when quota is nearly gone.
    if rate_limit.get("remaining", 999) > 5:
        commits = _get(f"/repos/{owner}/{repo}/commits?per_page=1")   # API call 3
        if isinstance(commits, list) and commits and isinstance(commits[0], dict):
            sig.commit = (commits[0].get("sha") or "")[:12]

    _cache_write(sig)
    return sig


# -- published image discovery ----------------------------------------
def find_published_image(sig: Signals) -> str | None:
    """Find a prebuilt image, CORROBORATED by the repo's own docs.

    Discovery is by reading the README's own `docker pull/run` lines rather than
    guessing `owner/repo` — guessing could land on a squatted image and we would
    happily run it. We then require the name to reference the owner or repo, and
    (for Docker Hub) confirm it actually exists.
    """
    text = sig.readme or ""
    candidates: list[str] = []
    # Scan every token after `docker pull|run`, skipping flags and their values —
    # `docker run -it owner/tool` must not stop at `-it`.
    for m in re.finditer(r"docker\s+(?:pull|run)\s+([^\n`]*)", text, re.I):
        for tok in m.group(1).split():
            if tok.startswith("-"):
                continue
            if tok in ("\\", "|"):
                break
            candidates.append(tok.strip("\"'"))

    owner_l, repo_l = sig.owner.lower(), sig.repo.lower()
    for ref in candidates:
        base = ref.split("@")[0].split(":")[0].lower()
        if repo_l not in base and owner_l not in base:
            continue  # not corroborated as this project's image
        if base.startswith(("ghcr.io/", "public.ecr.aws/", "quay.io/")):
            return ref  # namespaced registry; the path itself is the corroboration
        if "/" in base and _dockerhub_exists(base):
            return ref
    return None


def _dockerhub_exists(name: str) -> bool:
    ns, _, repo = name.partition("/")
    return _get(f"/v2/repositories/{ns}/{repo}/", host="https://hub.docker.com") is not None


# -- command extraction from the repo's own docs ----------------------
def extract_install(sig: Signals) -> str | None:
    """Pull the real install command out of the README."""
    owner_l, repo_l = sig.owner.lower(), sig.repo.lower()
    best: str | None = None
    for raw in (sig.readme or "").splitlines():
        line = raw.strip().lstrip("$#").strip()
        low = line.lower()
        if not any(low.startswith(v) for v in _INSTALL_VERBS):
            continue
        if "|" in line or ">" in line:
            continue  # skip piped/redirected forms; the validator would reject them
        # Prefer a command that names this project (avoids picking up a
        # prerequisite like "go install some/other/tool").
        if repo_l in low or owner_l in low:
            return line
        best = best or line
    return best


def extract_run(sig: Signals) -> str | None:
    """Best-effort run template from the repo's own docs.

    Two deterministic tiers (the LLM stage can do better later):
      1. a usage example containing a sample target
      2. the documented target flag from the flags/usage block
    """
    binary = sig.repo.lower()
    readme = sig.readme or ""

    # Tier 1: a real usage example, e.g. `subfinder -d example.com`
    sample = (r"(example\.com|target\.com|domain\.com|hackerone\.com|scanme\.[a-z.]+"
              r"|<domain>|<target>|\$DOMAIN|1\.1\.1\.1|127\.0\.0\.1)")
    pat = re.compile(rf"\b{re.escape(binary)}\b\s+([^\n`|>]*?){sample}", re.I)
    for raw in readme.splitlines():
        line = raw.strip().lstrip("$#").strip()
        m = pat.search(line)
        if m:
            flags = _clean_flags(m.group(1))
            return f"{binary} {flags} {{{{target}}}}".replace("  ", " ").strip()

    # Tier 2: the flags block documents the target flag, e.g.
    #   "-d, -domain string[]  domains to find subdomains for"
    flag = _target_flag(readme)
    if flag:
        return f"{binary} {flag} {{{{target}}}}"
    return None


def _clean_flags(flags: str) -> str:
    """Drop usage-syntax noise from an extracted example.

    READMEs write optional flags as `[--subs-only]` or `<-flag>`; passed through
    literally those become bogus arguments. Optional means omittable, so drop them.
    """
    flags = re.sub(r"\[[^\]]*\]", " ", flags)   # [--optional]
    flags = re.sub(r"<[^>]*>", " ", flags)      # <placeholder>
    flags = flags.replace("...", " ")
    return re.sub(r"\s+", " ", flags).strip()


def target_flag(text: str) -> str | None:
    """Public wrapper — also used against `--help`, which is authoritative."""
    return _target_flag(text)


def _target_flag(readme: str) -> str | None:
    """Find the flag that takes the target, from a documented flags block."""
    # Flags whose description points at a *file* or a filter are not the target.
    reject = ("file", "list of", "exclude", "filter", "match", "output", "resolver",
              "wordlist", "config")
    want = re.compile(r"\b(domain|target|host|url)s?\b", re.I)
    for raw in readme.splitlines():
        line = raw.strip()
        m = re.match(r"^(-{1,2}[A-Za-z][\w-]*)\s*,?\s*(-{1,2}[\w-]+)?\s+(.*)$", line)
        if not m:
            continue
        desc = m.group(3)
        low = desc.lower()
        if not want.search(low) or any(r in low for r in reject):
            continue
        return m.group(1)
    return None


def target_kind(sig: Signals) -> str:
    text = f"{sig.repo} {sig.description}".lower()
    if re.search(r"\b(port|nmap|masscan|host)\b", text):
        return "host"
    if re.search(r"\b(url|http|https|screenshot|crawl|endpoint)\b", text):
        return "url"
    return "domain"


# -- deterministic Dockerfile template (LLM improves on this later) ---
def normalize_install(sig: Signals, cmd: str) -> str:
    """Modernize known-deprecated install forms.

    `go get -u <pkg>` was the pre-modules way to install a binary; modern Go
    requires `go install <pkg>@latest`. This is a mechanical, well-understood
    migration, not a guess.
    """
    eco, _ = sig.ecosystem()
    if eco == "go" and re.match(r"^go\s+get\b", cmd.strip(), re.I):
        pkg = cmd.split()[-1]
        if "@" not in pkg:
            pkg += "@latest"
        return f"go install {pkg}"
    return cmd


def generate_dockerfile(sig: Signals, install_cmd: str) -> str | None:
    """A Dockerfile for the detected ecosystem. Our own trusted template —
    the untrusted part is `install_cmd`, which the validator already gated."""
    eco, base = sig.ecosystem()
    if not eco:
        return None
    name = sig.repo.lower()

    # Pre-modules Go repo: `go install pkg@latest` can't work without a go.mod,
    # so clone and initialize a module before building.
    if eco == "go" and not sig.go_modules:
        return (
            f"FROM {base}\n"
            "RUN apk add --no-cache git ca-certificates\n"
            f"RUN git clone --depth 1 {sig.repo_url} /src\n"
            "WORKDIR /src\n"
            f"RUN go mod init {name} && go mod tidy && "
            f"go build -o /usr/local/bin/{name} .\n"
            f'ENTRYPOINT ["{name}"]\n'
        )

    lines = [f"FROM {base}"]
    if eco == "go":
        lines.append("RUN apk add --no-cache git ca-certificates")
    elif eco == "pip":
        lines.append("RUN apt-get update && apt-get install -y --no-install-recommends git "
                     "&& rm -rf /var/lib/apt/lists/*")
    elif eco == "cargo":
        lines.append("RUN apt-get update && apt-get install -y --no-install-recommends git "
                     "build-essential && rm -rf /var/lib/apt/lists/*")
    lines.append(f"RUN {install_cmd}")
    lines.append(f'ENTRYPOINT ["{name}"]')
    return "\n".join(lines) + "\n"
