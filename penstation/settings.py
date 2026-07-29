"""Persisted settings — currently just the GitHub token.

The token is a secret, so the file is written 0600 (owner-only) and the full
value is never sent back to the browser or written to a log; only a masked form
is exposed.

Precedence: an environment variable always wins over the stored value, so
`PENSTATION_GITHUB_TOKEN=… python3 serve.py` overrides the UI without surprises.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from penstation.paths import SETTINGS_FILE  # anchored to the project, not the CWD
ENV_VARS = ("PENSTATION_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")


def load() -> dict:
    try:
        data = json.loads(SETTINGS_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(data: dict) -> None:
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.chmod(tmp, 0o600)          # secret: owner read/write only
    tmp.replace(SETTINGS_FILE)


def env_token() -> str:
    for var in ENV_VARS:
        val = (os.environ.get(var) or "").strip()
        if val:
            return val
    return ""


def github_token() -> str:
    """The effective token: environment first, then the stored one."""
    return env_token() or (load().get("github_token") or "").strip()


def token_source() -> str:
    if env_token():
        return "environment"
    if (load().get("github_token") or "").strip():
        return "settings"
    return "none"


def set_github_token(token: str) -> None:
    data = load()
    token = (token or "").strip()
    if token:
        data["github_token"] = token
    else:
        data.pop("github_token", None)
    save(data)


def masked(token: str) -> str:
    """Enough to recognise which token it is, not enough to use it."""
    t = (token or "").strip()
    if not t:
        return ""
    if len(t) <= 12:
        return "•" * len(t)
    return f"{t[:7]}…{t[-4:]}"
