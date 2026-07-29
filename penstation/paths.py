"""Project paths, anchored to the package — never the current directory.

Relative paths like `data/settings.json` resolve against the process's working
directory, so launching from anywhere but the project root silently loses your
saved token, tools and cache. Everything is anchored here instead.

Override the location with PENSTATION_DATA if you want state elsewhere.
"""
from __future__ import annotations

import os
from pathlib import Path

# penstation/paths.py -> penstation/ -> project root
ROOT = Path(__file__).resolve().parent.parent

DATA = Path(os.environ.get("PENSTATION_DATA") or (ROOT / "data")).expanduser().resolve()

SETTINGS_FILE = DATA / "settings.json"
TOOLS_DIR = DATA / "tools"
CACHE_DIR = DATA / "cache"


def ensure() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
