#!/usr/bin/env python3
"""Launch penstation.

    python3 serve.py            # http://127.0.0.1:8787, setup output mirrored here
    python3 serve.py --quiet    # web UI only, no terminal output
"""
from __future__ import annotations

import argparse
import asyncio

from penstation.server import serve


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--quiet", action="store_true",
                    help="don't mirror tool setup output to the terminal")
    args = ap.parse_args()
    try:
        asyncio.run(serve(args.host, args.port, mirror=not args.quiet))
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
