"""The command line, so `penstation` works once installed.

Lives inside the package rather than in serve.py because an entry point has to
be importable — `python3 serve.py` still works and calls straight through here,
so a clone and an install run exactly the same code.
"""
from __future__ import annotations

import argparse
import asyncio

from penstation.server import serve

# Anything but loopback publishes an unauthenticated application that runs
# arbitrary commands as the account it starts under. On a box with a public
# address that is a remote code execution endpoint with a web interface, found
# by scanners within hours. Reach it over `ssh -L 8787:127.0.0.1:8787` instead;
# the SSH key is the authentication.
LOOPBACK = ("127.0.0.1", "localhost", "::1", "")


def main() -> None:
    ap = argparse.ArgumentParser(prog="penstation")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--quiet", action="store_true",
                    help="don't mirror tool setup output to the terminal")
    ap.add_argument("--i-know-this-is-unauthenticated", action="store_true",
                    help="allow binding somewhere other than loopback")
    args = ap.parse_args()

    if args.host not in LOOPBACK and not args.i_know_this_is_unauthenticated:
        ap.error(
            f"refusing to bind {args.host}: penstation has no authentication, so "
            "anything but loopback publishes a root-capable web interface.\n"
            "  Reach it over SSH instead:  "
            "ssh -L 8787:127.0.0.1:8787 <this box>\n"
            "  If you genuinely mean it:   --i-know-this-is-unauthenticated")

    try:
        asyncio.run(serve(args.host, args.port, mirror=not args.quiet))
    except KeyboardInterrupt:
        print("\nstopped.")
