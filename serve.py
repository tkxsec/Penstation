#!/usr/bin/env python3
"""Launch penstation from a clone.

    python3 serve.py            # http://127.0.0.1:8787, setup output mirrored here
    python3 serve.py --quiet    # web UI only, no terminal output

The command itself lives in penstation/cli.py so an installed `penstation` and a
plain clone run the same code. This file is the clone's front door, nothing more.
"""
from penstation.cli import main

if __name__ == "__main__":
    main()
