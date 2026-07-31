"""The tool library — installing, verifying and running command-line tools.

Paste a GitHub link → inspect the repo → install it natively → verify → run it.
Installed tools live here and are shared across engagements; which project uses
which tool is recorded in penstation/projects.py, not on the tool.

    store      ToolRecord + file-per-tool persistence
    jobs       serial job queue + status machine
    gather     repo signals; extracts install commands from the repo's own docs
    validate   allowlist validators for install commands and run commands
    nativeops  apt/pipx/go/clone installs with streamed output
    runner     assemble and run an installed tool as a subprocess
    pipeline   Inspect → Acquire → Verify, over an ordered list of recipes
    handoff    compose a failure into a prompt for a capable model

Depends on the app shell (penstation.paths / settings / events); never the
reverse, and never on projects or engagements.
"""
