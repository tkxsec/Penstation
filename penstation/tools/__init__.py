"""The tool library — installing, verifying and running command-line tools.

Paste a GitHub link → inspect the repo → install it in Docker → verify → run it.
Images live here and are shared across engagements; which project uses which
tool is recorded in penstation/projects.py, not on the tool.

    store      ToolRecord + file-per-tool persistence
    jobs       serial job queue + status machine
    gather     repo signals; extracts install commands from the repo's own docs
    validate   allowlist validators for install commands, run commands, Dockerfiles
    dockerops  docker pull/build/inspect/kill with streamed output
    runner     assemble and run `docker run` for an installed tool
    pipeline   Inspect → Acquire → Verify, over an ordered list of recipes
    handoff    compose a failure into a prompt for a capable model

Depends on the app shell (penstation.paths / settings / events); never the
reverse, and never on projects or engagements.
"""
