"""The add-a-tool feature.

Paste a GitHub link → inspect the repo → install it in Docker → verify → run it.

    store      ToolRecord + file-per-tool persistence
    jobs       serial job queue + status machine
    gather     repo signals; extracts install/run commands from the repo's own docs
    validate   allowlist validators for install commands, run commands, Dockerfiles
    dockerops  docker pull/build/inspect/kill with streamed output
    runner     assemble and run `docker run` for an installed tool
    pipeline   Inspect → Acquire (+Repair) → Verify

Depends on the app shell (penstation.paths / settings / events); never the reverse.
"""
