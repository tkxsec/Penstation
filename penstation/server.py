"""Web server for the auto-add-tool feature.

    GET  /                    the UI
    GET  /tools               list tool records
    POST /tools               {url, section} -> id immediately, setup runs in background
    GET  /tools/{id}/log      full setup log (for reload)
    GET  /events              SSE: status transitions + live build log lines
    GET  /tools/{id}/prompt   a ready-to-paste prompt describing the failure
    POST /tools/{id}/install  supply the recipe yourself when none could be derived
    POST /tools/{id}/retry    re-run setup for a failed tool
    DELETE /tools/{id}        drop the record (and its image)
    DELETE /tools             drop everything, including cached repo signals

`POST /tools` never blocks: docker builds take minutes, so it enqueues and returns.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

# app shell
from penstation import settings
from penstation.events import bus

# the add-a-tool feature
from penstation.addtool import dockerops as D
from penstation.addtool import gather as gather_mod
from penstation.addtool import handoff
from penstation.addtool import runner, store
from penstation.addtool.gather import GatherError, parse_url
from penstation.addtool.jobs import JobQueue
from penstation.addtool.pipeline import Pipeline
from penstation.addtool.runner import RunError
from penstation.addtool.validate import (validate_command, validate_dockerfile,
                                          validate_install)

WEB = Path(__file__).parent / "web"

# The Pipeline is fully deterministic — no model, no configuration.
queue = JobQueue(Pipeline())


# -- HTTP plumbing ----------------------------------------------------
async def _read(reader):
    line = await reader.readline()
    if not line:
        return None
    try:
        method, path, _ = line.decode("latin1").split()
    except ValueError:
        return None
    headers = {}
    while True:
        h = await reader.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        k, _, v = h.decode("latin1").partition(":")
        headers[k.strip().lower()] = v.strip()
    body = b""
    if "content-length" in headers:
        try:
            body = await reader.readexactly(int(headers["content-length"]))
        except (asyncio.IncompleteReadError, ValueError):
            body = b""
    return method, path, body


def _resp(status: str, body: bytes, ctype="application/json") -> bytes:
    return (f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


def _ok(data) -> bytes:
    return _resp("200 OK", json.dumps(data).encode())


def _json_body(body: bytes) -> dict:
    try:
        return json.loads(body or b"{}")
    except (ValueError, TypeError):
        return {}


# -- terminal mirror --------------------------------------------------
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_C = {"dim": "\033[2m", "cyan": "\033[36m", "green": "\033[32m",
      "yellow": "\033[33m", "red": "\033[31m", "reset": "\033[0m"}


def _paint(text: str, color: str) -> str:
    return f"{_C[color]}{text}{_C['reset']}" if _COLOR else text


def out(text: str, end: str = "\n") -> None:
    """Always flush — piping stdout makes print() block-buffered otherwise."""
    sys.stdout.write(text + end)
    sys.stdout.flush()


_STATUS_COLOR = {"ready": "green", "failed": "red", "queued": "dim"}


async def mirror_to_terminal() -> None:
    """Echo setup progress to stdout so the CLI is a live view, not just a boot log."""
    q = bus.subscribe()
    try:
        while True:
            msg = await q.get()
            data, event = msg["data"], msg["event"]
            if event in ("log", "run_log"):
                out(data["line"], end="")           # lines already end in \n
            elif event == "status":
                color = _STATUS_COLOR.get(data["status"], "yellow")
                line = f"[{data['id']}] {data['status']}"
                if data.get("detail"):
                    line += f" — {data['detail']}"
                out(_paint(line, color))
            elif event == "run_start":
                out(_paint(f"[{data['id']}] run: {data['command']}", "cyan"))
            elif event == "run_done":
                if data.get("error"):
                    out(_paint(f"[{data['id']}] run failed — {data['error']}", "red"))
                else:
                    color = "green" if data.get("code") == 0 else "red"
                    out(_paint(f"[{data['id']}] run finished — exit {data.get('code')}", color))
            elif event == "removed":
                out(_paint(f"[{data['id']}] removed", "dim"))
    except asyncio.CancelledError:
        bus.unsubscribe(q)
        raise


# -- SSE ---------------------------------------------------------------
async def _serve_sse(writer) -> None:
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                 b"Cache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n")
    await writer.drain()
    q = bus.subscribe()
    try:
        # Snapshot so a fresh client renders current state immediately.
        writer.write(f"event: snapshot\ndata: {json.dumps([t.to_dict() for t in store.load_all()])}\n\n".encode())
        await writer.drain()
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=20)
                payload = f"event: {msg['event']}\ndata: {json.dumps(msg['data'])}\n\n"
            except asyncio.TimeoutError:
                payload = ": keepalive\n\n"   # keeps proxies/browsers from closing
            writer.write(payload.encode())
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        bus.unsubscribe(q)


# -- routes -----------------------------------------------------------
def _settings_state() -> dict:
    tok = settings.github_token()
    return {"has_token": bool(tok),
            "masked": settings.masked(tok),
            "source": settings.token_source(),
            "quota": gather_mod.quota_note(),
            }


async def _add_tool(payload: dict) -> dict:
    # A token is required: unauthenticated GitHub is 60 req/hour and trips abuse
    # detection, which can get the whole IP dropped. Refuse rather than burn it.
    if not settings.github_token():
        return {"error": "A GitHub token is required before adding tools. "
                         "Add one in Settings.", "need_token": True}

    url = (payload.get("url") or "").strip()
    section = (payload.get("section") or "").strip() or "unsorted"
    try:
        owner, repo = parse_url(url)
    except GatherError as exc:
        return {"error": str(exc)}

    tool_id = store.slug(repo)
    if store.exists(tool_id):
        return {"error": f"'{tool_id}' already added"}

    # Fail fast if Docker isn't available — better than a confusing build error.
    try:
        await D.preflight()
    except D.DockerError as exc:
        return {"error": str(exc)}

    rec = store.create(f"https://github.com/{owner}/{repo}", section, tool_id)
    queue.submit(rec)
    return rec.to_dict()


async def _do_run(rec, command: str) -> None:
    """Run in the background, streaming output to the bus (UI + terminal)."""
    bus.publish("run_start", {"id": rec.id, "command": command})
    on_line = lambda line: bus.publish("run_log", {"id": rec.id, "line": line})
    try:
        result = await runner.run_command(rec, command, on_line)
        bus.publish("run_done", {"id": rec.id, "code": result["code"],
                                 "command": result["command"],
                                 "files": result["files"]})
    except RunError as exc:
        bus.publish("run_done", {"id": rec.id, "code": -1, "error": str(exc)})
    except Exception as exc:  # never let a run take the server down
        bus.publish("run_done", {"id": rec.id, "code": -1,
                                 "error": f"unexpected error: {exc}"})


def make_handler():
    async def handle(reader, writer):
        try:
            req = await _read(reader)
            if req is None:
                return
            method, path, body = req
            parts = [p for p in path.split("/") if p]

            if method == "GET" and path in ("/", "/index.html"):
                writer.write(_resp("200 OK", (WEB / "index.html").read_bytes(),
                                   "text/html; charset=utf-8"))
            elif method == "GET" and path == "/favicon.ico":
                writer.write(_resp("204 No Content", b"", "text/plain"))

            elif method == "GET" and path == "/events":
                await _serve_sse(writer)
                return

            elif method == "GET" and path == "/settings":
                writer.write(_ok(_settings_state()))

            elif method == "POST" and path == "/settings":
                tok = (_json_body(body).get("github_token") or "").strip()
                if not tok:
                    settings.set_github_token("")
                    writer.write(_ok({**_settings_state(), "saved": True,
                                      "detail": "token cleared"}))
                else:
                    check = await asyncio.to_thread(gather_mod.check_token, tok)
                    # Save unless GitHub explicitly rejected it — a network blip
                    # shouldn't throw away a token the user just pasted.
                    saved = bool(check["ok"] or check.get("unreachable"))
                    if saved:
                        settings.set_github_token(tok)
                        out(_paint(f"github token saved "
                                   f"({settings.masked(tok)}) — {check['detail']}", "green"))
                    else:
                        # Be loud: the UI must not mistake this for success.
                        out(_paint(f"github token NOT saved — {check['detail']}", "red"))
                    # `saved` is the authoritative signal for the UI; `has_token`
                    # only reports whether *any* token is stored.
                    writer.write(_ok({**_settings_state(), **check, "saved": saved}))


            elif method == "GET" and path == "/tools":
                writer.write(_ok({"tools": [t.to_dict() for t in store.load_all()],
                                  "queue_depth": queue.depth}))

            elif method == "POST" and path == "/tools":
                writer.write(_ok(await _add_tool(_json_body(body))))

            elif method == "GET" and len(parts) == 3 and parts[0] == "tools" and parts[2] == "log":
                rec = store.load(parts[1])
                writer.write(_ok({"log": rec.read_log()} if rec else {"error": "unknown tool"}))

            elif method == "POST" and len(parts) == 3 and parts[0] == "tools" and parts[2] == "run":
                command = (_json_body(body).get("command") or "").strip()
                rec = store.load(parts[1])
                check = validate_command(command)
                if rec is None:
                    writer.write(_ok({"error": "unknown tool"}))
                elif rec.status != "ready":
                    writer.write(_ok({"error": f"tool is not ready ({rec.status})"}))
                elif runner.is_running(rec.id):
                    writer.write(_ok({"error": "a run is already in progress"}))
                elif not check:
                    writer.write(_ok({"error": check.reason}))
                else:
                    # Remember the command so the box is pre-filled next time.
                    rec.last_command = command
                    rec.save()
                    asyncio.create_task(_do_run(rec, command))
                    writer.write(_ok({"ok": True}))

            elif method == "POST" and len(parts) == 3 and parts[0] == "tools" and parts[2] == "stop":
                stopped = await runner.stop(parts[1])
                writer.write(_ok({"stopped": stopped}))

            elif method == "POST" and len(parts) == 3 and parts[0] == "tools" and parts[2] == "help":
                rec = store.load(parts[1])
                if rec is None or not rec.image:
                    writer.write(_ok({"error": "unknown tool"}))
                else:
                    rec.help_text = await D.capture_help(rec.image)
                    rec.save()
                    bus.publish("status", rec.to_dict())
                    writer.write(_ok({"help_text": rec.help_text}))

            elif (method == "GET" and len(parts) == 3
                  and parts[0] == "tools" and parts[2] == "prompt"):
                rec = store.load(parts[1])
                writer.write(_ok({"prompt": handoff.prompt_for(rec, rec.tried)}
                                 if rec else {"error": "unknown tool"}))

            elif (method == "POST" and len(parts) == 3
                  and parts[0] == "tools" and parts[2] == "install"):
                # You supplying the recipe when the ladder couldn't derive one.
                rec = store.load(parts[1])
                p = _json_body(body)
                cmd = (p.get("install_cmd") or "").strip()
                dockerfile = (p.get("dockerfile") or "").strip()
                if rec is None:
                    writer.write(_ok({"error": "unknown tool"}))
                elif not cmd and not dockerfile:
                    writer.write(_ok({"error": "nothing provided"}))
                else:
                    # Same gates as any derived recipe, minus the "must name the
                    # repo" rule — you are the authority on your own input, but
                    # shell-injection hygiene still applies.
                    check = (validate_dockerfile(dockerfile) if dockerfile
                             else validate_install(cmd))
                    if not check:
                        writer.write(_ok({"error": check.reason}))
                    else:
                        rec.manual_install, rec.manual_dockerfile = cmd, dockerfile
                        rec.save()
                        rec.append_log(f"\n--- using the recipe you provided ---\n"
                                       f"{dockerfile or cmd}\n")
                        out(_paint(f"[{rec.id}] manual recipe supplied", "green"))
                        queue.submit(rec)
                        writer.write(_ok(rec.to_dict()))

            elif method == "POST" and len(parts) == 3 and parts[0] == "tools" and parts[2] == "retry":
                rec = store.load(parts[1])
                if rec is None:
                    writer.write(_ok({"error": "unknown tool"}))
                else:
                    rec.append_log("\n--- retry ---\n")
                    queue.submit(rec)
                    writer.write(_ok(rec.to_dict()))

            elif method == "DELETE" and len(parts) == 1 and parts[0] == "tools":
                # Start fresh: every record, its image, its per-tool volume, and
                # the cached repo signals. Destructive, so the UI confirms first.
                removed = []
                for rec in store.load_all():
                    if rec.image and rec.strategy != "docker-pull":
                        await D.remove_image(rec.image)
                    await D.remove_volume(f"penstation-home-{rec.id}")
                    if store.delete(rec.id):
                        removed.append(rec.id)
                    bus.publish("removed", {"id": rec.id})
                cached = gather_mod.clear_cache()
                out(_paint(f"cleared {len(removed)} tool(s) and {cached} cached "
                           f"repo signal(s)", "yellow"))
                writer.write(_ok({"removed": removed, "cache": cached}))

            elif method == "DELETE" and len(parts) == 2 and parts[0] == "tools":
                rec = store.load(parts[1])
                if rec and rec.image and rec.strategy != "docker-pull":
                    await D.remove_image(rec.image)   # only images we built
                await D.remove_volume(f"penstation-home-{parts[1]}")
                ok = store.delete(parts[1])
                bus.publish("removed", {"id": parts[1]})
                writer.write(_ok({"ok": ok}))

            else:
                writer.write(_resp("404 Not Found", b"not found", "text/plain"))

            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    return handle


async def serve(host: str, port: int, mirror: bool = True) -> None:
    # A restart kills any in-flight build; don't leave those records spinning.
    orphans = store.reap_orphans()
    if orphans:
        out(_paint(f"reset {len(orphans)} interrupted setup(s): "
                   f"{', '.join(orphans)}", "yellow"))

    server = await asyncio.start_server(make_handler(), host, port)
    try:
        version = await D.preflight()
        out(f"docker daemon {version} ✓")
    except D.DockerError as exc:
        out(_paint(f"⚠  {exc}\n   (adds will be refused until Docker is running)", "red"))
    if settings.github_token():
        out(f"github: token ✓ ({settings.masked(settings.github_token())}, "
            f"from {settings.token_source()})")
    else:
        out(_paint("github: NO TOKEN — adding tools is disabled. Add one in "
                   "Settings in the web UI (or set PENSTATION_GITHUB_TOKEN).", "red"))
    out(f"penstation  →  http://{host}:{port}")
    out(_paint("watching for tool activity… (setup output appears below)", "dim"))

    mirror_task = asyncio.create_task(mirror_to_terminal()) if mirror else None
    try:
        async with server:
            await server.serve_forever()
    finally:
        if mirror_task is not None:
            mirror_task.cancel()
