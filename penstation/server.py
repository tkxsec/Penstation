"""Web server for the auto-add-tool feature.

    GET  /                    the UI
    GET  /tools               list tool records
    POST /tools               {url, section} -> id immediately, setup runs in background
    GET  /tools/{id}/log      full setup log (for reload)
    GET  /events              SSE: status transitions + live build log lines
    GET  /tools/{id}/prompt   a ready-to-paste prompt describing the failure
    POST /tools/{id}/command  save or clear a command override
    POST /tools/{id}/install  supply the recipe yourself when none could be derived
    GET  /projects            engagements + their section/tool assignments
    POST /projects            create one
    POST /tools/{id}/retry    re-run setup for a failed tool
    DELETE /tools/{id}        drop the record (and its image)
    DELETE /tools             drop everything, including cached repo signals

`POST /tools` never blocks: docker builds take minutes, so it enqueues and returns.
"""
from __future__ import annotations

import asyncio
import urllib.parse
import json
import os
import sys
from pathlib import Path

# app shell
from penstation import map as gmap
from penstation import engagements, projects, runs, scope, settings
from penstation.events import bus

# the add-a-tool feature
from penstation.tools import dockerops as D
from penstation.tools import gather as gather_mod
from penstation.tools import handoff
from penstation.tools import runner, store
from penstation.tools.gather import GatherError, parse_url
from penstation.tools.jobs import JobQueue
from penstation.tools.pipeline import Pipeline
from penstation.tools.runner import RunError
from penstation.tools.validate import (validate_command, validate_dockerfile,
                                          validate_input, validate_install)

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


_CTYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
           ".gif": "image/gif", ".svg": "image/svg+xml", ".json": "application/json",
           ".xml": "application/xml", ".html": "text/html", ".csv": "text/csv"}


# Which relation links a parent to a newly promoted child.
_REL = {"domain": "contains", "host": "resolves_to",
        "port": "has_port", "webapp": "serves", "finding": "affects"}


def _url_unquote(s: str) -> str:
    return urllib.parse.unquote(s)


def _basename(name: str) -> str:
    """Last component of a recorded file name, whichever separator wrote it.

    Names are stored posix-style now, but runs recorded on Windows before that
    hold "scan_dir\\subdomains.txt" — and a split on "/" alone left that whole
    string as the "basename", so the declared result file never matched and
    promotion fell back to sweeping every log the scan wrote.
    """
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def _out_of_scope_targets(proj, command: str, input_text: str) -> list[str]:
    """Targets in this run that the map says are not ours to touch.

    Reads both places a target can come from: the input file a list-taking tool
    is handed, and the words of the command itself, which is where a hand-edited
    single-target run puts it.

    A value the map knows is judged by the map, so an address that is in scope
    only by inheritance still passes. A value the map has never seen is judged by
    the scope rules alone — typing an address into the box is not a way to reach
    something the engagement never authorised.
    """
    m = gmap.load(proj.id)
    verdicts = gmap.derive_scope(m, lambda v: scope.matching_rule(proj.scope, v))
    known = {}
    for nid, n in m.nodes.items():
        ok = verdicts.get(nid, {}).get("in_scope", True)
        known.setdefault(gmap.canon_domain(n.value), ok)
        known.setdefault(gmap.canon_host(n.value), ok)

    words = list((input_text or "").splitlines())
    words += [w for w in (command or "").replace("=", " ").split()
              if not w.startswith("-")]
    bad = []
    for raw in words:
        v = (raw or "").strip().strip("'\"")
        # Only things that name a target. Flags, file paths and the tool's own
        # name are not targets, and {{input}} is a placeholder the runner fills.
        if not v or v.startswith("{{") or "/" in v and not gmap.classify(v):
            continue
        kind = (gmap.classify(v) or ("", {}))[0]
        if kind not in ("domain", "host", "port", "webapp"):
            continue
        for key in (gmap.canon_domain(v), gmap.canon_host(v)):
            if key in known:
                if not known[key] and v not in bad:
                    bad.append(v)
                break
        else:
            if not scope.matches(proj.scope, v) and v not in bad:
                bad.append(v)
    return bad


def _ctype(name: str) -> str:
    ext = name[name.rfind("."):].lower() if "." in name else ""
    return _CTYPES.get(ext, "text/plain; charset=utf-8")


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


def ensure_baseline(kind: str = "") -> dict:
    """Make sure every engagement type's baseline exists in the library.

    Images are global, so this builds each baseline tool **once ever** — not
    once per engagement. Called at startup so cloning the repo and starting the
    server is all it takes; a project created later just points at what is
    already built.
    """
    queued, reused = [], []
    kinds = [kind] if kind else list(engagements.TYPES)
    for k in kinds:
        for order, entry in enumerate(
                getattr(engagements.TYPES.get(k), "BACKBONE", [])):
            tid = entry["id"]
            rec = store.load(tid)
            if rec is None:
                rec = store.create(entry.get("source", ""), entry["section"], tid)
                rec.manual_dockerfile = entry["dockerfile"]
                rec.run_template = entry.get("run", "")
                rec.baseline, rec.check = True, entry.get("check", "")
                rec.baseline_order = order
                rec.consumes = list(entry.get("consumes") or [])
                rec.result_file = entry.get("result_file", "")
                rec.output_files = list(entry.get("output_files") or [])
                rec.targets = list(entry.get("targets") or [])
                rec.save()
                queue.submit(rec)
                queued.append(tid)
            else:
                rec.baseline = True
                rec.baseline_order = order
                rec.consumes = list(entry.get("consumes") or [])
                rec.result_file = entry.get("result_file", "")
                rec.output_files = list(entry.get("output_files") or [])
                rec.targets = list(entry.get("targets") or [])
                rec.check = entry.get("check", "")
                rec.run_template = entry.get("run", "")
                rec.save()
                reused.append(tid)
    return {"queued": queued, "reused": reused}


def unassign_baseline(proj) -> int:
    """Take baseline tools out of a project's phases.

    The baseline belongs to the Map — it is the workflow that builds it — while
    the phases hold the tools you added yourself. Leaving it in both meant one
    tool with two cards, two input boxes and two output panes.
    """
    n = 0
    for entry in getattr(engagements.TYPES.get(proj.kind), "BACKBONE", []):
        for section in list(proj.sections):
            if proj.unassign(section, entry["id"]):
                n += 1
    if n:
        proj.save()
    return n


async def _add_tool(payload: dict) -> dict:
    # A token is required: unauthenticated GitHub is 60 req/hour and trips abuse
    # detection, which can get the whole IP dropped. Refuse rather than burn it.
    if not settings.github_token():
        return {"error": "A GitHub token is required before adding tools. "
                         "Add one in Settings.", "need_token": True}

    url = (payload.get("url") or "").strip()
    section = (payload.get("section") or "").strip() or "reconnaissance"
    proj = projects.load((payload.get("project") or "").strip()) or projects.ensure_default()
    try:
        owner, repo = parse_url(url)
    except GatherError as exc:
        return {"error": str(exc)}

    tool_id = store.slug(repo)
    if store.exists(tool_id):
        # The image already exists in the library — nothing to build, just file
        # it into this engagement. Rebuilding a shared image per project would
        # cost minutes for an identical artifact.
        if proj.assign(section, tool_id):
            proj.save()
            return {**(store.load(tool_id).to_dict()), "assigned": True}
        return {"error": f"'{tool_id}' is already in this section"}

    # Fail fast if Docker isn't available — better than a confusing build error.
    try:
        await D.preflight()
    except D.DockerError as exc:
        return {"error": str(exc)}

    rec = store.create(f"https://github.com/{owner}/{repo}", section, tool_id)
    proj.assign(section, tool_id)
    proj.save()
    queue.submit(rec)
    return rec.to_dict()


async def _do_run(rec, command: str, project: str, section: str,
                  input_text: str = "") -> None:
    """Run in the background, streaming output to the bus and to disk.

    Output is written under the engagement as it arrives rather than at the end,
    so a scan killed halfway still leaves the evidence it produced.
    """
    import time
    run = runs.start(project, rec.id, section, command)
    if input_text:
        run.input_lines = len([l for l in input_text.splitlines() if l.strip()])
        run.save()
    bus.publish("run_start", {"id": rec.id, "command": command, "run": run.id})

    def on_line(line: str) -> None:
        run.append(line)
        bus.publish("run_log", {"id": rec.id, "line": line})

    try:
        result = await runner.run_command(rec, command, on_line,
                                          outdir_keep=run.files_dir,
                                          input_text=input_text)
        run.exit_code, run.files = result["code"], result["files"]
        bus.publish("run_done", {"id": rec.id, "code": result["code"],
                                 "command": result["command"],
                                 "files": result["files"], "run": run.id})
    except RunError as exc:
        run.exit_code, run.error = -1, str(exc)
        bus.publish("run_done", {"id": rec.id, "code": -1, "error": str(exc)})
    except Exception as exc:  # never let a run take the server down
        run.exit_code, run.error = -1, f"unexpected error: {exc}"
        bus.publish("run_done", {"id": rec.id, "code": -1,
                                 "error": f"unexpected error: {exc}"})
    finally:
        run.finished_at = time.time()
        run.save()


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
                elif ("{{input}}" in command
                      and not validate_input(_json_body(body).get("input") or "")):
                    writer.write(_ok({"error": validate_input(
                        _json_body(body).get("input") or "").reason}))
                else:
                    p = _json_body(body)
                    proj = (projects.load((p.get("project") or "").strip())
                            or projects.ensure_default())
                    # The scope has shaped which targets get offered; here it
                    # decides. A tool that sends traffic does not run against
                    # something the map says is out of scope, and editing the
                    # box by hand is exactly the path that got round the filter.
                    #
                    # Passive steps are exempt: asking a public resolver about a
                    # third party's name sends them nothing, and that is how you
                    # learn whose it is in the first place.
                    refused = ([] if rec.check in ("subdomain-enum", "resolve")
                               or p.get("force")
                               else _out_of_scope_targets(
                                   proj, command, p.get("input") or ""))
                    if refused:
                        writer.write(_ok({"error":
                            "out of scope: " + ", ".join(refused[:5])
                            + (f" and {len(refused)-5} more" if len(refused) > 5 else "")
                            + " — move them in scope, or run it anyway",
                            "out_of_scope": refused}))
                    else:
                        rec.last_command = command      # history only
                        rec.save()
                        asyncio.create_task(_do_run(rec, command, proj.id,
                                                    (p.get("section") or "").strip(),
                                                    p.get("input") or ""))
                        writer.write(_ok({"ok": True}))

            elif (method == "POST" and len(parts) == 3
                  and parts[0] == "tools" and parts[2] == "command"):
                # Save an override, or clear it to fall back to the generated
                # command. Keeping these separate means improving a baseline
                # command reaches every project instead of being shadowed
                # forever by whatever was typed once.
                rec = store.load(parts[1])
                cmd = (_json_body(body).get("command") or "").strip()
                if rec is None:
                    writer.write(_ok({"error": "unknown tool"}))
                elif cmd and not validate_command(cmd):
                    writer.write(_ok({"error": validate_command(cmd).reason}))
                else:
                    rec.command_override = cmd
                    rec.save()
                    bus.publish("status", rec.to_dict())
                    writer.write(_ok({"command_override": cmd,
                                      "using_default": not cmd}))

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

            elif (method == "GET" and len(parts) == 4 and parts[0] == "projects"
                  and parts[2] == "runs"):
                # Every recorded run of one tool in this engagement.
                writer.write(_ok({"runs": [r.to_dict()
                                           for r in runs.for_tool(parts[1], parts[3])]}))

            elif (method == "POST" and len(parts) == 3 and parts[0] == "projects"
                  and parts[2] == "baseline"):
                # Materialise the engagement type's baseline toolset. Images are
                # shared, so a second project reuses whatever is already built.
                proj = projects.load(parts[1])
                if proj is None:
                    writer.write(_ok({"error": "unknown project"}))
                else:
                    res = ensure_baseline(proj.kind)
                    unassign_baseline(proj)
                    out(_paint(f"baseline for {proj.id}: building "
                               f"{res['queued'] or 'none'}, reusing "
                               f"{res['reused'] or 'none'}", "green"))
                    writer.write(_ok(res))

            elif (method == "GET" and len(parts) == 3 and parts[0] == "projects"
                  and parts[2] == "map"):
                proj = projects.load(parts[1])
                m = gmap.load(parts[1])
                # The scope is part of the map by definition, so a missing root
                # is repaired rather than reported. Deleting one — or clearing
                # the map on a build that had no re-seed — used to leave the
                # engagement's own targets off it with no way back short of
                # re-saving the scope field. Only when something is actually
                # missing: a map load is a read, and this is the repair.
                if proj and gmap.scope_missing(m, proj.scope):
                    await gmap.mutate(parts[1],
                                      lambda mm: gmap.seed_from_scope(mm, proj.scope))
                    m = gmap.load(parts[1])
                d = m.to_dict()
                # Scope travels with the nodes rather than being re-derived in
                # the browser, so the map and the promote box cannot disagree
                # about what is in scope — one rule, evaluated in one place.
                # Scope is the engagement's rules, full stop. It used to also
                # count "you promoted it", which made sense when promoting was a
                # decision you made row by row; nothing is confirmed now, so
                # that rule would mark everything a scan found as in scope and
                # collapse the map's in/out split into one bucket.
                derived = gmap.derive_scope(
                    m, (lambda v: scope.matching_rule(proj.scope, v)) if proj
                       else (lambda v: "*"))
                for nid, n in d["nodes"].items():
                    tags = n.get("tags") or []
                    verdict = derived.get(nid) or {"in_scope": True, "why": ""}
                    n["in_scope"] = verdict["in_scope"]
                    # Why, not just whether — the map states its reasoning so a
                    # host you are about to scan can be justified line by line.
                    n["scope_why"] = verdict["why"]
                    n["scope_forced"] = (gmap.SCOPE_IN in tags
                                         or gmap.SCOPE_OUT in tags)
                    n["third_party"] = gmap.is_third_party(tags)
                writer.write(_ok(d))

            elif (method == "POST" and len(parts) == 4 and parts[0] == "projects"
                  and parts[2] == "map" and parts[3] == "classify"):
                # What does this output look like? Nothing is written here —
                # this is the "38 new, 474 known" view you decide from.
                p = _json_body(body)
                text = p.get("text") or ""
                missing = ""     # a declared result file the run never wrote
                run = runs.load(parts[1], (p.get("run") or "").strip() or "-")
                if not text and run:
                    rec = store.load(run.tool)
                    want = (getattr(rec, "result_file", "") or "") if rec else ""
                    # A tool that names the file holding its results gets read
                    # there and nowhere else. Sweeping every log a scanner writes
                    # is how a bbot run that correctly found no subdomains came
                    # back offering Google's mail servers and a pip version string.
                    picked = None
                    if want:
                        for f in (run.files or []):
                            name = f.get("name", "")
                            # bbot nests its output under a generated scan name, so
                            # match the basename rather than the whole path.
                            if _basename(name).lower() == want.lower():
                                picked = run.file_path(name)
                                break
                    if want:
                        # Declared means declared, including when the file is
                        # absent: falling back to the sweep on a miss is how a
                        # scan that found 9 subdomains offered 50 rows, 49 of them
                        # out of scope, read out of its own debug log. Nothing to
                        # read is a truthful "nothing to promote".
                        #
                        # Say which file, though. "Nothing recognisable to
                        # promote" under a pane listing 11 subdomains reads as a
                        # parser bug; the actual fault was a command that never
                        # wrote the file, and naming it points straight at that.
                        try:
                            text = picked.read_text(errors="replace") if picked else ""
                        except OSError:
                            text = ""
                        if not picked:
                            missing = want
                    else:
                        # No declared result file (or it wasn't produced): stdout
                        # plus anything readable the run wrote. bbot's subdomains
                        # are in its output files, not on stdout — reading only
                        # stdout is why a real run reported nothing to promote.
                        text = run.output()
                        for f in (run.files or []):
                            name = f.get("name", "")
                            # A run's input is not its output. input.txt is the
                            # target list fed in from the map and retained as
                            # evidence; reading it back made every value a fresh
                            # "discovery", so anything wrong on the map re-promoted
                            # itself on the next run and could never be deleted.
                            if _basename(name) == runner.INPUT_NAME:
                                continue
                            fp = run.file_path(name)
                            if fp and fp.suffix.lower() in (
                                    ".txt", ".csv", ".json", ".jsonl", ".ndjson",
                                    ".xml", ".tsv", ".list", ""):
                                try:
                                    text += "\n" + fp.read_text(errors="replace")
                                except OSError:
                                    pass
                found = gmap.classify_all(text)
                m = gmap.load(parts[1])
                proj = projects.load(parts[1])
                # Wildcards known before this output plus any it declares itself,
                # so a single bbot run folds its own findings without needing a
                # second pass. The tool that detects the wildcard is rarely the
                # one that trips over it: bbot reports the fact, and subfinder
                # reports every name underneath.
                wilds = {gmap.canon_domain(n.value) for n in m.nodes.values()
                         if gmap.WILDCARD in n.tags}
                wilds |= {gmap.canon_domain(r["value"]) for r in found["rows"]
                          if r.get("wildcard")}

                seen, rows, folded = set(), [], {}
                for r in found["rows"]:
                    nid = gmap.node_id(r["kind"], r["value"],
                                       **({"port": r["port"]} if "port" in r else {}))
                    if nid in seen:
                        continue          # the same value twice in one output
                    seen.add(nid)
                    # Under a wildcard, but still recorded. A wildcard means DNS
                    # cannot confirm a name, not that the name was invented —
                    # and nothing in the baseline invents names: a passive source
                    # reporting one means a certificate or a public record
                    # carries it, and two names on one address are routinely two
                    # applications, because web servers route on Host. What the
                    # mark is for is the scanning layer, where they really are
                    # one host.
                    under = ""
                    if not r.get("wildcard") and r["kind"] == "domain":
                        under = gmap.wildcard_over(wilds, r["value"])
                        if under:
                            folded[under] = folded.get(under, 0) + 1
                    # Your override, else the rules. Inheritance is applied below
                    # once every row is known, because a host's verdict depends
                    # on the names in the same output that resolve to it.
                    node = m.nodes.get(nid)
                    marks = [t for t in (r.get("tags") or [])
                             if t in gmap.KEEP_TAGS]
                    third = gmap.is_third_party(
                        (node.tags if node else []) + marks)
                    in_scope = gmap.in_scope(
                        node.tags if node else [],
                        bool(scope.matches(proj.scope, r["value"])
                             if proj else True))
                    rows.append({**r, "id": nid, "known": nid in m.nodes,
                                 "under_wildcard": under, "in_scope": in_scope,
                                 "third_party": third,
                                 "forced": bool(node and (
                                     gmap.SCOPE_IN in node.tags
                                     or gmap.SCOPE_OUT in node.tags))})

                # Scope carries along resolution here too, or dig's output would
                # offer every address it found as out of scope — no domain rule
                # can match an IP — while the map, which does inherit, shows the
                # same addresses in scope a moment later.
                by_id = {r["id"]: r for r in rows}
                # A seed is a row the rules matched, or one already on the map in
                # scope — not a row that inherited it a moment ago, for the same
                # reason as derive_scope: one hop, never a closure.
                seeds = {r["id"] for r in rows if r["in_scope"]} | {
                    nid for nid, n in m.nodes.items() if gmap.SCOPE_IN in n.tags}
                for e in (found.get("edges") or []):
                    if e.get("rel") != "resolves_to":
                        continue
                    for src, dst in ((e.get("frm"), e.get("to")),
                                     (e.get("to"), e.get("frm"))):
                        b = by_id.get(dst)
                        if src in seeds and b and not b["in_scope"] \
                                and not b["forced"] and not b["third_party"]:
                            b["in_scope"] = True
                for _ in range(2):
                    for e in (found.get("edges") or []):
                        a, b = by_id.get(e.get("frm")), by_id.get(e.get("to"))
                        if e.get("rel") in ("has_port", "serves") and a and b \
                                and a["in_scope"] and not b["forced"]:
                            b["in_scope"] = True
                writer.write(_ok({"rows": rows, "kinds": found["kinds"],
                                  "uniform": found["uniform"],
                                  "edges": found.get("edges") or [],
                                  "total": len(rows), "folded": folded,
                                  "missing_result": missing,
                                  "new": sum(1 for r in rows if not r["known"])}))

            elif (method == "POST" and len(parts) == 3 and parts[0] == "projects"
                  and parts[2] == "map"):
                # Commit the rows you confirmed.
                p = _json_body(body)
                rows = p.get("rows") or []
                # Relations the tool itself reported — bbot's resolved_hosts says
                # which address a name resolved to. Only applied between nodes you
                # actually promoted, so unticking a row drops its edges with it.
                want_edges = p.get("edges") or []
                run_id = (p.get("run") or "").strip()
                run = runs.load(parts[1], run_id) if run_id else None
                tool = run.tool if run else "manual"
                tool_rec = store.load(run.tool) if run else None
                check_kind = (getattr(tool_rec, "check", "") or tool)
                parent = (p.get("parent") or "").strip()
                stale = 0          # resolutions this answer superseded

                def commit(m):
                    # Counted by how much the map grew, not by how many calls were
                    # made: the same resolution appears on several events, and
                    # reporting "36 links" when 34 landed is just wrong.
                    nonlocal stale
                    added, before = 0, len(m.edges)
                    for r in rows:
                        kind, value = r.get("kind"), r.get("value") or r.get("line")
                        if kind not in gmap.KINDS or not value:
                            continue
                        extra = {"port": int(r["port"])} if r.get("port") else {}
                        if kind == "finding" and r.get("on"):
                            extra["on"] = r["on"]
                        node = m.add_node(kind, value, run=run_id, tool=tool, **extra)
                        # Promoting is the scope decision. A row you reviewed and
                        # put on the map is in scope from then on, whatever the
                        # scope text says — that is what "Add all" means when it
                        # takes rows the rules flagged. The tag is what makes it
                        # stick: without it the same value came back flagged
                        # out of scope on every later classify.
                        if gmap.ACCEPTED not in node.tags:
                            node.tags.append(gmap.ACCEPTED)
                        # Whose infrastructure the scan said this is. Carried
                        # onto the node so the map can show it and scope can
                        # refuse to inherit into it.
                        for mark in (r.get("tags") or []):
                            if mark in gmap.KEEP_TAGS and mark not in node.tags:
                                node.tags.append(mark)
                        # Promoting the marker is what makes it stick: from here
                        # on, every tool's names under this domain are marked.
                        if r.get("wildcard") and gmap.WILDCARD not in node.tags:
                            node.tags.append(gmap.WILDCARD)
                        # And the other side of it — kept, marked, and hung off
                        # the wildcard so the map shows the relationship rather
                        # than a flat list that hides it.
                        under = (r.get("under_wildcard") or "").strip()
                        if under:
                            if gmap.UNDER_WILDCARD not in node.tags:
                                node.tags.append(gmap.UNDER_WILDCARD)
                            pid = gmap.node_id("domain", under)
                            if pid in m.nodes and pid != node.id:
                                m.link(pid, "contains", node.id,
                                       run=run_id, tool=tool)
                        if parent and parent in m.nodes:
                            m.link(parent, _REL.get(kind, "contains"), node.id,
                                   run=run_id, tool=tool)
                        added += 1
                    for e in want_edges:
                        frm, rel, to = e.get("frm"), e.get("rel"), e.get("to")
                        if rel in gmap.RELATIONS and frm in m.nodes and to in m.nodes:
                            m.link(frm, rel, to, run=run_id, tool=tool)
                    # A resolver's answer replaces the previous one for the names
                    # it answered about. Edges were only ever added, so a name
                    # that moved to a new address kept the old one too — and the
                    # old address stayed in scope by inheritance forever, from a
                    # resolution that had stopped being true.
                    if check_kind == "resolve":
                        fresh = {(e.get("frm"), e.get("to")) for e in want_edges
                                 if e.get("rel") == "resolves_to"}
                        answered = {f for f, _ in fresh}
                        for key, edge in list(m.edges.items()):
                            if (edge.rel == "resolves_to" and edge.frm in answered
                                    and (edge.frm, edge.to) not in fresh):
                                m.edges.pop(key, None)
                                stale += 1
                    if parent and run and run.section:
                        # Recorded as the coverage kind, not the tool id. The
                        # node then reads "checked: http-probe", curl and httpx
                        # count as the same coverage, and the phase checklist —
                        # which counts nodes by their phase's checks — can see
                        # its own work. Keyed by tool, nothing matched.
                        m.mark_checked(parent, check_kind, run_id)
                    return added, len(m.edges) - before

                added, linked = await gmap.mutate(parts[1], commit)
                out(_paint(f"[map] {parts[1]}: +{added} node(s), "
                           f"+{linked} edge(s) from {tool}"
                           + (f", {stale} stale resolution(s) dropped"
                              if stale else ""), "green"))
                writer.write(_ok({"added": added, "linked": linked,
                                  "stale": stale}))

            elif (method == "POST" and len(parts) == 4 and parts[0] == "projects"
                  and parts[2] == "map" and parts[3] == "scope"):
                # Your scope call on any number of nodes at once. One mutation
                # rather than one per node: moving twelve subdomains across is
                # a single decision, and a dozen separate writes would leave the
                # map half-changed if one of them failed.
                p = _json_body(body)
                ids = [str(x) for x in (p.get("ids") or [])]
                mode = (p.get("mode") or "auto").strip()

                def set_scope(m):
                    # One hop along the relations that mean "this thing lives on
                    # that thing", both ways: a name and the address it resolves
                    # to are the same target, and so are a host and its ports.
                    # Moving one without the other is how you end up with an
                    # in-scope name whose address is out of scope — nothing to
                    # scan — or an out-of-scope host still handing its ports to
                    # the web tools.
                    #
                    # One hop, not the transitive closure: thirteen names share
                    # one address here, and moving a single subdomain should not
                    # drag in the other twelve through it.
                    # No cascade. Scope carries along resolution on its own, in
                    # derive_scope, so moving a name already brings the address
                    # it answers with — and doing it here as well would write
                    # overrides onto nodes you never picked, which then stop
                    # following the map at all.
                    wanted = set(ids)
                    changed = 0
                    for nid in wanted:
                        node = m.nodes.get(nid)
                        if node is None:
                            continue
                        node.tags = [t for t in node.tags
                                     if t not in (gmap.SCOPE_IN, gmap.SCOPE_OUT)]
                        if mode == "in":
                            node.tags.append(gmap.SCOPE_IN)
                        elif mode == "out":
                            node.tags.append(gmap.SCOPE_OUT)
                        changed += 1
                    return changed, len(wanted - set(ids))

                changed, also = await gmap.mutate(parts[1], set_scope)
                out(_paint(f"[map] {parts[1]}: {changed} node(s) -> scope {mode}"
                           + (f" ({also} followed)" if also else ""), "green"))
                writer.write(_ok({"changed": changed, "also": also}))

            elif (method == "POST" and len(parts) == 4 and parts[0] == "projects"
                  and parts[2] == "map" and parts[3] == "undo"):
                run_id = (_json_body(body).get("run") or "").strip()
                gone = await gmap.mutate(parts[1], lambda m: m.undo_run(run_id))
                writer.write(_ok({"removed": gone}))

            elif (method in ("PATCH", "DELETE") and len(parts) == 4
                  and parts[0] == "projects" and parts[2] == "map"):
                nid = _url_unquote(parts[3])
                if method == "DELETE":
                    # One kind of delete, and it removes the node and its edges.
                    # A scope root is the exception the map repairs on the next
                    # load — the scope is not the map's to discard.
                    writer.write(_ok({"ok": await gmap.mutate(
                        parts[1], lambda m: m.remove(nid))}))
                else:
                    p = _json_body(body)
                    def edit(m):
                        n = m.nodes.get(nid)
                        if not n:
                            return False
                        if "note" in p:
                            n.note = (p.get("note") or "").strip()
                        if "tags" in p:
                            n.tags = list(p.get("tags") or [])
                        return True
                    writer.write(_ok({"ok": await gmap.mutate(parts[1], edit)}))

            elif (method == "GET" and len(parts) >= 6 and parts[0] == "projects"
                  and parts[2] == "runs" and parts[4] == "files"):
                # Serve a file the run produced. Screenshots are the point.
                #
                # Unquote per segment: the browser percent-encodes each one, so
                # a space or a backslash (older runs recorded names with the
                # Windows separator) arrived here as literal "%20"/"%5C" and
                # matched no file. file_path() still rejects anything that
                # resolves outside the run's directory, so decoding first cannot
                # open a traversal.
                r = runs.load(parts[1], _url_unquote(parts[3]))
                fp = r.file_path("/".join(_url_unquote(x)
                                          for x in parts[5:])) if r else None
                if fp is None:
                    writer.write(_resp("404 Not Found", b"not found", "text/plain"))
                else:
                    writer.write(_resp("200 OK", fp.read_bytes(), _ctype(fp.name)))

            elif (method == "GET" and len(parts) == 5 and parts[0] == "projects"
                  and parts[2] == "runs"):
                r = runs.load(parts[1], parts[4])
                writer.write(_ok({**r.to_dict(), "output": r.output()} if r
                                 else {"error": "unknown run"}))

            elif method == "GET" and len(parts) == 1 and parts[0] == "projects":
                writer.write(_ok({"projects": [p.to_dict() for p in projects.load_all()],
                                  "types": sorted(projects.TYPES)}))

            elif method == "POST" and len(parts) == 1 and parts[0] == "projects":
                p = _json_body(body)
                client = (p.get("client") or "").strip()
                if not client:
                    writer.write(_ok({"error": "a client name is required"}))
                else:
                    proj = projects.create(client, (p.get("scope") or "").strip(),
                                           (p.get("kind") or "external").strip())
                    if proj.scope:
                        await gmap.mutate(proj.id,
                            lambda m: gmap.seed_from_scope(m, proj.scope))
                    out(_paint(f"project created: {proj.id} ({proj.kind})", "green"))
                    writer.write(_ok(proj.to_dict()))

            elif (method == "POST" and len(parts) == 3 and parts[0] == "projects"
                  and parts[2] == "clear"):
                # Everything this engagement produced: its map, every recorded
                # run and the files those runs retained. The engagement itself
                # stays — client, scope, notes, and which tools sit in which
                # phase — because this is for starting the work again, not
                # setting it up again. Installed images are shared between
                # engagements and are never touched here; uninstalling lives
                # under Add Tool.
                proj = projects.load(parts[1])
                if proj is None:
                    writer.write(_ok({"error": "unknown project"}))
                else:
                    n_runs = runs.count(parts[1])

                    def wipe(m):
                        gone = len(m.nodes)
                        m.nodes.clear()
                        m.edges.clear()
                        # Re-seed, or the map comes back empty and there is
                        # nowhere for the next run to hang its output off.
                        gmap.seed_from_scope(m, proj.scope)
                        return gone

                    n_nodes = await gmap.mutate(parts[1], wipe)
                    runs.forget_project(parts[1])
                    out(_paint(f"[clear] {proj.id}: {n_nodes} node(s), "
                               f"{n_runs} run(s) removed", "green"))
                    writer.write(_ok({"nodes": n_nodes, "runs": n_runs}))

            elif method in ("PATCH", "DELETE") and len(parts) == 2 and parts[0] == "projects":
                proj = projects.load(parts[1])
                if proj is None:
                    writer.write(_ok({"error": "unknown project"}))
                elif method == "DELETE":
                    # Images are shared, so removing an engagement never
                    # uninstalls anything — it only drops the assignments.
                    projects.delete(parts[1])
                    runs.forget_project(parts[1])
                    gmap.forget(parts[1])
                    writer.write(_ok({"ok": True}))
                else:
                    p = _json_body(body)
                    for f in ("client", "scope", "kind", "notes"):
                        if f in p:
                            setattr(proj, f, (p.get(f) or "").strip())
                    proj.save()
                    if "scope" in p and proj.scope:
                        # Editing scope adds the new roots; it never removes
                        # anything you have already found.
                        await gmap.mutate(proj.id,
                            lambda m: gmap.seed_from_scope(m, proj.scope))
                    writer.write(_ok(proj.to_dict()))

            elif (len(parts) >= 4 and parts[0] == "projects" and parts[2] == "sections"
                  and method in ("POST", "DELETE")):
                proj = projects.load(parts[1])
                section = parts[3]
                if proj is None:
                    writer.write(_ok({"error": "unknown project"}))
                elif method == "POST":
                    tid = (_json_body(body).get("tool_id") or "").strip()
                    if not store.load(tid):
                        writer.write(_ok({"error": "unknown tool"}))
                    else:
                        proj.assign(section, tid)
                        writer.write(_ok(proj.save().to_dict()))
                else:
                    # /projects/{id}/sections/{sec}/tools/{tool_id}
                    tid = parts[5] if len(parts) > 5 else ""
                    proj.unassign(section, tid)
                    writer.write(_ok(proj.save().to_dict()))

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
                    projects.forget_tool(rec.id)
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
                projects.forget_tool(parts[1])   # no dangling assignments
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
    projects.ensure_default()      # adopt pre-project tools on first run
    base = ensure_baseline()       # build the baseline once, ever
    if base["queued"]:
        out(_paint(f"baseline: building {', '.join(base['queued'])} "
                   "(first run only)", "yellow"))
    for _p in projects.load_all():
        unassign_baseline(_p)   # baseline lives under Map, not in the phases
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
