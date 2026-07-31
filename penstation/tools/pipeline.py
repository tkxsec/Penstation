"""The setup pipeline: Inspect → Acquire → Verify.

Fully deterministic. Every install recipe is derived from what the repository
says about itself — the distro's own package, its documented install command,
its ecosystem's convention, or a clone of the repository itself.

There is no container runtime on an engagement box, so tools are installed
natively and run as subprocesses. Which rungs are permitted is a per-deployment
policy: everything on a box you provision and destroy, distro packages only on
hardware you do not own.

There was an LLM stage here that wrote and repaired install recipes. It was
removed: across every tool added in development, each one that installed did so
through a deterministic rung, while the model produced broken recipes and repair
loops that thrashed without ever rescuing a build. Fixing the *environment* —
the right toolchain, the C-extension headers a compile actually links against —
solved what the model could not, and did it in milliseconds instead of minutes.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass

from penstation.tools import nativeops as N
from penstation.tools import gather as G
from penstation.tools import validate as V
from penstation.events import bus
from penstation.tools.jobs import SetupFailed
from penstation.tools.store import ToolRecord

@dataclass
class Candidate:
    """One way to install a tool. The pipeline tries these in order."""
    kind: str                    # apt | pipx | go-install | release-binary | clone-venv
    install_cmd: str             # the command as shown to you
    pkg: str = ""                # package name or module path the rung installs
    binary: str = ""             # what to look for afterwards; defaults to the tool id
    note: str = ""               # human-readable, shown in the log


class Pipeline:
    # Every rung, in the order the ladder tries them. A deployment may allow
    # fewer: on hardware you do not own, `apt` alone means add-a-tool resolves
    # against the distro and never fetches from the internet.
    ALL_RUNGS = ("apt", "pipx", "go-install", "release-binary", "clone-venv")

    def __init__(self, allowed_rungs=None) -> None:
        self._sig: dict[str, G.Signals] = {}   # cached per tool, inspect -> acquire
        self._plan: dict[str, list[Candidate]] = {}   # recipes left to try
        self.allowed_rungs = tuple(allowed_rungs or self.ALL_RUNGS)

    # -- logging: persist + stream -------------------------------------
    def _log(self, rec: ToolRecord, text: str) -> None:
        rec.append_log(text)
        bus.publish("log", {"id": rec.id, "line": text})

    # -- 2. Inspect ----------------------------------------------------
    async def inspect(self, rec: ToolRecord) -> None:
        # A baseline tool has a declared install spec and no repository behind
        # it — nmap and dig are distro packages, so there is nothing to inspect
        # and gather would fail on an empty URL.
        #
        # Declared rather than derived on purpose: the spec carries the pinned
        # version where one matters (bbot==3.0.1, subfinder@v2.14.0), which the
        # ladder would otherwise resolve to whatever is current today.
        if rec.install_kind and not rec.source_url:
            self._log(rec, f"$ baseline tool — declared install: "
                           f"{rec.install_kind} {rec.install_pkg}\n")
            cmd = rec.install_cmd or f"{rec.install_kind} {rec.install_pkg}"
            self._plan[rec.id] = [Candidate(
                rec.install_kind, cmd, pkg=rec.install_pkg,
                binary=rec.install_binary or rec.id,
                note=f"the declared baseline recipe ({cmd})")]
            self._adopt(rec, self._plan[rec.id][0])
            rec.save()
            return

        self._log(rec, f"$ inspect {rec.source_url}\n")
        try:
            sig = await asyncio.to_thread(G.gather, rec.source_url)
        except G.GatherError as exc:
            raise SetupFailed(str(exc)) from exc
        self._sig[rec.id] = sig

        eco = sig.ecosystem()
        rec.resolved_ref = sig.commit
        rec.target_kind = G.target_kind(sig)
        self._log(rec, f"  repo={sig.owner}/{sig.repo} lang={sig.language or '?'} "
                       f"ecosystem={eco or '?'} commit={sig.commit or '?'}\n")
        self._log(rec, f"  {G.quota_note()}\n")

        # Deterministic run template first; --help overrides it at verify.
        #
        # Never for a baseline tool: its command is declared, not inferred, and
        # it encodes how the methodology uses the tool. The guard at verify was
        # not enough — inspection runs first and overwrote subfinder's
        # `-d {{targets}} -all -o {{outdir}}/subdomains.txt` with a bare
        # `subfinder -d {{target}}` lifted from the README, so the scan wrote no
        # result file and had nothing to promote.
        if not rec.baseline:
            rec.run_template = G.extract_run(sig) or ""

        plan = self._plan_recipes(rec, sig)
        self._plan[rec.id] = plan
        if not plan:
            raise SetupFailed(
                "no install command could be derived from this repository")
        self._log(rec, f"  {len(plan)} recipe(s) to try:\n")
        for i, cand in enumerate(plan, 1):
            self._log(rec, f"    {i}. {cand.note}\n")
        rec.tried = [c.note for c in plan]
        if plan:
            self._adopt(rec, plan[0])

        if not rec.run_template and not rec.baseline:
            rec.run_template = f"{sig.repo.lower()} {{{{target}}}}"
        self._log(rec, f"  run_template: {rec.run_template}\n")
        rec.save()

    def _plan_recipes(self, rec: ToolRecord, sig: G.Signals) -> list[Candidate]:
        """Every deterministic way we know to install this repo, best first.

        A *list*, not a single choice. Committing to one strategy at inspect
        time was the root cause of tools dying on their first setback: each new
        repo tripped over a different missing escalation edge. Anything that
        fails here simply hands off to the next entry.

        Ordered by how much of a stranger's code has to run to install it. A
        distro package runs maintainer scripts from a signed archive; a clone
        runs whatever is in the repository. That ordering is the reason apt
        leads and clone trails, not convenience.
        """
        plan: list[Candidate] = []
        allowed = self.allowed_rungs

        def add(kind: str, cmd: str, pkg: str, note: str, binary: str = "") -> None:
            if kind in allowed:
                plan.append(Candidate(kind, cmd, pkg=pkg, binary=binary, note=note))

        # Anything you supplied by hand goes first: you looked at the failure and
        # told us what the repo actually needs, which beats every guess below it.
        # Still validated — a pasted recipe gets the same gate as a derived one,
        # and here that gate is the only one, since nothing runs in a sandbox.
        if rec.manual_install:
            check = V.validate_install(rec.manual_install, sig.owner, sig.repo)
            if check:
                kind = self._kind_of(rec.manual_install)
                add(kind, rec.manual_install, self._pkg_of(rec.manual_install),
                    f"the install command you provided ({rec.manual_install})")
            else:
                self._log(rec, f"  [rejected] your command: {check.reason}\n")

        # 0. The distro's own package. Instant, signed, and it does not execute
        #    code from the repository being installed.
        name = (sig.repo or "").lower()
        for pkg in dict.fromkeys([name, name.replace("-", ""), f"{name}-toolkit"]):
            if pkg:
                add("apt", f"apt-get install -y {pkg}", pkg,
                    f"the distro package {pkg}", binary=name)

        # 1-2. What the repo documents. `go install owner/repo@latest` fails for
        #      most real Go tools — subfinder's path is
        #      `.../subfinder/v2/cmd/subfinder` — so the extracted command is the
        #      only reliable source, never the repo name.
        extracted = G.extract_install(sig)
        for cmd in (extracted, G.canonical_install(sig)):
            if not cmd or not V.validate_install(cmd, sig.owner, sig.repo):
                continue
            kind, pkg = self._kind_of(cmd), self._pkg_of(cmd)
            if kind and not any(c.pkg == pkg and c.kind == kind for c in plan):
                add(kind, cmd, pkg,
                    f"the command the repo documents ({cmd})", binary=name)

        # 4. Clone the repository and install into a venv beside it. Last, and
        #    behind explicit approval, because it runs whatever the repo says to.
        #    The tree is kept rather than discarded: tools like cloud_enum ship
        #    wordlists and mutation lists that a bare binary would lose.
        if sig.owner and sig.repo:
            add("clone-venv", f"git clone {rec.source_url} && pip install -r requirements.txt",
                rec.source_url, "clone the repository and install its requirements",
                binary=name)
        return plan

    # Which rung a command belongs to, and what it installs. The verb already
    # passed validate_install, so this is classification rather than parsing.
    @staticmethod
    def _kind_of(cmd: str) -> str:
        head = (cmd or "").strip().lower()
        if head.startswith(("apt install", "apt-get install")):
            return "apt"
        if head.startswith(("pipx install", "pip install", "pip3 install")):
            return "pipx"
        if head.startswith(("go install", "go get")):
            return "go-install"
        if head.startswith("git clone"):
            return "clone-venv"
        return ""

    @staticmethod
    def _pkg_of(cmd: str) -> str:
        parts = (cmd or "").split()
        for i, tok in enumerate(parts):
            if tok in ("install", "get") and i + 1 < len(parts):
                rest = [p for p in parts[i + 1:] if not p.startswith("-")]
                return rest[0] if rest else ""
        return ""

    def _tool_dir(self, rec: ToolRecord) -> str:
        """Where a cloned tool lives. One directory per tool, under the prefix."""
        return f"{N.tools_dir()}/{rec.id}"

    def _adopt(self, rec: ToolRecord, cand: Candidate) -> None:
        rec.strategy = cand.kind
        rec.install_cmd, rec.install_pkg = cand.install_cmd, cand.pkg
        self._log(rec, f"  recipe: {cand.note}\n")
        rec.save()

    # -- Acquire -------------------------------------------
    async def acquire(self, rec: ToolRecord) -> None:
        try:
            have = await N.preflight()
        except N.InstallError as exc:
            raise SetupFailed(str(exc)) from exc
        self._log(rec, f"install methods available: {have}\n")

        plan = list(self._plan.pop(rec.id, []))
        failures: list[str] = []

        for cand in plan:
            self._log(rec, f"\n=== trying: {cand.note} ===\n")
            self._adopt(rec, cand)
            rec.set_status("building", cand.note)
            bus.publish("status", rec.to_dict())
            try:
                await self._build(rec, cand)
                return
            except N.InstallError as exc:
                failures.append(f"{cand.note} — {exc}")
                self._log(rec, f"\n[failed] {cand.note}: {exc}\n")

        raise SetupFailed(
            "every install recipe failed: " + " | ".join(failures[-3:])
            if failures else "no install recipe could be derived for this repo")

    async def _build(self, rec: ToolRecord, cand: Candidate) -> None:
        """Install one candidate. Raises InstallError so the caller tries the next.

        There is deliberately no repair loop here. Measured across every tool
        added in development, the repair loop never rescued an install: it
        deleted its own earlier fixes, invented package versions that had never
        existed, and looped on identical answers — while every tool that
        actually installed did so through a deterministic rung, first try.
        Diagnosing a failure is a far harder job than writing a recipe from
        documentation, and a local model is not good at it. Falling through to
        the next recipe is both faster and more honest.
        """
        on_line = lambda text: self._log(rec, text)
        if cand.kind == "apt":
            # The one rung that does not execute code from the repository being
            # installed — apt runs maintainer scripts from a signed archive.
            await N.apt_install(cand.pkg, on_line)
        elif cand.kind == "pipx":
            await N.pipx_install(cand.pkg, on_line)
            await N.pipx_inject(cand.pkg, list(rec.install_inject), on_line)
        elif cand.kind == "go-install":
            await N.go_install(cand.pkg, on_line)
        elif cand.kind == "clone-venv":
            await N.clone_venv(f"{rec.source_url}.git", self._tool_dir(rec), on_line)
        else:
            raise SetupFailed(f"unknown strategy {cand.kind!r}")

    # -- 6. Verify -----------------------------------------------------
    async def verify(self, rec: ToolRecord) -> None:
        # Resolved, not assumed. apt writes to /usr/bin, go install and pipx to
        # penstation's own prefix, and knowing exactly which file runs is what
        # decides between two binaries that share a name.
        binary = rec.install_binary or rec.id
        path = await N.binary_path(binary)
        if not path:
            raise SetupFailed(
                f"installed, but no `{binary}` on PATH afterwards — the package "
                "may install a differently named command")
        rec.binary_path, rec.entrypoint = path, binary
        rec.save()
        self._log(rec, f"binary: {path}\n")

        # The tool's own --help, so run guidance is instant later — and its
        # version, which replaces pinning now that the box resolves it rather
        # than an image we built.
        self._log(rec, "capturing --help and --version…\n")
        rec.help_text, rec.version = await N.verify(path)
        rec.save()
        if rec.version:
            self._log(rec, f"version: {rec.version}\n")
        self._log(rec, f"help: {len(rec.help_text)} chars\n" if rec.help_text
                  else "help: none captured (run `<tool> --help` yourself to see usage)\n")

        # A baseline tool's command is declared, not inferred — it encodes how
        # the methodology uses the tool. Deriving one from --help replaced
        # nmap's `-iL {{input}}` with `-iR {{target}}`, which scans *random*
        # internet hosts.
        if rec.help_text and not rec.baseline:
            flag = G.target_flag(rec.help_text)
            binary = rec.entrypoint or rec.id
            if flag:
                better = f"{binary} {flag} {{{{target}}}}"
                if better != rec.run_template:
                    self._log(rec, f"  run hint from --help: {rec.run_template or '(none)'} "
                                   f"-> {better}\n")
                    rec.run_template = better
                    rec.save()
            elif rec.run_template == f"{binary} {{{{target}}}}":
                # We genuinely don't know the shape — say so rather than
                # presenting a fabricated command as if it were real.
                self._log(rec, "  no target flag documented; leaving the run hint "
                               "empty so it can't mislead\n")
                rec.run_template = ""
                rec.save()

        self._sig.pop(rec.id, None)
