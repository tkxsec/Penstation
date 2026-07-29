"""The setup pipeline: Inspect → Acquire → Verify.

Fully deterministic. Every install recipe is derived from what the repository
says about itself — a published image, its own Dockerfile, its documented
install command, its ecosystem's convention, or that same recipe on a base
image contemporary with its dependencies.

There was an LLM stage here that wrote and repaired Dockerfiles. It was removed:
across every tool added in development, each one that installed did so through a
deterministic rung, while the model produced broken recipes (a Dockerfile that
never cloned the repo) and repair loops that thrashed without ever rescuing a
build. Fixing the *environment* — era-matched base images, C-extension headers —
solved what the model could not, and did it in milliseconds instead of minutes.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass

from penstation.addtool import dockerops as D
from penstation.addtool import gather as G
from penstation.addtool import validate as V
from penstation.events import bus
from penstation.addtool.jobs import SetupFailed
from penstation.addtool.store import ToolRecord

@dataclass
class Candidate:
    """One way to install a tool. The pipeline tries these in order."""
    kind: str                    # docker-pull | docker-build | generated-dockerfile
    install_cmd: str
    dockerfile: str = ""         # empty for pull/build-from-git
    image: str = ""
    note: str = ""               # human-readable, shown in the log


class Pipeline:
    def __init__(self) -> None:
        self._sig: dict[str, G.Signals] = {}   # cached per tool, inspect -> acquire
        self._plan: dict[str, list[Candidate]] = {}   # recipes left to try

    # -- logging: persist + stream -------------------------------------
    def _log(self, rec: ToolRecord, text: str) -> None:
        rec.append_log(text)
        bus.publish("log", {"id": rec.id, "line": text})

    # -- 2. Inspect ----------------------------------------------------
    async def inspect(self, rec: ToolRecord) -> None:
        self._log(rec, f"$ inspect {rec.source_url}\n")
        try:
            sig = await asyncio.to_thread(G.gather, rec.source_url)
        except G.GatherError as exc:
            raise SetupFailed(str(exc)) from exc
        self._sig[rec.id] = sig

        eco, _ = sig.ecosystem()
        rec.resolved_ref = sig.commit
        rec.target_kind = G.target_kind(sig)
        self._log(rec, f"  repo={sig.owner}/{sig.repo} lang={sig.language or '?'} "
                       f"ecosystem={eco or '?'} dockerfile={sig.has_dockerfile} "
                       f"commit={sig.commit or '?'}\n")
        self._log(rec, f"  {G.quota_note()}\n")

        # Deterministic run template first; --help overrides it at verify.
        rec.run_template = G.extract_run(sig) or ""

        plan = self._plan_recipes(rec, sig)
        self._plan[rec.id] = plan
        if not plan:
            raise SetupFailed(
                "no published image, no Dockerfile, and no install command could "
                "be derived from this repository")
        self._log(rec, f"  {len(plan)} recipe(s) to try:\n")
        for i, cand in enumerate(plan, 1):
            self._log(rec, f"    {i}. {cand.note}\n")
        rec.tried = [c.note for c in plan]
        if plan:
            self._adopt(rec, plan[0])

        if not rec.run_template:
            rec.run_template = f"{sig.repo.lower()} {{{{target}}}}"
        self._log(rec, f"  run_template: {rec.run_template}\n")
        rec.save()

    def _plan_recipes(self, rec: ToolRecord, sig: G.Signals) -> list[Candidate]:
        """Every deterministic way we know to install this repo, best first.

        A *list*, not a single choice. Committing to one strategy at inspect
        time was the root cause of tools dying on their first setback: each new
        repo tripped over a different missing escalation edge. Anything that
        fails here simply hands off to the next entry.
        """
        plan: list[Candidate] = []

        # Anything you supplied by hand goes first: you looked at the failure
        # and told us what the repo actually needs, which beats every guess
        # below it. Still validated — a pasted recipe gets the same gate.
        if rec.manual_dockerfile:
            check = V.validate_dockerfile(rec.manual_dockerfile)
            if check:
                plan.append(Candidate(
                    "generated-dockerfile", rec.manual_install or "(your Dockerfile)",
                    dockerfile=rec.manual_dockerfile, image=f"penstation/{rec.id}",
                    note="the Dockerfile you provided"))
            else:
                self._log(rec, f"  [rejected] your Dockerfile: {check.reason}\n")
        elif rec.manual_install:
            check = V.validate_install(rec.manual_install)
            df = G.generate_dockerfile(sig, rec.manual_install) if check else None
            if df:
                plan.append(Candidate(
                    "generated-dockerfile", rec.manual_install, dockerfile=df,
                    image=f"penstation/{rec.id}",
                    note=f"your install command ({rec.manual_install})"))
            elif not check:
                self._log(rec, f"  [rejected] your command: {check.reason}\n")
            else:
                self._log(rec, "  [rejected] your command: can't tell which "
                               "ecosystem this repo uses, so there's no template "
                               "to wrap it in — paste a full Dockerfile instead\n")

        image = G.find_published_image(sig)
        if image and V.validate_install(f"docker pull {image}", sig.owner, sig.repo):
            plan.append(Candidate("docker-pull", f"docker pull {image}",
                                  image=image,
                                  note=f"published image documented by the repo ({image})"))

        if sig.has_dockerfile:
            plan.append(Candidate(
                "docker-build", f"docker build -t penstation/{rec.id} {sig.repo_url}.git",
                note="the repo's own Dockerfile"))

        # Both the README's command and the ecosystem convention are worth
        # trying — the README is more authoritative, the convention more likely
        # to still work on a repo whose docs have bit-rotted.
        extracted = G.extract_install(sig)
        if extracted:
            normalized = G.normalize_install(sig, extracted)
            if normalized != extracted:
                self._log(rec, f"  normalized: {extracted}  ->  {normalized}\n")
                extracted = normalized

        for cmd, why in ((extracted, "the README's install command"),
                         (G.canonical_install(sig), f"the {sig.ecosystem()[0]} convention")):
            if not cmd:
                continue
            check = V.validate_install(cmd, sig.owner, sig.repo)
            if not check:
                self._log(rec, f"  [rejected] {cmd}: {check.reason}\n")
                continue
            df = G.generate_dockerfile(sig, cmd)
            if df and not any(c.dockerfile == df for c in plan):
                plan.append(Candidate("generated-dockerfile", cmd, dockerfile=df,
                                      image=f"penstation/{rec.id}",
                                      note=f"a Dockerfile generated from {why}"))

        # Last deterministic rung: the same recipe on a base image contemporary
        # with the repo. An old repo's dependencies were resolved against an old
        # toolchain, and today's manufactures failures the authors never had —
        # GitGot needs no fixes at all on python:3.9 and cannot build on 3.14.
        # Tried *after* the modern build, since old images carry old CVEs.
        era = G.era_base(sig)
        if era:
            for cmd in (extracted, G.canonical_install(sig)):
                if not cmd or not V.validate_install(cmd, sig.owner, sig.repo):
                    continue
                df = G.generate_dockerfile(sig, cmd, base_override=era)
                if df and not any(c.dockerfile == df for c in plan):
                    plan.append(Candidate(
                        "generated-dockerfile", cmd, dockerfile=df,
                        image=f"penstation/{rec.id}",
                        note=f"the same recipe on {era}, contemporary with the "
                             f"dependencies (last changed {sig.deps_dated or sig.committed})"))
                    break
        return plan

    def _adopt(self, rec: ToolRecord, cand: Candidate) -> None:
        rec.strategy = cand.kind
        rec.image = cand.image or f"penstation/{rec.id}"
        rec.install_cmd, rec.dockerfile = cand.install_cmd, cand.dockerfile
        self._log(rec, f"  recipe: {cand.note}\n")
        for line in cand.dockerfile.strip().splitlines():
            self._log(rec, f"    | {line}\n")
        rec.save()

    # -- Acquire -------------------------------------------
    async def acquire(self, rec: ToolRecord) -> None:
        try:
            version = await D.preflight()
        except D.DockerError as exc:
            raise SetupFailed(str(exc)) from exc
        self._log(rec, f"docker daemon {version}\n")

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
            except D.DockerError as exc:
                failures.append(f"{cand.note} — {exc}")
                self._log(rec, f"\n[failed] {cand.note}: {exc}\n")

        raise SetupFailed(
            "every install recipe failed: " + " | ".join(failures[-3:])
            if failures else "no install recipe could be derived for this repo")

    async def _build(self, rec: ToolRecord, cand: Candidate) -> None:
        """Build one candidate. Raises DockerError so the caller tries the next.

        There is deliberately no repair loop here. Measured across every tool
        added in development, the repair loop never rescued a build: it deleted
        its own earlier fixes, invented package versions that had never existed,
        and looped on identical answers — while every tool that actually
        installed did so through a deterministic rung or a Dockerfile the model
        wrote in one shot. Diagnosing a build failure is a far harder job than
        writing a recipe from documentation, and a local model is not good at
        it. Falling through to the next recipe is both faster and more honest.
        """
        on_line = lambda text: self._log(rec, text)
        if cand.kind == "docker-pull":
            await D.pull(rec.image, on_line)
        elif cand.kind == "docker-build":
            await D.build_from_git(rec.image, f"{rec.source_url}.git", on_line)
        elif cand.kind == "generated-dockerfile":
            await D.build_from_dockerfile(rec.image, rec.dockerfile, on_line)
        else:
            raise SetupFailed(f"unknown strategy {cand.kind!r}")

    # -- 6. Verify -----------------------------------------------------
    async def verify(self, rec: ToolRecord) -> None:
        if not await D.image_exists(rec.image):
            raise SetupFailed(f"image {rec.image} not present after acquire")
        entry = await D.entrypoint_of(rec.image)
        rec.argv_mode = "entrypoint" if entry else "argv"
        rec.entrypoint = os.path.basename(entry[0]) if entry else ""
        rec.save()
        self._log(rec, f"image present · entrypoint={entry or 'none'} "
                       f"· argv_mode={rec.argv_mode}\n")

        # Capture the tool's own --help now so run guidance is instant later.
        self._log(rec, "capturing --help for run guidance…\n")
        rec.help_text = await D.capture_help(rec.image)
        rec.save()
        self._log(rec, f"help: {len(rec.help_text)} chars\n" if rec.help_text
                  else "help: none captured (run `<tool> --help` yourself to see usage)\n")

        # --help documents flags authoritatively, so prefer it over the README
        # guess. Without this, a tool like bbot (which needs `-t`) yields a
        # bare `bbot {{target}}` hint that teaches the wrong invocation.
        if rec.help_text:
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
