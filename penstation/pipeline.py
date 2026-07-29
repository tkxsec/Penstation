"""The setup pipeline: Inspect → Acquire (+Repair) → Verify.

All build steps are now real. The LLM is optional throughout: deterministic
extraction runs first, and the model is consulted only when it comes up short
(step 4) or when a build fails (step 6). Everything the model produces is gated
by validate.py before it is executed.
"""
from __future__ import annotations

import asyncio
import os

from penstation import dockerops as D
from penstation import gather as G
from penstation import llm as L
from penstation import validate as V
from penstation.events import bus
from penstation.jobs import SetupFailed
from penstation.store import ToolRecord

MAX_REPAIR = 3   # bounded: a weak model must not loop forever


class Pipeline:
    def __init__(self, llm: L.LLMProvider | None = None) -> None:
        self.llm = llm or L.NullProvider()
        self._sig: dict[str, G.Signals] = {}   # cached per tool for the repair loop

    # -- logging: persist + stream -------------------------------------
    def _log(self, rec: ToolRecord, text: str) -> None:
        rec.append_log(text)
        bus.publish("log", {"id": rec.id, "line": text})

    def _llm_ready(self) -> bool:
        try:
            return self.llm.available()
        except Exception:
            return False

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

        await self._choose_strategy(rec, sig)

        result = V.validate_install(rec.install_cmd, sig.owner, sig.repo)
        self._log(rec, f"  install_cmd: {rec.install_cmd}\n")
        if not result:
            self._log(rec, f"  [rejected] {result.reason}\n")
            raise SetupFailed(f"install command rejected: {result.reason}")
        self._log(rec, "  install_cmd validated\n")

        if not rec.run_template:
            rec.run_template = f"{sig.repo.lower()} {{{{target}}}}"
        self._log(rec, f"  run_template: {rec.run_template}\n")
        rec.save()

    async def _choose_strategy(self, rec: ToolRecord, sig: G.Signals) -> None:
        """The ladder — first hit wins (docs/architecture.md)."""
        # Deterministic run template first; LLM only if it came up short.
        rec.run_template = G.extract_run(sig) or ""

        image = G.find_published_image(sig)
        if image:
            rec.strategy, rec.image = "docker-pull", image
            rec.install_cmd = f"docker pull {image}"
            self._log(rec, f"  ladder: published image documented by the repo ({image})\n")
            await self._maybe_reason(rec, sig, need_install=False)
            rec.save()
            return

        # A generated Dockerfile is prepared either way: for the docker-build
        # strategy it becomes the fallback if the repo's own build fails.
        extracted = G.extract_install(sig)
        if extracted:
            normalized = G.normalize_install(sig, extracted)
            if normalized != extracted:
                # Be explicit when we rewrite what the repo documented.
                self._log(rec, f"  normalized: {extracted}  ->  {normalized}\n")
                extracted = normalized
        generated = G.generate_dockerfile(sig, extracted) if extracted else None

        if sig.has_dockerfile:
            rec.strategy, rec.image = "docker-build", f"penstation/{rec.id}"
            rec.install_cmd = f"docker build -t {rec.image} {sig.repo_url}.git"
            self._log(rec, "  ladder: repo ships a Dockerfile\n")
            if generated and V.validate_install(extracted, sig.owner, sig.repo):
                rec.dockerfile, rec.alt_install_cmd = generated, extracted
                self._log(rec, "  (generated Dockerfile kept as a fallback)\n")
            await self._maybe_reason(rec, sig, need_install=False)
            rec.save()
            return

        if not extracted or not generated:
            # Deterministic extraction failed — this is where the LLM earns its place.
            await self._maybe_reason(rec, sig, need_install=True)
            if not rec.install_cmd:
                raise SetupFailed(
                    "no published image, no Dockerfile, and no install command found "
                    "in the README" + ("" if self._llm_ready() else
                                       " (no LLM configured to infer one)"))
            generated = G.generate_dockerfile(sig, rec.install_cmd)
            if not generated:
                raise SetupFailed(
                    f"found an install command but the ecosystem is unrecognized "
                    f"({sig.language or 'unknown'}) — can't generate a Dockerfile")
            extracted = rec.install_cmd

        rec.strategy, rec.image = "generated-dockerfile", f"penstation/{rec.id}"
        rec.install_cmd, rec.dockerfile = extracted, generated
        self._log(rec, "  ladder: generated a Dockerfile from the install command\n")
        for line in generated.strip().splitlines():
            self._log(rec, f"    | {line}\n")
        await self._maybe_reason(rec, sig, need_install=False)
        rec.save()

    # -- 4. LLM Reason stage (only fills gaps) -------------------------
    async def _maybe_reason(self, rec: ToolRecord, sig: G.Signals,
                            need_install: bool) -> None:
        need_run = not rec.run_template
        if not (need_install or need_run):
            return
        if not self._llm_ready():
            if need_run:
                self._log(rec, "  run template not documented; using a default "
                               "(editable at run time)\n")
            return

        self._log(rec, f"  asking {self.llm.name} to infer "
                       f"{'install command + ' if need_install else ''}run template…\n")
        try:
            spec = await asyncio.to_thread(
                L.reason_spec, self.llm, owner=sig.owner, repo=sig.repo,
                language=sig.language, files=sorted(sig.files), readme=sig.readme)
        except Exception as exc:
            self._log(rec, f"  LLM unavailable ({exc}); continuing deterministically\n")
            return
        rec.llm_attempts += 1

        if need_install:
            cand = (spec.get("install_cmd") or "").strip()
            check = V.validate_install(cand, sig.owner, sig.repo)
            self._log(rec, f"  LLM install_cmd: {cand}\n")
            if check:
                rec.install_cmd = cand
            else:
                self._log(rec, f"  [rejected] {check.reason}\n")

        if need_run:
            cand = (spec.get("run_template") or "").strip()
            self._log(rec, f"  LLM run_template: {cand}\n")
            if V.validate_run(cand):
                rec.run_template = cand
            else:
                self._log(rec, "  [rejected] falling back to a default run template\n")

        kind = (spec.get("target_kind") or "").strip()
        if kind in ("domain", "host", "ip", "url"):
            rec.target_kind = kind
        rec.save()

    # -- Acquire + 5. Repair -------------------------------------------
    async def acquire(self, rec: ToolRecord) -> None:
        try:
            version = await D.preflight()
        except D.DockerError as exc:
            raise SetupFailed(str(exc)) from exc
        self._log(rec, f"docker daemon {version}\n")

        on_line = lambda text: self._log(rec, text)
        attempt = 0
        while True:
            try:
                await self._acquire_once(rec, on_line)
                return
            except D.DockerError as exc:
                # Escalation 1 (deterministic): the repo's own Dockerfile failed
                # but we prepared a generated one — switch to it.
                if rec.strategy == "docker-build" and rec.dockerfile:
                    self._log(rec, f"\n[{exc}] repo Dockerfile failed — "
                                   "falling back to the generated Dockerfile\n")
                    rec.strategy = "generated-dockerfile"
                    rec.install_cmd = rec.alt_install_cmd or rec.install_cmd
                    rec.save()
                    bus.publish("status", rec.to_dict())
                    continue

                # Escalation 2 (LLM): repair the Dockerfile we authored. A fix
                # that fails validation consumes an attempt and we ask again —
                # a weak model gets more chances, but always bounded.
                if rec.strategy == "generated-dockerfile" and rec.dockerfile and self._llm_ready():
                    applied = False
                    while attempt < MAX_REPAIR and not applied:
                        attempt += 1
                        applied = await self._repair(rec, str(exc), attempt)
                    if applied:
                        continue

                raise SetupFailed(str(exc)) from exc

    async def _acquire_once(self, rec: ToolRecord, on_line) -> None:
        if rec.strategy == "docker-pull":
            await D.pull(rec.image, on_line)
        elif rec.strategy == "docker-build":
            await D.build_from_git(rec.image, f"{rec.source_url}.git", on_line)
        elif rec.strategy == "generated-dockerfile":
            await D.build_from_dockerfile(rec.image, rec.dockerfile, on_line)
        else:
            raise SetupFailed(f"unknown strategy {rec.strategy!r}")

    async def _repair(self, rec: ToolRecord, error: str, attempt: int) -> bool:
        """Ask the LLM to fix the Dockerfile. True if a validated fix was applied."""
        rec.set_status("repairing", f"LLM repair attempt {attempt}/{MAX_REPAIR}")
        bus.publish("status", rec.to_dict())
        sig = self._sig.get(rec.id)
        self._log(rec, f"\n--- repair attempt {attempt}/{MAX_REPAIR} "
                       f"({self.llm.name}) ---\n{error}\n")
        try:
            out = await asyncio.to_thread(
                L.repair_dockerfile, self.llm,
                dockerfile=rec.dockerfile, error_log=rec.read_log(tail=L.MAX_LOG_TAIL),
                owner=sig.owner if sig else "", repo=sig.repo if sig else rec.id,
                language=sig.language if sig else "")
        except Exception as exc:
            self._log(rec, f"  repair unavailable ({exc})\n")
            return False

        rec.llm_attempts += 1
        candidate = (out.get("dockerfile") or "").strip()
        self._log(rec, f"  diagnosis: {(out.get('explanation') or '').strip()[:200]}\n")
        check = V.validate_dockerfile(candidate)
        if not check:
            self._log(rec, f"  [rejected] {check.reason}\n")
            rec.save()
            return False
        if candidate == rec.dockerfile.strip():
            self._log(rec, "  [rejected] repair returned an unchanged Dockerfile\n")
            rec.save()
            return False

        rec.dockerfile = candidate + "\n"
        rec.save()
        self._log(rec, "  applying repaired Dockerfile:\n")
        for line in candidate.splitlines():
            self._log(rec, f"    | {line}\n")
        rec.set_status("building", f"rebuild after repair {attempt}")
        bus.publish("status", rec.to_dict())
        return True

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
