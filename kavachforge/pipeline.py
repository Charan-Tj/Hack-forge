"""The KavachForge orchestrator: runs the closed loop for one task and
publishes the evidence bundle + dashboard incrementally after every stage,
so a live viewer can watch the gates turn green.

    diff/alerts -> risk ranking -> LLM seeds + fuzzing -> reproduce & dedup
    -> LLM patch (+reflection) -> build + PoV-replay + tests -> evidence
"""
from __future__ import annotations

import os
import time
import traceback
from typing import Dict, List, Optional

from . import (config, discovery, ingest, llm, patcher, pr, report, risk,
               toolchain, util, validator, verifier, __version__)

STAGES = [
    ("risk", "Risk prioritization"),
    ("build", "Build & seeds"),
    ("discover", "Hybrid discovery"),
    ("verify", "Reproduce & dedup"),
    ("repair", "Repair & verify"),
    ("evidence", "Evidence bundle"),
]


STAGES_UNIVERSAL = [
    ("risk", "Stack & surface"),
    ("discover", "Static discovery"),
    ("verify", "Triage & dedup"),
    ("repair", "Repair, approve & verify"),
    ("evidence", "Evidence bundle"),
]


class _Progress:
    """Tracks stage status and republishes the evidence bundle on change."""

    def __init__(self, task, tc, client, work_dir, stages=None):
        self.task, self.tc, self.client, self.work_dir = task, tc, client, work_dir
        self.stages = stages or STAGES
        self.status = {k: "pending" for k, _ in self.stages}
        self.ledger: List[Dict] = []
        self.disc_stats: Dict = {}
        self.findings: List[Dict] = []
        self.uplift: Optional[Dict] = None
        self.baseline = None
        self.t0 = time.time()
        self.first_pov = None
        self.run_status = "running"
        self.error = ""

    def set(self, key: str, state: str) -> None:
        self.status[key] = state
        self.publish()

    def evidence(self) -> Dict:
        n_verified = sum(1 for f in self.findings
                         if f["validation"]["status"] == "Verified")
        metrics = {
            "unique_findings": len(self.findings),
            "verified_patches": n_verified,
            "unverified_alerts_reported": 0,
            "raw_crashes": self.disc_stats.get("raw_crashes", 0),
            "time_to_first_pov": self.first_pov or "n/a",
            "baseline_tests_pass": (self.baseline.passed if self.baseline else None),
            "total_seconds": round(time.time() - self.t0, 2),
            "llm_budget": self.client.budget,
        }
        ev = report.build_evidence(
            self.task, self.tc.note, self.client.describe(), self.ledger,
            self.disc_stats, self.findings, metrics,
            {"live": self.client.calls, "cached": self.client.cached,
             "budget": self.client.budget})
        ev["stages"] = [{"key": k, "label": lbl, "status": self.status[k]}
                        for k, lbl in self.stages]
        ev["run_status"] = self.run_status
        ev["error"] = self.error
        ev["uplift"] = self.uplift
        ev["ingestion"] = {
            "diff_source": self.task.diff_source,
            "changed_files": self.task.diff_changed,
            "sarif_source": self.task.sarif_source or "none",
            "alerts": len(self.task.static_alerts),
        }
        ev["revision"] = int(time.time() * 1000)
        return ev

    def publish(self) -> Dict[str, str]:
        return report.write_reports(self.evidence(), self.work_dir)


def _finding_dict(f: "verifier.Finding", work_dir: str, pr, validation) -> Dict:
    with open(f.pov_path, "rb") as fh:
        pov_bytes = fh.read()
    patch_entry = {}
    if pr is not None:
        patch_entry = {"diff": pr.diff, "rel_path": pr.rel_path,
                       "source": pr.source, "attempts": pr.attempts,
                       "rationale": pr.rationale, "rejected": pr.rejected}
    return {
        "id": f.id, "signature": f.signature, "asan_class": f.asan_class,
        "cwe": f.cwe, "cwe_name": f.cwe_name, "severity": f.severity,
        "access": f.access, "crash_file": f.crash_file, "crash_func": f.crash_func,
        "frames": f.frames, "duplicates": f.duplicates,
        "pov_file": os.path.relpath(f.pov_path, work_dir),
        "pov_sha256": f.pov_sha256, "pov_size": f.pov_size,
        "pov_hexdump": util.hexdump(pov_bytes, 128),
        "repro_cmd": f.repro_cmd, "asan_report": f.asan_report,
        "patch": patch_entry, "validation": validation,
    }


def _write_manifest(work_dir: str) -> str:
    """Tamper-evident listing: sha256 of every immutable evidence artifact
    (PoV inputs, crashes, corpus, patches, regression tests, prompt log).

    The generated *views* (evidence.json, dashboard.html) and the run log are
    excluded: they are rewritten after the manifest is computed (the dashboard
    displays the bundle hash, which would otherwise be a cycle), so hashing
    them would always mismatch. The manifest attests the evidence, not the
    report rendered from it."""
    EXCLUDE = {"manifest.json", "evidence.json", "dashboard.html", "run.log",
               "_candidate", "index.html", ".showcase.json"}
    entries = []
    for dp, _, files in os.walk(work_dir):
        # skip transient fuzzing/diff scratch dirs
        rel_dir = os.path.relpath(dp, work_dir)
        if rel_dir.split(os.sep)[0] in ("diffcorpus", "uplift", "gen"):
            continue
        for name in sorted(files):
            if name in EXCLUDE:
                continue
            p = os.path.join(dp, name)
            if os.path.islink(p):
                continue
            try:
                entries.append({"path": os.path.relpath(p, work_dir),
                                "sha256": util.sha256_file(p),
                                "bytes": os.path.getsize(p)})
            except OSError:
                pass
    entries.sort(key=lambda e: e["path"])
    man = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
           "attests": "immutable evidence inputs (PoV, crashes, corpus, patches, "
                      "regression tests, prompt log); excludes generated views and logs",
           "files": entries}
    man["bundle_sha256"] = util.sha256_bytes(
        "\n".join(e["path"] + ":" + e["sha256"] for e in entries).encode())
    path = os.path.join(work_dir, "manifest.json")
    util.write_json(path, man)
    return man["bundle_sha256"]


class _NoToolchain:
    note = "static analysis (no compiler needed)"


def run_universal(task, work_dir: str, client, approve: str = "critical",
                  interactive: bool = True, scanner: str = "auto", max_findings: int = 12,
                  deps: bool = False, review: bool = True, deadline_min: float = 0,
                  precision: str = "balanced") -> Dict:
    """Any-stack track: static discovery -> repair ensemble -> approval -> gates."""
    from . import universal
    P = _Progress(task, _NoToolchain(), client, work_dir, stages=STAGES_UNIVERSAL)
    util.info("track     : universal (static analysis + model repair + test/rescan gates)")
    util.info("model     : %s" % client.describe())
    deadline = (time.time() + deadline_min * 60) if deadline_min else None
    if deadline:
        util.info("deadline  : %.0f min — no new finding or model call after that; report always written" % deadline_min)
    P.publish()
    try:
        P.set("risk", "running")
        res = universal.run(task, client, work_dir, approve=approve, interactive=interactive,
                            scanner=scanner, max_findings=max_findings, publish=P.publish, progress=P,
                            deps=deps, review=review, deadline=deadline, precision=precision)
        P.ledger = res["risk_ledger"]
        P.disc_stats = res["discovery"]
        P.findings = res["findings"]
        P.first_pov = res["metrics"]["time_to_first_pov"]
        for k in ("risk", "discover", "verify", "repair"):
            P.status[k] = "done"
        util.stage("Evidence bundle")
        P.set("evidence", "running")
        P.run_status = "done"
        P.set("evidence", "done")
        bundle_sha = _write_manifest(work_dir)
        paths = P.publish()
        m = res["metrics"]
        util.good("findings: %d   verified patches: %d   skipped by reviewer: %d"
                  % (m["unique_findings"], m["verified_patches"], m["skipped_by_reviewer"]))
        util.good("evidence : %s" % paths["json"])
        util.good("dashboard: %s" % paths["html"])
        util.good("manifest : bundle sha256 %s" % bundle_sha[:16])
        util.info(util.dim("total %.1fs | LLM live calls %d / budget %d"
                           % (time.time() - P.t0, client.calls, client.budget)))
        ev = P.evidence()
        ev["metrics"].update(m)
        sub = report.write_submission(ev, work_dir)
        util.good("report   : %s (%d row(s)) + report.csv" % (sub["md"], sub["rows"]))
        return {"evidence": ev, "paths": paths, "metrics": ev["metrics"]}
    except (Exception, KeyboardInterrupt) as e:
        P.run_status = "error"
        P.error = "%s: %s" % (type(e).__name__, e)
        util.bad(P.error)
        if not isinstance(e, KeyboardInterrupt):
            util.plain(util.dim(traceback.format_exc()[-600:]))
        # whatever happened, the judges get a report of what was finished
        try:
            paths = P.publish()
            sub = report.write_submission(P.evidence(), work_dir)
            util.warn("partial report written: %s (%d row(s))" % (sub["md"], sub["rows"]))
        except Exception:
            pass
        raise
    finally:
        util.set_log_file(None)


def run_task(task_path: str, out_root: str = "artifacts",
             provider=None, model=None, budget: int = 6,
             engine_pref=None, keep_worktree: bool = False,
             uplift: bool = False, diff: Optional[str] = None,
             sarif: Optional[str] = None, approve: str = "critical",
             interactive: bool = True, scanner: str = "auto",
             max_findings: int = 12, deps: bool = False, review: bool = True,
             deadline_min: float = 0, precision: str = "balanced") -> Dict:
    task = config.load_task(task_path, diff_override=diff, sarif_override=sarif)
    work_dir = os.path.join(out_root, task.name)
    os.makedirs(work_dir, exist_ok=True)
    util.set_log_file(os.path.join(work_dir, "run.log"))
    util.reset_stage_counter()

    util.plain(util.bold("\nKavachForge — target: %s" % task.name))
    util.info(util.dim(task.description))

    if task.kind == "universal":
        client = llm.LLMClient(provider=provider, model=model, budget=budget,
                               cache_dir="cache/llm", log_dir=os.path.join(work_dir, "llm_log"))
        if client.provider == "ollama" and budget <= 6:
            client.budget = 40          # a local model is free: review + repair need more than 6 calls
        return run_universal(task, work_dir, client, approve=approve, interactive=interactive,
                             scanner=scanner, max_findings=max_findings, deps=deps, review=review,
                             deadline_min=deadline_min, precision=precision)

    tc = toolchain.detect(engine_pref)
    client = llm.LLMClient(provider=provider, model=model, budget=budget,
                           cache_dir="cache/llm",
                           log_dir=os.path.join(work_dir, "llm_log"))
    util.info("toolchain : %s" % tc.note)
    util.info("model     : %s" % client.describe())
    util.info("signals   : %s" % ingest.summarize_sources(
        task.diff_source, len(task.diff_changed),
        task.sarif_source or ("task" if task.static_alerts else "none"),
        len(task.static_alerts)))

    P = _Progress(task, tc, client, work_dir)
    P.publish()

    try:
        # ---- Stage 1: risk -------------------------------------------------
        util.stage("Risk prioritization (diff → sink)")
        P.set("risk", "running")
        harness_text = util.read_text(task.harness)
        P.ledger = risk.analyze(task, harness_text)
        for r in P.ledger[:5]:
            util.step("score %d  %s  (%s:%d)  %s"
                      % (r["score"], r["function"], r["file"], r["line"],
                         ", ".join(r["sinks"]) or "-"))
        if P.ledger:
            util.good("ranked %d function(s); top = %s (score %d)"
                      % (len(P.ledger), P.ledger[0]["function"], P.ledger[0]["score"]))
        P.set("risk", "done")

        # ---- Stage 2: build + seeds ----------------------------------------
        util.stage("Build target & generate seeds")
        P.set("build", "running")
        try:
            fuzzer_bin = discovery.build_fuzzer(task, tc, work_dir)
        except discovery.BuildError as e:
            util.bad("target failed to build")
            util.plain(e.log[-800:])
            raise
        util.good("built discovery binary (%s engine)" % tc.engine)
        gen_seeds, gen_src = discovery.generator_seeds(task, client, work_dir)
        byte_seeds, seed_src = discovery.llm_seeds(task, client)
        seeds = gen_seeds + byte_seeds
        if gen_seeds:
            util.good("%d generator seeds (%s) + %d byte seeds (%s); gate: %s"
                      % (len(gen_seeds), gen_src, len(byte_seeds), seed_src, task.magic or "none"))
            seed_src = gen_src
        else:
            util.good("%d seeds ready (%s); magic gate: %s"
                      % (len(seeds), seed_src, task.magic or "none"))
        P.disc_stats = {"engine": tc.engine, "seed_source": seed_src,
                        "seeds": len(seeds)}
        P.set("build", "done")

        # ---- Stage 3: discovery --------------------------------------------
        util.stage("Hybrid discovery (seeds + fuzzing)")
        P.set("discover", "running")
        disc = discovery.run(task, tc, fuzzer_bin, seeds, work_dir)
        st = disc["stats"]
        st["seed_source"] = seed_src
        st["seeds"] = len(seeds)
        P.disc_stats = st
        if disc["crashes"]:
            P.first_pov = "%.1fs" % (st.get("first_crash_s") or st["seconds"])
            util.good("first crash via %s after %s; harvested %d raw crash(es), "
                      "%s execs" % (st["engine"], P.first_pov, st["raw_crashes"],
                                    "{:,}".format(st["execs"])))
        else:
            util.warn("no crash within budget (%ds, %s execs) — clean target?"
                      % (st["seconds"], "{:,}".format(st["execs"])))
        if uplift:
            util.step("measuring seed uplift (empty-corpus A/B)...")
            P.uplift = discovery.measure_uplift(task, tc, fuzzer_bin, work_dir)
            u = P.uplift
            util.info("uplift: seeded=%s  unseeded=%s  (%s)"
                      % (P.first_pov or "none",
                         ("%.1fs" % u["first_crash_s"]) if u["first_crash_s"] else
                         "none in %ds" % u["budget_s"], u["note"]))
        P.set("discover", "done")

        # ---- Stage 4: verify + dedup ---------------------------------------
        util.stage("Reproduce, deduplicate & classify")
        P.set("verify", "running")
        findings = verifier.verify(task, fuzzer_bin, disc["crashes"])
        for f in findings:
            util.good("%s  %s (%s, %s)  at %s  [%d duplicate(s) collapsed]"
                      % (f.id, f.cwe, f.cwe_name, f.severity, f.crash_file,
                         f.duplicates))
        if not findings:
            util.info("no reproducible finding to report")
        # publish findings immediately (unpatched) so the dashboard shows them
        P.findings = [_finding_dict(f, work_dir, None,
                                    {"status": "Unpatched", "gates": []})
                      for f in findings]
        P.set("verify", "done")

        # ---- Stage 5: patch ensemble + validate + rank --------------------
        P.set("repair", "running" if findings else "skipped")
        for idx, f in enumerate(findings):
            util.stage("Repair ensemble & verify \u2014 %s" % f.id)
            cands = patcher.propose_ensemble(task, f, client, attempts=2)
            if not cands:
                util.warn("no patch candidates could be synthesized")
                P.findings[idx] = _finding_dict(f, work_dir, None,
                                                {"status": "Unpatched", "gates": []})
                P.publish()
                continue
            util.step("%d candidate(s): %s" % (len(cands), "; ".join(c.label for c in cands)))
            for rej in (cands[0].rejected or []):
                util.step(util.dim("reflected: " + rej))

            # Phase 1: executable gates G0-G4 on every candidate (fast).
            results = []
            for c in cands:
                v = validator.validate(task, tc, f, c.diff, work_dir,
                                       keep=keep_worktree, with_g5=False)
                results.append((c, v))
                failed = next((g.name for g in v.gates if not g.passed), None)
                util.step("%-38s %s" % (c.label, util.green("G0-G4 pass") if v.status == "Verified"
                                        else util.red("rejected at " + str(failed))))
            # Phase 2: rank survivors by root-cause proximity; prove the top
            # one with G5 (behaviour preservation), falling through on failure.
            ranked = sorted(results, key=lambda cv: patcher.rank_key(cv[0], cv[1].status == "Verified"))
            winner = None
            final_v = None
            cand_rows = []
            for rank, (c, v) in enumerate(ranked, 1):
                row = {"rank": rank, "label": c.label, "strategy": c.strategy,
                       "source": c.source, "guard_line": c.guard_line,
                       "root_cause_line": c.root_cause_line, "distance": c.distance,
                       "added_lines": c.added_lines, "status": v.status,
                       "gates": v.as_dict()["gates"], "chosen": False, "diff": c.diff}
                if winner is None and v.status == "Verified":
                    v5 = validator.validate(task, tc, f, c.diff, work_dir,
                                            keep=keep_worktree, with_g5=True)
                    row["gates"] = v5.as_dict()["gates"]
                    row["status"] = v5.status
                    g5 = next((g for g in v5.gates if g.name.startswith("G5")), None)
                    if v5.status == "Verified":
                        winner, final_v = c, v5
                        row["chosen"] = True
                        util.good("#%d %s \u2014 G5 %s" % (rank, c.label, g5.detail if g5 else ""))
                    else:
                        util.bad("#%d %s \u2014 G5 rejected: %s" % (rank, c.label, g5.detail if g5 else ""))
                cand_rows.append(row)

            if winner is None:
                util.bad("no candidate survived all gates")
                best_c, best_v = ranked[0]
                fd = _finding_dict(f, work_dir, best_c, best_v.as_dict())
                fd["validation"]["status"] = "Rejected"
                fd["candidates"] = cand_rows
                P.findings[idx] = fd
                P.publish()
                continue

            validation = final_v.as_dict()
            for g in final_v.gates:
                (util.good if g.passed else util.bad)("%s \u2014 %s" % (g.name, g.detail))
            util.good(util.green("PATCH VERIFIED \u2014 chose #%d '%s' (guard %d line(s) from root cause)"
                                 % (next(r["rank"] for r in cand_rows if r["chosen"]), winner.label,
                                    winner.distance)))
            if final_v.regress is not None and final_v.regress.guards_bug:
                util.good(util.green("REGRESSION TEST PROVEN \u2014 %s"
                                     % os.path.basename(final_v.regress.source_path)))
            fd = _finding_dict(f, work_dir, winner, validation)
            fd["candidates"] = cand_rows
            rs = final_v.regress.source_path if final_v.regress is not None else None
            fd["pr_bundle"] = pr.build(task, f, fd["patch"], validation, rs, work_dir, __version__)
            util.good("PR bundle: %s" % fd["pr_bundle"]["dir"])
            P.findings[idx] = fd
            P.publish()
        if findings:
            P.set("repair", "done")

        # ---- baseline + evidence -------------------------------------------
        util.stage("Evidence bundle")
        P.set("evidence", "running")
        P.baseline = validator.baseline_tests(task, tc, work_dir)
        P.run_status = "done"
        P.set("evidence", "done")
        bundle_sha = _write_manifest(work_dir)
        paths = P.publish()
        n_verified = sum(1 for f in P.findings
                         if f["validation"]["status"] == "Verified")
        util.good("findings: %d   verified patches: %d   unverified alerts: 0"
                  % (len(P.findings), n_verified))
        util.good("baseline regression tests: %s"
                  % ("PASS" if P.baseline.passed else "FAIL"))
        util.good("evidence : %s" % paths["json"])
        util.good("dashboard: %s" % paths["html"])
        util.good("manifest : bundle sha256 %s" % bundle_sha[:16])
        util.info(util.dim("total %.1fs | LLM live calls %d / budget %d"
                           % (time.time() - P.t0, client.calls, client.budget)))
        return {"evidence": P.evidence(), "paths": paths,
                "metrics": P.evidence()["metrics"]}
    except Exception as e:
        P.run_status = "error"
        P.error = "%s: %s" % (type(e).__name__, e)
        util.bad(P.error)
        util.plain(util.dim(traceback.format_exc()[-600:]))
        P.publish()
        raise
    finally:
        util.set_log_file(None)
