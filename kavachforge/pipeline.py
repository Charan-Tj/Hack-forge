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


class _Progress:
    """Tracks stage status and republishes the evidence bundle on change."""

    def __init__(self, task, tc, client, work_dir):
        self.task, self.tc, self.client, self.work_dir = task, tc, client, work_dir
        self.status = {k: "pending" for k, _ in STAGES}
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
                        for k, lbl in STAGES]
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
    """Tamper-evident listing: sha256 of every artifact in the bundle."""
    entries = []
    for dp, _, files in os.walk(work_dir):
        for name in sorted(files):
            if name in ("manifest.json", "_candidate"):
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
    man = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
           "files": entries}
    man["bundle_sha256"] = util.sha256_bytes(
        "\n".join(e["path"] + ":" + e["sha256"] for e in entries).encode())
    path = os.path.join(work_dir, "manifest.json")
    util.write_json(path, man)
    return man["bundle_sha256"]


def run_task(task_path: str, out_root: str = "artifacts",
             provider=None, model=None, budget: int = 6,
             engine_pref=None, keep_worktree: bool = False,
             uplift: bool = False, diff: Optional[str] = None,
             sarif: Optional[str] = None) -> Dict:
    task = config.load_task(task_path, diff_override=diff, sarif_override=sarif)
    work_dir = os.path.join(out_root, task.name)
    os.makedirs(work_dir, exist_ok=True)
    util.set_log_file(os.path.join(work_dir, "run.log"))
    util.reset_stage_counter()

    util.plain(util.bold("\nKavachForge — target: %s" % task.name))
    util.info(util.dim(task.description))

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
        seeds, seed_src = discovery.llm_seeds(task, client)
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

        # ---- Stage 5: patch + validate -------------------------------------
        P.set("repair", "running" if findings else "skipped")
        for idx, f in enumerate(findings):
            util.stage("Repair & verify — %s" % f.id)
            pr_res = patcher.propose(task, f, client, attempts=2)
            validation = {"status": "Unpatched", "gates": []}
            v = None
            if pr_res is None:
                util.warn("no patch could be synthesized")
            else:
                util.step("patch via %s (%d attempt(s))" % (pr_res.source, pr_res.attempts))
                for rej in pr_res.rejected:
                    util.step(util.dim("reflected: " + rej))
                v = validator.validate(task, tc, f, pr_res.diff, work_dir,
                                       keep=keep_worktree)
                validation = v.as_dict()
                for g in v.gates:
                    (util.good if g.passed else util.bad)("%s — %s" % (g.name, g.detail))
                if v.status == "Verified":
                    util.good(util.green("PATCH VERIFIED — builds, blocks PoV, tests pass"))
                    if v.regress is not None and v.regress.guards_bug:
                        util.good(util.green("REGRESSION TEST PROVEN — %s"
                                             % os.path.basename(v.regress.source_path)))
                else:
                    util.bad("patch rejected at an evidence gate")
            fd = _finding_dict(f, work_dir, pr_res, validation)
            if pr_res is not None and validation.get("status") == "Verified":
                rs = v.regress.source_path if v.regress is not None else None
                fd["pr_bundle"] = pr.build(task, f, fd["patch"], validation, rs,
                                           work_dir, __version__)
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
