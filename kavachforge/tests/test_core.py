"""Built-in unit tests (standard library only). Run: ./kavach selftest"""
from __future__ import annotations

import os
import tempfile
import unittest

from kavachforge import config, cwe, ingest, patcher, risk, util, verifier

ROOT = config.PROJECT_ROOT


class TestCWE(unittest.TestCase):
    def test_maps_asan_classes(self):
        self.assertEqual(cwe.classify("heap-buffer-overflow")["cwe"], "CWE-787")
        self.assertEqual(cwe.classify("heap-use-after-free")["cwe"], "CWE-416")
        self.assertEqual(cwe.classify("SEGV on unknown address")["cwe"], "CWE-476")
        self.assertEqual(cwe.classify("something-new")["severity"], "Unknown")

    def test_severity_rank_orders(self):
        self.assertGreater(cwe.severity_rank("Critical"), cwe.severity_rank("High"))


class TestIngest(unittest.TestCase):
    def test_diff_changed_lines(self):
        text = ("--- a/src/x.c\n+++ b/src/x.c\n@@ -10,2 +10,4 @@\n"
                " ctx\n+added1\n+added2\n ctx\n")
        got = ingest.changed_files_from_diff_text(text)
        self.assertEqual(got, {"src/x.c": [11, 12]})

    def test_sarif_alerts(self):
        p = os.path.join(ROOT, "targets", "recordcfg", "scan", "clang-tidy.sarif")
        alerts = ingest.alerts_from_sarif(p)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["file"], "src/recordcfg.c")
        self.assertEqual(alerts[0]["line"], 54)
        self.assertIn("memcpy", alerts[0]["rule"])


class TestRisk(unittest.TestCase):
    def test_ranks_parser_top_with_all_components(self):
        t = config.load_task("tinyimg")
        ledger = risk.analyze(t, util.read_text(t.harness))
        self.assertTrue(ledger)
        top = ledger[0]
        self.assertEqual(top["function"], "tinyimg_parse")
        self.assertEqual(top["score"], 10)   # 4 + 3 + 2 + 1
        self.assertTrue(any("changed in diff" in r for r in top["rationale"]))

    def test_clean_control_has_no_alert_component(self):
        t = config.load_task("cleanjson")
        ledger = risk.analyze(t, util.read_text(t.harness))
        self.assertFalse(any("static alert" in r for r in ledger[0]["rationale"]))


class TestSignature(unittest.TestCase):
    def _blob(self, pid, addr):
        return ("==%d==ERROR: AddressSanitizer: heap-buffer-overflow on address %s\n"
                "    #0 0x%x in memcpy sanitizer.inc:115\n"
                "    #1 0x%x in recordcfg_parse /abs/path/src/recordcfg.c:54:9\n"
                "    #2 0x%x in LLVMFuzzerTestOneInput harness/fuzz_recordcfg.c:6\n"
                % (pid, addr, pid * 7, pid * 11, pid * 13))

    def test_same_bug_different_addresses_dedups(self):
        a = self._blob(1234, "0x50400000032")
        b = self._blob(9876, "0x6040000000a1")
        fa = verifier._extract_frames(a, {"recordcfg.c"})
        fb = verifier._extract_frames(b, {"recordcfg.c"})
        self.assertEqual(verifier._signature("heap-buffer-overflow", fa),
                         verifier._signature("heap-buffer-overflow", fb))

    def test_different_line_is_different_signature(self):
        a = self._blob(1, "0x1").replace(":54:", ":60:")
        b = self._blob(1, "0x1")
        fa = verifier._extract_frames(a, {"recordcfg.c"})
        fb = verifier._extract_frames(b, {"recordcfg.c"})
        self.assertNotEqual(verifier._signature("heap-buffer-overflow", fa),
                            verifier._signature("heap-buffer-overflow", fb))


class TestPatchPolicy(unittest.TestCase):
    def setUp(self):
        self.t = config.load_task("recordcfg")

    def test_good_guard_passes(self):
        diff = ("--- a/src/recordcfg.c\n+++ b/src/recordcfg.c\n@@ -53,3 +53,4 @@\n"
                " x\n+        if (rec->length > RECORDCFG_VALUE_CAP) { free(rec); return RECORDCFG_ERR_ARG; }\n"
                " memcpy(rec->value, data + off, rec->length);\n y\n")
        self.assertIsNone(patcher.check_policy(self.t, diff))

    def test_out_of_scope_file_rejected(self):
        diff = ("--- a/tests/test_recordcfg.c\n+++ b/tests/test_recordcfg.c\n@@ -1,1 +1,2 @@\n"
                " x\n+if (a > b) return 0;\n")
        self.assertIn("out-of-scope", patcher.check_policy(self.t, diff))

    def test_sanitizer_tampering_rejected(self):
        diff = ("--- a/src/recordcfg.c\n+++ b/src/recordcfg.c\n@@ -1,1 +1,2 @@\n"
                " x\n+#pragma GCC diagnostic ignored \"-fsanitize\"\n+if (a > b) return 0;\n")
        self.assertIn("policy violation", patcher.check_policy(self.t, diff))

    def test_removal_only_rejected(self):
        diff = ("--- a/src/recordcfg.c\n+++ b/src/recordcfg.c\n@@ -54,1 +54,0 @@\n"
                "-        memcpy(rec->value, data + off, rec->length);\n")
        self.assertIsNotNone(patcher.check_policy(self.t, diff))


class TestHeuristicRepair(unittest.TestCase):
    def _finding(self, crash_file, func):
        return verifier.Finding(id="t", signature="s", asan_class="x", cwe="c",
                                cwe_name="n", severity="High", access="w",
                                crash_file=crash_file, crash_func=func)

    def test_synthesizes_memcpy_guard(self):
        t = config.load_task("recordcfg")
        pr = patcher.synth_patch(t, self._finding("recordcfg.c:54", "recordcfg_parse"))
        self.assertIsNotNone(pr)
        self.assertIn("rec->length > RECORDCFG_VALUE_CAP", pr.diff)
        self.assertIn("free(rec);", pr.diff)
        self.assertIsNone(patcher.check_policy(t, pr.diff))

    def test_synthesizes_loop_clamp(self):
        t = config.load_task("tinyimg")
        pr = patcher.synth_patch(t, self._finding("tinyimg.c:46", "tinyimg_parse"))
        self.assertIsNotNone(pr)
        self.assertIn("n_channels > TINYIMG_MAX_CHANNELS", pr.diff)
        self.assertIsNone(patcher.check_policy(t, pr.diff))

    def test_extract_diff_from_fenced_response(self):
        text = "Here you go:\n```diff\n--- a/x.c\n+++ b/x.c\n@@ -1 +1,2 @@\n x\n+y\n```\nDone."
        d = patcher._extract_diff(text)
        self.assertTrue(d.startswith("--- a/x.c"))
        self.assertIn("+y", d)


class TestUtil(unittest.TestCase):
    def test_hexdump_truncates(self):
        s = util.hexdump(bytes(range(256)) * 2, limit=32)
        self.assertIn("more bytes", s)

    def test_run_captures_exit(self):
        r = util.run(["sh", "-c", "echo hi; exit 3"])
        self.assertEqual(r.code, 3)
        self.assertIn("hi", r.out)


if __name__ == "__main__":
    unittest.main()


class TestLLMTransport(unittest.TestCase):
    """Response-shape parsing for each provider, with HTTP stubbed out."""

    def _client(self, provider):
        from kavachforge import llm
        d = tempfile.mkdtemp()
        c = llm.LLMClient(provider=provider, model="m", budget=2,
                          cache_dir=os.path.join(d, "c"), log_dir=os.path.join(d, "l"))
        return c

    def test_anthropic_shape(self):
        os.environ["ANTHROPIC_API_KEY"] = "test"
        c = self._client("anthropic")
        c._http = lambda url, h, p, timeout=60: {"content": [{"type": "text", "text": "A"},
                                                             {"type": "text", "text": "B"}]}
        self.assertEqual(c.complete("p", "s"), "AB")
        self.assertEqual(c.calls, 1)

    def test_openai_shape(self):
        os.environ["OPENAI_API_KEY"] = "test"
        c = self._client("openai")
        c._http = lambda url, h, p, timeout=60: {"choices": [{"message": {"content": "ok"}}]}
        self.assertEqual(c.complete("p", "s"), "ok")

    def test_budget_exhaustion_raises(self):
        from kavachforge import llm
        c = self._client("ollama")
        c._http = lambda url, h, p, timeout=60: {"message": {"content": "x"}}
        c.complete("p1", "s"); c.complete("p2", "s")
        with self.assertRaises(llm.LLMUnavailable):
            c.complete("p3", "s")

    def test_cache_hit_does_not_consume_budget(self):
        c = self._client("ollama")
        c._http = lambda url, h, p, timeout=60: {"message": {"content": "x"}}
        c.complete("same", "s"); c.complete("same", "s")
        self.assertEqual((c.calls, c.cached), (1, 1))

    def test_offline_always_unavailable(self):
        from kavachforge import llm
        c = self._client("offline")
        with self.assertRaises(llm.LLMUnavailable):
            c.complete("p", "s")

    def test_report_normalization_stable(self):
        a = patcher._normalize_report("==123==ERROR at 0xdeadbeef /home/u/x/src/t.c:5")
        b = patcher._normalize_report("==999==ERROR at 0x00c0ffee /tmp/q/src/t.c:5")
        self.assertEqual(a, b)


class TestSelfHealing(unittest.TestCase):
    """PoV -> regression test, read-overflow repair, CWE direction."""

    def test_cwe_read_direction(self):
        self.assertEqual(cwe.classify("heap-buffer-overflow", "Read 1B")["cwe"], "CWE-125")
        self.assertEqual(cwe.classify("heap-buffer-overflow", "Write 33B")["cwe"], "CWE-787")

    def test_short_body_seeds_present(self):
        from kavachforge import discovery
        t = config.load_task("cleanjson")
        seeds = discovery.synth_seeds(t)
        self.assertIn(b"CJSN\xff", seeds)

    def test_read_overflow_repair_restores_bound(self):
        """Delete the bounds check from the control target in a temp copy and
        confirm the heuristic brain re-synthesizes it (clamp semantics)."""
        import shutil
        t = config.load_task("cleanjson")
        tmp = tempfile.mkdtemp()
        shutil.copytree(t.root, os.path.join(tmp, "cleanjson"))
        src = os.path.join(tmp, "cleanjson", "src", "cleanjson.c")
        text = util.read_text(src).replace("        if (idx >= size) break;          /* bounds-checked: no overflow */\n", "")
        util.write_text(src, text)
        t2 = config.Task(**{**t.__dict__, "root": os.path.join(tmp, "cleanjson"),
                            "sources": [src], "patch_scope": [src]})
        line = next(i for i, l in enumerate(text.splitlines(), 1) if "sum += data[idx]" in l)
        f = verifier.Finding(id="t", signature="s", asan_class="heap-buffer-overflow",
                             cwe="CWE-125", cwe_name="n", severity="High", access="Read 1B",
                             crash_file="cleanjson.c:%d" % line, crash_func="cleanjson_parse")
        pr = patcher.synth_patch(t2, f)
        self.assertIsNotNone(pr)
        self.assertIn("+        if (idx >= size) break;", pr.diff)

    def test_regression_test_generation(self):
        from kavachforge import regress
        t = config.load_task("tinyimg")
        d = tempfile.mkdtemp()
        pov = os.path.join(d, "pov")
        with open(pov, "wb") as fh:
            fh.write(b"TIMG\x01\xff" + b"A" * 300)
        f = verifier.Finding(id="KV-T-001", signature="s", asan_class="x", cwe="CWE-787",
                             cwe_name="OOB", severity="High", access="Write 1B",
                             crash_file="tinyimg.c:46", crash_func="tinyimg_parse",
                             pov_path=pov, pov_sha256="ab" * 32, pov_size=306)
        p = regress.generate(t, f, d)
        s = util.read_text(p)
        self.assertIn("LLVMFuzzerTestOneInput(kPoV_KV_T_001", s)
        self.assertIn("0x54, 0x49, 0x4d, 0x47", s)   # "TIMG"


class TestNewFeatures(unittest.TestCase):
    def test_differential_kind(self):
        from kavachforge import differential as d
        self.assertEqual(d._kind("exit=0 rc=0 x=1", "CRASH"), "new fault")
        self.assertEqual(d._kind("exit=0 rc=0 x=1", "exit=0 rc=0 x=2"), "result changed")
        self.assertEqual(d._kind("exit=0 rc=0 x=1", "exit=0 rc=-1"), "accepted/rejected flipped")
        self.assertEqual(d._kind("exit=0 rc=-2", "exit=0 rc=-1"), "error code changed")

    def test_ensemble_variants_distinct(self):
        t = config.load_task("recordcfg")
        f = verifier.Finding(id="x", signature="s", asan_class="heap-buffer-overflow",
                             cwe="CWE-787", cwe_name="n", severity="Critical", access="Write 33B",
                             crash_file="recordcfg.c:54", crash_func="recordcfg_parse")
        vs = patcher.synth_variants(t, f)
        self.assertGreaterEqual(len(vs), 2)
        str=[v.strategy for v in vs]
        self.assertIn("use-site", [v.strategy for v in vs])
        # root-cause candidate should sit closer to the assignment than the use-site one
        bylabel = {v.strategy: v for v in vs}
        if "root-cause" in bylabel and "use-site" in bylabel:
            self.assertLessEqual(bylabel["root-cause"].distance, bylabel["use-site"].distance)

    def test_rank_prefers_verified_then_distance(self):
        a = patcher.PatchResult("", "", "h", 1, "", [], label="far", strategy="use-site", distance=9)
        b = patcher.PatchResult("", "", "h", 1, "", [], label="near", strategy="root-cause", distance=1)
        order = sorted([a, b], key=lambda p: patcher.rank_key(p, True))
        self.assertEqual(order[0].label, "near")
        order2 = sorted([a, b], key=lambda p: patcher.rank_key(p, p is b))  # only b verified
        self.assertEqual(order2[0].label, "near")

    def test_ci_rebase_patch(self):
        from kavachforge import ci
        diff = "--- a/src/x.c\n+++ b/src/x.c\n@@ -1 +1,2 @@\n a\n+b\n"
        r = ci._rebase_patch(diff, "targets/mylib")
        self.assertIn("--- a/targets/mylib/src/x.c", r)
        self.assertIn("+++ b/targets/mylib/src/x.c", r)

    def test_harness_analyze_ranks_buf_size(self):
        from kavachforge import harness
        src = os.path.join(ROOT, "targets", "urlparse", "src", "urlparse.c")
        es = harness.analyze(src)
        self.assertTrue(es)
        self.assertEqual(es[0].name, "urlparse")
        self.assertEqual(es[0].shape, "buf_size")

    def test_generator_program_runs(self):
        from kavachforge import discovery
        t = config.load_task("sigpkt")
        import tempfile
        seeds = discovery._run_generator_program(util.read_text(t.seed_generator),
                                                  tempfile.mkdtemp())
        self.assertTrue(any(s[:4] == b"SPK1" for s in seeds))
        # a generated seed must satisfy the parser's digest gate (first 9 bytes header)
        self.assertTrue(any(len(s) >= 9 for s in seeds))


class TestManifest(unittest.TestCase):
    def test_excludes_views_and_hashes_match(self):
        import hashlib
        from kavachforge import pipeline
        d = tempfile.mkdtemp()
        # immutable evidence + mutable views
        util.write_text(os.path.join(d, "crashes", "crash-abc"), "pov")
        util.write_text(os.path.join(d, "pr", "KV-1", "fix.patch"), "diff")
        util.write_text(os.path.join(d, "evidence.json"), '{"a":1}')
        util.write_text(os.path.join(d, "dashboard.html"), "<html>")
        util.write_text(os.path.join(d, "run.log"), "log")
        pipeline._write_manifest(d)
        import json
        man = json.load(open(os.path.join(d, "manifest.json")))
        paths = {e["path"] for e in man["files"]}
        self.assertIn(os.path.join("crashes", "crash-abc"), paths)
        self.assertIn(os.path.join("pr", "KV-1", "fix.patch"), paths)
        for excluded in ("evidence.json", "dashboard.html", "run.log", "manifest.json"):
            self.assertNotIn(excluded, paths)
        # every listed hash matches the file on disk
        for e in man["files"]:
            h = hashlib.sha256(open(os.path.join(d, e["path"]), "rb").read()).hexdigest()
            self.assertEqual(h, e["sha256"])


class TestRealWorldTarget(unittest.TestCase):
    def test_cjson_task_loads_and_ranks(self):
        t = config.load_task("cjson")
        self.assertTrue(t.sources and t.sources[0].endswith("cJSON.c"))
        ledger = risk.analyze(t, util.read_text(t.harness))
        self.assertTrue(ledger)  # finds fuzzable functions in real code

    def test_cjson_dictionary_nonempty(self):
        from kavachforge import discovery
        t = config.load_task("cjson")
        self.assertTrue(len(discovery.extract_dictionary(t)) > 0)

    def test_standalone_cov_flag_detected(self):
        from kavachforge import toolchain
        tc = toolchain.detect("standalone")
        # On clang/gcc with SanitizerCoverage, the engine is greybox-capable.
        self.assertIn(tc.engine, ("standalone", "libfuzzer"))
