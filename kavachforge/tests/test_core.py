"""Built-in unit tests (standard library only). Run: ./kavach selftest"""
from __future__ import annotations

import os
import sys
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
        r = util.run([sys.executable, "-c", "print('hi'); raise SystemExit(3)"])
        self.assertEqual(r.code, 3)
        self.assertIn("hi", r.out)


class TestUniversalPatchPortability(unittest.TestCase):
    def test_python_applier_lf(self):
        from kavachforge import universal as u
        root = tempfile.mkdtemp()
        path = os.path.join(root, "app.js")
        util.write_text(path, "one\ntwo\nthree\n")
        diff = "--- a/app.js\n+++ b/app.js\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n"
        u._apply_unified_python(root, diff)
        self.assertEqual(util.read_text(path), "one\nTWO\nthree\n")

    def test_python_applier_preserves_crlf(self):
        from kavachforge import universal as u
        root = tempfile.mkdtemp()
        path = os.path.join(root, "app.js")
        util.write_text(path, "one\r\ntwo\r\nthree\r\n")
        diff = "--- a/app.js\n+++ b/app.js\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n"
        u._apply_unified_python(root, diff)
        self.assertEqual(util.read_text(path), "one\r\nTWO\r\nthree\r\n")

    def test_python_applier_rejects_traversal(self):
        from kavachforge import universal as u
        root = tempfile.mkdtemp()
        diff = "--- a/../escape.txt\n+++ b/../escape.txt\n@@ -0,0 +1 @@\n+nope\n"
        with self.assertRaises(ValueError):
            u._apply_unified_python(root, diff)

    def test_python_applier_rejects_mismatched_hunk(self):
        from kavachforge import universal as u
        root = tempfile.mkdtemp()
        util.write_text(os.path.join(root, "app.js"), "one\ntwo\n")
        diff = "--- a/app.js\n+++ b/app.js\n@@ -1,2 +1,2 @@\n one\n-wrong\n+right\n"
        with self.assertRaisesRegex(ValueError, "does not match"):
            u._apply_unified_python(root, diff)

    def test_unified_headers_use_forward_slashes(self):
        from kavachforge import universal as u
        diff = u._unified("app\\nested\\app.js", "one\n", "two\n")
        self.assertIn("--- a/app/nested/app.js\n", diff)
        self.assertIn("+++ b/app/nested/app.js\n", diff)


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
        try:
            tc = toolchain.detect("standalone")
        except RuntimeError as exc:
            self.skipTest("native sanitizer toolchain unavailable: %s" % exc)
        # On clang/gcc with SanitizerCoverage, the engine is greybox-capable.
        self.assertIn(tc.engine, ("standalone", "libfuzzer"))


class TestOnboard(unittest.TestCase):
    """Bring-your-own-repo onboarding: scanning, header-only libraries, the
    mixed C/C++ build command, entry-point ranking and the heuristic brain's
    typed bail-outs - all offline, on synthetic repos."""

    def _repo(self):
        root = tempfile.mkdtemp(prefix="kv_onb_t_")
        os.makedirs(os.path.join(root, "src")); os.makedirs(os.path.join(root, "tests"))
        os.makedirs(os.path.join(root, "fuzz"))
        util.write_text(os.path.join(root, "src", "lib.h"),
                        "#include <stddef.h>\nint lib_parse(const char *s, size_t n);\n")
        util.write_text(os.path.join(root, "src", "lib.c"),
                        '#include "lib.h"\nint lib_parse(const char *s, size_t n){return n>0&&s[0]==\'x\';}\n'
                        "static int helper(const char *p, size_t n){return 0;}\n"
                        "#ifdef LIB_TEST_MAIN\nint main(void){return 0;}\n#endif\n")
        util.write_text(os.path.join(root, "tests", "test_lib.c"), "int main(void){return 0;}\n")
        util.write_text(os.path.join(root, "fuzz", "fuzz_lib.c"),
                        '#include <stdint.h>\n#include <stddef.h>\n#include "lib.h"\n'
                        "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){lib_parse((const char*)d,n);return 0;}\n")
        return root

    def test_scan_classifies_files(self):
        from kavachforge import onboard
        info = onboard.scan(self._repo())
        self.assertEqual(info["sources"], ["src/lib.c"])          # ifdef'd main stays a library file
        self.assertEqual(info["harnesses"], ["fuzz/fuzz_lib.c"])
        self.assertIn("tests/test_lib.c", info["skipped"])
        self.assertIn("src", info["include_dirs"])

    def test_header_only_translation_unit(self):
        from kavachforge import onboard
        root = tempfile.mkdtemp(prefix="kv_onb_h_")
        util.write_text(os.path.join(root, "tiny.h"),
                        "#ifndef TINY_H\n#define TINY_H\n" + "/* pad */\n" * 120 +
                        "#ifdef TINY_IMPLEMENTATION\nint tiny_parse(const char *s, size_t n){return 0;}\n#endif\n#endif\n")
        tus = onboard.header_only_sources(root, ["."])
        self.assertEqual(len(tus), 1)
        body = util.read_text(os.path.join(root, tus[0]))
        self.assertIn("#define TINY_IMPLEMENTATION", body)
        self.assertTrue(onboard.analysis_file(root, tus[0]).endswith("tiny.h"))

    def test_mixed_cxx_build_is_shell_command(self):
        from kavachforge import toolchain
        tc = toolchain.Toolchain("standalone", "clang", "t", "")
        cmd = toolchain.build_fuzzer_cmd(tc, ["/r/a.c"], "/r/h.cc", ["/r/inc"], "/o/fz", ["-lm"])
        self.assertIsInstance(cmd, str)
        self.assertIn("clang++", cmd); self.assertIn("-c /r/a.c", cmd); self.assertIn("-lm", cmd)
        self.assertIn("kv_standalone_main.c", cmd)
        pure = toolchain.build_fuzzer_cmd(tc, ["/r/a.c"], "/r/h.c", ["/r/inc"], "/o/fz")
        self.assertIsInstance(pure, list)
        self.assertEqual(toolchain.cxx_for("/usr/lib/llvm-18/bin/clang"), "/usr/lib/llvm-18/bin/clang++")

    def test_entry_ranking_prefers_public_parser(self):
        from kavachforge import harness
        root = self._repo()
        ents = harness.analyze(os.path.join(root, "src", "lib.c"))
        self.assertEqual([e.name for e in ents], ["lib_parse"])     # static helper never an entry
        self.assertEqual(ents[0].shape, "cstr_size")
        self.assertEqual(harness._classify("const char *filename"), ("cstr", 50))
        self.assertEqual(harness._classify("ctx *c, const char *s, size_t n")[0], "other")
        self.assertEqual(harness._classify("const char *js, const size_t len, tok *t"), ("cstr_size", 80))

    def test_error_return_matches_signature(self):
        from kavachforge import patcher
        self.assertEqual(patcher._pick_error_return("", "{ x; }", "char *process(const char *in)"), "return NULL;")
        self.assertEqual(patcher._pick_error_return("", "{ x; }", "void f(int a)"), "return;")
        self.assertEqual(patcher._pick_error_return("", "{ ...\nerror:\n  free(p);\n}", "int f(void)"), "goto error;")
        self.assertEqual(patcher._pick_error_return("", "{ x; }", "size_t f(void)"), "return 0;")
        self.assertEqual(patcher._pick_error_return("", "{ x; }", "int f(void)"), "return -1;")

    def test_allocation_enlarge_strategy(self):
        """A heap WRITE one past a buffer the function allocates is repaired at
        the allocation (the classic missing '+ 1'), not by guarding the write."""
        from kavachforge import patcher
        root = tempfile.mkdtemp(prefix="kv_alloc_")
        src = os.path.join(root, "p.c")
        util.write_text(src, "#include <stdlib.h>\n#include <string.h>\n"
                             "char *dup(const char *in, size_t n) {\n"
                             "    char *out = (char*)malloc(n * sizeof(char));\n"
                             "    if (!out) return NULL;\n"
                             "    memcpy(out, in, n);\n"
                             "    out[n] = '\\0';\n"
                             "    return out;\n}\n")
        task = config.Task(name="t", language="c", root=root, sources=[src], harness="",
                           include_dirs=[root], test_sources=[], patch_scope=[src], magic=None,
                           diff_changed=[], static_alerts=[], description="", seeds=[])
        f = verifier.Finding(id="KV-T-001", signature="s", asan_class="heap-buffer-overflow",
                             cwe="CWE-787", cwe_name="", severity="Critical", access="Write 1B",
                             crash_file="p.c:7", crash_func="dup")
        vs = patcher.synth_variants(task, f)
        labels = [v.label for v in vs]
        self.assertIn("allocate room for terminator", labels)
        v = next(v for v in vs if v.label == "allocate room for terminator")
        self.assertIn("malloc((n * sizeof(char)) + 1)", v.diff)
        self.assertIsNone(patcher.check_policy(task, v.diff))


class TestUniversal(unittest.TestCase):
    """Any-stack track: stack detection, built-in rules, dedupe, mechanical
    fixes, policy, tolerant model-edit parsing and the syntax/rescan gates -
    offline, on synthetic repos."""

    def _repo(self):
        root = tempfile.mkdtemp(prefix="kv_uni_")
        os.makedirs(os.path.join(root, "app"))
        util.write_text(os.path.join(root, "package.json"), '{"name":"x","scripts":{}}')
        util.write_text(os.path.join(root, "app", "auth.js"),
                        "function login(req, res) {\n"
                        "  const n = eval(req.body.n);\n"
                        "  const m = eval(req.body.m);\n"
                        "  res.cookie('sid', n, { httpOnly: false });\n"
                        "}\nmodule.exports = login;\n")
        util.write_text(os.path.join(root, "app", "util.py"),
                        "import yaml\n\ndef load(t):\n    return yaml.load(t)\n")
        return root

    def test_detect_and_builtin_rules(self):
        from kavachforge import universal as u
        root = self._repo()
        os.makedirs(os.path.join(root, "config"))
        util.write_text(os.path.join(root, "config", "app.config.js"), "const x = eval(input);\n")
        self.assertEqual(u.detect_stacks(root), ["node"])
        found, note = u.discover(root, ["node"], scanner="builtin")
        self.assertIn("built-in", note)
        cwes = [f.cwe for f in found]
        self.assertIn("CWE-95", cwes); self.assertIn("CWE-1004", cwes); self.assertIn("CWE-502", cwes)
        ev = next(f for f in found if f.cwe == "CWE-95")
        self.assertEqual((ev.line, ev.end_line, ev.duplicates), (2, 3, 1))   # two evals, one finding
        self.assertTrue(ev.critical)                                          # auth.js is a critical area
        self.assertEqual(found[0].severity, "Critical")                       # ranked first
        self.assertTrue(found[0].file.startswith("app/"))                     # app code before config

    def test_mechanical_fix_and_gates(self):
        from kavachforge import universal as u
        root = self._repo()
        found, _ = u.discover(root, ["node"], scanner="builtin")
        ck = next(f for f in found if f.cwe == "CWE-1004")
        c = u.mechanical_fix(root, ck)
        self.assertIsNotNone(c)
        self.assertIn("+  res.cookie('sid', n, { httpOnly: true });", c.diff)
        self.assertIsNone(u.check_policy(ck, c.diff))
        tree = tempfile.mkdtemp(prefix="kv_tree_")
        u._scratch_copy(root, tree)
        ok, d = u.g0_apply(tree, c.diff); self.assertTrue(ok, d)
        ok, d = u.g1_syntax(tree, "app/auth.js"); self.assertTrue(ok, d)
        ok, d = u.g2_rescan(tree, ck, ["node"], "builtin"); self.assertTrue(ok, d)
        yl = next(f for f in found if f.cwe == "CWE-502")
        self.assertIn("yaml.safe_load(", u.mechanical_fix(root, yl).diff)

    def test_policy_rejects_bad_patches(self):
        from kavachforge import universal as u
        root = self._repo()
        f = u.discover(root, ["node"], scanner="builtin")[0][0]
        other = "--- a/app/other.js\n+++ b/app/other.js\n@@ -1 +1 @@\n-a\n+b\n"
        self.assertIn("out-of-scope", u.check_policy(f, other))
        evil = "--- a/%s\n+++ b/%s\n@@ -1 +1,2 @@\n a\n+ child_process.exec(x)\n" % (f.file, f.file)
        self.assertIn("dangerous", u.check_policy(f, evil))

    def test_policy_rejects_web_guardrails(self):
        from kavachforge import universal as u
        root = self._repo()
        f = u.discover(root, ["node"], scanner="builtin")[0][0]
        for addition, reason in (("app.get('/new', handler);", "HTTP route"),
                                 ("fetch('https://example.test');", "outbound network"),
                                 ("users.insertOne({role: 'admin'});", "users")):
            diff = "--- a/%s\n+++ b/%s\n@@ -1,1 +1,2 @@\n a\n+%s\n" % (f.file, f.file, addition)
            self.assertIn(reason, u.check_policy(f, diff))

    def test_http_allowlist_and_normalization(self):
        from kavachforge import universal as u
        self.assertTrue(u._allowed_target("http://localhost:4000/login", ["localhost:4000"]))
        self.assertFalse(u._allowed_target("http://localhost:5000/login", ["localhost:4000"]))
        body = '<input type="hidden" name="_csrf" value="abc123"><p>1730000000000</p>'
        normalized = u._normalise_http_body(body)
        self.assertIn("<csrf>", normalized)
        self.assertNotIn("abc123", normalized)
        self.assertIn("<timestamp>", normalized)

    def test_model_edit_formats(self):
        from kavachforge import universal as u
        root = self._repo()
        f = next(x for x in u.discover(root, ["node"], scanner="builtin")[0] if x.cwe == "CWE-95")
        sr = ("<<<<<<< SEARCH\n  const n = eval(req.body.n);\n=======\n"
              "  const n = parseInt(req.body.n, 10);\n>>>>>>> REPLACE\n")
        c = u.candidate_from_text(root, f, "parse", sr)
        self.assertIn("+  const n = parseInt(req.body.n, 10);", c.diff)
        # indentation drift + line-number prefixes are tolerated
        drift = ("<<<<<<< SEARCH\n    2  const m = eval(req.body.m);\n=======\n"
                 "const m = Number(req.body.m);\n>>>>>>> REPLACE\n")
        c2 = u.candidate_from_text(root, f, "num", drift)
        self.assertIn("+  const m = Number(req.body.m);", c2.diff)
        # whole-file answer with line numbers
        whole = "```js\n" + "\n".join("%5d  %s" % (i + 1, l) for i, l in enumerate(
            util.read_text(os.path.join(root, f.file)).replace("eval(", "Number(").splitlines())) + "\n```"
        c3 = u.candidate_from_text(root, f, "whole", whole)
        self.assertIn("Number(req.body.n)", c3.diff)
        self.assertIsNone(u.candidate_from_text(root, f, "none", "I cannot help with that."))

    def test_model_edit_preserves_crlf_diff_shape(self):
        from kavachforge import universal as u
        root = self._repo()
        path = os.path.join(root, "app", "auth.js")
        util.write_text(path, util.read_text(path).replace("\n", "\r\n"))
        f = next(x for x in u.discover(root, ["node"], scanner="builtin")[0] if x.cwe == "CWE-95")
        sr = ("<<<<<<< SEARCH\n  const n = eval(req.body.n);\n=======\n"
              "  const n = Number(req.body.n);\n>>>>>>> REPLACE\n")
        c = u.candidate_from_text(root, f, "crlf", sr)
        self.assertIn("+  const n = Number(req.body.n);", c.diff)
        self.assertNotIn("+function login", c.diff)

    def test_approval_rules(self):
        from kavachforge import universal as u
        f = u.SFinding("KV-1", "r", "CWE-95", "Eval", "Critical", "app/auth.js", 1, 1, "", "", critical=True)
        g = u.SFinding("KV-2", "r", "CWE-601", "Redir", "Medium", "app/x.js", 1, 1, "", "", critical=False)
        self.assertTrue(u.needs_approval("critical", f)); self.assertFalse(u.needs_approval("critical", g))
        self.assertTrue(u.needs_approval("all", g)); self.assertFalse(u.needs_approval("auto", f))


class TestFinalRound(unittest.TestCase):
    """Final-round mechanics: precision (SUBMIT/HOLD), organizer-format report,
    one failing finding never kills the run, archive input, Java rules."""

    def _repo(self):
        root = tempfile.mkdtemp(prefix="kv_fr_")
        os.makedirs(os.path.join(root, "app")); os.makedirs(os.path.join(root, "static", "js"))
        os.makedirs(os.path.join(root, "src"))
        util.write_text(os.path.join(root, "package.json"), '{"name":"x"}')
        util.write_text(os.path.join(root, "app", "auth.js"),
                        "function login(req, res) {\n  const n = eval(req.body.n);\n"
                        "  res.cookie('sid', n, { httpOnly: false });\n}\n")
        util.write_text(os.path.join(root, "static", "js", "vendor.js"), "x = eval(y);\n")
        util.write_text(os.path.join(root, "app", "impossible.js"), "function safe(req){ return eval(req.q); }\n")
        util.write_text(os.path.join(root, "src", "Run.java"),
                        "class Run { void go(String a){ new ProcessBuilder(\"sh\", \"-c\", \"ls \" + a).start();\n"
                        " response.sendRedirect(target); } }\n")
        return root

    def test_hold_rules_and_java_rules(self):
        from kavachforge import universal as u
        root = self._repo()
        found, _ = u.discover(root, ["node", "java"], scanner="builtin")
        for f in found:
            f.hold = u.hold_reason(f, root)
        by = {(f.file, f.cwe): f for f in found}
        self.assertIn("non-application", by[("static/js/vendor.js", "CWE-95")].hold)
        self.assertIn("secure variant", by[("app/impossible.js", "CWE-95")].hold)
        self.assertEqual(by[("app/auth.js", "CWE-95")].hold, "")
        self.assertIn(("src/Run.java", "CWE-78"), by); self.assertIn(("src/Run.java", "CWE-601"), by)
        self.assertEqual(by[("src/Run.java", "CWE-78")].severity, "Critical")

    def test_report_format_and_error_isolation(self):
        from kavachforge import universal as u, llm, report, config
        root = self._repo()
        task = config.Task(name="fr", language="node", root=root, sources=[], harness="", include_dirs=[],
                           test_sources=[], patch_scope=[], magic=None, diff_changed=[], static_alerts=[],
                           description="", seeds=[], raw={"stacks": ["node"]}, kind="universal")
        client = llm.LLMClient(provider="offline", budget=1, cache_dir=tempfile.mkdtemp(), log_dir=tempfile.mkdtemp())
        work = tempfile.mkdtemp(prefix="kv_frw_")
        orig = u.mechanical_fix
        calls = {"n": 0}

        def boom(root_, f):            # the FIRST repair blows up; the rest must still complete
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated crash")
            return orig(root_, f)
        u.mechanical_fix = boom
        try:
            res = u.run(task, client, work, approve="auto", interactive=False, scanner="builtin", review=False)
        finally:
            u.mechanical_fix = orig
        st = [f["validation"]["status"] for f in res["findings"]]
        self.assertIn("Error", st)
        self.assertGreaterEqual(len(res["findings"]), 3)
        self.assertEqual(sum(1 for f in res["findings"] if f["validation"]["status"] == "Held"), 2)
        ev = {"task": {"name": "fr"}, "generated_at": "now", "metrics": res["metrics"], "findings": res["findings"]}
        out = report.write_submission(ev, work)
        md = util.read_text(out["md"])
        self.assertIn("| S.No | Vulnerability title | Severity | Vulnerable file / function / location | Steps taken |", md)
        self.assertNotIn("vendor.js", md)                 # HOLD rows never reach the report
        self.assertIn("app/auth.js", md)
        rows = report.submission_rows(ev)
        self.assertEqual([r["sno"] for r in rows], list(range(1, len(rows) + 1)))
        sev = [r["severity"] for r in rows]
        self.assertEqual(sev, sorted(sev, key=report.SEV_ORDER.index))

    def test_archive_input(self):
        import tarfile
        from kavachforge import onboard
        root = self._repo()
        tgz = os.path.join(tempfile.mkdtemp(), "handover.tar.gz")
        with tarfile.open(tgz, "w:gz") as t:
            t.add(root, arcname="app-src")
        name, dest = onboard.fetch(tgz, name="handover", dest_dir=tempfile.mkdtemp())
        self.assertEqual(name, "handover")
        self.assertTrue(os.path.exists(os.path.join(dest, "package.json")))   # unwrapped top-level dir


class TestTimePlan(unittest.TestCase):
    """A slow model must never eat the repair slot (the 0-patch VulnerableApp run)."""

    class _Slow:
        model = "slow:14b"
        def __init__(self): self.n = 0
        def avg_call(self, default=0.0, kind=""): return 150.0
        def complete(self, *a, **k):
            self.n += 1; return "UNSURE\nno idea"

    def _f(self, i, conf=0.55):
        from kavachforge import universal as u
        return u.SFinding("KV-%d" % i, "r", "CWE-79", "XSS", "High", "app/a%d.js" % i, 1, 1, "", "",
                          confidence=conf, conf_why="t")

    def test_second_opinion_stops_before_repair_slot(self):
        import time as _t
        from kavachforge import universal as u
        found = [self._f(i) for i in range(6)]
        c = self._Slow()
        with tempfile.TemporaryDirectory() as d:
            for i in range(6):
                os.makedirs(os.path.join(d, "app"), exist_ok=True)
                open(os.path.join(d, "app", "a%d.js" % i), "w").write("x\n")
            u.apply_scoring(found, d, c, "balanced", stop_at=_t.time() + 100)   # < one 150 s call
        self.assertEqual(c.n, 0)                     # not a single call: it would overrun the slot
        self.assertTrue(all(f.confidence == 0.55 for f in found))

    def test_review_stops_when_next_call_overruns(self):
        import time as _t
        from kavachforge import universal as u
        c = self._Slow()
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "routes"))
            for i in range(3):
                open(os.path.join(d, "routes", "r%d.js" % i), "w").write("app.get('/x', (req,res)=>{res.send(req.query.q)})\n")
            files = u.source_files(d)
            out = u.model_review(d, files, c, [], limit=3, stop_at=_t.time() + 60)
        self.assertEqual(c.n, 0)
        self.assertEqual(out, [])

    def test_search_replace_accepts_unique_subline_fragment(self):
        from kavachforge import universal as u
        src = '    q = f"SELECT * FROM users WHERE username = \'{username}\'"\n    run(q)\n'
        out = u._apply_search_replace(src, [('"SELECT * FROM users WHERE username = \'{username}\'"',
                                             '"SELECT * FROM users WHERE username = :u"')])
        self.assertEqual(out, '    q = f"SELECT * FROM users WHERE username = :u"\n    run(q)\n')
        # ambiguous fragment (appears twice) is still refused
        self.assertIsNone(u._apply_search_replace("a = x\nb = x\n", [("x", "y")]))
