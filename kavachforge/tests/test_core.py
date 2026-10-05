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
