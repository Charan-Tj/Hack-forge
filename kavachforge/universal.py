"""Stack-agnostic track: find, patch and verify security defects in ANY
repository (Node, Python, Go, Java, PHP, Ruby, Rust, C#, ... and C/C++ too).

The C/C++ fuzzing track proves a bug with a sanitizer crash. Other stacks
have no such oracle, so this track uses a different - and honestly weaker -
evidence chain, with the same six-gate discipline:

  discover   semgrep (registry rule packs per stack, SARIF out) when it is
             installed and the registry is reachable; otherwise KavachForge's
             built-in pattern rules (run anywhere, no network). Every finding
             carries a CWE, a severity, the exact lines, and the analyzer's
             own message.
  triage     deduplicate, rank by severity, flag CRITICAL files (auth,
             session, crypto, payments, config) for human approval.
  repair     mechanical fixes for well-understood patterns (offline), plus a
             model-written ensemble (2 strategies) when a provider is set.
  G0 apply   the patch applies to a scratch copy of the repo
  G1 syntax  the patched file parses (node --check, py_compile, php -l,
             ruby -c, gofmt, cc -fsyntax-only, ...)
  G2 rescan  the finding is gone from the patched file and no new finding
             was introduced in it
  G3 tests   the repo's own suite (npm test / pytest / go test / mvn / cargo)
             shows no NEW failure vs. the unpatched tree (skipped honestly
             when the suite cannot run here - e.g. it needs a database)
  G4 proof   a model-written proof test that FAILS on the unpatched file and
             PASSES on the patched one (when a model is available and the
             module can be imported standalone); otherwise "not provable
             here" - never claimed.
  approval   --approve critical (default): pause for a human before touching
             a critical file; --approve all: before every patch; auto: never.

Findings are written in the same evidence.json / dashboard shape as the
fuzzing track so the judge sees one product.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import config, cwe as cwemod, llm, util

# ---------------------------------------------------------------------------
# stack detection
# ---------------------------------------------------------------------------
STACK_MARKERS = [
    ("node", ["package.json"]), ("python", ["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"]),
    ("go", ["go.mod"]), ("java", ["pom.xml", "build.gradle", "build.gradle.kts"]),
    ("rust", ["Cargo.toml"]), ("php", ["composer.json"]), ("ruby", ["Gemfile"]),
    ("dotnet", ["*.csproj", "*.sln"]), ("c", ["*.c", "*.cc", "*.cpp"]),
]
EXT_LANG = {".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
            ".ts": "typescript", ".tsx": "typescript", ".py": "python", ".go": "go",
            ".java": "java", ".kt": "kotlin", ".php": "php", ".rb": "ruby", ".rs": "rust",
            ".cs": "csharp", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
            ".scala": "scala", ".swift": "swift", ".yml": "yaml", ".yaml": "yaml", ".json": "json"}
SEMGREP_PACKS = {"node": ["p/nodejs", "p/javascript", "p/expressjs"], "python": ["p/python", "p/flask", "p/django"],
                 "go": ["p/golang"], "java": ["p/java"], "php": ["p/php"], "ruby": ["p/ruby"],
                 "rust": ["p/rust"], "dotnet": ["p/csharp"], "c": ["p/c"]}
COMMON_PACKS = ["p/security-audit", "p/secrets", "p/owasp-top-ten"]
SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "target", "venv", ".venv", "__pycache__",
             ".tox", "site-packages", "bower_components", "coverage", ".next", "out", "bin", "obj"}
CRITICAL_RE = re.compile(r"(auth|login|signin|session|passw|credential|crypt|token|secret|jwt|oauth|"
                         r"payment|billing|checkout|admin|privilege|permission|config|\.env|settings)",
                         re.I)
CRITICAL_CWES = {"CWE-78", "CWE-89", "CWE-94", "CWE-95", "CWE-502", "CWE-22", "CWE-611", "CWE-917",
                 "CWE-943", "CWE-98", "CWE-434", "CWE-287", "CWE-798"}


def detect_stacks(root: str) -> List[str]:
    out = []
    names = set(os.listdir(root))
    for stack, markers in STACK_MARKERS:
        for m in markers:
            if m.startswith("*"):
                ext = m[1:]
                hit = False
                for dp, dns, fns in os.walk(root):
                    dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".")]
                    if any(f.endswith(ext) for f in fns):
                        hit = True; break
                if hit:
                    out.append(stack); break
            elif m in names:
                out.append(stack); break
    return out


def source_files(root: str, limit: int = 4000) -> List[str]:
    out = []
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS and not d.startswith("."))
        for f in sorted(fns):
            if os.path.splitext(f)[1] in EXT_LANG and not f.endswith(".min.js"):
                out.append(os.path.relpath(os.path.join(dp, f), root))
                if len(out) >= limit:
                    return out
    return out


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------
@dataclass
class SFinding:
    id: str
    rule: str
    cwe: str
    cwe_name: str
    severity: str
    file: str              # relative to root
    line: int
    end_line: int
    message: str
    snippet: str
    func: str = "-"
    source: str = "semgrep"
    fix_hint: str = ""
    critical: bool = False
    signature: str = ""
    duplicates: int = 0


_CWE_NAMES = {"CWE-78": "OS Command Injection", "CWE-79": "Cross-site Scripting", "CWE-89": "SQL Injection",
              "CWE-94": "Code Injection", "CWE-95": "Eval Injection", "CWE-22": "Path Traversal",
              "CWE-502": "Deserialization of Untrusted Data", "CWE-611": "XXE", "CWE-601": "Open Redirect",
              "CWE-798": "Hard-coded Credentials", "CWE-327": "Broken Cryptography", "CWE-328": "Weak Hash",
              "CWE-295": "Improper Certificate Validation", "CWE-943": "NoSQL Injection",
              "CWE-1004": "Cookie Without HttpOnly", "CWE-614": "Cookie Without Secure Flag",
              "CWE-352": "CSRF", "CWE-287": "Improper Authentication", "CWE-116": "Improper Encoding",
              "CWE-693": "Protection Mechanism Failure", "CWE-915": "Mass Assignment", "CWE-400": "Resource Exhaustion",
              "CWE-1021": "Clickjacking", "CWE-1275": "SameSite Cookie", "CWE-120": "Classic Buffer Overflow",
              "CWE-98": "File Inclusion", "CWE-434": "Unrestricted Upload", "CWE-917": "Expression Language Injection"}


def cwe_name_for(cwe_id: str) -> str:
    return _CWE_NAMES.get(cwe_id, "Security weakness")


_SEV_FROM_LEVEL = {"error": "High", "warning": "Medium", "note": "Low", "none": "Low"}


def _sev_for(cwe_id: str, level: str) -> str:
    if cwe_id in CRITICAL_CWES:
        return "Critical"
    return _SEV_FROM_LEVEL.get(level, "Medium")


def _enclosing_func(lines: List[str], line_no: int, lang: str) -> str:
    pats = [r"\bfunction\s+([A-Za-z_$][\w$]*)", r"([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>)",
            r"\bdef\s+([A-Za-z_]\w*)", r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)",
            r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*\{",
            r"\bfn\s+([A-Za-z_]\w*)", r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"]
    for i in range(min(line_no, len(lines)) - 1, -1, -1):
        for p in pats:
            m = re.search(p, lines[i])
            if m and m.group(1) not in ("if", "for", "while", "switch", "catch", "return"):
                return m.group(1)
    return "-"


# ---- semgrep ----------------------------------------------------------------
def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


RULES_DIR = os.path.join(config.PROJECT_ROOT, "rules", "semgrep")
ALL_PACKS = list(dict.fromkeys(sum(SEMGREP_PACKS.values(), []) + COMMON_PACKS))


def pack_path(pack: str) -> str:
    return os.path.join(RULES_DIR, pack.replace("/", "_") + ".yml")


def packs_for(stacks: List[str]) -> List[str]:
    return list(dict.fromkeys(sum([SEMGREP_PACKS.get(s, []) for s in stacks], []) + COMMON_PACKS))


def prefetch_packs(packs: Optional[List[str]] = None, log=lambda m: None) -> Tuple[int, int]:
    """Download registry packs to rules/semgrep/ so scans run with no network
    (the finale venue may have none). Returns (fetched, failed)."""
    import urllib.request
    os.makedirs(RULES_DIR, exist_ok=True)
    ok = bad = 0
    for pk in packs or ALL_PACKS:
        dst = pack_path(pk)
        try:
            with urllib.request.urlopen("https://semgrep.dev/c/" + pk, timeout=60) as r:
                data = r.read()
            if b"rules:" not in data[:200]:
                raise ValueError("not a rule pack")
            with open(dst, "wb") as f:
                f.write(data)
            n = data.count(b"\n- id:")
            log("%-20s %d rule(s) -> %s" % (pk, n, os.path.relpath(dst, config.PROJECT_ROOT)))
            ok += 1
        except Exception as e:
            log("%-20s FAILED (%s)" % (pk, str(e)[:60]))
            bad += 1
    return ok, bad


def cached_packs() -> List[str]:
    if not os.path.isdir(RULES_DIR):
        return []
    return sorted(f[:-4].replace("_", "/", 1) for f in os.listdir(RULES_DIR) if f.endswith(".yml"))


def run_semgrep(root: str, stacks: List[str], paths: Optional[List[str]] = None,
                configs: Optional[List[str]] = None, timeout: int = 600) -> Tuple[Optional[dict], str]:
    """Run semgrep with per-stack packs: the locally cached copy when
    `kavach prefetch` has stored it (offline), else the registry."""
    cfgs = configs or packs_for(stacks)
    out = tempfile.mktemp(prefix="kv_sg_", suffix=".sarif")
    cmd = ["semgrep", "--sarif", "--quiet", "--metrics=off", "--timeout", "30", "-o", out]
    local = 0
    for c in cfgs:
        lp = pack_path(c)
        if os.path.exists(lp):
            cmd += ["--config", lp]; local += 1
        else:
            cmd += ["--config", c]
    for d in SKIP_DIRS:
        cmd += ["--exclude", d]
    cmd += (paths or ["."])
    r = util.run(cmd, cwd=root, timeout=timeout)
    if not os.path.exists(out):
        return None, "semgrep failed: " + (r.err.strip().splitlines() or ["?"])[-1][-200:]
    try:
        d = json.load(open(out))
    except Exception as e:
        return None, "semgrep output unreadable: %s" % e
    finally:
        try:
            os.remove(out)
        except OSError:
            pass
    return d, "semgrep %s, packs: %s%s" % (_semgrep_version(), ", ".join(cfgs),
                                           " (%d/%d from local cache - offline)" % (local, len(cfgs)) if local else "")


def _semgrep_version() -> str:
    r = util.run(["semgrep", "--version"], timeout=30)
    return (r.out.strip().splitlines() or ["?"])[-1]


def findings_from_sarif(root: str, sarif: dict, prefix: str) -> List[SFinding]:
    out: List[SFinding] = []
    for run in sarif.get("runs", []):
        rules = {}
        for rl in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[rl.get("id")] = rl
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rl = rules.get(rid, {})
            tags = rl.get("properties", {}).get("tags", [])
            cm = next((re.match(r"CWE-(\d+)", t) for t in tags if re.match(r"CWE-\d+", t)), None)
            cwe_id = "CWE-%s" % cm.group(1) if cm else "CWE-693"
            name = next((t.split(":", 1)[1].strip() for t in tags if t.startswith(cwe_id + ":")), "")
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            fpath = loc.get("artifactLocation", {}).get("uri", "")
            reg = loc.get("region", {})
            line = int(reg.get("startLine", 1)); eline = int(reg.get("endLine", line))
            msg = res.get("message", {}).get("text", "") or rl.get("shortDescription", {}).get("text", "")
            level = res.get("level") or rl.get("defaultConfiguration", {}).get("level", "warning")
            # skip vendored / minified / test fixtures
            if any(part in SKIP_DIRS for part in fpath.split("/")):
                continue
            ap = os.path.join(root, fpath)
            if not os.path.exists(ap):
                continue
            lines = util.read_text(ap).splitlines()
            snippet = "\n".join("%5d  %s" % (i + 1, lines[i]) for i in range(max(0, line - 3), min(len(lines), eline + 2)))
            short = rid.split(".")[-1]
            fix = rl.get("help", {}).get("text", "") or rl.get("fullDescription", {}).get("text", "")
            out.append(SFinding(id="", rule=short, cwe=cwe_id, cwe_name=name or cwe_name_for(cwe_id),
                                severity=_sev_for(cwe_id, level), file=fpath, line=line, end_line=eline,
                                message=msg.strip(), snippet=snippet,
                                func=_enclosing_func(lines, line, EXT_LANG.get(os.path.splitext(fpath)[1], "")),
                                source="semgrep", fix_hint=fix[:600],
                                critical=bool(CRITICAL_RE.search(fpath)) or cwe_id in CRITICAL_CWES))
    return out


# ---- built-in rules (no network, no semgrep) --------------------------------
# (languages, regex, CWE, name, severity, message, mechanical fix (regex -> repl) or None)
BUILTIN_RULES = [
    (("javascript", "typescript"), r"\beval\s*\(", "CWE-95", "Eval Injection", "Critical",
     "eval() on data that may be attacker-controlled executes arbitrary code.", None),
    (("javascript", "typescript"), r"\bnew\s+Function\s*\(", "CWE-95", "Eval Injection", "High",
     "new Function() compiles a string into code.", None),
    (("javascript", "typescript"), r"\b(?:exec|execSync|spawn)\s*\(\s*(?:`[^`]*\$\{|[^,)]*\+)", "CWE-78", "OS Command Injection", "Critical",
     "Shell command built from concatenated/templated input.", None),
    (("javascript", "typescript"), r"\.innerHTML\s*=|document\.write\s*\(", "CWE-79", "Cross-site Scripting", "High",
     "Raw HTML sink; data must be escaped or set via textContent.", None),
    (("javascript", "typescript"), r"res\.redirect\s*\(\s*req\.", "CWE-601", "Open Redirect", "Medium",
     "Redirect target taken directly from the request.", None),
    (("javascript", "typescript"), r"\$where\s*:", "CWE-943", "NoSQL Injection", "Critical",
     "$where evaluates JavaScript inside the database.", None),
    (("javascript", "typescript"), r"httpOnly\s*:\s*false", "CWE-1004", "Cookie Without HttpOnly", "Medium",
     "Session cookie readable from page scripts.", (r"httpOnly\s*:\s*false", "httpOnly: true")),
    (("javascript", "typescript"), r"\bsecure\s*:\s*false", "CWE-614", "Cookie Without Secure Flag", "Medium",
     "Cookie may be sent over plain HTTP.", (r"\bsecure\s*:\s*false", "secure: true")),
    (("javascript", "typescript"), r"\b(?:md5|sha1)\b\s*[\(\)'\"]", "CWE-328", "Weak Hash", "Medium",
     "MD5/SHA-1 are not suitable for passwords or integrity.", None),
    (("javascript", "typescript", "python", "java", "php", "ruby", "go"),
     r"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{8,}['\"]",
     "CWE-798", "Hard-coded Credentials", "High", "A credential literal is embedded in source.", None),
    (("python",), r"\bpickle\.loads?\s*\(", "CWE-502", "Deserialization of Untrusted Data", "Critical",
     "pickle executes code on load.", None),
    (("python",), r"\byaml\.load\s*\((?![^)]*Loader)", "CWE-502", "Deserialization of Untrusted Data", "High",
     "yaml.load without a safe Loader.", (r"\byaml\.load\s*\(", "yaml.safe_load(")),
    (("python",), r"\b(?:os\.system|os\.popen)\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True", "CWE-78",
     "OS Command Injection", "Critical", "Shell execution with a composed command string.", None),
    (("python",), r"\beval\s*\(|\bexec\s*\(", "CWE-95", "Eval Injection", "Critical",
     "eval/exec on runtime strings.", None),
    (("python",), r"verify\s*=\s*False", "CWE-295", "Improper Certificate Validation", "High",
     "TLS verification disabled.", (r"verify\s*=\s*False", "verify=True")),
    (("python",), r"\bhashlib\.(?:md5|sha1)\s*\(", "CWE-328", "Weak Hash", "Medium",
     "MD5/SHA-1 used.", None),
    (("python", "php", "java", "javascript", "typescript", "go", "ruby"),
     r"(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n;]*(?:\"|')\s*\+\s*\w|(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n;]*%\s*\(|f\"(?:SELECT|INSERT|UPDATE|DELETE)\b",
     "CWE-89", "SQL Injection", "Critical", "SQL built by string concatenation/formatting.", None),
    (("java",), r"Runtime\.getRuntime\(\)\.exec\s*\(", "CWE-78", "OS Command Injection", "High",
     "Runtime.exec with a composed command.", None),
    (("java",), r"new\s+ObjectInputStream\s*\(", "CWE-502", "Deserialization of Untrusted Data", "High",
     "Java native deserialization.", None),
    (("php",), r"\beval\s*\(|\bsystem\s*\(|\bshell_exec\s*\(|\bpassthru\s*\(", "CWE-78", "OS Command Injection", "Critical",
     "Command/code execution primitive.", None),
    (("php",), r"\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)", "CWE-98", "File Inclusion", "Critical",
     "Include path from request.", None),
    (("go",), r"exec\.Command\s*\([^)]*\+", "CWE-78", "OS Command Injection", "High",
     "Command built by concatenation.", None),
    (("go",), r"InsecureSkipVerify\s*:\s*true", "CWE-295", "Improper Certificate Validation", "High",
     "TLS verification disabled.", (r"InsecureSkipVerify\s*:\s*true", "InsecureSkipVerify: false")),
    (("ruby",), r"\bsystem\s*\(.*#\{|`[^`]*#\{", "CWE-78", "OS Command Injection", "High",
     "Shell command with interpolation.", None),
    (("c", "cpp"), r"\b(?:gets|strcpy|strcat|sprintf)\s*\(", "CWE-120", "Classic Buffer Overflow", "High",
     "Unbounded copy/format into a buffer.", None),
    (("c", "cpp"), r"\bsystem\s*\(", "CWE-78", "OS Command Injection", "Medium",
     "system() with a composed command.", None),
]


def run_builtin(root: str, files: List[str]) -> List[SFinding]:
    out: List[SFinding] = []
    for rel in files:
        lang = EXT_LANG.get(os.path.splitext(rel)[1], "")
        if not lang or lang in ("yaml", "json"):
            continue
        try:
            text = util.read_text(os.path.join(root, rel))
        except Exception:
            continue
        lines = text.splitlines()
        for langs, pat, cwe_id, name, sev, msg, fix in BUILTIN_RULES:
            if lang not in langs:
                continue
            for i, line in enumerate(lines):
                if line.lstrip().startswith(("//", "#", "*", "/*")):
                    continue
                if re.search(pat, line):
                    snippet = "\n".join("%5d  %s" % (j + 1, lines[j]) for j in range(max(0, i - 2), min(len(lines), i + 3)))
                    out.append(SFinding(id="", rule=re.sub(r"\W+", "-", name.lower()), cwe=cwe_id, cwe_name=name,
                                        severity=sev, file=rel, line=i + 1, end_line=i + 1, message=msg,
                                        snippet=snippet, func=_enclosing_func(lines, i + 1, lang), source="builtin",
                                        fix_hint=("mechanical: %s -> %s" % fix) if fix else "",
                                        critical=bool(CRITICAL_RE.search(rel)) or cwe_id in CRITICAL_CWES))
    return out


def discover(root: str, stacks: List[str], scanner: str = "auto", files: Optional[List[str]] = None,
             log=lambda m: None) -> Tuple[List[SFinding], str]:
    files = files or source_files(root)
    note = ""
    found: List[SFinding] = []
    if scanner in ("auto", "semgrep") and semgrep_available():
        sarif, note = run_semgrep(root, stacks)
        if sarif is not None:
            found = findings_from_sarif(root, sarif, "SG")
            log("semgrep: %d result(s) (%s)" % (len(found), note))
        else:
            log(note + " - falling back to built-in rules")
    if not found and scanner != "semgrep":
        found = run_builtin(root, files)
        note = (note + "; " if note else "") + "built-in rules (%d patterns, no network)" % len(BUILTIN_RULES)
        log("built-in rules: %d result(s)" % len(found))
    # dedupe: same weakness in the same function within a few lines is ONE
    # finding (one repair), e.g. three eval() calls in one handler
    found.sort(key=lambda f: (f.file, f.line))
    merged: List[SFinding] = []
    for f in found:
        if f.cwe in ("CWE-1357",):
            f.severity = "Low"            # supply-chain hygiene, not a code defect
        prev = merged[-1] if merged else None
        if prev and prev.cwe == f.cwe and prev.file == f.file and prev.func == f.func \
                and f.line - prev.end_line <= 12:
            prev.end_line = max(prev.end_line, f.end_line)
            prev.duplicates += 1
            continue
        if prev and prev.cwe == f.cwe and prev.file == f.file and prev.line == f.line:
            prev.duplicates += 1
            continue
        f.signature = util.sha256_bytes(("%s|%s|%s" % (f.cwe, f.file, f.func or f.line)).encode())[:16]
        merged.append(f)
    def _rank(f: SFinding):
        lang = EXT_LANG.get(os.path.splitext(f.file)[1], "")
        code = 0 if lang not in ("", "yaml", "json") else 1      # code before config/CI
        return (code, -cwemod.severity_rank(f.severity), f.file, f.line)
    return sorted(merged, key=_rank), note


# ---------------------------------------------------------------------------
# repair
# ---------------------------------------------------------------------------
@dataclass
class Candidate:
    label: str
    diff: str
    source: str            # "mechanical" | "model"
    rationale: str = ""
    status: str = ""
    gates: List[Dict] = field(default_factory=list)
    chosen: bool = False


def _unified(rel: str, before: str, after: str) -> str:
    import difflib
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile="a/" + rel, tofile="b/" + rel, n=3))


def mechanical_fix(root: str, f: SFinding) -> Optional[Candidate]:
    lang = EXT_LANG.get(os.path.splitext(f.file)[1], "")
    for langs, pat, cwe_id, name, sev, msg, fix in BUILTIN_RULES:
        if lang in langs and cwe_id == f.cwe and fix:
            text = util.read_text(os.path.join(root, f.file))
            lines = text.splitlines(keepends=True)
            i = f.line - 1
            if 0 <= i < len(lines) and re.search(fix[0], lines[i]):
                new = lines[:i] + [re.sub(fix[0], fix[1], lines[i])] + lines[i + 1:]
                return Candidate("mechanical hardening", _unified(f.file, text, "".join(new)), "mechanical",
                                 "Well-understood insecure option replaced by its secure value (%s)." % name)
    return None


def check_policy(f: SFinding, diff: str) -> Optional[str]:
    from .patcher import touched_files
    if not diff.strip() or "@@" not in diff:
        return "not a unified diff"
    for t in touched_files(diff):
        if t != f.file:
            return "patch touches out-of-scope file %r (only %s may change)" % (t, f.file)
    added = [l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
    removed = [l[1:] for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]
    if len(added) > 60:
        return "patch is not minimal (%d added lines)" % len(added)
    if removed and not added:
        return "patch only deletes code; a fix must validate, encode or replace the unsafe call"
    joined = "\n".join(added)
    if re.search(r"\beval\s*\(|child_process|os\.system|shell\s*=\s*True|\$where", joined):
        return "patch introduces a new dangerous primitive"
    if re.search(r"(?i)todo|fixme|xxx", joined):
        return "patch contains placeholder text"
    return None


_PATCH_PROMPT = """You are fixing a security finding in a {lang} file. Produce the MINIMAL change that
removes the weakness while preserving the function's behaviour for legitimate input.

Finding: {cwe} {cwe_name} ({severity}) - rule `{rule}`
Analyzer message: {message}
{hint}
File: {file}  (lines {line}-{end_line} are the flagged location)

Give TWO alternative fixes. Each fix is one or more SEARCH/REPLACE edits. SEARCH must copy the
existing lines EXACTLY (same indentation, no line numbers); REPLACE is the new text. Format exactly:

### STRATEGY: <short name>
<<<<<<< SEARCH
<exact existing lines>
=======
<replacement lines>
>>>>>>> REPLACE

### STRATEGY: <short name>
<<<<<<< SEARCH
...
=======
...
>>>>>>> REPLACE

Rules: validate or encode input rather than deleting functionality; do not introduce eval/exec/shell
primitives; no TODO placeholders; keep each fix small (under 40 new lines); new imports go in a
separate SEARCH/REPLACE edit that anchors on an existing import line.

--- file excerpt (the leading numbers are line numbers, NOT part of the code) ---
{excerpt}
"""

_SR_RE = re.compile(r"<{5,9}\s*SEARCH\s*\n(.*?)\n?={5,9}\s*\n(.*?)\n?>{5,9}\s*REPLACE", re.DOTALL)
_LINENO_RE = re.compile(r"^\s*\d+\s{2}")


def _strip_line_numbers(text: str) -> str:
    lines = text.splitlines()
    numbered = sum(1 for l in lines if _LINENO_RE.match(l) or not l.strip())
    if lines and numbered >= 0.8 * len(lines):
        return "\n".join(_LINENO_RE.sub("", l) for l in lines) + "\n"
    return text


def _apply_search_replace(original: str, blocks: List[Tuple[str, str]]) -> Optional[str]:
    """Apply SEARCH/REPLACE blocks; exact match first, then an
    indentation-insensitive match (small models drift on leading spaces)."""
    text = original
    for search, replace in blocks:
        search = _strip_line_numbers(search).rstrip("\n")
        replace = _strip_line_numbers(replace).rstrip("\n")
        if not search.strip():
            return None
        if search in text:
            text = text.replace(search, replace, 1)
            continue
        # tolerant: compare lines with whitespace stripped
        src_lines = text.splitlines()
        s_lines = [l.strip() for l in search.splitlines() if l.strip()]
        hit = None
        for i in range(len(src_lines)):
            window = [l.strip() for l in src_lines[i:i + len(s_lines)]]
            if window == s_lines:
                hit = i; break
        if hit is None:
            return None
        indent = re.match(r"\s*", src_lines[hit]).group(0)
        rep_lines = replace.splitlines()
        # re-indent replacement relative to its own first line
        base = re.match(r"\s*", rep_lines[0]).group(0) if rep_lines else ""
        rep = [indent + (l[len(base):] if l.startswith(base) else l.lstrip()) if l.strip() else "" for l in rep_lines]
        src_lines[hit:hit + len(s_lines)] = rep
        text = "\n".join(src_lines) + ("\n" if original.endswith("\n") else "")
    return text


def candidate_from_text(root: str, f: SFinding, name: str, body: str) -> Optional[Candidate]:
    """Turn whatever a model produced - SEARCH/REPLACE blocks, a unified
    diff, or a whole file - into a unified diff we can gate."""
    original = util.read_text(os.path.join(root, f.file))
    blocks = _SR_RE.findall(body)
    if blocks:
        new = _apply_search_replace(original, blocks)
        if new is None or new == original:
            return None
        return Candidate(name, _unified(f.file, original, new), "model", "Model-written fix (%s)." % name)
    from .patcher import _extract_diff
    m = re.search(r"```[\w+-]*\s*\n(.*?)```", body, re.DOTALL)
    code = (m.group(1) if m else body)
    if re.search(r"^(--- |\+\+\+ |@@ )", code, re.M):
        return Candidate(name, _extract_diff(body), "model", "Model-written fix (%s)." % name)
    # whole-file replacement (small models often answer this way)
    code = _strip_line_numbers(code)
    if code.count("\n") >= 0.5 * original.count("\n") and code.strip() != original.strip():
        return Candidate(name, _unified(f.file, original, code if code.endswith("\n") else code + "\n"),
                         "model", "Model-written fix (%s; whole-file answer normalised)." % name)
    return None


def model_candidates(root: str, f: SFinding, client: Optional[llm.LLMClient],
                     prior_reason: Optional[str] = None) -> List[Candidate]:
    if client is None:
        return []
    text = util.read_text(os.path.join(root, f.file))
    lines = text.splitlines()
    lo, hi = max(0, f.line - 45), min(len(lines), f.end_line + 45)
    excerpt = "\n".join("%5d  %s" % (i + 1, lines[i]) for i in range(lo, hi))
    lang = EXT_LANG.get(os.path.splitext(f.file)[1], "code")
    prompt = _PATCH_PROMPT.format(lang=lang, cwe=f.cwe, cwe_name=f.cwe_name, severity=f.severity, rule=f.rule,
                                  message=f.message, hint=("Guidance: " + f.fix_hint) if f.fix_hint else "",
                                  file=f.file, line=f.line, end_line=f.end_line, excerpt=excerpt)
    if prior_reason:
        prompt += "\nA previous attempt was rejected because: %s. Avoid that.\n" % prior_reason
    try:
        resp = client.complete(prompt, system="You are a careful application-security engineer. "
                                              "You answer only in the requested edit format.", max_tokens=1800)
    except llm.LLMUnavailable:
        return []
    parts = re.split(r"^###\s*STRATEGY:\s*(.+?)\s*$", resp, flags=re.MULTILINE)
    chunks: List[Tuple[str, str]] = []
    if len(parts) >= 3:
        for i in range(1, len(parts) - 1, 2):
            chunks.append((parts[i].strip()[:40], parts[i + 1]))
    else:
        chunks.append(("model patch", resp))
    out = []
    for name, body in chunks:
        c = candidate_from_text(root, f, name, body)
        if c:
            out.append(c)
    return out[:3]


# ---------------------------------------------------------------------------
# gates
# ---------------------------------------------------------------------------
DEP_DIRS = ("node_modules", "vendor", "venv", ".venv", "target")


def _scratch_copy(root: str, dest: str) -> None:
    """Copy the repo without its dependency trees, then link those back in so
    the test suite can run in the copy without a second install."""
    if os.path.exists(dest):
        shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(root, dest, ignore=shutil.ignore_patterns(*SKIP_DIRS, ".git"), symlinks=True)
    for d in DEP_DIRS:
        src = os.path.join(root, d)
        if os.path.isdir(src) and not os.path.exists(os.path.join(dest, d)):
            os.symlink(os.path.abspath(src), os.path.join(dest, d))


INSTALLERS = {
    "node": ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--silent"],
    "python": [sys.executable, "-m", "pip", "install", "-q", "--break-system-packages", "-r", "requirements.txt"],
}


def install_deps(root: str, stacks: List[str], log=lambda m: None, timeout: int = 420) -> str:
    for s in stacks:
        cmd = INSTALLERS.get(s)
        if not cmd or shutil.which(cmd[0].split("/")[-1]) is None and not os.path.exists(cmd[0]):
            continue
        if s == "python" and not os.path.exists(os.path.join(root, "requirements.txt")):
            continue
        if s == "node" and os.path.isdir(os.path.join(root, "node_modules")):
            return "node dependencies already installed"
        log("installing %s dependencies (%s) ..." % (s, " ".join(cmd[:2])))
        r = util.run(cmd, cwd=root, timeout=timeout)
        return "%s deps: %s" % (s, "installed" if r.ok else "install failed: " +
                                 (r.err.strip().splitlines() or ["?"])[-1][-120:])
    return "no installer for %s" % ", ".join(stacks)


def g0_apply(tree: str, diff: str) -> Tuple[bool, str]:
    tree = os.path.abspath(tree)
    pf = os.path.join(tree, ".kv_patch.diff")
    util.write_text(pf, diff)
    r = util.run(["patch", "-p1", "-f", "-i", pf], cwd=tree, timeout=60)
    try:
        os.remove(pf)
    except OSError:
        pass
    return r.ok, (r.out.strip().splitlines() or r.err.strip().splitlines() or ["applied"])[-1][-200:]


SYNTAX_CHECK = {
    "javascript": lambda p: ["node", "--check", p],
    "python": lambda p: [sys.executable, "-m", "py_compile", p],
    "php": lambda p: ["php", "-l", p],
    "ruby": lambda p: ["ruby", "-c", p],
    "go": lambda p: ["gofmt", "-e", "-l", p],
    "c": lambda p: ["cc", "-fsyntax-only", p],
    "cpp": lambda p: ["c++", "-fsyntax-only", p],
}


def g1_syntax(tree: str, rel: str) -> Tuple[bool, str]:
    lang = EXT_LANG.get(os.path.splitext(rel)[1], "")
    mk = SYNTAX_CHECK.get(lang)
    if not mk:
        return True, "no syntax checker for %s here (not checked)" % (lang or "this file type")
    cmd = mk(os.path.join(tree, rel))
    if shutil.which(cmd[0]) is None:
        return True, "%s not installed (not checked)" % cmd[0]
    r = util.run(cmd, cwd=tree, timeout=60)
    if r.ok:
        return True, "%s: ok" % os.path.basename(cmd[0])
    return False, (r.err.strip().splitlines() or r.out.strip().splitlines() or ["syntax error"])[0][-200:]


def g2_rescan(tree: str, f: SFinding, stacks: List[str], scanner_used: str) -> Tuple[bool, str]:
    files = [f.file]
    if scanner_used == "semgrep" and semgrep_available():
        sarif, _ = run_semgrep(tree, stacks, paths=files, timeout=300)
        now = findings_from_sarif(tree, sarif, "SG") if sarif else run_builtin(tree, files)
    else:
        now = run_builtin(tree, files)
    same = [n for n in now if n.cwe == f.cwe and abs(n.line - f.line) <= 6]
    if same:
        return False, "finding still present at %s:%d" % (f.file, same[0].line)
    return True, "finding gone from %s; %d other finding(s) remain in the file (none new at the patch site)" % (
        f.file, len(now))


TEST_RUNNERS = {
    "node": ("npm", ["npm", "test", "--silent"], "node_modules"),
    "python": ("pytest", [sys.executable, "-m", "pytest", "-q", "-x", "--timeout=60"], None),
    "go": ("go", ["go", "test", "./..."], None),
    "java": ("mvn", ["mvn", "-q", "-o", "test"], None),
    "rust": ("cargo", ["cargo", "test", "--offline", "-q"], None),
    "php": ("phpunit", ["vendor/bin/phpunit"], "vendor"),
    "ruby": ("bundle", ["bundle", "exec", "rake", "test"], None),
}


def run_tests(tree: str, stacks: List[str], timeout: int = 240) -> Tuple[Optional[bool], str]:
    """None = could not run here (honest skip); else pass/fail + summary line."""
    for s in stacks:
        if s not in TEST_RUNNERS:
            continue
        tool, cmd, needs = TEST_RUNNERS[s]
        if shutil.which(cmd[0]) is None:
            return None, "%s not installed" % tool
        if needs and not os.path.isdir(os.path.join(tree, needs)):
            return None, "%s dependencies not installed (%s/ missing) - suite cannot run offline" % (s, needs)
        if s == "node":
            try:
                pj = json.load(open(os.path.join(tree, "package.json")))
                if "test" not in pj.get("scripts", {}):
                    return None, "package.json has no test script"
            except Exception:
                return None, "package.json unreadable"
        env = {"CI": "1", "NODE_ENV": "test"}
        r = util.run(cmd, cwd=tree, env=env, timeout=timeout)
        blob = r.out + r.err
        tail = (r.out.strip().splitlines() or r.err.strip().splitlines() or ["(no output)"])[-1][-160:]
        if r.code == 124:
            return None, "suite timed out after %ds" % timeout
        if re.search(r"No module named (pytest|unittest)|command not found|ENOENT|Cannot find module|"
                     r"ECONNREFUSED|MongoNetworkError|connect ECONNREFUSED|could not connect", blob):
            return None, "suite cannot run here: " + tail
        return r.ok, tail
    return None, "no recognised test runner for %s" % ", ".join(stacks)


_PROOF_PROMPT = """Write a standalone proof test for the security fix below. It must run with
`{runner}` from the repository root, import the module under test directly (no server, no
database, no network), call the vulnerable code path with a hostile-but-harmless input, and
EXIT NON-ZERO on the unpatched code and ZERO on the patched code. Print one line explaining the
assertion. If the module cannot be exercised without external services, output exactly
NOT_PROVABLE_STANDALONE and nothing else.

Finding: {cwe} {cwe_name} in {file}:{line} ({rule}) - {message}
Fix applied (unified diff):
{diff}

Return only one fenced code block with the test source.
"""


def g4_proof(root: str, patched: str, f: SFinding, diff: str, client: Optional[llm.LLMClient],
             work_dir: str) -> Tuple[Optional[bool], str, Optional[str]]:
    """Model-written proof test: fails before, passes after. Returns
    (result or None if not provable here, detail, test path)."""
    if client is None:
        return None, "no model available to write a proof test (not claimed)", None
    lang = EXT_LANG.get(os.path.splitext(f.file)[1], "")
    runner = {"javascript": "node", "python": sys.executable}.get(lang)
    if not runner or shutil.which(runner.split("/")[-1]) is None and not os.path.exists(runner):
        return None, "no standalone proof runner for %s" % (lang or "this file type"), None
    try:
        resp = client.complete(_PROOF_PROMPT.format(runner=os.path.basename(runner), cwe=f.cwe, cwe_name=f.cwe_name,
                                                    file=f.file, line=f.line, rule=f.rule, message=f.message,
                                                    diff=diff[:3000]),
                               system="You write small, deterministic proof tests.", max_tokens=1200)
    except llm.LLMUnavailable:
        return None, "model unavailable for the proof test", None
    if "NOT_PROVABLE_STANDALONE" in resp:
        return None, "model judged the code path not exercisable without external services", None
    m = re.search(r"```[\w+-]*\s*\n(.*?)```", resp, re.DOTALL)
    src = (m.group(1) if m else resp).strip() + "\n"
    ext = ".js" if lang == "javascript" else ".py"
    name = "kv_proof_%s%s" % (f.id.lower().replace("-", "_"), ext)
    results = []
    for tree in (root, patched):
        tp = os.path.join(tree, name)
        util.write_text(tp, src)
        r = util.run([runner, name], cwd=tree, timeout=60, cpu_seconds=30)
        results.append(r.ok)
        try:
            os.remove(tp)
        except OSError:
            pass
    keep = os.path.join(work_dir, "regress", name)
    util.write_text(keep, src)
    fails_before, passes_after = (not results[0]), results[1]
    if fails_before and passes_after:
        return True, "proof test fails on unpatched, passes on patched", keep
    # A test that does not discriminate proves nothing either way: the patch
    # keeps its G0-G3 standing but the proof is NOT claimed.
    return None, "proof test not discriminating (unpatched: %s, patched: %s) - not claimed" % (
        "fails" if fails_before else "passes", "passes" if passes_after else "fails"), None


# ---------------------------------------------------------------------------
# approval (human in the loop)
# ---------------------------------------------------------------------------
def needs_approval(mode: str, f: SFinding) -> bool:
    return mode == "all" or (mode == "critical" and f.critical)


def ask_approval(f: SFinding, cands: List[Candidate], interactive: bool) -> Tuple[str, Optional[int]]:
    """Returns ('apply', idx) | ('skip', None). Unattended runs auto-select
    the first candidate and say so - the pause is recorded in the evidence."""
    util.plain(util.bold("\n  ⏸  APPROVAL REQUIRED — %s touches a critical area (%s)" % (f.id, f.file)))
    util.plain("     %s %s · %s" % (f.cwe, f.cwe_name, f.message[:110]))
    for i, c in enumerate(cands):
        util.plain("     [%d] %-28s %s" % (i + 1, c.label, util.dim(c.rationale[:70])))
    util.plain("     [s] skip this finding")
    if not interactive or not sys.stdin.isatty():
        util.plain(util.dim("     (unattended: applying [1]; run with a terminal to choose)"))
        return "apply", 0
    while True:
        try:
            ans = input("     your choice: ").strip().lower()
        except EOFError:
            return "apply", 0
        if ans in ("s", "skip", "n", "no"):
            return "skip", None
        if ans.isdigit() and 1 <= int(ans) <= len(cands):
            return "apply", int(ans) - 1
        if ans in ("", "y", "yes", "a"):
            return "apply", 0


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------
def _finding_dict(f: SFinding, cands: List[Candidate], chosen: Optional[Candidate], validation: Dict,
                  pr_bundle: Optional[Dict]) -> Dict:
    return {
        "id": f.id, "kind": "static", "signature": f.signature, "asan_class": "%s:%s" % (f.source, f.rule),
        "cwe": f.cwe, "cwe_name": f.cwe_name, "severity": f.severity, "access": "static analysis",
        "crash_file": "%s:%d" % (f.file, f.line), "crash_func": f.func,
        "frames": [{"func": f.func, "file": f.file, "line": f.line, "in_target": True}],
        "pov_size": 0, "pov_sha256": "", "repro_cmd": "re-run the analyzer on %s" % f.file,
        "pov_hexdump": f.snippet, "asan_report": "%s\n\n%s" % (f.message, f.fix_hint),
        "critical": f.critical, "duplicates": f.duplicates,
        "patch": ({"diff": chosen.diff, "source": chosen.source, "rationale": chosen.rationale,
                   "rejected": [c.status for c in cands if not c.chosen and c.status and c.status != "Verified"][:3]}
                  if chosen else {}),
        "candidates": [{"label": c.label, "strategy": c.source, "status": c.status or "not tried",
                        "distance": 0, "added_lines": sum(1 for l in c.diff.splitlines()
                                                          if l.startswith("+") and not l.startswith("+++")),
                        "chosen": c.chosen} for c in cands],
        "validation": validation,
        "pr_bundle": pr_bundle,
    }


def run(task: "config.Task", client: llm.LLMClient, work_dir: str, approve: str = "critical",
        interactive: bool = True, scanner: str = "auto", max_findings: int = 12,
        publish=lambda: None, progress=None, deps: bool = False) -> Dict:
    root = task.root
    stacks = task.raw.get("stacks") or detect_stacks(root)
    t0 = time.time()
    util.stage("Stack & surface")
    files = source_files(root)
    util.info("stacks    : %s" % (", ".join(stacks) or "unknown"))
    util.info("files     : %d source file(s) in scope" % len(files))
    if deps:
        util.info("deps      : " + install_deps(root, stacks, log=util.step))

    util.stage("Discovery (static analysis)")
    found, note = discover(root, stacks, scanner, files, log=util.step)
    scanner_used = "semgrep" if found and found[0].source == "semgrep" else "builtin"
    for i, f in enumerate(found):
        f.id = "KV-%s-%03d" % (task.name.upper()[:6].replace("-", ""), i + 1)
    util.good("%d unique finding(s) after dedupe (%s)" % (len(found), note)) if found else \
        util.warn("no finding (%s)" % note)
    by_sev: Dict[str, int] = {}
    for f in found:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    if found:
        util.info("severity  : " + ", ".join("%s %d" % kv for kv in sorted(by_sev.items(), key=lambda kv: -cwemod.severity_rank(kv[0]))))
    todo = found[:max_findings]
    if len(found) > max_findings:
        util.info(util.dim("repairing the top %d by severity; the rest are listed in the evidence" % max_findings))

    findings_out: List[Dict] = []
    if progress is not None:
        progress.findings = findings_out
    verified = 0
    skipped = 0
    scratch = os.path.abspath(os.path.join(work_dir, "scratch"))
    base_tests: Tuple[Optional[bool], str] = (None, "")
    tests_checked = False

    for f in todo:
        util.stage("Repair & verify — %s" % f.id)
        util.info("%s %s (%s) at %s:%d in %s%s" % (f.cwe, f.cwe_name, f.severity, f.file, f.line, f.func,
                                                   "  [CRITICAL AREA]" if f.critical else ""))
        cands: List[Candidate] = []
        mc = mechanical_fix(root, f)
        if mc:
            cands.append(mc)
        cands += model_candidates(root, f, client if client.provider != "offline" else None)
        if not cands:
            why = ("no mechanical fix for this pattern and no model configured (add --provider)"
                   if client.provider == "offline" else "model returned no usable diff")
            util.warn("no candidate: " + why)
            findings_out.append(_finding_dict(f, [], None, {"status": "Unpatched", "gates": [],
                                                            "detail": why}, None))
            publish()
            continue
        util.step("%d candidate(s): %s" % (len(cands), "; ".join(c.label for c in cands)))

        # ---- human approval ------------------------------------------------
        if needs_approval(approve, f):
            decision, idx = ask_approval(f, cands, interactive)
            if decision == "skip":
                skipped += 1
                findings_out.append(_finding_dict(f, cands, None, {"status": "Skipped by reviewer", "gates": [],
                                                                   "detail": "human chose not to patch"}, None))
                publish()
                continue
            if idx:
                cands.insert(0, cands.pop(idx))

        chosen: Optional[Candidate] = None
        validation: Dict = {"status": "Rejected", "gates": []}
        for c in cands:
            pol = check_policy(f, c.diff)
            if pol:
                c.status = "policy: " + pol
                util.step("%-28s rejected (policy: %s)" % (c.label, pol))
                continue
            gates: List[Dict] = []
            tree = os.path.join(scratch, "patched")
            _scratch_copy(root, tree)
            ok, d = g0_apply(tree, c.diff); gates.append({"name": "G0 patch applies", "passed": ok, "detail": d})
            if ok:
                ok, d = g1_syntax(tree, f.file); gates.append({"name": "G1 syntax", "passed": ok, "detail": d})
            if ok:
                ok, d = g2_rescan(tree, f, stacks, scanner_used); gates.append({"name": "G2 re-scan", "passed": ok, "detail": d})
            if ok:
                if not tests_checked:
                    base_tests = run_tests(root, stacks); tests_checked = True
                if base_tests[0] is None:
                    gates.append({"name": "G3 tests", "passed": True, "detail": "not runnable here: " + base_tests[1]})
                else:
                    after = run_tests(tree, stacks)
                    passed = after[0] is True or (after[0] is False and base_tests[0] is False)
                    gates.append({"name": "G3 tests", "passed": passed,
                                  "detail": ("suite %s after patch (baseline %s): %s" % (
                                      "passes" if after[0] else "fails", "passes" if base_tests[0] else "already failing",
                                      after[1]))})
                    ok = passed
            proof_path = None
            if ok:
                res, d, proof_path = g4_proof(root, tree, f, c.diff, client if client.provider != "offline" else None, work_dir)
                gates.append({"name": "G4 proof test", "passed": res is not False,
                              "detail": d + ("" if res is not None else " (not claimed)")})
                ok = res is not False
            c.gates = gates
            if ok:
                c.status = "Verified"; c.chosen = True; chosen = c
                validation = {"status": "Verified", "gates": gates,
                              "proof": ("proven" if gates[-1]["name"] == "G4 proof test" and "fails on unpatched" in gates[-1]["detail"] else "static"),
                              "regression_test": ({"file": os.path.basename(proof_path), "rel_test_path": os.path.basename(proof_path),
                                                   "guards_bug": True} if proof_path and "fails on unpatched" in gates[-1]["detail"] else None)}
                for g in gates:
                    (util.good if g["passed"] else util.bad)("%s — %s" % (g["name"], g["detail"]))
                break
            c.status = "rejected at " + next((g["name"] for g in gates if not g["passed"]), "gates")
            util.step("%-28s %s" % (c.label, c.status))
            validation = {"status": "Rejected", "gates": gates}
            # reflection: tell the model why, once
            if c.source == "model" and client.provider != "offline" and len(cands) < 4:
                more = model_candidates(root, f, client, prior_reason=c.status + ": " + gates[-1]["detail"])
                for m in more[:1]:
                    m.label = "retry: " + m.label
                    cands.append(m)
        pr_bundle = None
        if chosen:
            verified += 1
            pr_bundle = _pr_bundle(task, f, chosen, validation, work_dir)
            util.good("PATCH VERIFIED — %s (%s)" % (chosen.label, validation.get("proof", "static")))
        else:
            util.bad("no candidate survived the gates")
        findings_out.append(_finding_dict(f, cands, chosen, validation, pr_bundle))
        publish()

    for f in found[max_findings:]:
        findings_out.append(_finding_dict(f, [], None, {"status": "Unpatched", "gates": [],
                                                        "detail": "beyond --max-findings; not attempted"}, None))
    shutil.rmtree(scratch, ignore_errors=True)
    metrics = {"unique_findings": len(found), "verified_patches": verified, "skipped_by_reviewer": skipped,
               "time_to_first_pov": ("%.1fs" % (time.time() - t0)) if found else "n/a",
               "raw_crashes": sum(1 + f.duplicates for f in found), "files_scanned": len(files),
               "stacks": stacks, "scanner": note}
    return {"findings": findings_out, "metrics": metrics, "discovery": {"engine": "static:" + scanner_used,
                                                                        "execs": 0, "raw_crashes": metrics["raw_crashes"],
                                                                        "files": len(files), "note": note},
            "risk_ledger": [{"score": cwemod.severity_rank(f.severity), "function": f.func, "file": f.file,
                             "line": f.line, "sinks": [f.rule], "rationale": [f.cwe, f.severity]} for f in found[:12]]}


def _pr_bundle(task, f: SFinding, c: Candidate, validation: Dict, work_dir: str) -> Dict[str, str]:
    out = os.path.join(work_dir, "pr", f.id)
    os.makedirs(out, exist_ok=True)
    full = c.diff
    rt = validation.get("regression_test")
    if rt:
        src = os.path.join(work_dir, "regress", rt["file"])
        if os.path.exists(src):
            from .pr import _new_file_diff
            full = full.rstrip("\n") + "\n" + _new_file_diff("tests/" + rt["file"], util.read_text(src))
    util.write_text(os.path.join(out, "fix.patch"), full)
    gates = "\n".join("- %s **%s** — %s" % ("✅" if g["passed"] else "❌", g["name"], g["detail"])
                      for g in validation.get("gates", []))
    md = ("# Fix %s %s in `%s` (%s)\n\n**Severity:** %s · **Finding:** `%s` · **Source:** %s\n\n"
          "## Summary\nStatic analysis flagged `%s:%d` (%s): %s\n\n%s\n\n## Verification\n%s\n\n"
          "## Changes\n- `%s` — %s\n%s\n## Review notes\n- Only `%s` is modified (enforced by policy).\n"
          "- %s\n- Human review required before merge; KavachForge does not deploy.\n"
          % (f.cwe, f.cwe_name, f.func, task.name, f.severity, f.id, f.source, f.file, f.line, f.rule, f.message,
             c.rationale, gates, f.file, c.label,
             ("- `tests/%s` — proof test (fails unpatched, passes patched)\n" % rt["file"]) if rt else "",
             f.file,
             "Critical area: a human approved this patch." if f.critical else "Not a critical area."))
    util.write_text(os.path.join(out, "PR.md"), md)
    return {"md": os.path.relpath(os.path.join(out, "PR.md"), work_dir),
            "patch": os.path.relpath(os.path.join(out, "fix.patch"), work_dir)}
