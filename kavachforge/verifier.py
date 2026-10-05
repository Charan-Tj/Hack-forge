"""Evidence verifier: confirm each crash reproduces, normalize its stack
signature for deduplication, and classify it (CWE + severity).

A crash is only promoted to a *finding* if it reproduces on a fresh run, so
no unverified alert ever reaches the report (false-positive control)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import config, cwe, discovery, util

# ASan: "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address ..."
_CLASS_RE = re.compile(r"ERROR: AddressSanitizer:\s*([a-zA-Z0-9\-]+)")
_UBSAN_RE = re.compile(r"runtime error:\s*(.+)")
# frame: "    #1 0x.... in func /path/file.c:54:12"
_FRAME_RE = re.compile(r"#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^\s:]+):(\d+)")
_OP_RE = re.compile(r"\b(READ|WRITE)\s+of\s+size\s+(\d+)")


@dataclass
class Finding:
    id: str
    signature: str
    asan_class: str
    cwe: str
    cwe_name: str
    severity: str
    access: str
    crash_file: str                    # display path "file.c:line"
    crash_func: str
    frames: List[Dict] = field(default_factory=list)
    pov_path: str = ""
    pov_sha256: str = ""
    pov_size: int = 0
    repro_cmd: str = ""
    asan_report: str = ""
    root_cause: str = ""


def _extract_class(blob: str) -> str:
    m = _CLASS_RE.search(blob)
    if m:
        return m.group(1)
    u = _UBSAN_RE.search(blob)
    if u:
        return "undefined-behavior"
    return "unknown"


def _extract_frames(blob: str, source_basenames) -> List[Dict]:
    frames = []
    for m in _FRAME_RE.finditer(blob):
        func, path, line = m.group(2), m.group(3), int(m.group(4))
        frames.append({"func": func, "file": os.path.basename(path),
                       "line": line, "in_target":
                       os.path.basename(path) in source_basenames})
    return frames


def _trim_report(blob: str, max_lines: int = 40) -> str:
    start = blob.find("ERROR: AddressSanitizer")
    if start < 0:
        start = max(0, blob.find("runtime error:"))
    chunk = blob[start:]
    return "\n".join(chunk.splitlines()[:max_lines])


def _signature(asan_class: str, frames: List[Dict]) -> str:
    """Normalized, address-free signature: class + top in-target frames."""
    top = [f for f in frames if f["in_target"]][:3] or frames[:3]
    key = asan_class + "|" + "|".join("%s@%s:%d" % (f["func"], f["file"], f["line"])
                                      for f in top)
    return util.sha256_bytes(key.encode())[:16]


def verify(task: "config.Task", fuzzer_bin: str,
           raw_crashes: List[Dict]) -> List[Finding]:
    source_basenames = {os.path.basename(s) for s in task.sources}
    seen = {}
    findings: List[Finding] = []

    for rc in raw_crashes:
        pov = rc["input_path"]
        # Reproduce on a fresh run (confirm it is real and deterministic).
        res = discovery._run_one(fuzzer_bin, pov, task.rss_mb)
        if not discovery._is_crash(res):
            util.warn("candidate did not reproduce; discarded: %s" % os.path.basename(pov))
            continue
        blob = res.err + res.out
        asan_class = _extract_class(blob)
        frames = _extract_frames(blob, source_basenames)
        sig = _signature(asan_class, frames)
        if sig in seen:
            continue
        seen[sig] = True

        cls = cwe.classify(asan_class)
        op = _OP_RE.search(blob)
        access = ("%s %sB" % (op.group(1).title(), op.group(2))) if op else "n/a"
        site = next((f for f in frames if f["in_target"]), frames[0] if frames else None)
        with open(pov, "rb") as f:
            data = f.read()

        fid = "KV-%s-%03d" % (task.name.upper()[:6], len(findings) + 1)
        findings.append(Finding(
            id=fid, signature=sig, asan_class=asan_class,
            cwe=cls["cwe"], cwe_name=cls["cwe_name"], severity=cls["severity"],
            access=access,
            crash_file=("%s:%d" % (site["file"], site["line"]) if site else "unknown"),
            crash_func=(site["func"] if site else "unknown"),
            frames=frames, pov_path=pov, pov_sha256=util.sha256_file(pov),
            pov_size=len(data),
            repro_cmd="%s %s" % (os.path.basename(fuzzer_bin), os.path.basename(pov)),
            asan_report=_trim_report(blob),
        ))
    findings.sort(key=lambda f: -cwe.severity_rank(f.severity))
    return findings
