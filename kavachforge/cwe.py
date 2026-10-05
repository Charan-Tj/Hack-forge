"""Map AddressSanitizer / UBSan error classes to CWE identifiers and a
coarse severity. Used to turn a raw sanitizer report into a
judge-readable finding (predictive threat-intelligence framing)."""
from __future__ import annotations

from typing import Dict

# sanitizer error-class substring -> (CWE id, human name, severity)
_TABLE = [
    ("stack-buffer-overflow",   ("CWE-787", "Out-of-bounds Write (stack)", "High")),
    ("heap-buffer-overflow",    ("CWE-787", "Out-of-bounds Write (heap)", "Critical")),
    ("global-buffer-overflow",  ("CWE-787", "Out-of-bounds Write (global)", "High")),
    ("stack-buffer-underflow",  ("CWE-124", "Buffer Underwrite", "High")),
    ("heap-use-after-free",     ("CWE-416", "Use After Free", "Critical")),
    ("double-free",             ("CWE-415", "Double Free", "High")),
    ("attempting free",         ("CWE-590", "Free of Invalid Pointer", "High")),
    ("alloc-dealloc-mismatch",  ("CWE-762", "Mismatched Memory Management", "Medium")),
    ("memory leak",             ("CWE-401", "Memory Leak", "Low")),
    ("stack-overflow",          ("CWE-674", "Uncontrolled Recursion", "Medium")),
    ("negative-size-param",     ("CWE-131", "Incorrect Buffer Size Calculation", "High")),
    ("SEGV",                    ("CWE-476", "NULL Pointer Dereference / Invalid Access", "High")),
    ("integer-overflow",        ("CWE-190", "Integer Overflow", "Medium")),
    ("signed-integer-overflow", ("CWE-190", "Integer Overflow", "Medium")),
    ("shift",                   ("CWE-1335", "Incorrect Bitwise Shift", "Low")),
    ("undefined-behavior",      ("CWE-758", "Undefined Behavior", "Medium")),
]

_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def classify(asan_class: str, access: str = "") -> Dict[str, str]:
    """Map a sanitizer class (+ READ/WRITE direction) to CWE + severity.
    ASan reports *-buffer-overflow for both reads and writes; the direction
    decides between CWE-787 (write) and CWE-125 (read)."""
    cls = (asan_class or "").lower()
    for needle, (cwe, name, sev) in _TABLE:
        if needle.lower() in cls:
            if "buffer-overflow" in cls and (access or "").lower().startswith("read"):
                region = name[name.find("("):] if "(" in name else ""
                return {"cwe": "CWE-125", "cwe_name": "Out-of-bounds Read " + region,
                        "severity": "High"}
            return {"cwe": cwe, "cwe_name": name, "severity": sev}
    return {"cwe": "CWE-Unknown", "cwe_name": "Unclassified memory-safety fault",
            "severity": "Unknown"}


def severity_rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev, 0)
