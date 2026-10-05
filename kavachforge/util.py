"""Shared utilities: logging, subprocess control, hashing, JSON I/O."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Terminal styling (degrades to plain text when not a TTY or NO_COLOR is set)
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    if not _USE_COLOR:
        return s
    return f"\033[{code}m{s}\033[0m"


def bold(s: str) -> str:   return _c("1", s)
def dim(s: str) -> str:    return _c("2", s)
def red(s: str) -> str:    return _c("31", s)
def green(s: str) -> str:  return _c("32", s)
def yellow(s: str) -> str: return _c("33", s)
def blue(s: str) -> str:   return _c("36", s)
def mag(s: str) -> str:    return _c("35", s)

# Glyphs kept as constants so they never appear as backslash escapes inside
# f-string expressions (a syntax error on Python < 3.12).
G_TRI = "▶"    # triangle
G_CHK = "✔"    # check
G_WRN = "⚠"    # warning
G_X = "✖"      # cross
G_ARR = "→"    # arrow
G_BAR = "━"    # heavy bar

_STAGE = 0


def stage(title: str) -> None:
    """Print a numbered pipeline-stage banner."""
    global _STAGE
    _STAGE += 1
    bar = G_BAR * max(4, 56 - len(title))
    label = bold("[%d] %s" % (_STAGE, title))
    print("\n%s %s %s" % (blue(G_TRI), label, dim(bar)))


def info(msg: str) -> None:  print("  " + msg)
def good(msg: str) -> None:  print("  %s %s" % (green(G_CHK), msg))
def warn(msg: str) -> None:  print("  %s %s" % (yellow(G_WRN), msg))
def bad(msg: str) -> None:   print("  %s %s" % (red(G_X), msg))
def step(msg: str) -> None:  print("  %s %s" % (dim(G_ARR), msg))


# ---------------------------------------------------------------------------
# Subprocess
# ---------------------------------------------------------------------------
@dataclass
class CmdResult:
    code: int
    out: str
    err: str
    seconds: float

    @property
    def ok(self) -> bool:
        return self.code == 0


def run(cmd, cwd=None, env=None, timeout=None, input_bytes=None) -> CmdResult:
    """Run a command (list or str). Never raises on non-zero exit."""
    shell = isinstance(cmd, str)
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, cwd=cwd, env=full_env, shell=shell,
            capture_output=True, timeout=timeout, input=input_bytes,
        )
        return CmdResult(
            p.returncode,
            p.stdout.decode("utf-8", "replace"),
            p.stderr.decode("utf-8", "replace"),
            time.time() - t0,
        )
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace")
        err = (e.stderr or b"").decode("utf-8", "replace")
        return CmdResult(124, out, err + "\n[timeout]", time.time() - t0)
    except FileNotFoundError as e:
        return CmdResult(127, "", str(e), time.time() - t0)


# ---------------------------------------------------------------------------
# Hashing / IO
# ---------------------------------------------------------------------------
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.write("\n")


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def hexdump(b: bytes, limit: int = 256) -> str:
    """Compact hex+ascii dump, truncated to `limit` bytes."""
    out = []
    data = b[:limit]
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join(f"{x:02x}" for x in chunk)
        asci = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out.append(f"{off:08x}  {hexs:<47}  {asci}")
    if len(b) > limit:
        out.append(f"... ({len(b) - limit} more bytes)")
    return "\n".join(out)
