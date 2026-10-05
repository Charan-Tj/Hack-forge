"""Evidence report: a machine-readable JSON bundle and a self-contained
HTML dashboard that renders the full evidence chain for each finding."""
from __future__ import annotations

import html
import os
import time
from typing import Dict, List

from . import util, __version__

SEV_COLOR = {"Critical": "#ff4d6d", "High": "#ff8c42", "Medium": "#ffd23f",
             "Low": "#4dd0a7", "Unknown": "#8aa0b2"}


def build_evidence(task, toolchain_desc, llm_desc, risk_ledger, discovery_stats,
                   findings: List[Dict], metrics: Dict, llm_calls: Dict) -> Dict:
    return {
        "tool": "KavachForge",
        "version": __version__,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + " UTC",
        "task": {"name": task.name, "description": task.description,
                 "language": task.language,
                 "patch_scope": [os.path.relpath(p, task.root) for p in task.patch_scope]},
        "toolchain": toolchain_desc,
        "llm": llm_desc,
        "llm_calls": llm_calls,
        "risk_ledger": risk_ledger,
        "discovery": discovery_stats,
        "metrics": metrics,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def _e(s) -> str:
    return html.escape(str(s))


def _diff_html(diff: str) -> str:
    rows = []
    for line in diff.splitlines():
        cls = "ctx"
        if line.startswith("+++") or line.startswith("---"):
            cls = "meta"
        elif line.startswith("@@"):
            cls = "hunk"
        elif line.startswith("+"):
            cls = "add"
        elif line.startswith("-"):
            cls = "del"
        rows.append('<div class="dl %s">%s</div>' % (cls, _e(line) or "&nbsp;"))
    return "".join(rows)


def _gate_badge(g: Dict) -> str:
    cls = "ok" if g["passed"] else "no"
    sym = "&#10004;" if g["passed"] else "&#10008;"
    return ('<span class="gate %s" title="%s"><b>%s</b> %s</span>'
            % (cls, _e(g["detail"]), sym, _e(g["name"])))


def _finding_card(f: Dict) -> str:
    sev = f.get("severity", "Unknown")
    color = SEV_COLOR.get(sev, "#8aa0b2")
    verified = f.get("validation", {}).get("status") == "Verified"
    vcls = "verified" if verified else "rejected"
    vtxt = "PATCH VERIFIED" if verified else f.get("validation", {}).get("status", "UNPATCHED").upper()
    gates = "".join(_gate_badge(g) for g in f.get("validation", {}).get("gates", []))
    frames = "".join(
        '<div class="frame %s">#%d %s <span class="loc">%s:%d</span></div>'
        % ("t" if fr["in_target"] else "", i, _e(fr["func"]), _e(fr["file"]), fr["line"])
        for i, fr in enumerate(f.get("frames", [])[:6]))
    patch = f.get("patch", {})
    diff_block = ('<div class="diff">%s</div>' % _diff_html(patch.get("diff", ""))
                  if patch.get("diff") else '<div class="muted">No patch produced.</div>')
    reflect = ""
    if patch.get("rejected"):
        reflect = ('<div class="reflect"><b>Self-reflection:</b> '
                   + " &rarr; ".join(_e(r) for r in patch["rejected"]) + "</div>")
    return """
    <div class="card">
      <div class="chead">
        <div>
          <span class="fid">%s</span>
          <span class="cwe" style="border-color:%s;color:%s">%s &middot; %s</span>
          <span class="sev" style="background:%s">%s</span>
        </div>
        <span class="verdict %s">%s</span>
      </div>
      <div class="meta2">%s &nbsp;|&nbsp; access: %s &nbsp;|&nbsp; signature <code>%s</code></div>
      <div class="grid">
        <div class="col">
          <h4>Crash site</h4>
          <div class="crash">%s in <code>%s</code></div>
          <div class="frames">%s</div>
          <h4>Proof-of-vulnerability</h4>
          <div class="pov">%d bytes &middot; sha256 <code>%s</code><br>repro: <code>%s</code></div>
          <pre class="hex">%s</pre>
          <h4>Sanitizer report</h4>
          <pre class="asan">%s</pre>
        </div>
        <div class="col">
          <h4>Root cause &amp; repair <span class="src">%s</span></h4>
          <div class="rc">%s</div>
          %s
          %s
          <h4>Verification gates</h4>
          <div class="gates">%s</div>
        </div>
      </div>
    </div>""" % (
        _e(f["id"]), color, color, _e(f.get("cwe")), _e(f.get("cwe_name")),
        color, _e(sev), vcls, vtxt,
        _e(f.get("asan_class")), _e(f.get("access")), _e(f.get("signature")),
        _e(f.get("crash_file")), _e(f.get("crash_func")), frames,
        f.get("pov_size", 0), _e(f.get("pov_sha256", ""))[:32], _e(f.get("repro_cmd", "")),
        _e(f.get("pov_hexdump", "")),
        _e(f.get("asan_report", "")),
        _e(patch.get("source", "")), _e(patch.get("rationale", "")),
        reflect, diff_block, gates)


def _risk_rows(ledger: List[Dict]) -> str:
    rows = []
    for r in ledger[:12]:
        rows.append(
            "<tr><td class='sc'>%d</td><td><code>%s</code></td><td>%s:%d</td>"
            "<td>%s</td><td class='rat'>%s</td></tr>"
            % (r["score"], _e(r["function"]), _e(r["file"]), r["line"],
               _e(", ".join(r["sinks"]) or "-"),
               _e(" ".join(r["rationale"]))))
    return "".join(rows)


def render_html(ev: Dict) -> str:
    findings = ev["findings"]
    n_verified = sum(1 for f in findings if f.get("validation", {}).get("status") == "Verified")
    m = ev["metrics"]
    cards = "".join(_finding_card(f) for f in findings) or \
        ('<div class="card"><div class="verdict ok2">NO VERIFIED CRASH</div>'
         '<p class="muted">Within the bounded run, KavachForge found no '
         'reproducible fault in this target and did not invent one.</p></div>')
    stat = lambda label, val: ('<div class="stat"><div class="sv">%s</div>'
                               '<div class="sl">%s</div></div>' % (_e(val), _e(label)))
    stats = "".join([
        stat("findings", len(findings)),
        stat("verified patches", n_verified),
        stat("unverified alerts", 0),
        stat("time to 1st PoV", m.get("time_to_first_pov", "n/a")),
        stat("LLM calls", ev["llm_calls"].get("live", 0)),
        stat("engine", ev["discovery"].get("engine", "?")),
    ])
    return _TEMPLATE % {
        "title": _e("KavachForge — " + ev["task"]["name"]),
        "task": _e(ev["task"]["name"]),
        "desc": _e(ev["task"]["description"]),
        "gen": _e(ev["generated_at"]),
        "ver": _e(ev["version"]),
        "tc": _e(ev["toolchain"]),
        "llm": _e(ev["llm"]),
        "stats": stats,
        "risk_rows": _risk_rows(ev["risk_ledger"]),
        "cards": cards,
    }


def write_reports(ev: Dict, out_dir: str) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    jpath = os.path.join(out_dir, "evidence.json")
    hpath = os.path.join(out_dir, "dashboard.html")
    util.write_json(jpath, ev)
    util.write_text(hpath, render_html(ev))
    return {"json": jpath, "html": hpath}


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
<style>
:root{--bg:#0b0f14;--panel:#121923;--panel2:#0e141c;--line:#1e2a38;--tx:#e6edf3;--mut:#8aa0b2;--acc:#4da3ff;--add:#1b3a2b;--del:#3a1b22;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
code{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace;font-size:12px;color:#9fd0ff}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
header{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:20px}
.brand{font-size:22px;font-weight:700;letter-spacing:.3px}
.brand .k{color:var(--acc)}
.sub{color:var(--mut);margin-top:4px}
.pill{display:inline-block;background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:3px 10px;margin:6px 6px 0 0;color:var(--mut);font-size:12px}
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:18px 0}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px}
.sv{font-size:20px;font-weight:700}
.sl{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);margin:26px 0 10px}
h4{font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);margin:16px 0 6px}
table{width:100%%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
td.sc{font-weight:700;color:var(--acc)}
td.rat{color:var(--mut);font-size:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
.chead{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.fid{font-weight:700;margin-right:8px}
.cwe{border:1px solid;border-radius:6px;padding:2px 8px;font-size:12px;margin-right:8px}
.sev{border-radius:6px;padding:2px 8px;font-size:12px;color:#0b0f14;font-weight:700}
.verdict{font-weight:700;font-size:12px;padding:5px 12px;border-radius:8px}
.verdict.verified{background:#12361f;color:#49e08a;border:1px solid #1f5e36}
.verdict.rejected{background:#3a1b22;color:#ff8097;border:1px solid #5e1f2c}
.verdict.ok2{background:#12361f;color:#49e08a;border:1px solid #1f5e36;display:inline-block;margin-bottom:8px}
.meta2{color:var(--mut);font-size:12px;margin:8px 0 4px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:8px}
.crash{font-size:13px}.rc{font-size:13px}
.frame{font-size:12px;color:var(--mut);padding:1px 0}
.frame.t{color:var(--tx)}
.frame .loc{color:var(--acc)}
.pov{font-size:12px;color:var(--mut)}
pre{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;font-size:11.5px;margin:6px 0}
pre.hex{max-height:150px}pre.asan{max-height:230px;white-space:pre-wrap}
.src{float:right;color:var(--mut);font-size:10px;border:1px solid var(--line);border-radius:6px;padding:1px 6px;text-transform:none;letter-spacing:0}
.diff{background:var(--panel2);border:1px solid var(--line);border-radius:8px;overflow:auto;font-family:"SFMono-Regular",Consolas,monospace;font-size:11.5px}
.dl{padding:0 10px;white-space:pre}
.dl.add{background:var(--add);color:#8fe0a8}
.dl.del{background:var(--del);color:#ffa0b0}
.dl.hunk{color:var(--acc)}
.dl.meta{color:var(--mut)}
.gate{display:inline-block;border-radius:6px;padding:3px 8px;margin:3px 4px 0 0;font-size:11px;border:1px solid var(--line)}
.gate.ok{background:#12361f;color:#49e08a;border-color:#1f5e36}
.gate.no{background:#3a1b22;color:#ff8097;border-color:#5e1f2c}
.reflect{color:var(--mut);font-size:12px;margin:6px 0}
.muted{color:var(--mut)}
@media(max-width:820px){.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}}
</style></head>
<body><div class="wrap">
<header>
  <div class="brand"><span class="k">Kavach</span>Forge <span style="font-size:13px;color:var(--mut)">v%(ver)s</span></div>
  <div class="sub">Evidence-gated vulnerability discovery &amp; repair &mdash; from alert to proof</div>
  <div style="margin-top:8px">
    <span class="pill">target: <b style="color:var(--tx)">%(task)s</b></span>
    <span class="pill">%(desc)s</span>
    <span class="pill">toolchain: %(tc)s</span>
    <span class="pill">model: %(llm)s</span>
    <span class="pill">generated %(gen)s</span>
  </div>
</header>
<div class="stats">%(stats)s</div>
<h2>Risk ledger &mdash; diff-to-sink prioritization (pre-LLM, deterministic)</h2>
<table><tr><th>score</th><th>function</th><th>location</th><th>sinks</th><th>why</th></tr>%(risk_rows)s</table>
<h2>Findings &mdash; verified evidence chain</h2>
%(cards)s
<p class="muted" style="margin-top:24px;font-size:12px">KavachForge reports a finding only with a reproducible proof-of-vulnerability, and marks a patch Verified only after it builds, blocks that PoV, and passes the regression suite. Patches are recommendations for human review, not autonomous deployment.</p>
</div></body></html>"""
