"""Evidence report: a machine-readable JSON bundle, a self-contained HTML
dashboard that renders the full evidence chain (and auto-refreshes while a
run is in progress), and a showcase index page listing every target."""
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
# HTML helpers
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


def _stage_strip(stages: List[Dict]) -> str:
    out = []
    for s in stages:
        out.append('<div class="st %s"><span class="dot"></span>%s</div>'
                   % (_e(s["status"]), _e(s["label"])))
    return '<div class="stages">%s</div>' % "".join(out)


def _finding_card(f: Dict) -> str:
    sev = f.get("severity", "Unknown")
    color = SEV_COLOR.get(sev, "#8aa0b2")
    vstat = f.get("validation", {}).get("status", "Unpatched")
    verified = vstat == "Verified"
    vcls = "verified" if verified else ("pending" if vstat == "Unpatched" else "rejected")
    vtxt = ("PATCH VERIFIED" if verified else
            "REPAIR PENDING" if vstat == "Unpatched" else vstat.upper())
    gates = "".join(_gate_badge(g) for g in f.get("validation", {}).get("gates", []))
    if not gates:
        gates = '<span class="muted">awaiting repair &amp; verification&hellip;</span>'
    frames = "".join(
        '<div class="frame %s">#%d %s <span class="loc">%s:%d</span></div>'
        % ("t" if fr["in_target"] else "", i, _e(fr["func"]), _e(fr["file"]), fr["line"])
        for i, fr in enumerate(f.get("frames", [])[:6]))
    patch = f.get("patch", {})
    diff_block = ('<div class="diff">%s</div>' % _diff_html(patch.get("diff", ""))
                  if patch.get("diff") else '<div class="muted">No patch yet.</div>')
    reflect = ""
    if patch.get("rejected"):
        reflect = ('<div class="reflect"><b>Self-reflection:</b> '
                   + " &rarr; ".join(_e(r) for r in patch["rejected"]) + "</div>")
    dups = f.get("duplicates", 0)
    dup_txt = (" &nbsp;|&nbsp; <b>%d</b> duplicate crash(es) collapsed into this finding"
               % dups) if dups else ""
    deliver = ""
    rt = f.get("validation", {}).get("regression_test")
    pb = f.get("pr_bundle")
    if rt or pb:
        bits = []
        if rt:
            bits.append('<a class="dl-link %s" href="regress/%s" target="_blank">'
                        '&#9881; regression test %s</a>'
                        % ("ok" if rt.get("guards_bug") else "", _e(rt["file"]),
                           "(proven: fails unpatched, passes patched)" if rt.get("guards_bug")
                           else "(generated)"))
        if pb:
            bits.append('<a class="dl-link ok" href="%s" target="_blank">&#128203; PR.md</a>'
                        % _e(pb["md"]))
            bits.append('<a class="dl-link ok" href="%s" target="_blank">&#128190; fix.patch '
                        '(fix + test)</a>' % _e(pb["patch"]))
        deliver = '<h4>Merge-ready deliverables</h4><div class="deliver">%s</div>' % " ".join(bits)
    ens = ""
    cs = f.get("candidates")
    if cs and len(cs) > 1:
        rows = []
        for c in cs:
            mark = " &#9733;" if c.get("chosen") else ""
            st = c.get("status", "")
            cls = "ok" if st == "Verified" else ("" if c.get("chosen") else "no")
            rows.append("<tr class='%s'><td>%s%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>"
                        % (cls, _e(c.get("label","")), mark, _e(c.get("strategy","")),
                           _e(st), c.get("distance",0), c.get("added_lines",0)))
        ens = ("<h4>Patch ensemble &mdash; ranked by root-cause proximity</h4>"
               "<table class='ens'><tr><th>candidate</th><th>strategy</th><th>result</th>"
               "<th>dist&nbsp;to&nbsp;root</th><th>+lines</th></tr>%s</table>"
               % "".join(rows))
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
      <div class="meta2">%s &nbsp;|&nbsp; access: %s &nbsp;|&nbsp; signature <code>%s</code>%s</div>
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
          %s
          <h4>Verification gates</h4>
          <div class="gates">%s</div>
          %s
        </div>
      </div>
    </div>""" % (
        _e(f["id"]), color, color, _e(f.get("cwe")), _e(f.get("cwe_name")),
        color, _e(sev), vcls, vtxt,
        _e(f.get("asan_class")), _e(f.get("access")), _e(f.get("signature")), dup_txt,
        _e(f.get("crash_file")), _e(f.get("crash_func")), frames,
        f.get("pov_size", 0), _e(f.get("pov_sha256", ""))[:32], _e(f.get("repro_cmd", "")),
        _e(f.get("pov_hexdump", "")),
        _e(f.get("asan_report", "")),
        _e(patch.get("source", "")), _e(patch.get("rationale", "")),
        reflect, diff_block, ens, gates, deliver)


def _risk_rows(ledger: List[Dict]) -> str:
    rows = []
    for r in ledger[:12]:
        rows.append(
            "<tr><td class='sc'>%d</td><td><code>%s</code></td><td>%s:%d</td>"
            "<td>%s</td><td class='rat'>%s</td></tr>"
            % (r["score"], _e(r["function"]), _e(r["file"]), r["line"],
               _e(", ".join(r["sinks"]) or "-"),
               _e(" ".join(r["rationale"]))))
    return "".join(rows) or "<tr><td colspan=5 class='muted'>ranking&hellip;</td></tr>"


def _uplift_html(u) -> str:
    if not u:
        return ""
    unseeded = ("%.1fs" % u["first_crash_s"]) if u.get("first_crash_s") is not None \
        else "none within %ds" % u["budget_s"]
    return ('<h2>Seed uplift &mdash; measured A/B (structure-aware seeds vs empty corpus)</h2>'
            '<div class="card small">unseeded time-to-first-crash: <b>%s</b> '
            '(%s execs) &nbsp;&middot;&nbsp; %s</div>'
            % (_e(unseeded), "{:,}".format(u.get("execs", 0)), _e(u.get("note", ""))))


def render_html(ev: Dict) -> str:
    findings = ev["findings"]
    n_verified = sum(1 for f in findings if f.get("validation", {}).get("status") == "Verified")
    m = ev["metrics"]
    d = ev.get("discovery", {})
    live = ev.get("run_status") == "running"
    if findings:
        cards = "".join(_finding_card(f) for f in findings)
    elif ev.get("run_status") == "done":
        cards = ('<div class="card"><div class="verdict ok2">NO VERIFIED CRASH</div>'
                 '<p class="muted">Within the bounded run (%s execs on %s), KavachForge '
                 'found no reproducible fault in this target and did not invent one.</p></div>'
                 % ("{:,}".format(d.get("execs", 0)), _e(d.get("engine", "fuzzer"))))
    elif ev.get("run_status") == "error":
        cards = ('<div class="card"><div class="verdict rejected">RUN ERROR</div>'
                 '<pre class="asan">%s</pre></div>' % _e(ev.get("error", "")))
    else:
        cards = '<div class="card muted">discovery in progress&hellip;</div>'

    stat = lambda label, val: ('<div class="stat"><div class="sv">%s</div>'
                               '<div class="sl">%s</div></div>' % (_e(val), _e(label)))
    raw = d.get("raw_crashes", m.get("raw_crashes", 0)) or 0
    stats = "".join([
        stat("raw crashes → unique", "%d → %d" % (raw, len(findings))),
        stat("verified patches", n_verified),
        stat("unverified alerts", 0),
        stat("time to 1st PoV", m.get("time_to_first_pov", "n/a")),
        stat("fuzz execs", "{:,}".format(d.get("execs", 0))),
        stat("LLM calls", "%s / %s" % (ev["llm_calls"].get("live", 0),
                                       ev["llm_calls"].get("budget", 0))),
    ])
    ing = ev.get("ingestion", {})
    ing_txt = ("diff: <b>%s</b> (%d file(s)) &nbsp;&middot;&nbsp; static alerts: <b>%s</b> (%d)"
               % (_e(ing.get("diff_source", "task")), len(ing.get("changed_files", [])),
                  _e(ing.get("sarif_source", "none")), ing.get("alerts", 0)))
    status_pill = ('<span class="pill live">&#9679; LIVE &mdash; running</span>' if live
                   else '<span class="pill done">run complete</span>')
    return _TEMPLATE % {
        "title": _e("KavachForge — " + ev["task"]["name"]),
        "task": _e(ev["task"]["name"]),
        "desc": _e(ev["task"]["description"]),
        "gen": _e(ev["generated_at"]),
        "ver": _e(ev["version"]),
        "tc": _e(ev["toolchain"]),
        "llm": _e(ev["llm"]),
        "status_pill": status_pill,
        "stages": _stage_strip(ev.get("stages", [])),
        "stats": stats,
        "ingest": ing_txt,
        "risk_rows": _risk_rows(ev["risk_ledger"]),
        "uplift": _uplift_html(ev.get("uplift")),
        "cards": cards,
        "revision": ev.get("revision", 0),
        "poll": "true" if live else "false",
    }


def write_reports(ev: Dict, out_dir: str) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    jpath = os.path.join(out_dir, "evidence.json")
    hpath = os.path.join(out_dir, "dashboard.html")
    util.write_json(jpath, ev)
    util.write_text(hpath, render_html(ev))
    # Keep the showcase index live too, if one has been set up.
    root = os.path.dirname(os.path.abspath(out_dir))
    cfg = os.path.join(root, ".showcase.json")
    if os.path.exists(cfg):
        try:
            write_index(root, util.read_json(cfg).get("tasks", []))
        except Exception:
            pass
    return {"json": jpath, "html": hpath}


# ---------------------------------------------------------------------------
# Showcase index
# ---------------------------------------------------------------------------
def render_index(root: str, tasks: List[str]) -> str:
    cards = []
    for name in tasks:
        jp = os.path.join(root, name, "evidence.json")
        if os.path.exists(jp):
            try:
                ev = util.read_json(jp)
            except Exception:
                ev = None
        else:
            ev = None
        if not ev:
            cards.append('<a class="tcard pending" href="%s/dashboard.html"><div class="tn">%s</div>'
                         '<div class="ts">queued</div></a>' % (_e(name), _e(name)))
            continue
        m = ev["metrics"]
        rs = ev.get("run_status", "done")
        nf, nv = m["unique_findings"], m["verified_patches"]
        if rs == "running":
            cls, txt = "running", "&#9679; running"
        elif rs == "error":
            cls, txt = "err", "error"
        elif nv > 0:
            cls, txt = "ok", "%d finding(s) &middot; %d patch(es) VERIFIED" % (nf, nv)
        elif nf > 0:
            cls, txt = "warn", "%d finding(s) &middot; repair rejected" % nf
        else:
            cls, txt = "clean", "no verified crash (control)"
        cards.append('<a class="tcard %s" href="%s/dashboard.html"><div class="tn">%s</div>'
                     '<div class="td">%s</div><div class="ts">%s</div>'
                     '<div class="tm">%s execs &middot; first PoV %s</div></a>'
                     % (cls, _e(name), _e(name), _e(ev["task"]["description"]), txt,
                        "{:,}".format(ev.get("discovery", {}).get("execs", 0)),
                        _e(m.get("time_to_first_pov", "n/a"))))
    return _INDEX % {"cards": "".join(cards), "ver": _e(__version__)}


def write_index(root: str, tasks: List[str]) -> str:
    p = os.path.join(root, "index.html")
    util.write_text(p, render_index(root, tasks))
    return p


_CSS = """
:root{--bg:#0b0f14;--panel:#121923;--panel2:#0e141c;--line:#1e2a38;--tx:#e6edf3;--mut:#8aa0b2;--acc:#4da3ff;--add:#1b3a2b;--del:#3a1b22;--ok:#49e08a;--bad:#ff8097;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
code{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace;font-size:12px;color:#9fd0ff}
a{color:inherit;text-decoration:none}
.wrap{max-width:1120px;margin:0 auto;padding:24px 16px 64px}
header{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:18px}
.brand{font-size:22px;font-weight:700;letter-spacing:.3px}
.brand .k{color:var(--acc)}
.sub{color:var(--mut);margin-top:4px}
.pill{display:inline-block;background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:3px 10px;margin:6px 6px 0 0;color:var(--mut);font-size:12px}
.pill.live{color:#ffd23f;border-color:#5a4a12;animation:pulse 1.4s infinite}
.pill.done{color:var(--ok);border-color:#1f5e36}
@keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:.55}}
.stages{display:flex;gap:6px;flex-wrap:wrap;margin:14px 0 4px}
.st{flex:1;min-width:140px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:12px;color:var(--mut);display:flex;align-items:center;gap:8px}
.st .dot{width:9px;height:9px;border-radius:50%%;background:#2b3a4c;display:inline-block}
.st.running{color:#ffd23f;border-color:#5a4a12}.st.running .dot{background:#ffd23f;animation:pulse 1s infinite}
.st.done{color:var(--ok);border-color:#1f5e36}.st.done .dot{background:var(--ok)}
.st.skipped{opacity:.5}
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:14px 0}
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
.card.small{padding:10px 14px;font-size:13px}
.chead{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.fid{font-weight:700;margin-right:8px}
.cwe{border:1px solid;border-radius:6px;padding:2px 8px;font-size:12px;margin-right:8px}
.sev{border-radius:6px;padding:2px 8px;font-size:12px;color:#0b0f14;font-weight:700}
.verdict{font-weight:700;font-size:12px;padding:5px 12px;border-radius:8px}
.verdict.verified{background:#12361f;color:var(--ok);border:1px solid #1f5e36}
.verdict.rejected{background:#3a1b22;color:var(--bad);border:1px solid #5e1f2c}
.verdict.pending{background:#2d2a12;color:#ffd23f;border:1px solid #5a4a12}
.verdict.ok2{background:#12361f;color:var(--ok);border:1px solid #1f5e36;display:inline-block;margin-bottom:8px}
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
.gate.ok{background:#12361f;color:var(--ok);border-color:#1f5e36}
.gate.no{background:#3a1b22;color:var(--bad);border-color:#5e1f2c}
.reflect{color:var(--mut);font-size:12px;margin:6px 0}
.deliver{display:flex;flex-wrap:wrap;gap:6px}\ntable.ens{margin:4px 0 2px}table.ens td,table.ens th{padding:4px 8px;font-size:12px}table.ens tr.ok td{color:var(--ok)}table.ens tr.no td{color:var(--mut)}
.dl-link{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:4px 9px;font-size:12px;color:var(--mut)}
.dl-link.ok{color:var(--ok);border-color:#1f5e36}
.dl-link:hover{border-color:var(--acc);color:var(--tx)}
.muted{color:var(--mut)}
.tgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}
.tcard{display:block;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;transition:transform .12s}
.tcard:hover{transform:translateY(-2px);border-color:var(--acc)}
.tn{font-weight:700;font-size:16px}.td{color:var(--mut);font-size:12px;margin:4px 0 10px}
.ts{font-weight:700;font-size:12px}.tm{color:var(--mut);font-size:11px;margin-top:6px}
.tcard.ok .ts{color:var(--ok)}.tcard.clean .ts{color:var(--acc)}.tcard.warn .ts,.tcard.err .ts{color:var(--bad)}
.tcard.running .ts{color:#ffd23f;animation:pulse 1.2s infinite}.tcard.pending{opacity:.6}
@media(max-width:820px){.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.tgrid{grid-template-columns:1fr}}
"""

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
<style>""" + _CSS + """</style></head>
<body><div class="wrap">
<header>
  <div class="brand"><a href="../index.html"><span class="k">Kavach</span>Forge</a> <span style="font-size:13px;color:var(--mut)">v%(ver)s</span></div>
  <div class="sub">Evidence-gated vulnerability discovery &amp; repair &mdash; from alert to proof</div>
  <div style="margin-top:8px">
    %(status_pill)s
    <span class="pill">target: <b style="color:var(--tx)">%(task)s</b></span>
    <span class="pill">%(desc)s</span>
    <span class="pill">engine: %(tc)s</span>
    <span class="pill">model: %(llm)s</span>
    <span class="pill">updated %(gen)s</span>
  </div>
  %(stages)s
</header>
<div class="stats">%(stats)s</div>
<h2>Input signals</h2>
<div class="card small">%(ingest)s</div>
<h2>Risk ledger &mdash; diff-to-sink prioritization (pre-LLM, deterministic)</h2>
<table><tr><th>score</th><th>function</th><th>location</th><th>sinks</th><th>why</th></tr>%(risk_rows)s</table>
%(uplift)s
<h2>Findings &mdash; verified evidence chain</h2>
%(cards)s
<p class="muted" style="margin-top:24px;font-size:12px">KavachForge reports a finding only with a reproducible proof-of-vulnerability, and marks a patch Verified only after it builds, blocks that PoV, and passes the regression suite. Patches are recommendations for human review, not autonomous deployment.</p>
</div>
<script>
(function(){
  var rev=%(revision)d, poll=%(poll)s;
  if(!poll) return;
  function tick(){
    fetch('evidence.json?t='+Date.now(),{cache:'no-store'}).then(function(r){return r.json()})
      .then(function(j){ if(j.revision && j.revision!==rev){ location.reload(); } })
      .catch(function(){});
  }
  setInterval(tick, 1500);
})();
</script>
</body></html>"""

_INDEX = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KavachForge &mdash; Showcase</title>
<meta http-equiv="refresh" content="2">
<style>""" + _CSS + """</style></head>
<body><div class="wrap">
<header>
  <div class="brand"><span class="k">Kavach</span>Forge <span style="font-size:13px;color:var(--mut)">v%(ver)s</span></div>
  <div class="sub">Evidence-gated vulnerability discovery &amp; repair &mdash; live showcase</div>
  <div style="margin-top:8px">
    <span class="pill">no finding without a reproducible PoV</span>
    <span class="pill">no fix until it builds, blocks the PoV, and passes tests</span>
    <span class="pill">human approves every patch</span>
  </div>
</header>
<div class="tgrid">%(cards)s</div>
<p class="muted" style="margin-top:24px;font-size:12px">Click a target to open its full evidence chain. This page refreshes automatically while a run is in progress.</p>
</div></body></html>"""
