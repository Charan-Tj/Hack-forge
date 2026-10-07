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
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]

# Vulnerability TYPE (family) from CWE - what judges ask after severity and class.
CWE_TYPE = {
    "Injection": {"78", "89", "94", "95", "943", "917", "98", "611", "77", "90", "91", "1336"},
    "Memory safety": {"120", "121", "122", "125", "787", "416", "476", "674", "190", "191", "415",
                      "119", "170", "131", "369", "401"},
    "Access control / auth": {"639", "862", "863", "306", "287", "284", "285", "352", "521", "307", "204"},
    "Crypto & secrets": {"327", "328", "326", "798", "347", "522", "295", "614", "1004", "319", "321", "330", "338"},
    "Data exposure & config": {"200", "215", "489", "1357", "269", "250", "829", "16", "532", "209", "1275"},
    "Input validation / DoS": {"1333", "770", "400", "20", "22", "23", "36", "434", "915", "502"},
    "Cross-site scripting": {"79", "116", "80"},
    "Redirect / SSRF": {"601", "918"},
}


def cwe_type(cwe: str) -> str:
    n = (cwe or "").upper().replace("CWE-", "")
    for fam, ids in CWE_TYPE.items():
        if n in ids:
            return fam
    return "Other"


TYPE_COLOR = {"Injection": "#ff4d6d", "Memory safety": "#ff8c42", "Access control / auth": "#c084fc",
              "Crypto & secrets": "#ffd23f", "Data exposure & config": "#8aa0b2", "Input validation / DoS": "#4da3ff",
              "Cross-site scripting": "#f472b6", "Redirect / SSRF": "#2dd4bf", "Other": "#64748b"}

# The six gates, per track: a patch is trusted ONLY because each of these held.
GATE_SPEC = {
    "fuzz": [("G0", "Applies", "patch applies cleanly to the source tree"),
             ("G1", "Rebuilds", "patched tree compiles with sanitizers"),
             ("G2", "PoV blocked", "the exact crashing input no longer crashes"),
             ("G3", "Tests", "repo regression suite still passes"),
             ("G4", "Regression test", "new test fails unpatched, passes patched"),
             ("G5", "Behaviour", "hundreds of valid inputs behave identically")],
    "static": [("G0", "Applies", "patch applies cleanly to the repo"),
               ("G1", "Syntax / build", "patched file parses or project compiles"),
               ("G2", "Re-scan", "the finding is gone and nothing new appeared"),
               ("G3", "Tests", "repo test suite shows no new failure"),
               ("G4", "Proof test", "a test fails unpatched and passes patched"),
               ("G5", "Human approval", "a reviewer approved critical-area changes")],
}


def _overview_html(findings: List[Dict]) -> str:
    """Threat overview: severity histogram, CWE class table, type donut."""
    if not findings:
        return ""
    sev = {k: 0 for k in SEV_ORDER}
    sev_fixed = {k: 0 for k in SEV_ORDER}
    cls: Dict[str, Dict] = {}
    typ: Dict[str, int] = {}
    for f in findings:
        sv = f.get("severity", "Unknown") if f.get("severity") in SEV_ORDER else "Unknown"
        sev[sv] += 1
        if f.get("validation", {}).get("status") == "Verified":
            sev_fixed[sv] += 1
        c = cls.setdefault(f.get("cwe", "CWE-?"), {"name": f.get("cwe_name", ""), "n": 0, "fixed": 0, "sev": sv})
        c["n"] += 1
        c["fixed"] += 1 if f.get("validation", {}).get("status") == "Verified" else 0
        if SEV_ORDER.index(sv) < SEV_ORDER.index(c["sev"]):
            c["sev"] = sv
        t = cwe_type(f.get("cwe", ""))
        typ[t] = typ.get(t, 0) + 1
    total = len(findings)
    mx = max(sev.values()) or 1
    bars = "".join(
        '<div class="sevrow"><span class="sevname" style="color:%s">%s</span>'
        '<span class="sevbar"><i style="width:%d%%;background:%s"></i></span>'
        '<span class="sevn">%d<small>%s</small></span></div>'
        % (SEV_COLOR[k], k, int(100 * sev[k] / mx), SEV_COLOR[k], sev[k],
           (" · %d fixed" % sev_fixed[k]) if sev_fixed[k] else "")
        for k in SEV_ORDER if sev[k] or k != "Unknown")
    rows = "".join(
        '<tr><td><span class="cwe" style="border-color:%s;color:%s">%s</span></td><td>%s</td>'
        '<td class="n">%d</td><td class="n ok">%s</td></tr>'
        % (SEV_COLOR[v["sev"]], SEV_COLOR[v["sev"]], _e(k), _e(v["name"][:60]), v["n"],
           v["fixed"] if v["fixed"] else "&ndash;")
        for k, v in sorted(cls.items(), key=lambda kv: (-kv[1]["n"], kv[0]))[:14])
    # donut (pure SVG, no libraries - the dashboard must work offline)
    segs, legend, acc = [], [], 0.0
    R, C = 54, 70
    circ = 2 * 3.14159 * R
    for t, n in sorted(typ.items(), key=lambda kv: -kv[1]):
        frac = n / total
        segs.append('<circle r="%d" cx="%d" cy="%d" fill="none" stroke="%s" stroke-width="18" '
                    'stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 %d %d)"></circle>'
                    % (R, C, C, TYPE_COLOR.get(t, "#64748b"), circ * frac, circ * (1 - frac), -circ * acc, C, C))
        legend.append('<div class="lg"><i style="background:%s"></i>%s <b>%d</b></div>'
                      % (TYPE_COLOR.get(t, "#64748b"), _e(t), n))
        acc += frac
    donut = ('<svg viewBox="0 0 140 140" class="donut">%s<text x="70" y="66" text-anchor="middle" class="dn">%d</text>'
             '<text x="70" y="84" text-anchor="middle" class="dl">findings</text></svg>' % ("".join(segs), total))
    return """
<h2>Threat overview &mdash; what was found</h2>
<div class="ov">
  <div class="card ovp"><h4>1 &middot; Severity</h4>%s</div>
  <div class="card ovp"><h4>2 &middot; Class (CWE) &middot; count</h4><table class="cls"><tr><th>class</th><th>name</th><th>found</th><th>fixed</th></tr>%s</table></div>
  <div class="card ovp"><h4>3 &middot; Type of vulnerability</h4><div class="dwrap">%s<div class="legend">%s</div></div></div>
</div>""" % (bars, rows, donut, "".join(legend))


def _gate_pipeline(f: Dict) -> str:
    """The six-gate workflow for THIS patch: why it is (or is not) trusted."""
    track = "static" if f.get("kind") == "static" else "fuzz"
    spec = GATE_SPEC[track]
    gates = f.get("validation", {}).get("gates", [])
    by_prefix = {}
    for g in gates:
        by_prefix[g["name"].split()[0]] = g
    nodes, reasons = [], []
    status = f.get("validation", {}).get("status", "Unpatched")
    for gid, label, meaning in spec:
        g = by_prefix.get(gid)
        if g is None:
            cls, mark, detail = "wait", "&middot;", "not reached"
        elif not g["passed"]:
            cls, mark, detail = "fail", "&#10008;", g["detail"]
        elif any(w in g["detail"].lower() for w in ("not claimed", "not runnable", "not checked", "no in-repo",
                                                      "unattended", "no model", "skipped")):
            cls, mark, detail = "soft", "&#8776;", g["detail"]
        else:
            cls, mark, detail = "pass", "&#10004;", g["detail"]
        nodes.append('<div class="gn %s"><div class="gc">%s</div><div class="gid">%s</div><div class="gl">%s</div>'
                     '<div class="gd" title="%s">%s</div></div>'
                     % (cls, mark, gid, _e(label), _e(detail), _e(detail[:90])))
        if g is not None and g["passed"] and cls == "pass":
            reasons.append("<b>%s</b> %s" % (gid, _e(meaning)))
    if status == "Verified":
        soft = [n for n in spec if by_prefix.get(n[0]) and by_prefix[n[0]]["passed"]
                and n[0] not in [r.split("</b>")[0][3:] for r in reasons]]
        why = ("<div class=\"why\"><b>Why this patch is trusted:</b> " + "; ".join(reasons) +
               ((". <span class='muted'>Honestly skipped: %s.</span>" % ", ".join(
                   "%s (%s)" % (n[0], _e(by_prefix[n[0]]["detail"][:60])) for n in soft)) if soft else ".") + "</div>")
    elif status.startswith("Rejected") or status.startswith("rejected"):
        bad = next((g for g in gates if not g["passed"]), None)
        why = ("<div class=\"why no\"><b>Not trusted:</b> stopped at %s &mdash; %s</div>"
               % (_e(bad["name"]), _e(bad["detail"][:160])) if bad else "")
    else:
        why = '<div class="why muted">No candidate has entered the gates%s.</div>' % (
            " &mdash; " + _e(f.get("validation", {}).get("detail", "")) if f.get("validation", {}).get("detail") else "")
    return '<div class="pipe">%s</div>%s' % ("".join(nodes), why)


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
    vcls = "verified" if verified else ("pending" if vstat in ("Unpatched", "Needs human action", "Held") else "rejected")
    vtxt = ("PATCH VERIFIED" if verified else
            "REPAIR PENDING" if vstat == "Unpatched" else vstat.upper())
    if "submit" in f:
        vtxt += (' <span class="subchip">SUBMIT</span>' if f.get("submit")
                 else ' <span class="subchip hold" title="%s">HOLD</span>' % _e(f.get("hold_reason", "")))
    gates = _gate_pipeline(f)
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
    static = f.get("kind") == "static"
    lbl_site, lbl_pov, lbl_rep = (("Location", "Flagged code", "Analyzer finding") if static
                                  else ("Crash site", "Proof-of-vulnerability", "Sanitizer report"))
    pov_line = ("rule: <code>%s</code>%s%s" % (_e(f.get("asan_class")),
                " &nbsp;&middot;&nbsp; <b style='color:#8a63d2'>model review — unverified by a tool</b>" if f.get("review") else "",
                " &nbsp;&middot;&nbsp; <b style='color:#d9822b'>critical area — human approval</b>" if f.get("critical") else "")
                if static else
                "%d bytes &middot; sha256 <code>%s</code><br>repro: <code>%s</code>"
                % (f.get("pov_size", 0), _e(f.get("pov_sha256", ""))[:32], _e(f.get("repro_cmd", ""))))
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
      <div class="meta2"><span class="typechip" style="border-color:%s;color:%s">%s</span> %s &nbsp;|&nbsp; access: %s &nbsp;|&nbsp; signature <code>%s</code>%s</div>
      <div class="grid">
        <div class="col">
          <h4>%s</h4>
          <div class="crash">%s in <code>%s</code></div>
          <div class="frames">%s</div>
          <h4>%s</h4>
          <div class="pov">%s</div>
          <pre class="hex">%s</pre>
          <h4>%s</h4>
          <pre class="asan">%s</pre>
        </div>
        <div class="col">
          <h4>Root cause &amp; repair <span class="src">%s</span></h4>
          <div class="rc">%s</div>
          %s
          %s
          %s
          %s
        </div>
      </div>
      <h4>Six-gate verification &mdash; why we trust this patch</h4>
      %s
    </div>""" % (
        _e(f["id"]), color, color, _e(f.get("cwe")), _e(f.get("cwe_name")),
        color, _e(sev), vcls, vtxt,
        TYPE_COLOR.get(cwe_type(f.get("cwe", "")), "#64748b"), TYPE_COLOR.get(cwe_type(f.get("cwe", "")), "#64748b"),
        _e(cwe_type(f.get("cwe", ""))),
        _e(f.get("asan_class")), _e(f.get("access")), _e(f.get("signature")), dup_txt,
        lbl_site, _e(f.get("crash_file")), _e(f.get("crash_func")), frames,
        lbl_pov, pov_line,
        _e(f.get("pov_hexdump", "")),
        lbl_rep, _e(f.get("asan_report", "")),
        _e(patch.get("source", "")), _e(patch.get("rationale", "")),
        reflect, diff_block, ens, deliver, gates)


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
    elif ev.get("run_status") == "done" and str(d.get("engine", "")).startswith("static"):
        cards = ('<div class="card"><div class="verdict ok2">NO FINDING</div>'
                 '<p class="muted">Static analysis (%s) over %s file(s) reported nothing; '
                 'KavachForge did not invent a finding.</p></div>'
                 % (_e(d.get("note", "")), "{:,}".format(d.get("files", 0))))
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
        stat("submit / hold", "%d / %d" % (sum(1 for f in findings if f.get("submit", True)),
                                          sum(1 for f in findings if not f.get("submit", True)))),
        stat("time to 1st PoV" if not str(d.get("engine", "")).startswith("static") else "time to 1st finding",
             m.get("time_to_first_pov", "n/a")),
        stat("fuzz execs", "{:,}".format(d.get("execs", 0))) if not str(d.get("engine", "")).startswith("static")
        else stat("files scanned", "{:,}".format(d.get("files", 0))),
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
        "overview": _overview_html(findings),
        "ingest": ing_txt,
        "risk_rows": _risk_rows(ev["risk_ledger"]),
        "uplift": _uplift_html(ev.get("uplift")),
        "cards": cards,
        "revision": ev.get("revision", 0),
        "poll": "true" if live else "false",
    }


def _steps_taken(f: Dict) -> str:
    """What KavachForge did about this finding, in the organizer's words."""
    v = f.get("validation", {})
    st = v.get("status", "Unpatched")
    gates_run = [g["name"] for g in v.get("gates", []) if g.get("passed")
                 and not any(w in g.get("detail", "").lower() for w in ("not claimed", "not runnable", "not checked", "no in-repo", "skipped"))]
    patch = f.get("patch", {})
    label = ""
    for c in f.get("candidates", []):
        if c.get("chosen"):
            label = c.get("label", "")
    if st == "Verified":
        return "Verified patch (%s)%s; gates passed: %s%s" % (
            label or patch.get("source", "patch"),
            " — see pr/%s/fix.patch" % f["id"] if f.get("pr_bundle") else "",
            ", ".join(gates_run) or "none",
            "; proof: " + v["proof"] if v.get("proof") else "")
    if f.get("cwe") == "CWE-798":
        return "Reported; recommended fix: remove the credential from the repository and rotate it"
    if st == "Needs human action":
        return "Reported; recommended fix: " + (v.get("detail", "").replace("manual action: ", "") or "manual configuration change")
    if st.startswith("Rejected") or st == "Rejected":
        bad = next((g for g in v.get("gates", []) if not g.get("passed")), None)
        return "Patch attempted but NOT submitted (failed %s: %s); reported with recommended fix: %s" % (
            bad["name"] if bad else "gates", (bad["detail"][:80] if bad else ""), _fix_hint(f))
    if st == "Held":
        return "Held (not submitted): " + v.get("detail", "")
    pre = ""
    if v.get("detail") and "deadline" in v.get("detail", ""):
        pre = "Deadline reached before repair; "
    elif v.get("detail") and "model" in v.get("detail", "").lower():
        pre = "No patch candidate (%s); " % v["detail"][:60]
    return pre + "Reported, recommended fix: " + _fix_hint(f)


_FIX_BY_CWE = {
    "CWE-79": "HTML-encode output / use the template engine's auto-escaping; never insert request data as raw HTML",
    "CWE-89": "use parameterised queries / prepared statements instead of string-built SQL",
    "CWE-943": "never pass request data into $where/operators; validate type and use equality filters",
    "CWE-95": "replace eval() with a safe parser (parseInt/Number/JSON.parse/ast.literal_eval) and validate the value",
    "CWE-94": "do not compile or execute strings derived from input; use a whitelist of allowed operations",
    "CWE-78": "avoid shell execution; call the program with an argument array and validate each argument",
    "CWE-22": "resolve the path and require it to stay under the allowed base directory; reject '..'",
    "CWE-601": "allow-list redirect targets or only accept relative paths",
    "CWE-918": "allow-list destination hosts/schemes before making server-side requests",
    "CWE-611": "disable external entities / DTD processing in the XML parser",
    "CWE-502": "do not deserialise untrusted data; use a safe format (JSON) or a strict allow-list",
    "CWE-798": "remove the credential from the repository, rotate it, and load it from the environment",
    "CWE-327": "use a current algorithm (AES-GCM, SHA-256+, bcrypt/argon2 for passwords)",
    "CWE-328": "replace MD5/SHA-1 with SHA-256 (or a password hash such as bcrypt/argon2)",
    "CWE-295": "re-enable TLS certificate verification",
    "CWE-614": "set the Secure flag on the cookie", "CWE-1004": "set HttpOnly on the session cookie",
    "CWE-639": "check that the authenticated user owns the object (or is admin) before reading/updating it",
    "CWE-862": "add an authorization check before the operation", "CWE-306": "require authentication on this endpoint",
    "CWE-915": "copy only an explicit allow-list of fields from the request into the model",
    "CWE-1333": "rewrite the regex without nested/adjacent unbounded quantifiers or bound the input length",
    "CWE-770": "add rate limiting / lockout to login, OTP and token endpoints",
    "CWE-347": "verify the JWT signature with a pinned algorithm and a strong secret",
    "CWE-215": "remove or protect the debug endpoint", "CWE-489": "disable debug mode and hard-coded config in production",
    "CWE-352": "add CSRF tokens / SameSite cookies on state-changing requests",
    "CWE-1357": "pin the dependency/action to a specific version or digest",
    "CWE-269": "run the container as a non-root user", "CWE-250": "drop unnecessary privileges",
    "CWE-120": "bound the copy by the destination size (strncpy/snprintf with explicit lengths)",
    "CWE-787": "check the index/length against the buffer capacity before writing",
    "CWE-125": "check the index/length against the available input before reading",
}


def _fix_hint(f: Dict) -> str:
    rep = f.get("asan_report", "") or ""
    hint = rep.split("\n\n", 1)[1].strip() if "\n\n" in rep else ""
    hint = hint.replace("mechanical: ", "")
    return (_FIX_BY_CWE.get(f.get("cwe", ""), "") or hint
            or "validate/encode the input at the flagged line and add a regression test")[:220]


def submission_rows(ev: Dict) -> List[Dict]:
    """Rows for the organizer's report: SUBMIT findings only, Critical -> Low."""
    rows = []
    for f in ev.get("findings", []):
        if "submit" in f and not f.get("submit"):
            continue
        rows.append({
            "title": "%s — %s" % (f.get("cwe", ""), f.get("cwe_name", "")),
            "severity": f.get("severity", "Unknown"),
            "location": "%s in %s" % (f.get("crash_file", ""), f.get("crash_func", "-")),
            "steps": _steps_taken(f),
            "id": f.get("id", ""),
            "status": f.get("validation", {}).get("status", "Unpatched"),
        })
    rows.sort(key=lambda r: (SEV_ORDER.index(r["severity"]) if r["severity"] in SEV_ORDER else 9, r["id"]))
    for i, r in enumerate(rows, 1):
        r["sno"] = i
    return rows


def write_submission(ev: Dict, out_dir: str) -> Dict[str, str]:
    """report.md + report.csv in the final-round format:
    S.No · Vulnerability title · Severity · Vulnerable file/function/location · Steps taken."""
    import csv
    rows = submission_rows(ev)
    t = ev.get("task", {})
    m = ev.get("metrics", {})
    md = ["# KavachForge — Vulnerability report: %s" % t.get("name", ""),
          "", "Generated %s · %d finding(s) submitted · %d patch(es) verified · %d held back as low-confidence"
          % (ev.get("generated_at", ""), len(rows), m.get("verified_patches", 0),
             sum(1 for f in ev.get("findings", []) if "submit" in f and not f.get("submit"))),
          "", "| S.No | Vulnerability title | Severity | Vulnerable file / function / location | Steps taken |",
          "|---|---|---|---|---|"]
    for r in rows:
        md.append("| %d | %s | %s | `%s` | %s |" % (r["sno"], r["title"].replace("|", "/"), r["severity"],
                                                  r["location"].replace("|", "/"), r["steps"].replace("|", "/")))
    md += ["", "## How to read 'Steps taken'", "",
           "- **Verified patch** — the fix passed KavachForge's gates: G0 applies, G1 builds/parses, G2 the finding is gone "
           "(re-scan or PoV blocked), G3 the repo's tests show no new failure, G4 a regression/proof test, G5 behaviour "
           "preserved or human approval. The patch file and a PR write-up are under `pr/<finding id>/`.",
           "- **Reported** — the weakness is real enough to report but no patch met the gates; the recommended fix is given.",
           "- Findings in static assets, tests, CI config, vendored code, deliberately 'secure' variants, or unverified model "
           "opinions are kept in `evidence.json` but not submitted (precision over volume).",
           "", "Full evidence chain: `dashboard.html` · machine-readable: `evidence.json` · integrity: `manifest.json`."]
    mpath = os.path.join(out_dir, "report.md")
    cpath = os.path.join(out_dir, "report.csv")
    util.write_text(mpath, "\n".join(md) + "\n")
    with open(cpath, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["S.No", "Vulnerability title", "Severity", "Vulnerable file / function / location", "Steps taken"])
        for r in rows:
            w.writerow([r["sno"], r["title"], r["severity"], r["location"], r["steps"]])
    return {"md": mpath, "csv": cpath, "rows": len(rows)}


def write_reports(ev: Dict, out_dir: str) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    jpath = os.path.join(out_dir, "evidence.json")
    hpath = os.path.join(out_dir, "dashboard.html")
    util.write_json(jpath, ev)
    util.write_text(hpath, render_html(ev))
    if ev.get("run_status") in ("done", "error"):
        try:
            write_submission(ev, out_dir)
        except Exception:
            pass
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
        sev = {}
        types = {}
        for f in ev.get("findings", []):
            sev[f.get("severity", "Unknown")] = sev.get(f.get("severity", "Unknown"), 0) + 1
            t = cwe_type(f.get("cwe", "")); types[t] = types.get(t, 0) + 1
        sevchips = "".join('<span class="sc2" style="background:%s">%d %s</span>' % (SEV_COLOR[k], sev[k], k)
                           for k in SEV_ORDER if sev.get(k))
        typechips = " &middot; ".join("%s %d" % (_e(t), n) for t, n in sorted(types.items(), key=lambda kv: -kv[1])[:4])
        static = str(ev.get("discovery", {}).get("engine", "")).startswith("static")
        tm = ("%d file(s) scanned" % ev.get("discovery", {}).get("files", 0)) if static else \
             "%s execs &middot; first PoV %s" % ("{:,}".format(ev.get("discovery", {}).get("execs", 0)),
                                                   _e(m.get("time_to_first_pov", "n/a")))
        cards.append('<a class="tcard %s" href="%s/dashboard.html"><div class="tn">%s</div>'
                     '<div class="td">%s</div><div class="ts">%s</div><div class="sevchips">%s</div>'
                     '<div class="tm">%s</div><div class="tm">%s</div></a>'
                     % (cls, _e(name), _e(name), _e(ev["task"]["description"]), txt, sevchips,
                        typechips, tm))
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
.cwe{border:1px solid;border-radius:6px;padding:2px 8px;font-size:12px;margin-right:8px;white-space:nowrap}
.sev{border-radius:6px;padding:2px 8px;font-size:12px;color:#0b0f14;font-weight:700}
.verdict{font-weight:700;font-size:12px;padding:5px 12px;border-radius:8px}
.verdict.verified{background:#12361f;color:var(--ok);border:1px solid #1f5e36}
.verdict.rejected{background:#3a1b22;color:var(--bad);border:1px solid #5e1f2c}
.verdict.pending{background:#2d2a12;color:#ffd23f;border:1px solid #5a4a12}
.verdict.ok2{background:#12361f;color:var(--ok);border:1px solid #1f5e36;display:inline-block;margin-bottom:8px}
.meta2{color:var(--mut);font-size:12px;margin:8px 0 4px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:8px}.grid>.col{min-width:0}
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
.deliver{display:flex;flex-wrap:wrap;gap:6px}.pipe{margin-top:10px}\ntable.ens{margin:4px 0 2px}table.ens td,table.ens th{padding:4px 8px;font-size:12px}table.ens tr.ok td{color:var(--ok)}table.ens tr.no td{color:var(--mut)}
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
.subchip{display:inline-block;margin-left:6px;padding:1px 6px;border-radius:5px;font-size:10px;background:#1f5e36;color:#cfead9}
.subchip.hold{background:#3b3b1f;color:#ffd23f}
.sevchips{margin:8px 0 2px}.sc2{display:inline-block;border-radius:5px;padding:1px 7px;font-size:11px;font-weight:700;color:#0b0f14;margin:2px 4px 2px 0}
/* --- look --- */
body{background:radial-gradient(1200px 500px at 10%% -10%%,#122238 0%%,var(--bg) 60%%) fixed}
header{position:relative}
header:before{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;background:linear-gradient(90deg,var(--acc),transparent 70%%)}
.brand{font-size:26px}
.stat{position:relative;overflow:hidden}
.stat:after{content:"";position:absolute;inset:auto 0 0 0;height:2px;background:linear-gradient(90deg,var(--acc),transparent)}
.card{box-shadow:0 1px 0 rgba(255,255,255,.02) inset,0 8px 24px -18px #000}
/* --- threat overview --- */
.ov{display:grid;grid-template-columns:1.1fr 1.5fr 1.1fr;gap:12px}
.ovp h4{margin-top:0}
.sevrow{display:grid;grid-template-columns:76px 1fr 72px;align-items:center;gap:8px;margin:7px 0}
.sevname{font-size:12px;font-weight:700}
.sevbar{height:10px;background:var(--panel2);border:1px solid var(--line);border-radius:999px;overflow:hidden}
.sevbar i{display:block;height:100%%;border-radius:999px;transition:width .6s}
.sevn{font-weight:700;text-align:right;font-size:13px}.sevn small{color:var(--mut);font-weight:400;font-size:10px;display:block;line-height:1}
table.cls{border:0;background:transparent}table.cls td,table.cls th{padding:5px 6px;font-size:12px}
table.cls td.n{text-align:right;font-weight:700}table.cls td.ok{color:var(--ok)}
.dwrap{display:flex;gap:12px;align-items:center}
.donut{width:150px;height:150px;flex:none}
.donut .dn{fill:var(--tx);font-size:26px;font-weight:700}.donut .dl{fill:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:1px}
.legend .lg{font-size:12px;color:var(--mut);margin:3px 0;display:flex;align-items:center;gap:6px}
.legend .lg i{width:9px;height:9px;border-radius:2px;display:inline-block}.legend .lg b{color:var(--tx);margin-left:auto;padding-left:8px}
.typechip{border:1px solid;border-radius:6px;padding:1px 7px;font-size:11px;font-weight:700;margin-right:6px}
/* --- six-gate pipeline --- */
.legendrow{display:flex;gap:14px;flex-wrap:wrap;margin:-4px 0 12px;font-size:11px;color:var(--mut)}
.gn.mini{display:flex;align-items:center;gap:6px}.gn.mini .gc{width:18px;height:18px;font-size:11px}
.pipe{display:grid;grid-template-columns:repeat(6,1fr);gap:4px;position:relative;margin:6px 0 4px}
.pipe:before{content:"";position:absolute;left:8%%;right:8%%;top:15px;height:2px;background:var(--line);z-index:0}
.gn{position:relative;z-index:1;text-align:center}
.gc{width:32px;height:32px;border-radius:50%%;margin:0 auto;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;border:2px solid var(--line);background:var(--panel2);color:var(--mut)}
.gn.pass .gc{border-color:var(--ok);color:var(--ok);background:#12361f;box-shadow:0 0 0 4px rgba(73,224,138,.12)}
.gn.fail .gc{border-color:var(--bad);color:var(--bad);background:#3a1b22;box-shadow:0 0 0 4px rgba(255,128,151,.12)}
.gn.soft .gc{border-color:#ffd23f;color:#ffd23f;background:#2d2a12}
.gn.wait .gc{opacity:.5}
.gid{font-size:10px;color:var(--mut);margin-top:5px;letter-spacing:1px}
.gl{font-size:12px;font-weight:700}
.gn.wait .gl{color:var(--mut);font-weight:400}
.gd{font-size:10.5px;color:var(--mut);line-height:1.3;margin-top:2px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical}
.why{font-size:12px;margin-top:10px;padding:8px 10px;border-radius:8px;background:#12361f;border:1px solid #1f5e36;color:#cfead9}
.why.no{background:#3a1b22;border-color:#5e1f2c;color:#ffd2da}
.why.muted{background:var(--panel2);border-color:var(--line);color:var(--mut)}
@media(max-width:820px){.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.tgrid{grid-template-columns:1fr}.ov{grid-template-columns:1fr}.pipe{grid-template-columns:repeat(3,1fr)}.pipe:before{display:none}}
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
%(overview)s
<h2>Input signals</h2>
<div class="card small">%(ingest)s</div>
<h2>Risk ledger &mdash; diff-to-sink prioritization (pre-LLM, deterministic)</h2>
<table><tr><th>score</th><th>function</th><th>location</th><th>sinks</th><th>why</th></tr>%(risk_rows)s</table>
%(uplift)s
<h2>Findings &mdash; evidence chain, one card per vulnerability</h2>
<div class="legendrow"><span class="gn pass mini"><span class="gc">&#10004;</span>gate passed</span><span class="gn soft mini"><span class="gc">&#8776;</span>honestly skipped / not claimed</span><span class="gn fail mini"><span class="gc">&#10008;</span>gate failed</span><span class="gn wait mini"><span class="gc">&middot;</span>not reached</span></div>
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
