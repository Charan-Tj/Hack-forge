"""KavachForge command-line interface.

    kavach run <task>         full closed loop (LLM if a key is set, else offline)
    kavach replay <task>      deterministic offline demo (no network, no key)
    kavach demo               run all bundled targets (2 vulnerable + 1 control)
    kavach doctor             check the toolchain / environment
    kavach serve [task]       serve the dashboard(s) over HTTP
    kavach list               list bundled tasks
    kavach clean              remove generated artifacts
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys

from . import __version__, config, toolchain, util
from .pipeline import run_task

TASKS = ["tinyimg", "recordcfg", "cleanjson"]


def _cmd_doctor(args) -> int:
    util.stage("Environment check")
    ok = True
    py = sys.version_info
    util.good("python %d.%d.%d" % (py.major, py.minor, py.micro))
    for tool in ("patch",):
        if shutil.which(tool):
            util.good("%s found" % tool)
        else:
            util.bad("%s NOT found (required to apply patches)" % tool); ok = False
    try:
        tc = toolchain.detect(args.engine)
        util.good("toolchain: %s" % tc.note)
    except RuntimeError as e:
        util.bad(str(e)); ok = False
    for cc in ("clang", "gcc"):
        util.info("  %s: %s" % (cc, shutil.which(cc) or "not found"))
    util.info("docker: %s" % (shutil.which("docker") or "not found (optional)"))
    print()
    (util.good if ok else util.bad)("doctor: %s" % ("READY" if ok else "ISSUES FOUND"))
    return 0 if ok else 1


def _run_many(names, args, provider=None) -> int:
    rc = 0
    results = []
    for n in names:
        try:
            r = run_task(n, provider=provider, model=args.model,
                         budget=args.budget, engine_pref=args.engine,
                         keep_worktree=args.keep)
            results.append((n, r["metrics"]))
        except Exception as e:
            util.bad("task %s failed: %s" % (n, e))
            rc = 1
    if len(results) > 1:
        util.stage("Summary")
        for n, m in results:
            util.info("%-12s findings=%d verified=%d first_pov=%s"
                      % (n, m["unique_findings"], m["verified_patches"],
                         m["time_to_first_pov"]))
    if results:
        util.info(util.dim("View a dashboard:  ./kavach serve"))
    return rc


def _cmd_run(args) -> int:
    return _run_many([args.task], args)


def _cmd_replay(args) -> int:
    os.environ["KAVACH_LLM_PROVIDER"] = "offline"
    names = TASKS if args.task in (None, "all") else [args.task]
    return _run_many(names, args, provider="offline")


def _cmd_demo(args) -> int:
    os.environ.setdefault("KAVACH_LLM_PROVIDER",
                          os.environ.get("KAVACH_LLM_PROVIDER", "offline"))
    return _run_many(TASKS, args, provider=os.environ.get("KAVACH_LLM_PROVIDER"))


def _cmd_list(args) -> int:
    util.stage("Bundled tasks")
    for n in TASKS:
        t = config.load_task(n)
        util.info("%-12s %s" % (n, t.description))
    return 0


def _cmd_clean(args) -> int:
    for d in ("artifacts",):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
            util.good("removed %s/" % d)
    return 0


def _serve(args) -> int:
    import http.server
    import socketserver
    root = os.path.abspath("artifacts")
    if not os.path.isdir(root):
        util.bad("no artifacts/ yet — run ./kavach demo first")
        return 1
    # build an index listing each task dashboard
    links = []
    for name in sorted(os.listdir(root)):
        dash = os.path.join(root, name, "dashboard.html")
        if os.path.exists(dash):
            links.append('<li><a href="%s/dashboard.html">%s</a></li>' % (name, name))
    util.write_text(os.path.join(root, "index.html"),
                    "<!doctype html><meta charset=utf-8><title>KavachForge</title>"
                    "<body style='font-family:system-ui;background:#0b0f14;color:#e6edf3;padding:40px'>"
                    "<h1 style='color:#4da3ff'>KavachForge dashboards</h1><ul style='font-size:18px'>"
                    + "".join(links) + "</ul></body>")
    os.chdir(root)
    port = args.port
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("0.0.0.0", port), handler) as httpd:
        util.good("serving dashboards at http://localhost:%d/  (Ctrl-C to stop)" % port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="kavach", description="KavachForge — evidence-gated "
        "vulnerability discovery and repair (v%s)" % __version__)
    p.add_argument("--version", action="version", version="KavachForge " + __version__)
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--model", default=None, help="LLM model id")
        sp.add_argument("--budget", type=int, default=6, help="max live LLM calls")
        sp.add_argument("--engine", choices=["libfuzzer", "standalone"], default=None)
        sp.add_argument("--keep", action="store_true", help="keep patch worktrees")

    sp = sub.add_parser("run", help="run the full loop on a task")
    sp.add_argument("task"); common(sp)
    sp.add_argument("--provider", default=None,
                    help="anthropic|openai|ollama|offline")
    sp.set_defaults(func=lambda a: _run_many([a.task], a, provider=a.provider))

    sp = sub.add_parser("replay", help="deterministic offline demo (no network)")
    sp.add_argument("task", nargs="?", default="all"); common(sp)
    sp.set_defaults(func=_cmd_replay)

    sp = sub.add_parser("demo", help="run all bundled targets")
    common(sp); sp.set_defaults(func=_cmd_demo)

    sp = sub.add_parser("doctor", help="check environment")
    sp.add_argument("--engine", choices=["libfuzzer", "standalone"], default=None)
    sp.set_defaults(func=_cmd_doctor)

    sp = sub.add_parser("list", help="list bundled tasks")
    sp.set_defaults(func=_cmd_list)

    sp = sub.add_parser("clean", help="remove artifacts/")
    sp.set_defaults(func=_cmd_clean)

    sp = sub.add_parser("serve", help="serve dashboards over HTTP")
    sp.add_argument("task", nargs="?", default=None)
    sp.add_argument("--port", type=int, default=8777)
    sp.set_defaults(func=_serve)

    args = p.parse_args(argv)
    if not getattr(args, "cmd", None):
        p.print_help()
        return 0
    return args.func(args)
