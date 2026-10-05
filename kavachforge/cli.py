"""KavachForge command-line interface.

    kavach showcase           serve the live dashboard AND run every target (judges)
    kavach run <task>         full closed loop on one task
    kavach replay [task]      deterministic offline run (no network, no key)
    kavach demo               run all bundled targets
    kavach doctor             check the toolchain / environment
    kavach selftest           run the built-in unit tests
    kavach serve              serve existing dashboards over HTTP
    kavach list               list bundled tasks
    kavach clean              remove generated artifacts
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import threading

from . import __version__, config, report, toolchain, util
from .pipeline import run_task

TASKS = ["tinyimg", "recordcfg", "cleanjson"]
ART = "artifacts"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _common_kwargs(args, provider=None):
    return dict(provider=provider, model=getattr(args, "model", None),
                budget=getattr(args, "budget", 6),
                engine_pref=getattr(args, "engine", None),
                keep_worktree=getattr(args, "keep", False),
                uplift=getattr(args, "uplift", False),
                diff=getattr(args, "diff", None),
                sarif=getattr(args, "sarif", None))


def _run_many(names, args, provider=None, on_each=None) -> int:
    rc = 0
    results = []
    for n in names:
        try:
            r = run_task(n, **_common_kwargs(args, provider))
            results.append((n, r["metrics"]))
        except Exception as e:
            util.bad("task %s failed: %s" % (n, e))
            rc = 1
        if on_each:
            on_each()
    if len(results) > 1:
        util.stage("Summary")
        for n, m in results:
            util.info("%-12s raw=%-3d unique=%d verified=%d first_pov=%s"
                      % (n, m.get("raw_crashes", 0), m["unique_findings"],
                         m["verified_patches"], m["time_to_first_pov"]))
    return rc


def _start_server(port: int, root: str):
    """Serve `root` on a background thread; returns the httpd."""
    import http.server
    import socketserver

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=root, **kw)

        def log_message(self, *a):
            pass

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("0.0.0.0", port), Quiet)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def _cmd_doctor(args) -> int:
    util.stage("Environment check")
    ok = True
    py = sys.version_info
    (util.good if py >= (3, 9) else util.bad)("python %d.%d.%d%s" % (
        py.major, py.minor, py.micro, "" if py >= (3, 9) else "  (need 3.9+)"))
    ok = ok and py >= (3, 9)
    if shutil.which("patch"):
        util.good("patch found")
    else:
        util.bad("patch NOT found (required to apply patches)"); ok = False
    try:
        tc = toolchain.detect(args.engine)
        util.good("toolchain: %s" % tc.note)
        if not tc.is_libfuzzer:
            util.info(util.dim("  (libFuzzer runtime not found: using the standalone "
                               "engine; run with --docker for coverage-guided fuzzing)"))
    except RuntimeError as e:
        util.bad(str(e)); ok = False
    for cc in ("clang", "gcc"):
        util.info("  %s: %s" % (cc, shutil.which(cc) or "not found"))
    util.info("docker: %s" % (shutil.which("docker") or "not found (optional)"))
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        if os.environ.get(k):
            util.good("%s set (live model available)" % k)
    if not any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")):
        util.info(util.dim("no API key set: offline deterministic brain will be used"))
    print()
    (util.good if ok else util.bad)("doctor: %s" % ("READY" if ok else "ISSUES FOUND"))
    return 0 if ok else 1


def _cmd_replay(args) -> int:
    os.environ["KAVACH_LLM_PROVIDER"] = "offline"
    names = TASKS if args.task in (None, "all") else [args.task]
    return _run_many(names, args, provider="offline")


def _cmd_demo(args) -> int:
    return _run_many(TASKS, args, provider=getattr(args, "provider", None))


def _cmd_showcase(args) -> int:
    """One command for the judges: dashboard first, then the run, live."""
    os.makedirs(ART, exist_ok=True)
    root = os.path.abspath(ART)
    names = TASKS if args.task in (None, "all") else [args.task]
    if args.fresh:
        for n in names:
            shutil.rmtree(os.path.join(root, n), ignore_errors=True)
    util.write_json(os.path.join(root, ".showcase.json"), {"tasks": names})
    report.write_index(root, names)
    httpd = _start_server(args.port, root)
    url = "http://localhost:%d/" % args.port
    util.plain(util.bold("\nKavachForge showcase"))
    util.good("live dashboard: %s" % util.blue(url))
    util.info(util.dim("open it now; it updates as each stage completes"))
    if args.provider:
        os.environ["KAVACH_LLM_PROVIDER"] = args.provider

    def refresh_index():
        report.write_index(root, names)

    rc = _run_many(names, args, provider=args.provider, on_each=refresh_index)
    refresh_index()
    util.plain("")
    util.good("showcase complete — dashboard stays live at %s (Ctrl-C to stop)" % url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print()
    httpd.shutdown()
    return rc


def _cmd_serve(args) -> int:
    root = os.path.abspath(ART)
    if not os.path.isdir(root):
        util.bad("no artifacts/ yet — run ./kavach showcase first")
        return 1
    present = [n for n in TASKS if os.path.isdir(os.path.join(root, n))]
    util.write_json(os.path.join(root, ".showcase.json"), {"tasks": present or TASKS})
    report.write_index(root, present or TASKS)
    _start_server(args.port, root)
    util.good("serving dashboards at http://localhost:%d/  (Ctrl-C to stop)" % args.port)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print()
    return 0


def _cmd_list(args) -> int:
    util.stage("Bundled tasks")
    for n in TASKS:
        t = config.load_task(n)
        util.info("%-12s %s" % (n, t.description))
    return 0


def _cmd_clean(args) -> int:
    if os.path.isdir(ART):
        shutil.rmtree(ART, ignore_errors=True)
        util.good("removed %s/" % ART)
    return 0


def _ensure_git(root: str) -> bool:
    """Make the target a git repo with a baseline commit (so edits show up
    as a diff and can be reset). Returns True if a repo was created."""
    if util.run(["git", "-C", root, "rev-parse", "--is-inside-work-tree"]).ok \
            and os.path.isdir(os.path.join(root, ".git")):
        return False
    util.run(["git", "-C", root, "init", "-q"])
    util.run(["git", "-C", root, "add", "-A"])
    util.run(["git", "-C", root, "-c", "user.name=KavachForge",
              "-c", "user.email=kavach@local", "commit", "-q", "-m", "baseline"])
    return True


def _cmd_watch(args) -> int:
    """Live mode: watch a target for edits; every saved change triggers the
    full loop with risk ranking driven by the live `git diff`."""
    import time
    task = config.load_task(args.task)
    root = task.root
    if _ensure_git(root):
        util.good("baseline committed for %s" % os.path.relpath(root))
    os.makedirs(ART, exist_ok=True)
    aroot = os.path.abspath(ART)
    util.write_json(os.path.join(aroot, ".showcase.json"), {"tasks": [task.name]})
    report.write_index(aroot, [task.name])
    _start_server(args.port, aroot)
    url = "http://localhost:%d/%s/dashboard.html" % (args.port, task.name)
    util.plain(util.bold("\nKavachForge watch — %s" % task.name))
    util.good("live dashboard: %s" % util.blue(url))
    util.info("edit anything under %s and save — e.g. delete a bounds check in "
              "%s" % (os.path.relpath(root), os.path.relpath(task.sources[0])))
    util.info(util.dim("restore the original any time:  ./kavach reset %s" % task.name))
    kw = _common_kwargs(args, getattr(args, "provider", None))
    kw["diff"] = "git"

    if not args.no_baseline:
        util.plain(util.dim("\n[baseline run on the unmodified target]"))
        try:
            run_task(task.name, **kw)
        except Exception as e:
            util.bad("baseline failed: %s" % e)
    util.plain("")
    util.good("watching for edits…  (Ctrl-C to stop)")

    last = ""
    try:
        while True:
            d = util.run(["git", "-C", root, "diff", "HEAD", "--no-color"]).out
            h = util.sha256_bytes(d.encode()) if d.strip() else ""
            if h and h != last:
                time.sleep(1.2)   # debounce: let the editor finish saving
                d2 = util.run(["git", "-C", root, "diff", "HEAD", "--no-color"]).out
                if util.sha256_bytes(d2.encode()) != h:
                    continue
                last = h
                nfiles = d.count("\n+++ ")
                util.plain(util.bold("\n%s change detected in %d file(s) — running"
                                     % (util.yellow("●"), nfiles)))
                try:
                    run_task(task.name, **kw)
                except Exception as e:
                    util.bad("run failed: %s" % e)
                util.plain("")
                util.good("watching for edits…  (./kavach reset %s restores the "
                          "original)" % task.name)
            elif not h and last:
                last = ""
                util.good("target restored to baseline — watching…")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print()
    return 0


def _cmd_reset(args) -> int:
    task = config.load_task(args.task)
    root = task.root
    if not os.path.isdir(os.path.join(root, ".git")):
        util.warn("%s has no baseline (run ./kavach watch first)" % task.name)
        return 1
    util.run(["git", "-C", root, "checkout", "--", "."])
    util.run(["git", "-C", root, "clean", "-fdq"])
    util.good("%s restored to baseline" % task.name)
    return 0


def _cmd_selftest(args) -> int:
    import unittest
    here = os.path.dirname(os.path.abspath(__file__))
    suite = unittest.defaultTestLoader.discover(os.path.join(here, "tests"),
                                                top_level_dir=os.path.dirname(here))
    res = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    return 0 if res.wasSuccessful() else 1


# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="kavach", description="KavachForge — evidence-gated "
        "vulnerability discovery and repair (v%s)" % __version__)
    p.add_argument("--version", action="version", version="KavachForge " + __version__)
    sub = p.add_subparsers(dest="cmd")

    def common(sp, with_provider=True):
        sp.add_argument("--model", default=None, help="LLM model id")
        sp.add_argument("--budget", type=int, default=6, help="max live LLM calls")
        sp.add_argument("--engine", choices=["libfuzzer", "standalone"], default=None)
        sp.add_argument("--keep", action="store_true", help="keep patch worktrees")
        sp.add_argument("--uplift", action="store_true",
                        help="also measure seed uplift (empty-corpus A/B)")
        sp.add_argument("--diff", default=None,
                        help="'git' or a .diff file to drive risk ranking")
        sp.add_argument("--sarif", default=None, help="SARIF file of static alerts")
        if with_provider:
            sp.add_argument("--provider", default=None,
                            help="anthropic|openai|ollama|offline")

    sp = sub.add_parser("showcase", help="serve live dashboard + run all targets")
    sp.add_argument("task", nargs="?", default="all")
    sp.add_argument("--port", type=int, default=8777)
    sp.add_argument("--fresh", action="store_true", help="clear previous artifacts first")
    common(sp); sp.set_defaults(func=_cmd_showcase)

    sp = sub.add_parser("run", help="run the full loop on a task")
    sp.add_argument("task"); common(sp)
    sp.set_defaults(func=lambda a: _run_many([a.task], a, provider=a.provider))

    sp = sub.add_parser("replay", help="deterministic offline run (no network)")
    sp.add_argument("task", nargs="?", default="all"); common(sp, with_provider=False)
    sp.set_defaults(func=_cmd_replay)

    sp = sub.add_parser("demo", help="run all bundled targets")
    common(sp); sp.set_defaults(func=_cmd_demo)

    sp = sub.add_parser("watch", help="live mode: edit a target, it heals itself")
    sp.add_argument("task", nargs="?", default="cleanjson")
    sp.add_argument("--port", type=int, default=8777)
    sp.add_argument("--no-baseline", action="store_true",
                    help="skip the initial run on the unmodified target")
    common(sp); sp.set_defaults(func=_cmd_watch)

    sp = sub.add_parser("reset", help="restore a watched target to its baseline")
    sp.add_argument("task", nargs="?", default="cleanjson")
    sp.set_defaults(func=_cmd_reset)

    sp = sub.add_parser("doctor", help="check environment")
    sp.add_argument("--engine", choices=["libfuzzer", "standalone"], default=None)
    sp.set_defaults(func=_cmd_doctor)

    sp = sub.add_parser("selftest", help="run unit tests")
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.set_defaults(func=_cmd_selftest)

    sp = sub.add_parser("list", help="list bundled tasks")
    sp.set_defaults(func=_cmd_list)

    sp = sub.add_parser("clean", help="remove artifacts/")
    sp.set_defaults(func=_cmd_clean)

    sp = sub.add_parser("serve", help="serve dashboards over HTTP")
    sp.add_argument("--port", type=int, default=8777)
    sp.set_defaults(func=_cmd_serve)

    args = p.parse_args(argv)
    if not getattr(args, "cmd", None):
        p.print_help()
        return 0
    return args.func(args)
