"""CLI: bootstrap demo data, or run a CI gate.
   python -m app.cli bootstrap
   python -m app.cli review --repo ecu_demo --fail-on high [--build-log f] [--cppcheck f] [--no-llm] [--user admin]"""
from __future__ import annotations
import argparse
import json
import sys

from .bootstrap import bootstrap_demo
from .engine import Engine
from .services import SEV_ORDER, Services


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scr")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("bootstrap")
    r = sub.add_parser("review")
    r.add_argument("--repo", required=True)
    r.add_argument("--paths", nargs="*")
    r.add_argument("--build-log")
    r.add_argument("--cppcheck")
    r.add_argument("--fail-on", default="high", choices=list(SEV_ORDER))
    r.add_argument("--no-llm", action="store_true")
    r.add_argument("--user", default="admin")
    a = ap.parse_args(argv)
    svc = Services()
    if a.cmd == "bootstrap":
        creds = bootstrap_demo(svc)
        print("Demo credentials (shown once):")
        for u, p in creds.items():
            print(f"  {u}: {p}")
        return 0
    user = svc.db.one("SELECT id,username,role FROM users WHERE username=?", (a.user,))
    if not user:
        print("unknown user; run bootstrap first", file=sys.stderr)
        return 2
    rd = lambda p: open(p, encoding="utf-8", errors="replace").read() if p else None
    res = Engine(svc).review(user, a.repo, a.paths, rd(a.build_log), rd(a.cppcheck), not a.no_llm)
    print(json.dumps(res["stats"], indent=2))
    blocking = [f for f in res["findings"] if SEV_ORDER[f["severity"]] >= SEV_ORDER[a.fail_on] and f["status"] not in ("rejected", "fixed")]
    for f in blocking:
        print(f"[{f['severity'].upper()}] {f['file']}:{f['line_start']} {f['rule']} {f['title']}")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
