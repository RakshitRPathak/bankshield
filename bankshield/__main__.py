"""Command line:  python -m bankshield <command>

  seed            reset the database and seed the simulated estate
  serve           start the console / API
  scan            run a posture scan and the log detections
  ask             ask a question as a user:  ask -u meera.ciso "which buckets are public?"
  paths           print the current attack paths
  verify-audit    recompute the audit chain and check it against the last checkpoint
  token           issue a signed bearer token (needs BANKSHIELD_SECRET)
  eval            run the RAG evaluation harness
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, config, db


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bankshield", description=f"BankShield {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed"); s.add_argument("--no-attacks", action="store_true"); s.add_argument("--history-days", type=int, default=10)
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
    sub.add_parser("scan")
    s = sub.add_parser("ask"); s.add_argument("question"); s.add_argument("-u", "--user", default="asha.analyst"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("paths"); s.add_argument("-u", "--user", default="meera.ciso")
    sub.add_parser("verify-audit")
    s = sub.add_parser("token"); s.add_argument("user"); s.add_argument("--ttl", type=int, default=None)
    sub.add_parser("eval")
    a = ap.parse_args(argv)

    if a.cmd == "seed":
        from .bootstrap import seed
        seed(attacks=not a.no_attacks, history_days=a.history_days)
    elif a.cmd == "serve":
        import uvicorn
        uvicorn.run("bankshield.api.main:app", host=a.host, port=a.port)
    elif a.cmd == "scan":
        from .detection import run_log_detections, scan_assets
        with db.session() as c:
            res = {"posture": scan_assets(c), "detections": run_log_detections(c)}
            db.audit(c, "cli", "scan.run", res)
            print(json.dumps(res, indent=2))
    elif a.cmd == "ask":
        from .rag import ask
        with db.session() as c:
            ans = ask(c, a.question, user=a.user)
        if a.json:
            print(json.dumps(ans.to_dict(), indent=2, default=str))
        else:
            tag = f"REFUSED ({ans.refusal_reason})" if ans.refused else f"cited {', '.join(ans.citations)} · confidence {ans.confidence}"
            print(f"[{ans.user} · {ans.role} · route {ans.route} · {tag}]\n\n{ans.answer}")
        return 2 if ans.refused else 0
    elif a.cmd == "paths":
        from .detection import compute_attack_paths
        from .rag.clearance import resolve
        with db.session() as c:
            for p in compute_attack_paths(c, resolve(a.user).visible_projects()):
                flag = "  ** ACTIVELY EXPLOITED **" if p["actively_exploited"] else ""
                print(f"{p['score']:>4}  {p['id']}  {p['title']}{flag}")
                print("      " + "  →  ".join(s["label"] for s in p["steps"]))
                print(f"      break the chain: fix {p['break_the_chain']['rule_id']} on {p['break_the_chain']['asset']}\n")
    elif a.cmd == "verify-audit":
        with db.session() as c:
            d = db.verify_audit_detail(c)
        print(json.dumps(d, indent=2))
        return 0 if d["ok"] else 1
    elif a.cmd == "token":
        from . import auth
        try:
            print(auth.issue_token(a.user, a.ttl))
        except auth.AuthError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    elif a.cmd == "eval":
        import runpy
        runpy.run_path(str(config.ROOT / "eval" / "run_eval.py"), run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())
