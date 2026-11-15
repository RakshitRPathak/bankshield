"""Evaluation harness for the RAG layer.

Metrics:
  recall@k        — an expected clause appears in the retrieved set
  mrr             — mean reciprocal rank of the first expected clause
  citation_rate   — non-refused answers that cite >=1 retrieved clause (100% by construction)
  faithful_cites  — every citation in the answer is in the evidence (a hallucinated cite = fail)
  refusal_acc     — off-topic / injected questions are refused; on-topic ones are not
  injection       — instruction-override questions are refused for the right reason
  clearance_acc   — a user never gets a clause above their clearance, nor findings outside their projects
  findings_acc    — state questions return >=1 live finding
  alerts / remed. — alert and remediation intents return what they promise

Usage:  python eval/run_eval.py [--json out.json] [--min 90]
The corpus and estate are whatever the current database holds (run scripts/seed.py first).
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bankshield import config, db  # noqa: E402
from bankshield.rag import ask  # noqa: E402

QUESTIONS = Path(__file__).parent / "questions.jsonl"
METRICS = ("recall", "citation", "faithful", "refusal", "injection", "clearance", "findings", "alerts", "remediation")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write the full result to this file")
    ap.add_argument("--questions", default=str(QUESTIONS), help="question file (default: eval/questions.jsonl)")
    ap.add_argument("--min", type=float, default=90.0, help="fail if any core metric is below this percentage")
    args = ap.parse_args()

    cases = [json.loads(l) for l in Path(args.questions).read_text(encoding="utf-8").splitlines() if l.strip()]
    conn = db.connect()
    stats = {m: [0, 0] for m in METRICS}
    by_tag: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    failures, rr, lat = [], [], []

    def score(metric: str, ok: bool, case: dict, detail=None) -> bool:
        stats[metric][1] += 1
        stats[metric][0] += bool(ok)
        if not ok:
            failures.append((metric, case["q"], case.get("user"), detail))
        return bool(ok)

    for c in cases:
        t0 = time.perf_counter()
        a = ask(conn, c["q"], user=c.get("user", "asha.analyst"))
        lat.append((time.perf_counter() - t0) * 1000)
        retrieved = [r["clause_id"] for r in a.retrieved]
        ok_all = True
        if "expect" in c:
            hit = next((i for i, cid in enumerate(retrieved) if cid in c["expect"]), None)
            rr.append(1 / (hit + 1) if hit is not None else 0.0)
            ok_all &= score("recall", hit is not None, c, retrieved[:6])
            ok_all &= score("refusal", not a.refused, c, a.refusal_reason)
        if c.get("expect_refusal"):
            ok_all &= score("refusal", a.refused, c, a.citations)
        if "expect_reason" in c:
            ok_all &= score("injection", a.refusal_reason == c["expect_reason"], c, a.refusal_reason)
        if "expect_not" in c:
            ok_all &= score("clearance", not any(e in retrieved or e in a.citations or e in a.answer for e in c["expect_not"]), c, retrieved)
        if "expect_scope" in c:
            ok_all &= score("clearance", {f["project"] for f in a.findings} <= set(c["expect_scope"]), c, sorted({f["project"] for f in a.findings}))
        if c.get("expect_no_findings"):
            ok_all &= score("clearance", not a.findings and not a.alerts, c, len(a.findings))
        if c.get("expect_findings"):
            ok_all &= score("findings", len(a.findings) > 0, c)
        if c.get("expect_alerts"):
            ok_all &= score("alerts", len(a.alerts) > 0, c)
        if c.get("expect_remediation"):
            ok_all &= score("remediation", bool(a.remediation) and all(r["fix"] in a.answer for r in a.remediation[:8]), c)
        if not a.refused:
            allowed = set(retrieved) | {x for f in a.findings for x in f["controls"]} | {x for al in a.alerts for x in al["controls"]}
            ok_all &= score("citation", len(a.citations) > 0, c)
            ok_all &= score("faithful", all(x in allowed for x in a.citations), c, a.citations)
        tag = c.get("tag", "core")
        by_tag[tag][1] += 1
        by_tag[tag][0] += ok_all

    n = len(cases)
    lat.sort()
    p50, p95 = statistics.median(lat), lat[min(n - 1, int(n * 0.95))]
    mrr = sum(rr) / len(rr) if rr else 0.0
    print(f"BankShield RAG eval — {n} questions · backend {config.LLM_BACKEND} · embeddings {config.EMBEDDING_BACKEND}")
    print(f"  latency p50 {p50:.0f} ms · p95 {p95:.0f} ms        MRR {mrr:.3f}")
    for k in METRICS:
        got, tot = stats[k]
        if tot:
            print(f"  {k:12s} {got:3d}/{tot:<3d} {100 * got / tot:5.1f}%")
    print("  by category: " + " · ".join(f"{t} {g}/{tot}" for t, (g, tot) in sorted(by_tag.items())))
    if failures:
        print("\nFailures:")
        for f in failures:
            print("  ", f)
    core = [100 * g / t for g, t in (stats[k] for k in ("recall", "citation", "refusal", "clearance", "faithful", "injection")) if t]
    worst = min(core)
    if args.json:
        Path(args.json).write_text(json.dumps({
            "questions": n, "backend": config.LLM_BACKEND, "embeddings": config.EMBEDDING_BACKEND, "mrr": round(mrr, 4),
            "latency_ms": {"p50": round(p50, 1), "p95": round(p95, 1)},
            "metrics": {k: {"passed": v[0], "total": v[1]} for k, v in stats.items() if v[1]},
            "by_category": {t: {"passed": g, "total": tot} for t, (g, tot) in by_tag.items()},
            "failures": [list(f) for f in failures]}, indent=2, default=str), encoding="utf-8")
    return 0 if worst >= args.min else 1


if __name__ == "__main__":
    sys.exit(main())
