"""Audit-ready reports built from live state + policy clauses.

compliance_report(): for each policy clause that has at least one enforcing rule, show the
rule(s), the assets in scope, which pass/fail, and the evidence. This is the "show me
evidence that control X holds" answer an auditor wants, produced from inventory rather than
from documentation (DRS-3.1).
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections import defaultdict
from typing import Any

from .. import config
from ..detection.rules import load_rules


def control_matrix() -> dict[str, list[dict]]:
    """clause_id -> rules enforcing it."""
    m: dict[str, list[dict]] = defaultdict(list)
    for r in load_rules():
        for c in r["controls"]:
            m[c].append({"rule_id": r["id"], "title": r["title"], "severity": r["severity"], "types": r["type"]})
    return dict(m)


def _clause_lookup(conn: sqlite3.Connection) -> dict[str, dict]:
    return {r["clause_id"]: dict(r) for r in conn.execute("SELECT clause_id, doc_id, doc_title, heading, text, version FROM chunks")}


def compliance_report(conn: sqlite3.Connection, projects: list[str] | None = None, doc_filter: str | None = None) -> dict[str, Any]:
    clauses = _clause_lookup(conn)
    matrix = control_matrix()
    rules = {r["id"]: r for r in load_rules()}
    assets = [dict(a) for a in conn.execute("SELECT id, project, type, name, region, sensitivity, owner FROM assets")]
    projects = ["*"] if projects is None else projects   # None = caller did not scope; [] = caller may see nothing
    if "*" not in projects:
        assets = [a for a in assets if a["project"] in projects]
    asset_ids = {a["id"] for a in assets}
    live = [dict(f) for f in conn.execute("SELECT * FROM findings WHERE status IN ('open','excepted')")]
    open_by_rule: dict[str, list[dict]] = defaultdict(list)
    excepted_by_rule: dict[str, list[dict]] = defaultdict(list)
    for f in live:
        if f["asset_id"] in asset_ids:
            f["evidence"] = json.loads(f["evidence"])
            (open_by_rule if f["status"] == "open" else excepted_by_rule)[f["rule_id"]].append(f)

    controls = []
    for clause_id in sorted(matrix):
        if doc_filter and not clause_id.startswith(doc_filter):
            continue
        cl = clauses.get(clause_id, {})
        entries = []
        total_scope = total_fail = total_exc = 0
        for rule_ref in matrix[clause_id]:
            rule = rules[rule_ref["rule_id"]]
            in_scope = [a for a in assets if a["type"] in rule["type"]]
            failing = open_by_rule.get(rule["id"], [])
            excepted = excepted_by_rule.get(rule["id"], [])
            total_scope += len(in_scope)
            total_fail += len(failing)
            total_exc += len(excepted)
            entries.append({
                "rule_id": rule["id"], "title": rule["title"], "severity": rule["severity"],
                "in_scope": len(in_scope), "failing": len(failing), "excepted": len(excepted),
                "failing_assets": [{"asset_id": f["asset_id"], "project": f["project"], "evidence": f["evidence"],
                                    "risk": f.get("risk"), "first_seen": f["first_seen"]} for f in failing],
                "excepted_assets": [{"asset_id": f["asset_id"], "project": f["project"]} for f in excepted],
            })
        # An approved exception is a recorded decision, not a pass: it is reported as its own status.
        status = "FAIL" if total_fail else ("EXCEPTION" if total_exc else "PASS")
        controls.append({
            "clause_id": clause_id, "doc": cl.get("doc_id"), "doc_title": cl.get("doc_title"), "version": cl.get("version"),
            "heading": cl.get("heading"), "requirement": cl.get("text"), "status": status,
            "in_scope": total_scope, "failing": total_fail, "excepted": total_exc, "rules": entries,
        })
    passed = sum(1 for c in controls if c["status"] == "PASS")
    failed = sum(1 for c in controls if c["status"] == "FAIL")
    # Honest coverage: clauses with no automated rule are NOT counted as passing — they are listed.
    all_clauses = sorted(c for c in clauses if not doc_filter or c.startswith(doc_filter))
    unmonitored = [c for c in all_clauses if c not in matrix]
    return {
        "generated_at": time.time(), "projects": projects or ["*"],
        "summary": {"controls": len(controls), "pass": passed, "fail": failed, "exception": len(controls) - passed - failed,
                    "open_findings": len({f["id"] for c in controls for r in c["rules"] for f in open_by_rule.get(r["rule_id"], [])}),
                    "clauses_total": len(all_clauses), "clauses_automated": len(all_clauses) - len(unmonitored)},
        "unmonitored_clauses": [{"clause_id": c, "heading": clauses[c].get("heading")} for c in unmonitored],
        "controls": controls,
    }


def residency_evidence(conn: sqlite3.Connection) -> list[dict]:
    """DRS-3.1: every restricted resource with its region, from live inventory."""
    out = []
    for a in conn.execute("SELECT id, project, type, name, region FROM assets WHERE sensitivity='restricted' AND region IS NOT NULL ORDER BY project, type"):
        d = dict(a)
        d["compliant"] = d["region"] in config.ALLOWED_REGIONS
        out.append(d)
    return out


def regulatory_gap(conn: sqlite3.Connection, new_requirements: list[dict], projects: list[str] | None = None) -> list[dict]:
    """Given new/changed external requirements [{id, text, maps_to:[clause ids]}], report which
    mapped internal controls currently FAIL, and which requirements map to nothing (true gaps)."""
    rep = compliance_report(conn, projects=projects)
    status = {c["clause_id"]: c for c in rep["controls"]}
    out = []
    for req in new_requirements:
        mapped = req.get("maps_to", [])
        if not mapped:
            out.append({**req, "gap": "no internal control mapped", "failing_controls": []})
            continue
        failing = [m for m in mapped if status.get(m, {}).get("status") == "FAIL"]
        unmonitored = [m for m in mapped if m not in status]
        out.append({**req, "gap": "controls failing" if failing else ("unmonitored" if unmonitored else None),
                    "failing_controls": failing, "unmonitored_controls": unmonitored})
    return out


def report_markdown(rep: dict[str, Any]) -> str:
    s = rep["summary"]
    lines = [f"# Compliance Evidence Report", "",
             f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(rep['generated_at']))}  ",
             f"Scope: {', '.join(rep['projects'])}  ",
             f"Controls: {s['controls']} — PASS {s['pass']} / FAIL {s['fail']} / EXCEPTION {s.get('exception', 0)} — open findings {s['open_findings']}  ",
             f"Automated coverage: {s.get('clauses_automated', '?')} of {s.get('clauses_total', '?')} policy clauses have an enforcing rule; "
             f"the rest need manual evidence and are listed at the end.", ""]
    for c in rep["controls"]:
        lines.append(f"## {c['clause_id']} — {c['heading']}  [{c['status']}]")
        lines.append(f"*{c['doc_title']} v{c['version']}*  ")
        lines.append(f"> {c['requirement']}")
        for r in c["rules"]:
            lines.append(f"- Rule {r['rule_id']} ({r['severity']}): {r['title']} — in scope {r['in_scope']}, failing {r['failing']}")
            for fa in r["failing_assets"]:
                lines.append(f"  - `{fa['project']}/{fa['asset_id']}` evidence: `{json.dumps(fa['evidence'])}`")
            for ea in r.get("excepted_assets", []):
                lines.append(f"  - `{ea['project']}/{ea['asset_id']}` — approved exception on record")
        lines.append("")
    if rep.get("unmonitored_clauses"):
        lines += ["## Clauses without automated evidence", ""]
        lines += [f"- {u['clause_id']} — {u['heading']}" for u in rep["unmonitored_clauses"]]
        lines.append("")
    return "\n".join(lines)
