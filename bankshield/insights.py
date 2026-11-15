"""Read models for the console: overview KPIs, ATT&CK coverage matrix, Prometheus metrics.
Everything here takes the caller's Principal and returns only what they may see."""

from __future__ import annotations

import json
import sqlite3
import time
from collections import defaultdict
from typing import Any

from . import config
from .detection import compute_attack_paths, correlate, load_rules
from .detection import mitre as mitre_mod
from .detection.log_detections import MITRE as DET_MITRE, TITLES as DET_TITLES
from .governance import hydrate_alert
from .rag.clearance import Principal


def _visible_findings(conn: sqlite3.Connection, p: Principal, status: str = "open") -> list[dict[str, Any]]:
    now = time.time()
    out = []
    for r in conn.execute("SELECT f.*, a.name AS asset_name, a.type AS asset_type, a.sensitivity, a.owner FROM findings f "
                          "JOIN assets a ON a.id=f.asset_id WHERE f.status=?", (status,)):
        if not p.can_see_project(r["project"]):
            continue
        d = dict(r)
        d["evidence"] = json.loads(d["evidence"]); d["controls"] = json.loads(d["controls"]); d["mitre"] = json.loads(d["mitre"] or "[]")
        d["sla_breached"] = bool(d["due_at"] and status == "open" and d["due_at"] < now)
        d["age_days"] = round((now - d["first_seen"]) / 86400, 1)
        out.append(d)
    out.sort(key=lambda f: (-f["risk"], config.SEVERITY_RANK.get(f["severity"], 9), f["project"], f["asset_id"]))
    return out


def visible_alerts(conn: sqlite3.Connection, p: Principal) -> list[dict[str, Any]]:
    now = time.time()
    return [hydrate_alert(r, now) for r in conn.execute("SELECT * FROM alerts ORDER BY ts DESC") if p.can_see_project(r["project"])]


def overview(conn: sqlite3.Connection, p: Principal) -> dict[str, Any]:
    findings = _visible_findings(conn, p)
    alerts = visible_alerts(conn, p)
    sev = {s: 0 for s in config.SEVERITY_BASE}
    by_project: dict[str, dict[str, int]] = defaultdict(lambda: {s: 0 for s in config.SEVERITY_BASE})
    for f in findings:
        sev[f["severity"]] += 1
        by_project[f["project"]][f["severity"]] += 1
    # Posture score for the caller's scope: severity-weighted share of (rule, asset) checks that pass.
    rules = load_rules()
    total_w = failed_w = 0.0
    for a in conn.execute("SELECT project, type FROM assets"):
        if p.can_see_project(a["project"]):
            total_w += sum(config.SEVERITY_BASE[r["severity"]] for r in rules if a["type"] in r["type"])
    failed_w = sum(config.SEVERITY_BASE[f["severity"]] for f in findings)
    score = round(100 * (1 - failed_w / total_w), 1) if total_w else None
    global_scope = "*" in p.projects
    history = [dict(r) for r in conn.execute("SELECT ts, score, open, critical, high, medium, low FROM posture_history ORDER BY ts DESC LIMIT 60")][::-1]
    incidents = [dict(r) for r in conn.execute("SELECT id, status, severity, context FROM incidents")]
    incidents = [i for i in incidents if p.can_see_project(json.loads(i["context"]).get("project", ""))]
    paths = compute_attack_paths(conn, p.visible_projects())
    cases = correlate(conn, p.visible_projects())
    open_alerts = [a for a in alerts if a["status"] == "open"]
    return {
        "score": score, "findings_open": len(findings), "severity": sev,
        "by_project": {k: v for k, v in sorted(by_project.items())},
        "sla_breached": sum(1 for f in findings if f["sla_breached"]),
        "excepted": len(_visible_findings(conn, p, "excepted")),
        "alerts_open": len(open_alerts), "alerts_ack_breached": sum(1 for a in open_alerts if a["ack_breached"]),
        "incidents_open": sum(1 for i in incidents if i["status"] == "open"),
        "attack_paths": len(paths), "attack_paths_exploited": sum(1 for x in paths if x["actively_exploited"]),
        "cases_open": sum(1 for c in cases if c["status"] != "closed"),
        "top_paths": paths[:3], "top_findings": findings[:5],
        # The stored trend is estate-wide; only callers with estate-wide scope get it.
        "history": history if global_scope else [], "history_scope": "estate" if global_scope else "not shown for partial scope",
        "scope": p.projects, "generated_at": time.time(),
    }


def mitre_matrix(conn: sqlite3.Connection, p: Principal) -> dict[str, Any]:
    """ATT&CK coverage: which techniques a rule or detection covers, and which are live right now."""
    cover: dict[str, dict[str, Any]] = {t: {**mitre_mod.describe(t), "rules": [], "detections": [], "open_findings": 0, "open_alerts": 0}
                                        for t in mitre_mod.TECHNIQUES}
    for r in load_rules():
        for t in r.get("mitre", []):
            if t in cover:
                cover[t]["rules"].append({"id": r["id"], "title": r["title"]})
    for det, ts in DET_MITRE.items():
        for t in ts:
            if t in cover:
                cover[t]["detections"].append({"id": det, "title": DET_TITLES.get(det, det)})
    for f in _visible_findings(conn, p):
        for t in f["mitre"]:
            if t in cover:
                cover[t]["open_findings"] += 1
    for a in visible_alerts(conn, p):
        if a["status"] != "closed":
            for t in a["mitre"]:
                if t in cover:
                    cover[t]["open_alerts"] += 1
    tactics = [{"tactic": tac, "techniques": [c for c in cover.values() if c["tactic"] == tac]} for tac in mitre_mod.TACTIC_ORDER]
    return {"tactics": tactics, "techniques": len(cover),
            "with_detection": sum(1 for c in cover.values() if c["detections"]),
            "with_posture_rule": sum(1 for c in cover.values() if c["rules"])}


def prometheus(conn: sqlite3.Connection) -> str:
    """Estate-wide gauges in Prometheus text format (scraped by a monitoring identity)."""
    lines = []

    def gauge(name: str, help_: str, samples: list[tuple[str, float]]) -> None:
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} gauge")
        lines.extend(f"{name}{labels} {value}" for labels, value in samples)

    gauge("bankshield_findings_open", "Open posture findings by severity",
          [(f'{{severity="{r["severity"]}"}}', r["n"]) for r in conn.execute("SELECT severity, COUNT(*) n FROM findings WHERE status='open' GROUP BY severity")])
    gauge("bankshield_alerts", "Behavioural alerts by status",
          [(f'{{status="{r["status"]}"}}', r["n"]) for r in conn.execute("SELECT status, COUNT(*) n FROM alerts GROUP BY status")])
    gauge("bankshield_incidents_open", "Open incidents", [("", conn.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0])])
    row = conn.execute("SELECT score FROM posture_history ORDER BY ts DESC LIMIT 1").fetchone()
    gauge("bankshield_posture_score", "Severity-weighted share of posture checks passing (0-100)", [("", row["score"] if row else 0)])
    gauge("bankshield_findings_sla_breached", "Open findings past their remediation SLA",
          [("", conn.execute("SELECT COUNT(*) FROM findings WHERE status='open' AND due_at < ?", (time.time(),)).fetchone()[0])])
    gauge("bankshield_audit_records", "Records in the audit chain", [("", conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0])])
    asks = conn.execute("SELECT COUNT(*) n, SUM(payload LIKE '%\"refused\": true%') r FROM audit WHERE action='rag.ask'").fetchone()
    gauge("bankshield_rag_questions_total", "Questions asked", [("", asks["n"] or 0)])
    gauge("bankshield_rag_refusals_total", "Questions refused by a guardrail", [("", asks["r"] or 0)])
    return "\n".join(lines) + "\n"
