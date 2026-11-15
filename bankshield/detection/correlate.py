"""Alert correlation: turn single alerts into cases.

Alerts for the same identity inside a time window are one story, not N tickets. A case
orders them into an ATT&CK tactic chain and attaches the posture weakness that made the
identity dangerous (e.g. "this service account also holds roles/editor").
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from typing import Any

from .. import config
from . import mitre as mitre_mod

WINDOW_S = 6 * 3600


def _posture_context(conn: sqlite3.Connection, principal: str) -> list[dict[str, Any]]:
    """Open findings that concern this identity."""
    out = []
    name = principal.split("@")[0]
    for r in conn.execute("SELECT f.id, f.rule_id, f.title, f.project, f.severity, a.name FROM findings f JOIN assets a ON a.id=f.asset_id "
                          "WHERE f.status='open' AND a.type='service_account' AND a.name=?", (name,)):
        out.append({"finding_id": r["id"], "rule_id": r["rule_id"], "title": r["title"], "project": r["project"], "severity": r["severity"]})
    for r in conn.execute("SELECT f.id, f.rule_id, f.title, f.project, f.severity, f.evidence FROM findings f WHERE f.status='open' AND f.rule_id='BS-090'"):
        if (json.loads(r["evidence"]).get("admin_mfa") or {}).get(principal) is False:
            out.append({"finding_id": r["id"], "rule_id": r["rule_id"], "title": f"{principal} is an admin without MFA",
                        "project": r["project"], "severity": r["severity"]})
    return out


def correlate(conn: sqlite3.Connection, projects: list[str] | None = None) -> list[dict[str, Any]]:
    if not projects:
        return []
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in conn.execute("SELECT * FROM alerts ORDER BY ts"):
        if "*" not in projects and r["project"] not in projects:
            continue
        d = dict(r)
        d["evidence"] = json.loads(d["evidence"]); d["controls"] = json.loads(d["controls"]); d["mitre"] = json.loads(d["mitre"] or "[]")
        groups[d["principal"] or "unknown"].append(d)
    cases = []
    for principal, alerts in groups.items():
        cluster: list[dict] = []
        clusters = []
        for a in alerts:
            if cluster and a["ts"] - cluster[-1]["ts"] > WINDOW_S:
                clusters.append(cluster); cluster = []
            cluster.append(a)
        if cluster:
            clusters.append(cluster)
        for cl in clusters:
            techniques = []
            for a in cl:
                techniques += [t for t in a["mitre"] if t not in techniques]
            tactics = mitre_mod.tactics(techniques)
            context = _posture_context(conn, principal)
            worst = min(cl, key=lambda a: config.SEVERITY_RANK.get(a["severity"], 9))["severity"]
            score = config.SEVERITY_BASE[worst] + 0.5 * max(0, len(tactics) - 1) + (1.0 if context else 0.0)
            statuses = {a["status"] for a in cl}
            cases.append({
                "id": "CASE-" + hashlib.sha1((principal + ":" + cl[0]["id"]).encode()).hexdigest()[:8].upper(),
                "principal": principal, "projects": sorted({a["project"] for a in cl}),
                "severity": worst, "score": round(min(10.0, score), 1),
                "first_ts": cl[0]["ts"], "last_ts": cl[-1]["ts"],
                "status": "open" if "open" in statuses else ("in_progress" if statuses & {"in_progress", "acknowledged"} else "closed"),
                "tactics": tactics, "techniques": [mitre_mod.describe(t) for t in techniques],
                "timeline": [{"ts": a["ts"], "alert_id": a["id"], "detection_id": a["detection_id"], "title": a["title"],
                              "severity": a["severity"], "status": a["status"], "project": a["project"]} for a in cl],
                "posture_context": context,
                "controls": sorted({c for a in cl for c in a["controls"]}),
                "summary": _summary(principal, cl, tactics, context),
            })
    cases.sort(key=lambda c: (-c["score"], -c["last_ts"]))
    return cases


def _summary(principal: str, cl: list[dict], tactics: list[str], context: list[dict]) -> str:
    s = f"{principal}: {len(cl)} alert(s)"
    if tactics:
        s += " spanning " + " → ".join(tactics)
    if context:
        s += ". Made worse by: " + "; ".join(sorted({c["title"] for c in context}))
    return s + "."
