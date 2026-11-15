"""Behavioural detections over audit logs.

Each detection is a function (conn, since) -> list[alert dicts]. Simple, explainable logic —
the point is the shape of the alert (evidence + policy clauses + ATT&CK technique), which is
what the RAG layer, the playbooks and the correlation engine consume.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ..simulator.log_generator import HOME_COUNTRY

IST = timezone(timedelta(hours=5, minutes=30))
CHANGE_WINDOW_HOURS = set(range(1, 5))  # 01:00–05:00 IST approved change window (toy)
PRIVILEGED_ROLES = ("roles/owner", "roles/editor", "roles/bigquery.admin", "roles/iam.securityAdmin",
                    "roles/resourcemanager.projectIamAdmin")

MITRE = {"LD-001": ["T1098.003"], "LD-002": ["T1530"], "LD-003": ["T1078.004"], "LD-004": ["T1078.004"],
         "LD-005": ["T1567", "T1537"], "LD-006": ["T1562.008"], "LD-007": ["T1110"], "LD-008": ["T1098.001"],
         "LD-009": ["T1485"], "LD-010": ["T1078.004"]}
TITLES = {
    "LD-001": "Privileged role granted without change ticket", "LD-002": "Bulk object reads by one identity",
    "LD-003": "Service account used from outside India", "LD-004": "Impossible travel",
    "LD-005": "Export of restricted data to a lower classification", "LD-006": "Audit logging disabled or log sink removed",
    "LD-007": "Password brute force followed by a successful login", "LD-008": "Service account key created",
    "LD-009": "Mass deletion of objects", "LD-010": "Human access from outside India",
}


def ist_hour(ts: float) -> int:
    """Hour of day in IST regardless of the server's own timezone."""
    return datetime.fromtimestamp(ts, IST).hour


def _is_service_account(principal: str) -> bool:
    return principal.endswith(".iam") or principal.endswith(".gserviceaccount.com")


def _alert(det_id: str, project: str, principal: str, severity: str, title: str,
           evidence: dict, controls: list[str], ts: float) -> dict[str, Any]:
    aid = hashlib.sha1(f"{det_id}:{project}:{principal}:{int(ts // 600)}".encode()).hexdigest()[:12]
    return {"id": aid, "detection_id": det_id, "project": project, "principal": principal, "severity": severity,
            "title": title, "evidence": evidence, "controls": controls, "ts": ts, "mitre": MITRE.get(det_id, [])}


def det_primitive_role_grant(conn: sqlite3.Connection, since: float) -> list[dict]:
    out = []
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND method LIKE '%etIamPolicy%' AND status='OK'", (since,)):
        extra = json.loads(r["extra"] or "{}")
        role = extra.get("granted_role", "")
        member = extra.get("member", "")
        self_grant = r["principal"] in member
        in_window = ist_hour(r["ts"]) in CHANGE_WINDOW_HOURS
        if role in PRIVILEGED_ROLES and (self_grant or not extra.get("change_ticket") or not in_window):
            out.append(_alert("LD-001", r["project"], r["principal"], "critical",
                              "Privileged role granted without change ticket" + (" (self-grant)" if self_grant else ""),
                              {"role": role, "member": member, "resource": r["resource"], "in_change_window": in_window,
                               "change_ticket": extra.get("change_ticket")},
                              ["IAM-2.1", "IAM-4.1", "REG-DIG-3"], r["ts"]))
    return out


def _densest_window(rs: list, span_s: float) -> list:
    best: list = []
    j = 0
    for i in range(len(rs)):
        while rs[i]["ts"] - rs[j]["ts"] > span_s:
            j += 1
        if i - j + 1 > len(best):
            best = rs[j:i + 1]
    return best


def det_bulk_object_reads(conn: sqlite3.Connection, since: float, threshold: int = 50) -> list[dict]:
    by_principal: dict[tuple, list] = defaultdict(list)
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND method='storage.objects.get' ORDER BY ts", (since,)):
        by_principal[(r["project"], r["principal"])].append(r)
    out = []
    for (project, principal), rs in by_principal.items():
        best = _densest_window(rs, 60)  # LOG-2.2: more than fifty reads per minute by one identity
        if len(best) >= threshold:
            out.append(_alert("LD-002", project, principal, "high",
                              f"Bulk object reads: {len(best)} GETs in one minute",
                              {"count": len(best), "countries": sorted({r["country"] for r in best}),
                               "source_ips": sorted({r["source_ip"] for r in best}),
                               "sample_resources": [r["resource"] for r in best[:3]]},
                              ["LOG-2.2", "DRS-2.3"], best[0]["ts"]))
    return out


def det_foreign_sa_key_use(conn: sqlite3.Connection, since: float) -> list[dict]:
    out = []
    seen = set()
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND country!=? ORDER BY ts", (since, HOME_COUNTRY)):
        if not _is_service_account(r["principal"]):
            continue
        key = (r["project"], r["principal"], r["country"])
        if key in seen:
            continue
        seen.add(key)
        extra = json.loads(r["extra"] or "{}")
        key_id = extra.get("key_id")
        if key_id is None:  # the first foreign call may not carry the key id; later ones do
            for r2 in conn.execute("SELECT extra FROM logs WHERE ts>=? AND principal=? AND country=?", (since, r["principal"], r["country"])):
                key_id = json.loads(r2["extra"] or "{}").get("key_id") or key_id
        out.append(_alert("LD-003", r["project"], r["principal"], "critical",
                          f"Service account used from outside India ({r['country']})",
                          {"country": r["country"], "source_ip": r["source_ip"], "method": r["method"], "key_id": key_id},
                          ["IAM-3.1", "IAM-3.2", "DRS-2.2"], r["ts"]))
    return out


def det_impossible_travel(conn: sqlite3.Connection, since: float, max_gap_s: int = 3600) -> list[dict]:
    out = []
    logins = defaultdict(list)
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND method='google.login' AND status='OK' ORDER BY ts", (since,)):
        logins[r["principal"]].append(r)
    for principal, rs in logins.items():
        for a, b in zip(rs, rs[1:]):
            if a["country"] != b["country"] and (b["ts"] - a["ts"]) <= max_gap_s:
                out.append(_alert("LD-004", b["project"], principal, "high",
                                  f"Impossible travel: {a['country']} → {b['country']} in {int((b['ts']-a['ts'])/60)} min",
                                  {"from": {"country": a["country"], "ip": a["source_ip"]}, "to": {"country": b["country"], "ip": b["source_ip"]}},
                                  ["IAM-1.2", "LOG-2.1"], b["ts"]))
    return out


def det_restricted_export(conn: sqlite3.Connection, since: float) -> list[dict]:
    out = []
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND method LIKE '%export%'", (since,)):
        extra = json.loads(r["extra"] or "{}")
        out.append(_alert("LD-005", r["project"], r["principal"], "high",
                          "Export of restricted dataset to a non-restricted location",
                          {"resource": r["resource"], "destination": extra.get("destination")},
                          ["DRS-2.3", "CSP-3.1"], r["ts"]))
    return out


def det_log_tampering(conn: sqlite3.Connection, since: float) -> list[dict]:
    """LOG-1.1: disabling audit logs is itself a critical security event."""
    out = []
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND (method LIKE '%SetIamAuditConfig%' OR method LIKE 'logging.sinks.delete%'"
                          " OR method LIKE 'logging.sinks.update%' OR method LIKE 'logging.buckets.delete%') ORDER BY ts", (since,)):
        extra = json.loads(r["extra"] or "{}")
        out.append(_alert("LD-006", r["project"], r["principal"], "critical",
                          "Audit logging disabled or log sink removed",
                          {"method": r["method"], "resource": r["resource"], "change": extra.get("change"), "source_ip": r["source_ip"]},
                          ["LOG-1.1", "LOG-1.2", "REG-DIG-6"], r["ts"]))
    return out


def det_brute_force(conn: sqlite3.Connection, since: float, threshold: int = 10, span_s: int = 300) -> list[dict]:
    out = []
    by_principal: dict[str, list] = defaultdict(list)
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND method='google.login' ORDER BY ts", (since,)):
        by_principal[r["principal"]].append(r)
    for principal, rs in by_principal.items():
        fails = [r for r in rs if r["status"] != "OK"]
        burst = _densest_window(fails, span_s)
        if len(burst) < threshold:
            continue
        success = next((r for r in rs if r["status"] == "OK" and 0 <= r["ts"] - burst[-1]["ts"] <= 900), None)
        out.append(_alert("LD-007", burst[0]["project"], principal, "critical" if success else "high",
                          f"{len(burst)} failed logins in {int((burst[-1]['ts'] - burst[0]['ts']) / 60) + 1} min"
                          + (" followed by a successful login" if success else ""),
                          {"failed": len(burst), "source_ips": sorted({r["source_ip"] for r in burst}),
                           "countries": sorted({r["country"] for r in burst}), "succeeded": bool(success)},
                          ["IAM-1.2", "LOG-2.1", "IAM-1.1"], burst[0]["ts"]))
    return out


def det_sa_key_created(conn: sqlite3.Connection, since: float) -> list[dict]:
    out = []
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND method='iam.serviceAccountKeys.create' AND status='OK'", (since,)):
        extra = json.loads(r["extra"] or "{}")
        by_sa = _is_service_account(r["principal"])
        out.append(_alert("LD-008", r["project"], r["principal"], "high" if by_sa else "medium",
                          "Service account key created" + (" by a service account" if by_sa else ""),
                          {"resource": r["resource"], "key_id": extra.get("key_id"), "created_by_service_account": by_sa},
                          ["IAM-3.1", "LOG-2.1"], r["ts"]))
    return out


def det_mass_deletion(conn: sqlite3.Connection, since: float, threshold: int = 20, span_s: int = 120) -> list[dict]:
    by_principal: dict[tuple, list] = defaultdict(list)
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND method LIKE '%.delete' AND method NOT LIKE 'logging.%' ORDER BY ts", (since,)):
        by_principal[(r["project"], r["principal"])].append(r)
    out = []
    for (project, principal), rs in by_principal.items():
        best = _densest_window(rs, span_s)
        if len(best) >= threshold:
            out.append(_alert("LD-009", project, principal, "critical",
                              f"Mass deletion: {len(best)} delete calls in {int(span_s / 60)} minutes",
                              {"count": len(best), "methods": sorted({r["method"] for r in best}),
                               "sample_resources": [r["resource"] for r in best[:3]]},
                              ["LOG-2.2", "CSP-3.4", "CSP-7.2"], best[0]["ts"]))
    return out


def det_foreign_human_access(conn: sqlite3.Connection, since: float) -> list[dict]:
    """IAM-1.3: human console/API access is permitted only from India."""
    out = []
    seen = set()
    for r in conn.execute("SELECT * FROM logs WHERE ts>=? AND country!=? AND status='OK' ORDER BY ts", (since, HOME_COUNTRY)):
        if _is_service_account(r["principal"]):
            continue
        key = (r["project"], r["principal"], r["country"])
        if key in seen:
            continue
        seen.add(key)
        out.append(_alert("LD-010", r["project"], r["principal"], "high",
                          f"Human access from outside India ({r['country']}) with no travel exception",
                          {"country": r["country"], "source_ip": r["source_ip"], "method": r["method"]},
                          ["IAM-1.3", "DRS-2.2"], r["ts"]))
    return out


DETECTIONS: dict[str, Callable] = {
    "LD-001": det_primitive_role_grant,
    "LD-002": det_bulk_object_reads,
    "LD-003": det_foreign_sa_key_use,
    "LD-004": det_impossible_travel,
    "LD-005": det_restricted_export,
    "LD-006": det_log_tampering,
    "LD-007": det_brute_force,
    "LD-008": det_sa_key_created,
    "LD-009": det_mass_deletion,
    "LD-010": det_foreign_human_access,
}


def run_log_detections(conn: sqlite3.Connection, lookback_hours: int = 24) -> dict[str, int]:
    now = time.time()
    since = now - lookback_hours * 3600
    new = 0
    for det in DETECTIONS.values():
        for a in det(conn, since):
            if conn.execute("SELECT 1 FROM alerts WHERE id=?", (a["id"],)).fetchone():
                continue
            new += 1
            conn.execute(
                "INSERT INTO alerts(id, detection_id, project, principal, severity, title, evidence, controls, ts, status, created_at, mitre)"
                " VALUES (?,?,?,?,?,?,?,?,?,'open',?,?)",
                (a["id"], a["detection_id"], a["project"], a["principal"], a["severity"], a["title"],
                 json.dumps(a["evidence"]), json.dumps(a["controls"]), a["ts"], now, json.dumps(a["mitre"])),
            )
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
    return {"new": new, "open": total}


def alerts_for_controls(conn: sqlite3.Connection, clause_ids: list[str], projects: list[str] | None) -> list[dict[str, Any]]:
    """Live-state join for behavioural alerts (same visibility contract as findings)."""
    if not clause_ids or not projects:
        return []
    wanted = set(clause_ids)
    out = []
    for r in conn.execute("SELECT * FROM alerts WHERE status!='closed' ORDER BY ts DESC"):
        if "*" not in projects and r["project"] not in projects:
            continue
        d = dict(r)
        d["controls"] = json.loads(d["controls"]); d["evidence"] = json.loads(d["evidence"]); d["mitre"] = json.loads(d["mitre"] or "[]")
        if wanted & set(d["controls"]):
            out.append(d)
    return out
