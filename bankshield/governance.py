"""Exception register (risk acceptance) and alert triage.

DRS-3.2 / CSP-3.1: an exception records the resource, the business reason, the approver, the
compensating control and an expiry no more than 12 months out. Here that is enforced, not
documented: a request without a compensating control is refused, the requester cannot
approve their own request, only the CISO role approves, and the scanner re-opens the finding
the moment the exception lapses.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from typing import Any

from . import config, db
from .rag.clearance import Principal


class GovernanceError(ValueError):
    pass


def _row(conn: sqlite3.Connection, exc_id: str) -> dict[str, Any]:
    r = conn.execute("SELECT * FROM exceptions WHERE id=?", (exc_id,)).fetchone()
    if not r:
        raise KeyError(exc_id)
    return dict(r)


def request_exception(conn: sqlite3.Connection, p: Principal, finding_id: str, reason: str, compensating_control: str,
                      expires_in_days: int) -> dict[str, Any]:
    p.require("exception.request")
    f = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not f or not p.can_see_project(f["project"]):
        raise KeyError(finding_id)   # invisible and non-existent look the same to the caller
    if len(reason.strip()) < 10 or len(compensating_control.strip()) < 10:
        raise GovernanceError("a business reason and a compensating control are both required (DRS-3.2)")
    if not 1 <= expires_in_days <= config.MAX_EXCEPTION_DAYS:
        raise GovernanceError(f"expiry must be between 1 and {config.MAX_EXCEPTION_DAYS} days (DRS-3.2)")
    if conn.execute("SELECT 1 FROM exceptions WHERE rule_id=? AND asset_id=? AND status='pending'", (f["rule_id"], f["asset_id"])).fetchone():
        raise GovernanceError("an exception request is already pending for this finding")
    now = time.time()
    exc_id = "EXC-" + uuid.uuid4().hex[:8].upper()
    conn.execute("INSERT INTO exceptions(id, rule_id, asset_id, project, reason, compensating_control, requested_by, requested_at, expires_at, status)"
                 " VALUES (?,?,?,?,?,?,?,?,?,'pending')",
                 (exc_id, f["rule_id"], f["asset_id"], f["project"], reason.strip(), compensating_control.strip(), p.user, now,
                  now + expires_in_days * 86400))
    conn.commit()
    db.audit(conn, p.user, "exception.request", {"exception": exc_id, "finding": finding_id, "rule": f["rule_id"], "asset": f["asset_id"],
                                                 "expires_in_days": expires_in_days, "reason": reason.strip()})
    return _row(conn, exc_id)


def decide_exception(conn: sqlite3.Connection, p: Principal, exc_id: str, approve: bool, note: str = "") -> dict[str, Any]:
    p.require("exception.approve")
    e = _row(conn, exc_id)
    if e["status"] != "pending":
        raise GovernanceError(f"exception is already {e['status']}")
    if e["requested_by"] == p.user:
        db.audit(conn, p.user, "exception.denied", {"exception": exc_id, "why": "self-approval"})
        raise PermissionError("the requester cannot approve their own exception (IAM-2.2)")
    status = "approved" if approve else "rejected"
    conn.execute("UPDATE exceptions SET status=?, decided_by=?, decided_at=?, decision_note=? WHERE id=?",
                 (status, p.user, time.time(), note, exc_id))
    if approve:
        conn.execute("UPDATE findings SET status='excepted' WHERE rule_id=? AND asset_id=? AND status='open'", (e["rule_id"], e["asset_id"]))
    conn.commit()
    db.audit(conn, p.user, f"exception.{status}", {"exception": exc_id, "rule": e["rule_id"], "asset": e["asset_id"], "note": note})
    return _row(conn, exc_id)


def revoke_exception(conn: sqlite3.Connection, p: Principal, exc_id: str, note: str = "") -> dict[str, Any]:
    p.require("exception.approve")
    e = _row(conn, exc_id)
    if e["status"] != "approved":
        raise GovernanceError("only an approved exception can be revoked")
    conn.execute("UPDATE exceptions SET status='revoked', decided_by=?, decided_at=?, decision_note=? WHERE id=?", (p.user, time.time(), note, exc_id))
    conn.execute("UPDATE findings SET status='open' WHERE rule_id=? AND asset_id=? AND status='excepted'", (e["rule_id"], e["asset_id"]))
    conn.commit()
    db.audit(conn, p.user, "exception.revoked", {"exception": exc_id, "note": note})
    return _row(conn, exc_id)


def list_exceptions(conn: sqlite3.Connection, p: Principal) -> list[dict[str, Any]]:
    now = time.time()
    out = []
    for r in conn.execute("SELECT e.*, a.name AS asset_name FROM exceptions e LEFT JOIN assets a ON a.id=e.asset_id ORDER BY requested_at DESC"):
        if not p.can_see_project(r["project"]):
            continue
        d = dict(r)
        d["effective_status"] = "expired" if d["status"] == "approved" and d["expires_at"] <= now else d["status"]
        d["days_left"] = max(0, int((d["expires_at"] - now) // 86400))
        out.append(d)
    return out


# ---------------------------------------------------------------- alert triage (LOG-2.3)

DISPOSITIONS = {"true_positive", "false_positive", "benign", "investigating"}


def triage_alert(conn: sqlite3.Connection, p: Principal, alert_id: str, disposition: str, note: str = "") -> dict[str, Any]:
    """LOG-2.3: every alert records who handled it and what was decided."""
    p.require("alert.triage")
    a = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not a or not p.can_see_project(a["project"]):
        raise KeyError(alert_id)
    if disposition not in DISPOSITIONS:
        raise GovernanceError(f"disposition must be one of {sorted(DISPOSITIONS)}")
    if disposition in ("false_positive", "benign") and len(note.strip()) < 5:
        raise GovernanceError("closing an alert as false positive / benign needs a note saying why")
    now = time.time()
    status = "closed" if disposition in ("false_positive", "benign") else ("in_progress" if a["status"] == "in_progress" else "acknowledged")
    conn.execute("UPDATE alerts SET status=?, ack_by=COALESCE(ack_by, ?), ack_at=COALESCE(ack_at, ?), disposition=?, note=? WHERE id=?",
                 (status, p.user, now, disposition, note, alert_id))
    conn.commit()
    db.audit(conn, p.user, "alert.triage", {"alert": alert_id, "disposition": disposition, "note": note, "status": status})
    return hydrate_alert(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())


def hydrate_alert(r: sqlite3.Row, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    d = dict(r)
    d["evidence"] = json.loads(d["evidence"]); d["controls"] = json.loads(d["controls"]); d["mitre"] = json.loads(d.get("mitre") or "[]")
    created = d.get("created_at") or d["ts"]
    d["ack_due_at"] = created + config.ALERT_ACK_MINUTES.get(d["severity"], 60) * 60
    d["ack_breached"] = (d.get("ack_at") or now) > d["ack_due_at"]
    return d
