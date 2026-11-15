"""Playbook controls, exception register, alert triage and audit-trail integrity."""
import json
import time

import pytest

from bankshield import config, db, governance
from bankshield.detection import scan_assets
from bankshield.playbooks import IncidentError, approve_step, get_incident, incident_report_md, open_incident, reject_step
from bankshield.rag.clearance import resolve
from bankshield.reports import compliance_report


def _finding(conn, rule, asset=None):
    q = "SELECT id FROM findings WHERE rule_id=? AND status='open'" + (" AND asset_id=?" if asset else "")
    return conn.execute(q, (rule, asset) if asset else (rule,)).fetchone()["id"]


def _alert(conn, det):
    return conn.execute("SELECT id FROM alerts WHERE detection_id=?", (det,)).fetchone()["id"]


# ------------------------------------------------------------------ playbooks

def test_auto_step_needs_unambiguous_evidence(conn):
    # LD-003 carries the foreign country → the key is disabled automatically (IR-3.2).
    inc = open_incident(conn, "PB-LEAKED-KEY", "asha.analyst", alert_id=_alert(conn, "LD-003"))
    assert inc["steps"][0]["state"] == "done" and inc["steps"][0]["actor"] == "system:auto"
    # LD-002 (bulk reads) has no `country` → same playbook, but the step waits for a human.
    inc = open_incident(conn, "PB-LEAKED-KEY", "asha.analyst", alert_id=_alert(conn, "LD-002"))
    step = inc["steps"][0]
    assert step["state"] == "pending" and step["mode"] == "approve" and "country" in step["downgraded"]


def test_auto_remediation_only_for_restricted_resources(conn):
    inc = open_incident(conn, "PB-PUBLIC-STORAGE", "ravi.senior", finding_id=_finding(conn, "BS-070"))   # internal dataset
    assert inc["steps"][0]["state"] == "pending" and "internal" in inc["steps"][0]["downgraded"]
    assert json.loads(conn.execute("SELECT config FROM assets WHERE id='dl-bq-share'").fetchone()["config"])["public"] is True


def test_four_eyes_and_role_gate(conn, restore_config):
    inc = open_incident(conn, "PB-COMPROMISED-ACCOUNT", "ravi.senior", alert_id=_alert(conn, "LD-004"))
    with pytest.raises(PermissionError, match="four-eyes"):
        approve_step(conn, inc["id"], "revoke_sessions", "ravi.senior")
    with pytest.raises(PermissionError):                       # asserting a role you do not hold changes nothing
        approve_step(conn, inc["id"], "revoke_sessions", "asha.analyst", "ciso")
    with pytest.raises(PermissionError):
        reject_step(conn, inc["id"], "revoke_sessions", "asha.analyst", "no")
    with pytest.raises(PermissionError):                       # auditors are read-only
        approve_step(conn, inc["id"], "review_window", "ext.auditor")
    assert approve_step(conn, inc["id"], "revoke_sessions", "meera.ciso", reason="verified")["state"] == "done"
    assert approve_step(conn, inc["id"], "review_window", "asha.analyst")["state"] == "done"   # guidance step: analysts may
    config.FOUR_EYES = False
    assert approve_step(conn, inc["id"], "force_reenrol", "ravi.senior")["state"] == "done"
    denied = [r["action"] for r in conn.execute("SELECT action FROM audit WHERE action='incident.step.denied'")]
    assert len(denied) >= 4                                    # refusals are evidence too


def test_incident_closes_alert_and_guards_duplicates(conn):
    aid = _alert(conn, "LD-004")
    inc = open_incident(conn, "PB-COMPROMISED-ACCOUNT", "asha.analyst", alert_id=aid)
    with pytest.raises(IncidentError):
        open_incident(conn, "PB-COMPROMISED-ACCOUNT", "asha.analyst", alert_id=aid)
    with pytest.raises(IncidentError):                         # playbook not approved for this trigger
        open_incident(conn, "PB-PUBLIC-STORAGE", "asha.analyst", alert_id=aid)
    assert conn.execute("SELECT status FROM alerts WHERE id=?", (aid,)).fetchone()["status"] == "in_progress"
    for s in ("revoke_sessions", "force_reenrol"):
        approve_step(conn, inc["id"], s, "ravi.senior")
    reject_step(conn, inc["id"], "review_window", "ravi.senior", "covered by case review")
    done = get_incident(conn, inc["id"])
    assert done["status"] == "closed" and done["closed_at"]
    assert conn.execute("SELECT status FROM alerts WHERE id=?", (aid,)).fetchone()["status"] == "closed"


def test_failed_action_is_not_marked_done(conn):
    inc = open_incident(conn, "PB-PUBLIC-DB", "asha.analyst", finding_id=_finding(conn, "BS-010"))
    conn.execute("DELETE FROM assets WHERE id='pay-sql-tokens'")   # the resource vanishes before approval
    conn.commit()
    step = approve_step(conn, inc["id"], "remove_public_ip", "ravi.senior")
    assert step["state"] == "failed" and step["result"]["ok"] is False
    assert get_incident(conn, inc["id"])["status"] == "open"
    assert conn.execute("SELECT 1 FROM audit WHERE action='incident.step.failed'").fetchone()


def test_new_playbook_actions_close_the_loop(conn):
    for pb, rule, step in [("PB-EXPOSED-ADMIN-PORT", "BS-030", "restrict_source"), ("PB-PUBLIC-DB", "BS-010", "remove_public_ip"),
                           ("PB-LOG-TAMPER", "BS-091", "restore_logging")]:
        fid = _finding(conn, rule)
        inc = open_incident(conn, pb, "asha.analyst", finding_id=fid)
        assert approve_step(conn, inc["id"], step, "ravi.senior")["state"] == "done"
        scan_assets(conn)
        assert conn.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()["status"] == "resolved", pb


def test_regulatory_clock_and_review_report(conn):
    inc = open_incident(conn, "PB-LEAKED-KEY", "asha.analyst", alert_id=_alert(conn, "LD-003"))
    ctx = inc["context"]
    assert inc["severity"] == 1 and ctx["reg_deadline"] - ctx["reg_clock_started"] == config.REG_REPORT_HOURS * 3600
    md = incident_report_md(conn, inc["id"])
    assert md.startswith("# Post-incident review") and "Regulatory clock" in md and "system:auto" in md
    low = open_incident(conn, "PB-PUBLIC-STORAGE", "asha.analyst", finding_id=_finding(conn, "BS-001"))
    assert low["severity"] == 1


# ------------------------------------------------------------------ exception register

def test_exception_lifecycle(conn):
    senior, ciso, analyst = resolve("ravi.senior"), resolve("meera.ciso"), resolve("asha.analyst")
    fid = _finding(conn, "BS-050")   # archive key rotation
    with pytest.raises(PermissionError):
        governance.request_exception(conn, analyst, fid, "legacy archive format", "key is offline and access is logged", 90)
    with pytest.raises(governance.GovernanceError):   # no compensating control
        governance.request_exception(conn, senior, fid, "legacy archive format", "none", 90)
    with pytest.raises(governance.GovernanceError):   # DRS-3.2: at most 12 months
        governance.request_exception(conn, senior, fid, "legacy archive format", "key is offline and access is logged", 400)
    e = governance.request_exception(conn, senior, fid, "legacy archive format", "key is offline and access is logged", 30)
    assert e["status"] == "pending"
    assert conn.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()["status"] == "open"   # pending changes nothing
    with pytest.raises(PermissionError):              # seniors request, only the CISO decides
        governance.decide_exception(conn, senior, e["id"], True)
    governance.decide_exception(conn, ciso, e["id"], True, "accepted until migration")
    assert conn.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()["status"] == "excepted"
    res = scan_assets(conn)
    assert res["excepted"] == 1
    ctrl = next(c for c in compliance_report(conn)["controls"] if c["clause_id"] == "CSP-4.2")
    assert ctrl["status"] in ("EXCEPTION", "FAIL") and ctrl["excepted"] == 1     # never silently PASS
    # the exception lapses → the next scan re-opens the finding
    scan_assets(conn, now=time.time() + 31 * 86400)
    assert conn.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()["status"] == "open"
    assert governance.list_exceptions(conn, ciso)[0]["status"] == "approved"


def test_exception_self_approval_and_revoke(conn):
    ciso = resolve("meera.ciso")
    fid = _finding(conn, "BS-094")
    e = governance.request_exception(conn, ciso, fid, "owner being appointed this quarter", "CISO office acts as interim owner", 60)
    with pytest.raises(PermissionError, match="own exception"):
        governance.decide_exception(conn, ciso, e["id"], True)
    e2 = governance.request_exception(conn, resolve("ravi.senior"), _finding(conn, "BS-092"), "retention migration in progress", "logs mirrored to the central bucket", 60)
    governance.decide_exception(conn, ciso, e2["id"], True)
    governance.revoke_exception(conn, ciso, e2["id"], "migration cancelled")
    assert conn.execute("SELECT status FROM findings WHERE rule_id='BS-092'").fetchone()["status"] == "open"


def test_alert_triage_records_decision(conn):
    analyst = resolve("asha.analyst")
    aid = conn.execute("SELECT id FROM alerts WHERE project='payments-prod' AND detection_id='LD-010'").fetchone()["id"]
    with pytest.raises(governance.GovernanceError):   # closing needs a reason
        governance.triage_alert(conn, analyst, aid, "false_positive", "")
    a = governance.triage_alert(conn, analyst, aid, "investigating", "checking travel register")
    assert a["status"] == "acknowledged" and a["ack_by"] == "asha.analyst" and a["ack_at"]
    a = governance.triage_alert(conn, analyst, aid, "benign", "approved travel exception TRV-118")
    assert a["status"] == "closed" and a["ack_by"] == "asha.analyst"
    other = conn.execute("SELECT id FROM alerts WHERE project='data-lake'").fetchone()["id"]
    with pytest.raises(KeyError):                     # not her project: looks like it does not exist
        governance.triage_alert(conn, analyst, other, "investigating", "")
    with pytest.raises(PermissionError):
        governance.triage_alert(conn, resolve("ext.auditor"), aid, "investigating", "")


# ------------------------------------------------------------------ audit trail

def test_audit_is_append_only_and_checkpoint_detects_truncation(conn):
    import sqlite3
    for i in range(5):
        db.audit(conn, "t", "x", {"i": i})
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)")
    db.audit_checkpoint(conn, "t")
    assert db.verify_audit_detail(conn)["checkpoint_ok"] is True
    # Attacker with file access drops the trigger and deletes the tail. Every remaining record still
    # hashes correctly — only the external checkpoint reveals that history was cut.
    conn.execute("DROP TRIGGER audit_no_delete")
    conn.execute("DELETE FROM audit WHERE seq > (SELECT MAX(seq) - 3 FROM audit)")
    conn.commit()
    d = db.verify_audit_detail(conn)
    assert d["broken_at"] is None and d["checkpoint_ok"] is False and d["ok"] is False


def test_keyed_audit_chain_cannot_be_reforged(conn, restore_config):
    config.AUDIT_HMAC_KEY = "audit-key-0123456789"
    db.reset()
    c = db.connect()
    for i in range(3):
        db.audit(c, "t", "x", {"i": i})
    assert db.verify_audit_detail(c) | {"head": 0, "checkpoint": 0} == {"ok": True, "records": 3, "broken_at": None, "head": 0,
                                                                       "keyed": True, "checkpoint": 0, "checkpoint_ok": None}
    config.AUDIT_HMAC_KEY = ""          # someone without the key recomputing plain SHA-256 gets a different chain
    assert db.verify_audit_chain(c) == (False, 0)
    c.close()


def test_audit_fields_cannot_smuggle_delimiters(conn):
    assert db._hash("p", 1.0, "a|b", "c", "{}") != db._hash("p", 1.0, "a", "b|c", "{}")


def test_old_database_is_migrated(tmp_path):
    import sqlite3
    p = tmp_path / "old.db"
    c = sqlite3.connect(p)
    c.executescript("""CREATE TABLE findings (id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, asset_id TEXT NOT NULL, project TEXT NOT NULL,
        severity TEXT NOT NULL, title TEXT NOT NULL, evidence TEXT NOT NULL, controls TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
        first_seen REAL NOT NULL, last_seen REAL NOT NULL);
        INSERT INTO findings VALUES ('f1','BS-001','a','p','critical','t','{}','[]','open',1,1);""")
    c.commit(); c.close()
    c = db.connect(p)
    cols = {r[1] for r in c.execute("PRAGMA table_info(findings)")}
    assert {"risk", "due_at", "mitre"} <= cols and c.execute("SELECT risk, mitre FROM findings").fetchone()[1] == "[]"
    c.close()
