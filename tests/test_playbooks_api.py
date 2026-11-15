import json
import sqlite3

import pytest

from bankshield import db
from bankshield.playbooks import approve_step, open_incident


def test_auto_step_runs_and_closes_loop(conn):
    fid = conn.execute("SELECT id FROM findings WHERE rule_id='BS-001' AND status='open'").fetchone()["id"]
    inc = open_incident(conn, "PB-PUBLIC-STORAGE", "asha.analyst", finding_id=fid)
    assert inc["steps"][0]["state"] == "done" and inc["steps"][0]["actor"] == "system:auto"
    cfg = json.loads(conn.execute("SELECT config FROM assets WHERE id='pay-gcs-exports'").fetchone()["config"])
    assert cfg["public"] is False


def test_analyst_cannot_approve_containment(conn):
    aid = conn.execute("SELECT id FROM alerts WHERE detection_id='LD-004'").fetchone()["id"]
    inc = open_incident(conn, "PB-COMPROMISED-ACCOUNT", "asha.analyst", alert_id=aid)
    with pytest.raises(PermissionError):
        approve_step(conn, inc["id"], "revoke_sessions", "asha.analyst", "analyst")
    step = approve_step(conn, inc["id"], "revoke_sessions", "ravi.senior", "senior_analyst", "verified")
    assert step["state"] == "done"


def test_audit_chain_verifies_and_detects_tamper(conn):
    db.audit(conn, "t", "x", {"a": 1})
    ok, n = db.verify_audit_chain(conn)
    assert ok and n >= 1
    # Layer 1: the table itself refuses edits.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE audit SET payload='{\"a\": 2}' WHERE seq=(SELECT MIN(seq) FROM audit)")
    # Layer 2: an attacker with file access drops the trigger — the hash chain still catches the edit.
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit SET payload='{\"a\": 2}' WHERE seq=(SELECT MIN(seq) FROM audit)")
    conn.commit()
    ok, _ = db.verify_audit_chain(conn)
    assert not ok


def test_api_ask_and_rbac(client):
    r = client.post("/api/ask", json={"question": "Is MFA required for admins?"}, headers={"X-User": "asha.analyst"})
    assert r.status_code == 200 and "IAM-1.1" in r.json()["citations"]
    r = client.get("/api/audit", headers={"X-User": "asha.analyst"})
    assert r.status_code == 403
    r = client.get("/api/audit", headers={"X-User": "meera.ciso"})
    assert r.status_code == 200 and r.json()["chain_ok"]


def test_api_findings_scoped(client):
    r = client.get("/api/findings", headers={"X-User": "asha.analyst"})
    assert r.status_code == 200
    assert {f["project"] for f in r.json()} <= {"payments-prod", "shared-services"}


def test_api_incident_flow(client):
    alerts = client.get("/api/alerts", headers={"X-User": "meera.ciso"}).json()
    a = next(x for x in alerts if x["detection_id"] == "LD-003")
    r = client.post("/api/incidents", json={"playbook_id": "PB-LEAKED-KEY", "alert_id": a["id"]}, headers={"X-User": "asha.analyst"})
    assert r.status_code == 200
    inc = r.json()
    assert inc["steps"][0]["state"] == "done"  # auto disable key
    r = client.post(f"/api/incidents/{inc['id']}/steps/revoke_sessions/approve", json={"reason": "x"}, headers={"X-User": "asha.analyst"})
    assert r.status_code == 403
    r = client.post(f"/api/incidents/{inc['id']}/steps/revoke_sessions/approve", json={"reason": "x"}, headers={"X-User": "ravi.senior"})
    assert r.status_code == 200 and r.json()["state"] == "done"


def test_api_report(client):
    r = client.get("/api/report/compliance?doc=DRS", headers={"X-User": "ext.auditor"})
    assert r.status_code == 200
    rep = r.json()
    assert all(c["clause_id"].startswith("DRS") for c in rep["controls"])
    assert any(c["status"] == "FAIL" for c in rep["controls"])
    r = client.get("/api/report/compliance.md", headers={"X-User": "ext.auditor"})
    assert r.status_code == 200 and r.text.startswith("# Compliance Evidence Report")


def test_api_gap_analysis(client):
    reqs = [{"id": "NEW-1", "text": "Keys must rotate within 90 days", "maps_to": ["CSP-4.2"]},
            {"id": "NEW-2", "text": "Quantum-safe crypto", "maps_to": []}]
    r = client.post("/api/report/gap", json={"requirements": reqs}, headers={"X-User": "meera.ciso"})
    out = r.json()
    assert out[0]["gap"] == "controls failing" and out[1]["gap"] == "no internal control mapped"
