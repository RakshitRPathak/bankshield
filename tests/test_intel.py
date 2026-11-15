"""Risk scoring, attack paths, correlation, detections and the console read models."""
import json
import time

from bankshield import config, db, insights
from bankshield.detection import compute_attack_paths, correlate, run_log_detections, scan_assets
from bankshield.detection.log_detections import ist_hour
from bankshield.rag.clearance import resolve
from bankshield.simulator import generate_baseline_logs, run_attack_scenario, seed_assets, seed_history


def test_risk_scores_rank_exposure_and_sensitivity(conn):
    risk = {(r["rule_id"], r["asset_id"]): r["risk"] for r in conn.execute("SELECT rule_id, asset_id, risk FROM findings")}
    assert risk[("BS-001", "pay-gcs-exports")] == 10.0                           # critical + restricted + internet
    assert risk[("BS-070", "dl-bq-share")] < risk[("BS-001", "pay-gcs-exports")]  # same class, internal data
    assert risk[("BS-094", "dl-proj")] < 3                                        # ownership hygiene
    assert all(0 < v <= 10 for v in risk.values())


def test_sla_due_dates_and_breach(conn):
    row = conn.execute("SELECT first_seen, due_at FROM findings WHERE rule_id='BS-001'").fetchone()
    assert round((row["due_at"] - row["first_seen"]) / 3600) == config.SLA_HOURS["critical"]
    ciso = resolve("meera.ciso")
    assert insights.overview(conn, ciso)["sla_breached"] == 0
    conn.execute("UPDATE findings SET due_at = ? WHERE rule_id='BS-001'", (time.time() - 60,))
    conn.commit()
    assert insights.overview(conn, ciso)["sla_breached"] == 1


def test_attack_paths_are_built_from_live_links(conn):
    paths = compute_attack_paths(conn, ["*"])
    kinds = {p["kind"] for p in paths}
    assert {"internet_to_data", "key_to_takeover", "exposed_admin_port", "residency_exfil", "admin_no_mfa"} <= kinds
    top = paths[0]
    assert top["kind"] == "key_to_takeover" and top["actively_exploited"] and top["score"] == 10.0
    assert any(a["detection_id"] == "LD-003" for a in top["alerts"])
    assert "T1078.004" in top["mitre"] and "IAM-2.1" in top["controls"]
    # Fix one link (remove the primitive role) → the path is gone on the next scan.
    cfg = json.loads(conn.execute("SELECT config FROM assets WHERE id='pay-sa-ci'").fetchone()["config"])
    cfg["roles"] = ["roles/run.developer"]
    conn.execute("UPDATE assets SET config=? WHERE id='pay-sa-ci'", (json.dumps(cfg),))
    scan_assets(conn)
    assert not [p for p in compute_attack_paths(conn, ["*"]) if p["kind"] == "key_to_takeover" and "payments-prod" in p["projects"]]


def test_attack_paths_respect_visibility(conn):
    assert compute_attack_paths(conn, []) == [] and compute_attack_paths(conn, None) == []
    scoped = compute_attack_paths(conn, ["payments-prod", "shared-services"])
    assert scoped and all(set(p["projects"]) <= {"payments-prod", "shared-services"} for p in scoped)
    assert len(scoped) < len(compute_attack_paths(conn, ["*"]))


def test_correlation_builds_a_kill_chain_with_posture_context(conn):
    cases = {c["principal"]: c for c in correlate(conn, ["*"])}
    leaked = cases["ci-deployer-sa@payments-prod.iam"]
    assert [t["detection_id"] for t in leaked["timeline"]] == ["LD-008", "LD-003", "LD-002"]        # ordered by time
    assert leaked["tactics"] == ["Initial Access", "Persistence", "Collection"]
    assert {c["rule_id"] for c in leaked["posture_context"]} >= {"BS-020", "BS-021"}
    assert any("without MFA" in c["title"] for c in cases["ops.admin@bank"]["posture_context"])
    assert correlate(conn, []) == []
    assert "analyst.one@bank" not in {c["principal"] for c in correlate(conn, ["payments-prod"])}


def test_new_detections_carry_evidence_and_mitre(conn):
    alerts = {r["detection_id"]: r for r in conn.execute("SELECT * FROM alerts")}
    assert json.loads(alerts["LD-007"]["evidence"])["succeeded"] is True and alerts["LD-007"]["severity"] == "critical"
    assert json.loads(alerts["LD-009"]["evidence"])["count"] == 40
    assert "logging.sinks.delete" in conn.execute("SELECT group_concat(method) FROM logs WHERE principal LIKE 'ci-jenkins%' AND ts > ?", (time.time() - 3600,)).fetchone()[0]
    assert json.loads(alerts["LD-006"]["mitre"]) == ["T1562.008"]
    assert json.loads(alerts["LD-003"]["evidence"])["key_id"] == "k9"            # resolved from later events


def test_baseline_traffic_raises_no_alerts():
    db.reset()
    c = db.connect()
    seed_assets(c)
    generate_baseline_logs(c, hours=24, per_hour=40)
    assert run_log_detections(c) == {"new": 0, "open": 0}
    c.close()


def test_detections_are_idempotent(conn):
    before = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    assert run_log_detections(conn)["new"] == 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == before


def test_change_window_uses_ist_not_server_time():
    # 2026-01-01 20:30 UTC is 02:00 IST the next day — inside the 01:00–05:00 IST window.
    assert ist_hour(1767299400) == 2


def test_posture_history_and_score(conn):
    n = conn.execute("SELECT COUNT(*) FROM posture_history").fetchone()[0]
    res = scan_assets(conn)
    assert conn.execute("SELECT COUNT(*) FROM posture_history").fetchone()[0] == n + 1
    assert 0 < res["score"] < 100
    cfg = json.loads(conn.execute("SELECT config FROM assets WHERE id='pay-gcs-exports'").fetchone()["config"])
    cfg.update(public=False, uniform_access=True, cmek=True, versioning=True, retention_days=365)
    conn.execute("UPDATE assets SET config=? WHERE id='pay-gcs-exports'", (json.dumps(cfg),))
    assert scan_assets(conn)["score"] > res["score"]


def test_replayed_history_gives_real_first_seen_times():
    db.reset()
    c = db.connect()
    seed_history(c, days=6)
    seed_assets(c)
    scan_assets(c)
    hist = [r["open"] for r in c.execute("SELECT open FROM posture_history ORDER BY ts")]
    assert len(hist) == 7 and hist[0] < hist[-1]
    oldest = c.execute("SELECT MIN(first_seen) FROM findings").fetchone()[0]
    assert time.time() - oldest > 5 * 86400
    assert c.execute("SELECT COUNT(*) FROM findings WHERE status='open' AND due_at < ?", (time.time(),)).fetchone()[0] > 0
    c.close()


def test_overview_and_matrix_are_scoped(conn):
    ciso, analyst = insights.overview(conn, resolve("meera.ciso")), insights.overview(conn, resolve("asha.analyst"))
    assert analyst["findings_open"] < ciso["findings_open"] and set(analyst["by_project"]) <= {"payments-prod", "shared-services"}
    assert analyst["history"] == [] and ciso["history"]
    m = insights.mitre_matrix(conn, resolve("meera.ciso"))
    techs = {t["id"]: t for tac in m["tactics"] for t in tac["techniques"]}
    assert techs["T1562.008"]["detections"] and techs["T1562.008"]["rules"] and techs["T1530"]["open_alerts"] >= 1
    assert all(t["rules"] or t["detections"] for t in techs.values())            # nothing listed without coverage


def test_prometheus_metrics(client, as_user):
    text = client.get("/api/metrics", headers=as_user("meera.ciso")).text
    assert 'bankshield_findings_open{severity="critical"}' in text and "bankshield_posture_score" in text


def test_api_new_endpoints(client, conn, as_user):
    h = as_user("meera.ciso")
    f = client.get("/api/findings?severity=critical&project=payments-prod", headers=h).json()
    assert f and all(x["severity"] == "critical" and x["project"] == "payments-prod" for x in f)
    assert f == sorted(f, key=lambda x: -x["risk"])
    d = client.get(f"/api/findings/{f[0]['id']}", headers=h).json()
    assert d["remediation"]["fix"] and d["clauses"] and "{" not in d["remediation"]["fix"]
    assert client.get("/api/findings?q=card-token", headers=h).json()
    assert client.get("/api/findings?status=bogus", headers=h).status_code == 400
    a = client.get("/api/alerts", headers=h).json()[0]
    r = client.post(f"/api/alerts/{a['id']}/triage", json={"disposition": "investigating", "note": "on it"}, headers=as_user("asha.analyst") if a["project"] in ("payments-prod", "shared-services") else h)
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    fid = conn.execute("SELECT id FROM findings WHERE rule_id='BS-061'").fetchone()["id"]
    e = client.post("/api/exceptions", json={"finding_id": fid, "reason": "vendor needs global endpoint until Q2", "compensating_control": "secret is rotated weekly and access alerts are on", "expires_in_days": 45}, headers=as_user("ravi.senior")).json()
    assert client.post(f"/api/exceptions/{e['id']}/approve", json={"note": "ok"}, headers=h).json()["status"] == "approved"
    rep = client.get("/api/report/compliance?doc=DRS", headers=as_user("ext.auditor")).json()
    assert next(c for c in rep["controls"] if c["clause_id"] == "DRS-1.3")["status"] == "EXCEPTION"
    assert rep["summary"]["clauses_total"] > rep["summary"]["clauses_automated"] and rep["unmonitored_clauses"]
    au = client.get("/api/audit?action=exception", headers=h).json()
    assert au["chain_ok"] and {x["action"] for x in au["entries"]} == {"exception.request", "exception.approved"}
    assert client.post("/api/audit/checkpoint", headers=h).json()["seq"] > 0
    assert client.get("/api/audit", headers=h).json()["checkpoint_ok"] is True
