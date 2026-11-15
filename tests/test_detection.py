import json

from bankshield.detection import scan_assets, findings_for_controls


def test_posture_scan_finds_planted_misconfigs(conn):
    rules = {r["rule_id"] for r in conn.execute("SELECT rule_id FROM findings WHERE status='open'")}
    # Every planted misconfiguration category is caught.
    for expected in ["BS-001", "BS-005", "BS-010", "BS-011", "BS-020", "BS-021", "BS-030", "BS-040",
                     "BS-041", "BS-050", "BS-060", "BS-061", "BS-070", "BS-080", "BS-090", "BS-091", "BS-092", "BS-093",
                     "BS-006", "BS-007", "BS-012", "BS-022", "BS-043", "BS-051", "BS-081", "BS-094", "BS-095"]:
        assert expected in rules, expected


def test_compliant_assets_do_not_fire(conn):
    assets = {r["asset_id"] for r in conn.execute("SELECT asset_id FROM findings WHERE status='open'")}
    for clean in ["cb-sql-ledger", "cb-kms-ledger", "cb-sa-coreapp", "cb-vm-app01", "pay-gcs-settlement", "ss-gcs-logs", "ss-gke-tools"]:
        assert clean not in assets, clean


def test_all_log_detections_fire(conn):
    dets = {r["detection_id"] for r in conn.execute("SELECT detection_id FROM alerts")}
    assert dets == {f"LD-{n:03d}" for n in range(1, 11)}


def test_fix_resolves_finding(conn):
    cfg = json.loads(conn.execute("SELECT config FROM assets WHERE id='pay-gcs-exports'").fetchone()["config"])
    cfg["public"] = False
    conn.execute("UPDATE assets SET config=? WHERE id='pay-gcs-exports'", (json.dumps(cfg),))
    res = scan_assets(conn)
    assert res["resolved"] >= 1
    assert not conn.execute("SELECT 1 FROM findings WHERE rule_id='BS-001' AND asset_id='pay-gcs-exports' AND status='open'").fetchone()


def test_live_state_join_is_project_scoped(conn):
    all_ = findings_for_controls(conn, ["CSP-3.1"], projects=["*"])
    scoped = findings_for_controls(conn, ["CSP-3.1"], projects=["payments-prod"])
    assert all_ and scoped
    assert {f["project"] for f in scoped} == {"payments-prod"}
    assert len(scoped) < len(all_)
