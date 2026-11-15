"""Simulated bank GCP estate with deliberate misconfigurations.

Four projects, 37 assets, mirroring a typical landing zone:
  core-banking-prod  (restricted)  — ledger DB, KMS, core app
  payments-prod      (restricted)  — UPI/IMPS gateway, card tokens
  data-lake          (internal)    — analytics buckets, BigQuery
  shared-services    (internal)    — logging, CI, bastion
Each asset carries a JSON config that the rules engine evaluates. Misconfigs are tagged in
comments so you can see what the engine is expected to catch.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

IN_REGION = "asia-south1"
OUT_REGION = "us-central1"


def _a(id_: str, project: str, type_: str, name: str, region: str, sensitivity: str, owner: str, **cfg: Any) -> dict:
    return {
        "id": id_, "project": project, "type": type_, "name": name, "region": region,
        "sensitivity": sensitivity, "owner": owner, "config": cfg,
    }


def build_estate() -> list[dict]:
    now = time.time()
    day = 86400
    assets: list[dict] = []

    # ---------------- core-banking-prod (restricted)
    p = "core-banking-prod"
    assets += [
        _a("cb-sql-ledger", p, "cloudsql", "ledger-primary", IN_REGION, "restricted", "core-platform@bank",
           public_ip=False, require_ssl=True, backups_enabled=True, cmek=True, deletion_protection=True),
        _a("cb-sql-replica", p, "cloudsql", "ledger-replica", OUT_REGION, "restricted", "core-platform@bank",  # MISCONFIG: out of region
           public_ip=False, require_ssl=True, backups_enabled=True, cmek=True, deletion_protection=True),
        _a("cb-sql-reporting", p, "cloudsql", "regulatory-reporting", IN_REGION, "restricted", "core-platform@bank",  # MISCONFIG: no backups
           public_ip=False, require_ssl=True, backups_enabled=False, cmek=True, deletion_protection=True),
        _a("cb-kms-ledger", p, "kms_key", "ledger-cmek", IN_REGION, "restricted", "security@bank",
           rotation_period_days=90, state="ENABLED"),
        _a("cb-kms-archive", p, "kms_key", "archive-cmek", IN_REGION, "restricted", "security@bank",
           rotation_period_days=365, state="ENABLED"),  # MISCONFIG: rotation too slow
        _a("cb-sa-coreapp", p, "service_account", "core-app-sa", None, "restricted", "core-platform@bank",
           roles=["roles/cloudsql.client", "roles/secretmanager.secretAccessor"], user_managed_keys=[]),
        _a("cb-sa-batch", p, "service_account", "batch-runner-sa", None, "restricted", "core-platform@bank",
           roles=["roles/owner"], user_managed_keys=[{"id": "k1", "age_days": 210}]),  # MISCONFIG: owner + old key
        _a("cb-vm-app01", p, "compute_instance", "core-app-01", IN_REGION, "restricted", "core-platform@bank",
           external_ip=False, disk_cmek=True, os_login=True, shielded_vm=True, service_account="core-app-sa"),
        _a("cb-vm-app02", p, "compute_instance", "core-app-02", IN_REGION, "restricted", "core-platform@bank",
           external_ip=False, disk_cmek=False, os_login=True, shielded_vm=True, service_account="default"),  # MISCONFIG: no CMEK, default SA
        _a("cb-fw-internal", p, "firewall", "allow-internal", IN_REGION, "restricted", "network@bank",
           direction="INGRESS", source_ranges=["10.0.0.0/8"], ports=["443", "3306"], action="allow"),
        _a("cb-proj", p, "project", p, None, "restricted", "core-platform@bank",
           business_owner="head.core-banking@bank", technical_owner="core-platform@bank", central_log_sink=True,
           vpc_sc_perimeter=True, audit_logs_enabled=True, admin_mfa_enforced=True, log_retention_days=400,
           admins=["alok.admin@bank", "priya.admin@bank"], admin_mfa={"alok.admin@bank": True, "priya.admin@bank": True}),
    ]

    # ---------------- payments-prod (restricted)
    p = "payments-prod"
    assets += [
        _a("pay-sql-tokens", p, "cloudsql", "card-token-vault", IN_REGION, "restricted", "payments@bank",
           public_ip=True, require_ssl=False, backups_enabled=True, cmek=True, deletion_protection=True),  # MISCONFIG: public IP, no SSL
        _a("pay-gcs-settlement", p, "bucket", "settlement-files", IN_REGION, "restricted", "payments@bank",
           public=False, versioning=True, uniform_access=True, cmek=True, retention_days=2555),
        _a("pay-gcs-exports", p, "bucket", "merchant-exports", IN_REGION, "restricted", "payments@bank",
           public=True, versioning=False, uniform_access=False, cmek=False, retention_days=0),  # MISCONFIG: public
        _a("pay-fw-bastion", p, "firewall", "allow-ssh-any", IN_REGION, "restricted", "network@bank",
           direction="INGRESS", source_ranges=["0.0.0.0/0"], ports=["22"], action="allow"),  # MISCONFIG
        _a("pay-sa-gateway", p, "service_account", "upi-gateway-sa", None, "restricted", "payments@bank",
           roles=["roles/pubsub.publisher", "roles/cloudsql.client"], user_managed_keys=[{"id": "k7", "age_days": 30}],
           external_workload=True),  # on-prem UPI switch: the one approved use of a key (IAM-3.1)
        _a("pay-sa-ci", p, "service_account", "ci-deployer-sa", None, "restricted", "payments@bank",
           roles=["roles/editor"], user_managed_keys=[{"id": "k9", "age_days": 120}]),  # MISCONFIG: editor + old key
        _a("pay-secret-api", p, "secret", "psp-api-key", IN_REGION, "restricted", "payments@bank",
           rotation_days=30, last_rotated_days_ago=12, replication="user-managed"),
        _a("pay-secret-legacy", p, "secret", "legacy-switch-pass", IN_REGION, "restricted", "payments@bank",
           rotation_days=0, last_rotated_days_ago=400, replication="automatic"),  # MISCONFIG: never rotated, auto-replicated
        _a("pay-kms-card", p, "kms_key", "card-vault-cmek", IN_REGION, "restricted", "security@bank",
           rotation_period_days=90, state="ENABLED", protects="card_data"),  # MISCONFIG: card keys rotate every 30d
        _a("pay-vm-gateway", p, "compute_instance", "upi-gateway-01", IN_REGION, "restricted", "payments@bank",  # MISCONFIG: external IP
           external_ip=True, disk_cmek=True, os_login=True, shielded_vm=True, service_account="upi-gateway-sa"),
        _a("pay-proj", p, "project", p, None, "restricted", "payments@bank",
           business_owner="head.payments@bank", technical_owner="payments@bank", central_log_sink=True,
           vpc_sc_perimeter=True, audit_logs_enabled=True, admin_mfa_enforced=False, log_retention_days=400,  # MISCONFIG: MFA
           admins=["dev.lead@bank", "ops.admin@bank"], admin_mfa={"dev.lead@bank": True, "ops.admin@bank": False}),
    ]

    # ---------------- data-lake (internal, but holds restricted datasets)
    p = "data-lake"
    assets += [
        _a("dl-gcs-raw", p, "bucket", "txn-raw-landing", IN_REGION, "restricted", "data-eng@bank",
           public=False, versioning=True, uniform_access=True, cmek=True, retention_days=365),
        _a("dl-gcs-ml", p, "bucket", "ml-feature-store", OUT_REGION, "restricted", "data-eng@bank",  # MISCONFIG: region
           public=False, versioning=False, uniform_access=True, cmek=False, retention_days=0),
        _a("dl-gcs-scratch", p, "bucket", "analyst-scratch", IN_REGION, "internal", "data-eng@bank",
           public=False, versioning=False, uniform_access=False, cmek=False, retention_days=0),  # MISCONFIG: no uniform access
        _a("dl-bq-txn", p, "bigquery_dataset", "transactions", IN_REGION, "restricted", "data-eng@bank",
           public=False, cmek=True, default_table_expiry_days=0),
        _a("dl-bq-share", p, "bigquery_dataset", "partner_share", IN_REGION, "internal", "data-eng@bank",
           public=True, cmek=False, default_table_expiry_days=0),  # MISCONFIG: allAuthenticatedUsers
        _a("dl-sa-pipeline", p, "service_account", "etl-pipeline-sa", None, "restricted", "data-eng@bank",
           roles=["roles/bigquery.dataEditor", "roles/storage.objectAdmin"], user_managed_keys=[]),
        _a("dl-proj", p, "project", p, None, "restricted", "data-eng@bank",
           business_owner="head.analytics@bank", technical_owner=None, central_log_sink=False,  # MISCONFIG: no technical owner, no log sink
           vpc_sc_perimeter=False, audit_logs_enabled=True, admin_mfa_enforced=True, log_retention_days=180,  # MISCONFIG: no perimeter, retention
           admins=["data.admin@bank"], admin_mfa={"data.admin@bank": True}),
    ]

    # ---------------- shared-services (internal)
    p = "shared-services"
    assets += [
        _a("ss-gcs-logs", p, "bucket", "central-audit-logs", IN_REGION, "internal", "secops@bank",
           public=False, versioning=True, uniform_access=True, cmek=True, retention_days=400, locked=True, log_bucket=True),
        _a("ss-gcs-archive", p, "bucket", "audit-archive-staging", IN_REGION, "internal", "secops@bank",  # MISCONFIG: unlocked, short retention
           public=False, versioning=True, uniform_access=True, cmek=True, retention_days=200, locked=False, log_bucket=True),
        _a("ss-vm-bastion", p, "compute_instance", "bastion-01", IN_REGION, "internal", "network@bank",
           external_ip=True, approved_bastion=True, disk_cmek=True, os_login=True, shielded_vm=True, service_account="bastion-sa"),
        _a("ss-vm-jenkins", p, "compute_instance", "ci-jenkins", IN_REGION, "internal", "platform@bank",
           external_ip=True, disk_cmek=True, os_login=False, shielded_vm=False, service_account="default"),  # MISCONFIG
        _a("ss-fw-rdp", p, "firewall", "allow-rdp-any", IN_REGION, "internal", "network@bank",
           direction="INGRESS", source_ranges=["0.0.0.0/0"], ports=["3389"], action="allow"),  # MISCONFIG
        _a("ss-gke-tools", p, "gke_cluster", "tools-cluster", IN_REGION, "internal", "platform@bank",
           private_nodes=True, legacy_abac=False, workload_identity=True, network_policy=True),
        _a("ss-gke-legacy", p, "gke_cluster", "legacy-cluster", IN_REGION, "internal", "platform@bank",
           private_nodes=False, legacy_abac=True, workload_identity=False, network_policy=False),  # MISCONFIG
        _a("ss-proj", p, "project", p, None, "internal", "secops@bank",
           business_owner="ciso.office@bank", technical_owner="secops@bank", central_log_sink=True,
           vpc_sc_perimeter=False, audit_logs_enabled=False, admin_mfa_enforced=True, log_retention_days=400,  # MISCONFIG: audit logs off
           admins=["sec.admin@bank"], admin_mfa={"sec.admin@bank": True}),
    ]
    return assets


def seed_assets(conn: sqlite3.Connection, assets: list[dict] | None = None) -> int:
    assets = assets or build_estate()
    conn.execute("DELETE FROM assets")
    conn.executemany(
        "INSERT INTO assets(id, project, type, name, region, sensitivity, owner, config) VALUES (?,?,?,?,?,?,?,?)",
        [(a["id"], a["project"], a["type"], a["name"], a["region"], a["sensitivity"], a["owner"], json.dumps(a["config"]))
         for a in assets],
    )
    conn.commit()
    return len(assets)


def seed_history(conn: sqlite3.Connection, days: int = 10) -> int:
    """Replay the estate's growth so the posture trend and SLA clocks have something to show.

    This is not fabricated data: each past day is a real scan of the estate as it stood then
    (assets are onboarded in order, ~60% present on the first day), run with a backdated clock.
    Findings therefore carry a true first-seen time and the oldest ones are past their SLA.
    """
    from ..detection.rules import scan_assets  # local import: detection imports the simulator
    assets = build_estate()
    now = time.time()
    conn.execute("DELETE FROM assets")
    n0 = int(len(assets) * 0.6)
    for d in range(days, 0, -1):
        upto = n0 + round((len(assets) - n0) * (days - d) / max(1, days - 1))
        have = {r["id"] for r in conn.execute("SELECT id FROM assets")}
        for a in assets[:upto]:
            if a["id"] not in have:
                conn.execute("INSERT INTO assets(id, project, type, name, region, sensitivity, owner, config) VALUES (?,?,?,?,?,?,?,?)",
                             (a["id"], a["project"], a["type"], a["name"], a["region"], a["sensitivity"], a["owner"], json.dumps(a["config"])))
        scan_assets(conn, now=now - d * 86400)
    conn.commit()
    return days
