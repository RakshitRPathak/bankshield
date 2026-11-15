"""Synthetic Cloud Audit Log generator + attack scenarios.

Baseline traffic is boring on purpose; the three scenarios inject the patterns the log
detections are built to catch:
  leaked_key            — a user-managed SA key is used from a new country, then bulk-reads a bucket
  privilege_escalation  — a non-admin grants themselves roles/owner outside the change window
  impossible_travel     — one human principal authenticates from two countries within an hour
  log_tampering         — a CI identity switches off data-access logging and deletes the log sink
  brute_force           — a burst of failed logins against an admin, then a success from abroad
  mass_deletion         — a pipeline identity turns off versioning and deletes a bucket's objects
"""

from __future__ import annotations

import json
import random
import sqlite3
import time
from typing import Any

PRINCIPALS = {
    "core-banking-prod": ["core-app-sa@core-banking-prod.iam", "alok.admin@bank", "priya.admin@bank"],
    "payments-prod": ["upi-gateway-sa@payments-prod.iam", "ci-deployer-sa@payments-prod.iam", "dev.lead@bank", "ops.admin@bank"],
    "data-lake": ["etl-pipeline-sa@data-lake.iam", "data.admin@bank", "analyst.one@bank"],
    "shared-services": ["bastion-sa@shared-services.iam", "sec.admin@bank", "ci-jenkins@shared-services.iam"],
}
METHODS = [
    "storage.objects.get", "storage.objects.create", "cloudsql.instances.connect",
    "bigquery.jobs.create", "compute.instances.list", "secretmanager.versions.access",
    "logging.entries.list", "pubsub.topics.publish",
]
INDIA_IPS = ["35.200.1.", "34.93.22.", "35.244.9."]
HOME_COUNTRY = "IN"


def _log(ts: float, project: str, principal: str, method: str, resource: str,
         ip: str = None, country: str = HOME_COUNTRY, status: str = "OK", **extra: Any) -> tuple:
    ip = ip or random.choice(INDIA_IPS) + str(random.randint(2, 250))
    return (ts, project, principal, method, resource, ip, country, status, json.dumps(extra))


def generate_baseline_logs(conn: sqlite3.Connection, hours: int = 48, per_hour: int = 40, seed: int = 7) -> int:
    random.seed(seed)
    now = time.time()
    start = now - hours * 3600
    rows = []
    for h in range(hours):
        for _ in range(per_hour):
            project = random.choice(list(PRINCIPALS))
            principal = random.choice(PRINCIPALS[project])
            method = random.choice(METHODS)
            ts = start + h * 3600 + random.uniform(0, 3600)
            rows.append(_log(ts, project, principal, method, f"projects/{project}/resources/{random.randint(1, 50)}"))
    conn.executemany(
        "INSERT INTO logs(ts, project, principal, method, resource, source_ip, country, status, extra) VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    return len(rows)


# ------------------------------------------------------------------ scenarios

def _leaked_key(now: float) -> list[tuple]:
    sa = "ci-deployer-sa@payments-prod.iam"
    ip = "185.220.101.44"  # not one of ours
    rows = [_log(now - 1500, "payments-prod", sa, "iam.serviceAccountKeys.create", "sa/ci-deployer-sa", key_id="k9")]
    rows.append(_log(now - 1300, "payments-prod", sa, "storage.buckets.list", "projects/payments-prod", ip=ip, country="DE"))
    for i in range(80):  # bulk object reads inside one minute
        rows.append(_log(now - 1200 + i * 0.6, "payments-prod", sa, "storage.objects.get",
                         f"buckets/settlement-files/objects/settle_{i}.csv", ip=ip, country="DE", key_id="k9"))
    return rows


def _privilege_escalation(now: float) -> list[tuple]:
    who = "analyst.one@bank"
    return [
        _log(now - 900, "data-lake", who, "SetIamPolicy", "projects/data-lake",
             granted_role="roles/owner", member=f"user:{who}", change_ticket=None),
        _log(now - 850, "data-lake", who, "bigquery.datasets.setIamPolicy", "datasets/transactions",
             granted_role="roles/bigquery.admin", member=f"user:{who}"),
        _log(now - 800, "data-lake", who, "bigquery.tables.export", "datasets/transactions/tables/cards",
             destination="gs://analyst-scratch/export/"),
    ]


def _impossible_travel(now: float) -> list[tuple]:
    who = "ops.admin@bank"
    return [
        _log(now - 3000, "payments-prod", who, "google.login", "console", ip="35.200.1.9", country="IN"),
        _log(now - 1400, "payments-prod", who, "google.login", "console", ip="103.21.244.7", country="SG"),
        _log(now - 1350, "payments-prod", who, "cloudsql.instances.update", "instances/card-token-vault",
             ip="103.21.244.7", country="SG", change="publicIp=true"),
    ]


def _log_tampering(now: float) -> list[tuple]:
    who = "ci-jenkins@shared-services.iam"
    return [
        _log(now - 700, "data-lake", who, "SetIamAuditConfig", "projects/data-lake", change="DATA_READ audit logging removed"),
        _log(now - 680, "data-lake", who, "logging.sinks.delete", "projects/data-lake/sinks/central-audit", change="sink deleted"),
    ]


def _brute_force(now: float) -> list[tuple]:
    who = "dev.lead@bank"
    ip = "45.155.205.12"
    rows = [_log(now - 2400 + i * 12, "payments-prod", who, "google.login", "console", ip=ip, country="NL", status="DENIED")
            for i in range(14)]
    rows.append(_log(now - 2400 + 14 * 12 + 30, "payments-prod", who, "google.login", "console", ip=ip, country="NL"))
    rows.append(_log(now - 2100, "payments-prod", who, "secretmanager.versions.access", "secrets/psp-api-key", ip=ip, country="NL"))
    return rows


def _mass_deletion(now: float) -> list[tuple]:
    sa = "etl-pipeline-sa@data-lake.iam"
    rows = [_log(now - 600, "data-lake", sa, "storage.buckets.update", "buckets/txn-raw-landing", change="versioning=false")]
    rows += [_log(now - 590 + i * 1.5, "data-lake", sa, "storage.objects.delete",
                  f"buckets/txn-raw-landing/objects/txn_{i:04d}.parquet") for i in range(40)]
    return rows


SCENARIOS = {
    "leaked_key": _leaked_key,
    "privilege_escalation": _privilege_escalation,
    "impossible_travel": _impossible_travel,
    "log_tampering": _log_tampering,
    "brute_force": _brute_force,
    "mass_deletion": _mass_deletion,
}


def run_attack_scenario(conn: sqlite3.Connection, name: str, now: float | None = None) -> int:
    if name not in SCENARIOS:
        raise ValueError(f"unknown scenario {name}; choose from {sorted(SCENARIOS)}")
    rows = SCENARIOS[name](now or time.time())
    conn.executemany(
        "INSERT INTO logs(ts, project, principal, method, resource, source_ip, country, status, extra) VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    return len(rows)
