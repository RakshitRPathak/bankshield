"""Real-GCP collectors (optional). Map Cloud Asset Inventory + Cloud Audit Logs into the same
`assets` / `logs` tables the simulator fills, so every other layer is unchanged.

Requires: google-cloud-asset, google-cloud-logging, and ADC credentials inside the bank's VPC.
Nothing here runs in the offline prototype; it documents the production ingestion contract.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Iterable


def _sensitivity(labels: dict) -> str:
    return labels.get("sensitivity", "internal")


def collect_assets(parent: str) -> Iterable[dict]:
    """Yield asset dicts for a folder/org: parent='folders/123' or 'organizations/456'."""
    from google.cloud import asset_v1  # lazy

    client = asset_v1.AssetServiceClient()
    types = {
        "storage.googleapis.com/Bucket": "bucket",
        "sqladmin.googleapis.com/Instance": "cloudsql",
        "compute.googleapis.com/Instance": "compute_instance",
        "compute.googleapis.com/Firewall": "firewall",
        "iam.googleapis.com/ServiceAccount": "service_account",
        "cloudkms.googleapis.com/CryptoKey": "kms_key",
        "bigquery.googleapis.com/Dataset": "bigquery_dataset",
        "container.googleapis.com/Cluster": "gke_cluster",
        "secretmanager.googleapis.com/Secret": "secret",
    }
    req = asset_v1.ListAssetsRequest(parent=parent, asset_types=list(types), content_type=asset_v1.ContentType.RESOURCE)
    for a in client.list_assets(request=req):
        data = dict(a.resource.data)
        project = a.name.split("/projects/")[1].split("/")[0] if "/projects/" in a.name else ""
        yield {
            "id": a.name.rsplit("/", 1)[-1],
            "project": project,
            "type": types[a.asset_type],
            "name": data.get("name", a.name.rsplit("/", 1)[-1]),
            "region": data.get("location") or data.get("region") or data.get("zone", "").rsplit("-", 1)[0] or None,
            "sensitivity": _sensitivity(data.get("labels", {})),
            "owner": data.get("labels", {}).get("owner"),
            "config": normalise(types[a.asset_type], data),
        }


def normalise(type_: str, d: dict) -> dict:
    """Map provider-specific fields onto the rule engine's config keys."""
    if type_ == "bucket":
        iam = d.get("iamConfiguration", {})
        return {
            "public": False,  # resolved separately from IAM policy (allUsers / allAuthenticatedUsers binding)
            "uniform_access": iam.get("uniformBucketLevelAccess", {}).get("enabled", False),
            "versioning": d.get("versioning", {}).get("enabled", False),
            "cmek": bool(d.get("encryption", {}).get("defaultKmsKeyName")),
            "retention_days": int(d.get("retentionPolicy", {}).get("retentionPeriod", 0)) // 86400,
        }
    if type_ == "cloudsql":
        s = d.get("settings", {})
        ip = s.get("ipConfiguration", {})
        return {
            "public_ip": ip.get("ipv4Enabled", False),
            "require_ssl": ip.get("requireSsl", False) or ip.get("sslMode") == "ENCRYPTED_ONLY",
            "backups_enabled": s.get("backupConfiguration", {}).get("enabled", False),
            "cmek": bool(d.get("diskEncryptionConfiguration", {}).get("kmsKeyName")),
            "deletion_protection": s.get("deletionProtectionEnabled", False),
        }
    if type_ == "firewall":
        return {
            "direction": d.get("direction", "INGRESS"),
            "source_ranges": d.get("sourceRanges", []),
            "ports": [p for a in d.get("allowed", []) for p in a.get("ports", [])],
            "action": "allow" if d.get("allowed") else "deny",
        }
    if type_ == "compute_instance":
        sa = (d.get("serviceAccounts") or [{}])[0].get("email", "")
        return {
            "external_ip": any(ac.get("natIP") for ni in d.get("networkInterfaces", []) for ac in ni.get("accessConfigs", [])),
            "disk_cmek": all(bool(disk.get("diskEncryptionKey", {}).get("kmsKeyName")) for disk in d.get("disks", [])),
            "os_login": d.get("metadata", {}).get("items", {}).get("enable-oslogin") == "TRUE",
            "shielded_vm": d.get("shieldedInstanceConfig", {}).get("enableSecureBoot", False),
            "service_account": "default" if sa.endswith("-compute@developer.gserviceaccount.com") else sa.split("@")[0],
        }
    return d


def upsert_assets(conn: sqlite3.Connection, assets: Iterable[dict]) -> int:
    n = 0
    for a in assets:
        conn.execute(
            "INSERT OR REPLACE INTO assets(id, project, type, name, region, sensitivity, owner, config) VALUES (?,?,?,?,?,?,?,?)",
            (a["id"], a["project"], a["type"], a["name"], a["region"], a["sensitivity"], a["owner"], json.dumps(a["config"])),
        )
        n += 1
    conn.commit()
    return n
