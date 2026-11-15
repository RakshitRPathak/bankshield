"""Attack-path analysis: toxic combinations of findings.

A single finding says "this bucket is public". An attack path says "an anonymous user on the
internet can read unencrypted cardholder data, and nobody would see it because audit logs
are off". Each path is built only from open findings and live alerts, so it disappears when
any link in the chain is fixed. Paths are computed on demand (no table) and are visible only
to a caller who can see every project the path touches.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from typing import Any

from .. import config


def _load(conn: sqlite3.Connection):
    findings = []
    for r in conn.execute("SELECT f.*, a.name AS asset_name, a.type AS asset_type, a.sensitivity, a.config AS asset_config "
                          "FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.status='open'"):
        d = dict(r)
        d["controls"] = json.loads(d["controls"]); d["evidence"] = json.loads(d["evidence"]); d["mitre"] = json.loads(d["mitre"] or "[]")
        d["asset_config"] = json.loads(d["asset_config"])
        findings.append(d)
    alerts = []
    for r in conn.execute("SELECT * FROM alerts WHERE status!='closed'"):
        d = dict(r); d["evidence"] = json.loads(d["evidence"]); d["mitre"] = json.loads(d["mitre"] or "[]")
        alerts.append(d)
    return findings, alerts


def _path(kind: str, title: str, steps: list[dict], links: list[dict], score: float, impact: str,
          alerts: list[dict] | None = None) -> dict[str, Any]:
    key = kind + ":" + ",".join(sorted(f["id"] for f in links))
    controls, mitre = [], []
    for f in links:
        controls += [c for c in f["controls"] if c not in controls]
        mitre += [m for m in f["mitre"] if m not in mitre]
    for a in alerts or []:
        mitre += [m for m in a["mitre"] if m not in mitre]
    score = round(min(10.0, score), 1)
    return {
        "id": "AP-" + hashlib.sha1(key.encode()).hexdigest()[:8].upper(), "kind": kind, "title": title,
        "severity": "critical" if score >= 9 else "high" if score >= 7 else "medium",
        "score": score, "impact": impact, "steps": steps,
        "projects": sorted({f["project"] for f in links}),
        "findings": [{"id": f["id"], "rule_id": f["rule_id"], "title": f["title"], "asset_id": f["asset_id"],
                      "asset_name": f["asset_name"], "project": f["project"], "severity": f["severity"]} for f in links],
        "alerts": [{"id": a["id"], "detection_id": a["detection_id"], "title": a["title"]} for a in (alerts or [])],
        "controls": controls, "mitre": mitre, "actively_exploited": bool(alerts),
        "break_the_chain": _cheapest_fix(links),
    }


def _cheapest_fix(links: list[dict]) -> dict[str, str]:
    """The single finding whose fix removes the path's entry point (first link)."""
    f = links[0]
    return {"finding_id": f["id"], "rule_id": f["rule_id"], "asset": f"{f['project']}/{f['asset_name']}", "title": f["title"]}


def _step(label: str, detail: str, rule: str | None = None) -> dict[str, str]:
    return {"label": label, "detail": detail, **({"rule_id": rule} if rule else {})}


def compute_attack_paths(conn: sqlite3.Connection, projects: list[str] | None = None) -> list[dict[str, Any]]:
    if not projects:
        return []
    findings, alerts = _load(conn)
    by_asset: dict[str, dict[str, dict]] = defaultdict(dict)
    by_project: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for f in findings:
        by_asset[f["asset_id"]][f["rule_id"]] = f
        by_project[f["project"]][f["rule_id"]].append(f)
    alerts_by_principal: dict[str, list[dict]] = defaultdict(list)
    for a in alerts:
        alerts_by_principal[a["principal"] or ""].append(a)
    blind = {p for p, rules in by_project.items() if "BS-091" in rules}
    paths: list[dict] = []

    # 1. Internet → data: public store / public database, made worse by missing encryption.
    for asset_id, rules in by_asset.items():
        entry = rules.get("BS-001") or rules.get("BS-070") or rules.get("BS-010")
        if not entry:
            continue
        links = [entry]
        steps = [_step("Internet", "any unauthenticated or untrusted client"),
                 _step(entry["asset_name"], entry["title"], entry["rule_id"])]
        score = 8.0 if entry["sensitivity"] == "restricted" else 6.5
        for rid, why in (("BS-011", "connections are not forced onto TLS"), ("BS-003", "data is not CMEK-encrypted"),
                         ("BS-013", "data is not CMEK-encrypted"), ("BS-004", "no versioning — tampering is unrecoverable")):
            if rid in rules:
                links.append(rules[rid]); score += 0.5
                steps.append(_step("Weakened", why, rid))
        if entry["project"] in blind:
            links.append(by_project[entry["project"]]["BS-091"][0]); score += 1.0
            steps.append(_step("Unobserved", "audit logging is off for the project", "BS-091"))
        steps.append(_step("Impact", f"{entry['sensitivity']} data in {entry['asset_name']} readable from outside the bank"))
        paths.append(_path("internet_to_data", f"Internet-reachable {entry['sensitivity']} data: {entry['asset_name']}",
                           steps, links, score, "Disclosure of customer or card data; regulator-reportable (REG-DIG-7)."))

    # 2. Leaked credential → project takeover: primitive role + long-lived key on one service account.
    for asset_id, rules in by_asset.items():
        if "BS-020" not in rules or not ("BS-021" in rules or "BS-022" in rules):
            continue
        priv = rules["BS-020"]
        key = rules.get("BS-021") or rules["BS-022"]
        links = [key, priv]
        principal = f"{priv['asset_name']}@{priv['project']}.iam"
        live = [a for a in alerts_by_principal.get(principal, []) if a["detection_id"] in ("LD-003", "LD-002", "LD-008")]
        steps = [_step("Stolen key", "a long-lived user-managed key leaks from a laptop, repo or CI log", key["rule_id"]),
                 _step(priv["asset_name"], "authenticates as the service account from anywhere"),
                 _step("Primitive role", f"holds {', '.join(r for r in priv['evidence'].get('roles', []) if r in ('roles/owner', 'roles/editor'))}", "BS-020"),
                 _step("Impact", f"full read/write over {priv['project']}")]
        score = 8.5 + (1.5 if live else 0)
        if live:
            steps.insert(1, _step("Observed", "; ".join(sorted({a["title"] for a in live}))))
        paths.append(_path("key_to_takeover", f"Leaked key → control of {priv['project']} via {priv['asset_name']}",
                           steps, links, score, "Project-wide data access and configuration change under a machine identity.", live))

    # 3. Internet → admin port → weak host → over-privileged identity.
    for project, rules in by_project.items():
        for fw in rules.get("BS-030", []):
            hosts = [f for f in rules.get("BS-043", [])] or []
            for host in hosts:
                links = [fw, host]
                steps = [_step("Internet", "scanner or attacker on any network"),
                         _step(fw["asset_name"], f"admin port {', '.join(fw['evidence'].get('ports', []))} open to 0.0.0.0/0 across the project network", "BS-030"),
                         _step(host["asset_name"], "host has an external IP", "BS-043")]
                score = 7.5
                for rid in ("BS-042", "BS-040"):
                    f = by_asset[host["asset_id"]].get(rid)
                    if f:
                        links.append(f); score += 0.75
                        steps.append(_step("Weak host" if rid == "BS-042" else "Default identity", f["title"], rid))
                steps.append(_step("Impact", f"foothold inside {project} with the host's service account"))
                paths.append(_path("exposed_admin_port", f"Internet-exposed admin port reaches {host['asset_name']}",
                                   steps, links, score, "Remote foothold on a bank host; lateral movement inside the VPC."))

    # 4. Exfiltration path: restricted data outside the perimeter and outside the country.
    for project, rules in by_project.items():
        if "BS-093" in rules and "BS-005" in rules:
            perim = rules["BS-093"][0]
            for res in rules["BS-005"]:
                links = [perim, res]
                steps = [_step(project, "restricted project is outside the VPC-SC perimeter", "BS-093"),
                         _step(res["asset_name"], f"restricted data held in {res['evidence'].get('region')}", "BS-005"),
                         _step("Impact", "data can leave India through an unrestricted data-plane API with no technical control in the way")]
                paths.append(_path("residency_exfil", f"Unperimetered restricted data abroad: {res['asset_name']}",
                                   steps, links, 8.5, "Data-localisation breach (REG-DIG-1) with no perimeter to contain it."))

    # 5. Admin without MFA on a project with an internet-facing data store.
    for project, rules in by_project.items():
        if "BS-090" in rules and ("BS-010" in rules or "BS-001" in rules):
            mfa = rules["BS-090"][0]
            target = (rules.get("BS-010") or rules.get("BS-001"))[0]
            weak_admins = [u for u, ok in (mfa["evidence"].get("admin_mfa") or {}).items() if ok is False]
            live = [a for u in weak_admins for a in alerts_by_principal.get(u, [])]
            steps = [_step("Phished password", f"admin without MFA: {', '.join(weak_admins) or 'enforcement off'}", "BS-090"),
                     _step(project, "admin session with no second factor"),
                     _step(target["asset_name"], target["title"], target["rule_id"]),
                     _step("Impact", "administrative control of a project that already exposes data")]
            if live:
                steps.insert(1, _step("Observed", "; ".join(sorted({a["title"] for a in live}))))
            paths.append(_path("admin_no_mfa", f"Single-factor admin on {project}", steps, [mfa, target],
                               8.0 + (1.5 if live else 0), "Account takeover of a privileged human identity.", live))

    visible = [p for p in paths if "*" in projects or all(pr in projects for pr in p["projects"])]
    visible.sort(key=lambda p: (-p["score"], p["title"]))
    return visible
