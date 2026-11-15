"""Config posture rules engine (CSPM-lite).

Rules live in rules.yaml and are evaluated by an AST-validated expression evaluator
(safe_expr.py) over the asset config. In production this is OPA/Rego or Security Command
Center; the shape of the output — a finding with evidence, a risk score, a remediation SLA
and the policy clauses it violates — is what matters for the RAG join.

Each scan also:
  * honours approved, unexpired exceptions (finding status 'excepted', not 'open');
  * re-opens a finding when its exception expires or is revoked;
  * writes a posture snapshot (score + counts) so the trend is auditable.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from functools import lru_cache
from typing import Any

import yaml

from .. import config
from .safe_expr import compile_rule, evaluate

_RULE_VARS = {"cfg", "asset", "ALLOWED_REGIONS"}
_EXPOSURE_BONUS = {"internet": 1.0, "identity": 0.5, "data": 0.0, "none": -0.5}
_SENSITIVITY_FACTOR = {"restricted": 1.0, "internal": 0.8, "public": 0.6}


def load_rules(path=None) -> list[dict[str, Any]]:
    p = str(path or config.RULES_PATH)
    import os
    return _load_rules_cached(p, os.path.getmtime(p))


@lru_cache(maxsize=8)
def _load_rules_cached(path: str, _mtime: float) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    seen: set[str] = set()
    for r in rules:
        if r["id"] in seen:
            raise ValueError(f"duplicate rule id {r['id']}")
        seen.add(r["id"])
        if r["severity"] not in config.SEVERITY_BASE:
            raise ValueError(f"{r['id']}: unknown severity {r['severity']}")
        if isinstance(r["type"], str):
            r["type"] = [r["type"]]
        r.setdefault("mitre", [])
        r.setdefault("exposure", "data")
        r["_code"] = compile_rule(r["when"], _RULE_VARS, f"rule:{r['id']}")
    return rules


def rule_index() -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in load_rules()}


def _fires(rule: dict, asset: dict, cfg: dict) -> bool:
    return bool(evaluate(rule["_code"], {"cfg": cfg, "asset": asset, "ALLOWED_REGIONS": config.ALLOWED_REGIONS}))


def risk_score(rule: dict, asset: dict) -> float:
    """0–10. Severity sets the base; data sensitivity scales it; exposure type nudges it."""
    base = config.SEVERITY_BASE[rule["severity"]]
    s = base * _SENSITIVITY_FACTOR.get(asset.get("sensitivity", "internal"), 0.8) + _EXPOSURE_BONUS.get(rule.get("exposure", "data"), 0.0)
    return round(max(0.5, min(10.0, s)), 1)


def remediation_for(rule: dict, asset: dict) -> dict[str, str]:
    """Human guidance plus a command template with this asset's names filled in."""
    fix = rule.get("fix", "")
    try:
        fix = fix.format(name=asset.get("name", asset.get("asset_name", "NAME")), project=asset.get("project", "PROJECT"))
    except (KeyError, IndexError):
        pass
    return {"guidance": rule.get("remediation", ""), "fix": fix}


def finding_id(rule_id: str, asset_id: str) -> str:
    return hashlib.sha1(f"{rule_id}:{asset_id}".encode()).hexdigest()[:12]


def active_exceptions(conn: sqlite3.Connection, now: float | None = None) -> set[tuple[str, str]]:
    now = time.time() if now is None else now
    return {(r["rule_id"], r["asset_id"]) for r in
            conn.execute("SELECT rule_id, asset_id FROM exceptions WHERE status='approved' AND expires_at>?", (now,))}


def scan_assets(conn: sqlite3.Connection, rules: list[dict] | None = None, now: float | None = None) -> dict[str, Any]:
    """Evaluate every rule against every asset; upsert findings; auto-resolve fixed ones."""
    rules = rules or load_rules()
    now = time.time() if now is None else now
    assets = [dict(r) for r in conn.execute("SELECT * FROM assets")]
    excepted = active_exceptions(conn, now)
    seen: set[str] = set()
    new = 0
    checks = failed_w = total_w = 0.0
    errors: list[str] = []
    for a in assets:
        cfg = json.loads(a["config"])
        for rule in rules:
            if a["type"] not in rule["type"]:
                continue
            w = config.SEVERITY_BASE[rule["severity"]]
            checks += 1
            total_w += w
            try:
                fired = _fires(rule, a, cfg)
            except Exception as e:  # a broken rule must never silently pass an asset
                errors.append(f"{rule['id']} on {a['id']}: {type(e).__name__}: {e}")
                continue
            if not fired:
                continue
            fid = finding_id(rule["id"], a["id"])
            seen.add(fid)
            status = "excepted" if (rule["id"], a["id"]) in excepted else "open"
            if status == "open":
                failed_w += w
            evidence = {k: cfg.get(k) for k in rule.get("evidence", [])}
            evidence["region"] = a["region"]
            evidence["sensitivity"] = a["sensitivity"]
            risk = risk_score(rule, a)
            exists = conn.execute("SELECT 1 FROM findings WHERE id=?", (fid,)).fetchone()
            if exists:
                conn.execute("UPDATE findings SET last_seen=?, status=?, evidence=?, severity=?, title=?, controls=?, risk=?, mitre=? WHERE id=?",
                             (now, status, json.dumps(evidence), rule["severity"], rule["title"], json.dumps(rule["controls"]),
                              risk, json.dumps(rule["mitre"]), fid))
            else:
                new += 1
                conn.execute(
                    "INSERT INTO findings(id, rule_id, asset_id, project, severity, title, evidence, controls, status, first_seen, last_seen, risk, due_at, mitre)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fid, rule["id"], a["id"], a["project"], rule["severity"], rule["title"],
                     json.dumps(evidence), json.dumps(rule["controls"]), status, now, now, risk,
                     now + config.SLA_HOURS[rule["severity"]] * 3600, json.dumps(rule["mitre"])),
                )
    # Findings not seen this scan are resolved (the misconfig was fixed).
    live = [r["id"] for r in conn.execute("SELECT id FROM findings WHERE status IN ('open','excepted')")]
    resolved = 0
    for fid in live:
        if fid not in seen:
            conn.execute("UPDATE findings SET status='resolved', last_seen=? WHERE id=?", (now, fid))
            resolved += 1
    counts = {s: 0 for s in config.SEVERITY_BASE}
    by_project: dict[str, int] = {}
    for r in conn.execute("SELECT severity, project FROM findings WHERE status='open'"):
        counts[r["severity"]] += 1
        by_project[r["project"]] = by_project.get(r["project"], 0) + 1
    total_open = sum(counts.values())
    n_excepted = conn.execute("SELECT COUNT(*) FROM findings WHERE status='excepted'").fetchone()[0]
    score = round(100.0 * (1 - failed_w / total_w), 1) if total_w else 100.0
    conn.execute("INSERT INTO posture_history(ts, score, open, critical, high, medium, low, excepted, by_project) VALUES (?,?,?,?,?,?,?,?,?)",
                 (now, score, total_open, counts["critical"], counts["high"], counts["medium"], counts["low"], n_excepted, json.dumps(by_project)))
    conn.commit()
    out: dict[str, Any] = {"assets": len(assets), "rules": len(rules), "checks": int(checks), "new": new, "resolved": resolved,
                           "open": total_open, "excepted": n_excepted, "score": score}
    if errors:
        out["errors"] = errors
    return out


def _hydrate(r: sqlite3.Row, now: float) -> dict[str, Any]:
    d = dict(r)
    d["controls"] = json.loads(d["controls"])
    d["evidence"] = json.loads(d["evidence"])
    d["mitre"] = json.loads(d.get("mitre") or "[]")
    d["sla_breached"] = bool(d.get("due_at") and d["status"] == "open" and d["due_at"] < now)
    return d


def findings_for_controls(conn: sqlite3.Connection, clause_ids: list[str], projects: list[str] | None = None,
                          status: str = "open") -> list[dict[str, Any]]:
    """Live-state join: which open findings violate any of these policy clauses?

    `projects` is the caller's visibility: ["*"] = everything, [] / None = nothing. (An empty
    list must mean "no projects", never "no filter".)
    """
    if not clause_ids or not projects:
        return []
    now = time.time()
    wanted = set(clause_ids)
    out = []
    for r in conn.execute("SELECT f.*, a.name AS asset_name, a.type AS asset_type, a.owner, a.sensitivity FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.status=?", (status,)):
        if "*" not in projects and r["project"] not in projects:
            continue
        d = _hydrate(r, now)
        if wanted & set(d["controls"]):
            out.append(d)
    out.sort(key=lambda f: (config.SEVERITY_RANK.get(f["severity"], 9), -f["risk"], f["project"], f["asset_id"]))
    return out


def findings_for_asset(conn: sqlite3.Connection, asset_ids: list[str], projects: list[str] | None = None) -> list[dict[str, Any]]:
    """Every open finding on the named assets, visibility-scoped like findings_for_controls."""
    if not asset_ids or not projects:
        return []
    now = time.time()
    q = ",".join("?" * len(asset_ids))
    out = []
    for r in conn.execute(f"SELECT f.*, a.name AS asset_name, a.type AS asset_type, a.owner, a.sensitivity FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.status='open' AND f.asset_id IN ({q})", tuple(asset_ids)):
        if "*" in projects or r["project"] in projects:
            out.append(_hydrate(r, now))
    out.sort(key=lambda f: (config.SEVERITY_RANK.get(f["severity"], 9), -f["risk"]))
    return out
