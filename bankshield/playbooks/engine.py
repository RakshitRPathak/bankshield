"""Playbook engine with human-in-the-loop.

Step modes:
  auto      — executed immediately when opened, but ONLY if the step's preconditions hold
              (IR-3.2 pre-approves an action "when the triggering evidence is unambiguous");
              otherwise the step degrades to `approve` and waits for a human
  approve   — waits for a senior_analyst/ciso approval, then executes
  recommend — guidance only; an analyst marks it done

Controls enforced here (server-side, not in the console):
  * approval needs the `incident.approve` permission (IR-3.1);
  * four-eyes: the approver is not the person who opened the incident (IAM-2.2);
  * project visibility: you cannot open or act on an incident outside your projects;
  * a failed action leaves the step `failed` (retryable), never `done`;
  * every decision is written to the hash-chained audit trail with its evidence (IR-3.3).

Actions are *simulated* against the asset inventory, which closes the loop: after
`make_private` runs, the next posture scan resolves the BS-001 finding. In production each
action is a least-privilege service account call behind the same approval gate.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .. import config, db
from ..rag.clearance import Principal, resolve

APPROVER_ROLES = {r for r, perms in config.ROLE_PERMISSIONS.items() if "incident.approve" in perms}
MODES = {"auto", "approve", "recommend"}
IAP_RANGE = "35.235.240.0/20"  # Identity-Aware Proxy TCP forwarding range


class IncidentError(ValueError):
    pass


def load_playbooks(path: Path | None = None) -> dict[str, dict]:
    d = path or config.PLAYBOOK_DIR
    stamp = tuple(sorted((f.name, f.stat().st_mtime) for f in d.glob("*.yaml")))
    return _load_cached(str(d), stamp)


@lru_cache(maxsize=4)
def _load_cached(d: str, _stamp: tuple) -> dict[str, dict]:
    out = {}
    for f in sorted(Path(d).glob("*.yaml")):
        pb = yaml.safe_load(f.read_text(encoding="utf-8"))
        ids = set()
        for s in pb["steps"]:
            if s["mode"] not in MODES:
                raise ValueError(f"{pb['id']}/{s['id']}: unknown mode {s['mode']}")
            if s["action"] not in ACTIONS:
                raise ValueError(f"{pb['id']}/{s['id']}: unknown action {s['action']}")
            if s["id"] in ids:
                raise ValueError(f"{pb['id']}: duplicate step id {s['id']}")
            ids.add(s["id"])
        out[pb["id"]] = pb
    return out


def playbooks_for(trigger_id: str) -> list[dict]:
    return [pb for pb in load_playbooks().values() if trigger_id in pb.get("triggers", [])]


# ------------------------------------------------------------------ simulated actions

def _update_asset_cfg(conn: sqlite3.Connection, asset_id: str | None, **changes: Any) -> dict:
    row = conn.execute("SELECT config FROM assets WHERE id=?", (asset_id,)).fetchone() if asset_id else None
    if not row:
        return {"ok": False, "error": f"asset {asset_id} not found"}
    cfg = json.loads(row["config"])
    before = {k: cfg.get(k) for k in changes}
    cfg.update(changes)
    conn.execute("UPDATE assets SET config=? WHERE id=?", (json.dumps(cfg), asset_id))
    return {"ok": True, "asset": asset_id, "before": before, "after": changes}


def _project_asset(conn, ctx) -> str | None:
    row = conn.execute("SELECT id FROM assets WHERE type='project' AND project=?", (ctx.get("project"),)).fetchone()
    return row["id"] if row else None


def act_disable_sa_key(conn, ctx):
    sa = ctx.get("asset_id") or _sa_asset_for_principal(conn, ctx.get("principal", ""))
    key_id = (ctx.get("evidence") or {}).get("key_id")
    row = conn.execute("SELECT config FROM assets WHERE id=? AND type='service_account'", (sa,)).fetchone() if sa else None
    if not row:
        return {"ok": False, "error": f"no service account asset for {ctx.get('principal') or ctx.get('asset_id')}"}
    cfg = json.loads(row["config"])
    keys = cfg.get("user_managed_keys", [])
    disabled = [k["id"] for k in keys if key_id is None or k["id"] == key_id]
    cfg["user_managed_keys"] = [k for k in keys if k["id"] not in disabled]
    conn.execute("UPDATE assets SET config=? WHERE id=?", (json.dumps(cfg), sa))
    return {"ok": True, "asset": sa, "disabled_keys": disabled}


def act_make_private(conn, ctx):
    return _update_asset_cfg(conn, ctx.get("asset_id"), public=False)


def act_enable_uniform_access(conn, ctx):
    return _update_asset_cfg(conn, ctx.get("asset_id"), uniform_access=True)


def act_enable_versioning(conn, ctx):
    asset = ctx.get("asset_id")
    if not asset:  # alert-driven: resolve the bucket from the evidence
        for res in (ctx.get("evidence") or {}).get("sample_resources", []):
            parts = res.split("/")
            if len(parts) > 1 and parts[0] == "buckets":
                row = conn.execute("SELECT id FROM assets WHERE type='bucket' AND name=?", (parts[1],)).fetchone()
                asset = row["id"] if row else None
                break
    return _update_asset_cfg(conn, asset, versioning=True)


def act_restrict_firewall(conn, ctx):
    return _update_asset_cfg(conn, ctx.get("asset_id"), source_ranges=[IAP_RANGE])


def act_disable_public_ip(conn, ctx):
    return _update_asset_cfg(conn, ctx.get("asset_id"), public_ip=False)


def act_enforce_ssl(conn, ctx):
    return _update_asset_cfg(conn, ctx.get("asset_id"), require_ssl=True)


def act_restore_audit_logging(conn, ctx):
    return _update_asset_cfg(conn, _project_asset(conn, ctx), audit_logs_enabled=True, central_log_sink=True)


def act_remove_binding(conn, ctx):
    ev = ctx.get("evidence") or {}
    asset = ctx.get("asset_id")
    if asset:  # finding-driven: strip primitive roles from the service account in the inventory
        row = conn.execute("SELECT config FROM assets WHERE id=? AND type='service_account'", (asset,)).fetchone()
        if row:
            cfg = json.loads(row["config"])
            removed = [r for r in cfg.get("roles", []) if r in ("roles/owner", "roles/editor")]
            cfg["roles"] = [r for r in cfg.get("roles", []) if r not in removed]
            conn.execute("UPDATE assets SET config=? WHERE id=?", (json.dumps(cfg), asset))
            return {"ok": True, "asset": asset, "removed": removed}
    return {"ok": True, "removed": ev.get("role"), "member": ev.get("member"), "simulated": True}


def act_suspend_user(conn, ctx):
    return {"ok": True, "suspended": ctx.get("principal"), "simulated": True}


def act_revoke_sessions(conn, ctx):
    return {"ok": True, "revoked_sessions_for": ctx.get("principal"), "simulated": True}


def act_force_reenrol(conn, ctx):
    return {"ok": True, "forced_reenrol": ctx.get("principal"), "simulated": True}


def act_rotate_secrets(conn, ctx):
    n = 0
    for r in conn.execute("SELECT id, config FROM assets WHERE type='secret' AND project=?", (ctx.get("project"),)).fetchall():
        cfg = json.loads(r["config"]); cfg["last_rotated_days_ago"] = 0
        if cfg.get("rotation_days", 0) == 0:
            cfg["rotation_days"] = 30
        conn.execute("UPDATE assets SET config=? WHERE id=?", (json.dumps(cfg), r["id"])); n += 1
    return {"ok": True, "rotated": n}


def act_snapshot_logs(conn, ctx):
    n = conn.execute("SELECT COUNT(*) FROM logs WHERE project=?", (ctx.get("project"),)).fetchone()[0]
    return {"ok": True, "snapshot_rows": n, "simulated": True}


ACTIONS = {
    "disable_sa_key": act_disable_sa_key, "make_private": act_make_private,
    "enable_uniform_access": act_enable_uniform_access, "enable_versioning": act_enable_versioning,
    "restrict_firewall": act_restrict_firewall, "disable_public_ip": act_disable_public_ip, "enforce_ssl": act_enforce_ssl,
    "restore_audit_logging": act_restore_audit_logging, "remove_binding": act_remove_binding,
    "suspend_user": act_suspend_user, "revoke_sessions": act_revoke_sessions,
    "force_reenrol": act_force_reenrol, "rotate_secrets": act_rotate_secrets, "snapshot_logs": act_snapshot_logs,
    "none": lambda conn, ctx: {"ok": True, "noop": True},
}


def _sa_asset_for_principal(conn, principal: str) -> str | None:
    name = (principal or "").split("@")[0]
    row = conn.execute("SELECT id FROM assets WHERE type='service_account' AND name=?", (name,)).fetchone()
    return row["id"] if row else None


# ------------------------------------------------------------------ incident lifecycle

def _precondition_gap(step: dict, ctx: dict) -> str | None:
    """Why an `auto` step may NOT run unattended, or None if its evidence is unambiguous."""
    ev = ctx.get("evidence") or {}
    missing = [k for k in step.get("requires_evidence", []) if ev.get(k) in (None, "", [])]
    if missing:
        return f"evidence lacks {', '.join(missing)}"
    need = step.get("requires_sensitivity")
    if need and ctx.get("sensitivity") != need:
        return f"resource is {ctx.get('sensitivity') or 'unclassified'}, not {need}"
    return None


def open_incident(conn: sqlite3.Connection, playbook_id: str, opened_by: str, alert_id: str | None = None,
                  finding_id: str | None = None, context: dict | None = None, principal: Principal | None = None) -> dict:
    p = principal or resolve(opened_by)
    pbs = load_playbooks()
    if playbook_id not in pbs:
        raise ValueError(f"unknown playbook {playbook_id}")
    pb = pbs[playbook_id]
    ctx = dict(context or {})
    trigger = None
    if alert_id:
        a = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not a or not p.can_see_project(a["project"]):
            raise ValueError(f"unknown alert {alert_id}")
        trigger = a["detection_id"]
        ctx.update({"project": a["project"], "principal": a["principal"], "evidence": json.loads(a["evidence"]),
                    "alert_title": a["title"], "controls": json.loads(a["controls"])})
    if finding_id:
        f = conn.execute("SELECT f.*, a.sensitivity, a.name AS asset_name FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.id=?", (finding_id,)).fetchone()
        if not f or not p.can_see_project(f["project"]):
            raise ValueError(f"unknown finding {finding_id}")
        trigger = f["rule_id"]
        ctx.update({"project": f["project"], "asset_id": f["asset_id"], "asset_name": f["asset_name"], "sensitivity": f["sensitivity"],
                    "evidence": json.loads(f["evidence"]), "finding_title": f["title"], "controls": json.loads(f["controls"])})
    if trigger and trigger not in pb.get("triggers", []):
        raise IncidentError(f"playbook {playbook_id} is not approved for {trigger}")
    ref = alert_id or finding_id
    if ref and conn.execute("SELECT 1 FROM incidents WHERE alert_id=? AND playbook_id=? AND status='open'", (ref, playbook_id)).fetchone():
        raise IncidentError(f"an open {playbook_id} incident already exists for {ref}")
    now = time.time()
    severity = int(pb.get("severity", 3))
    ctx["sop"] = pb.get("sop")
    if severity <= 2:  # IR-1.2: the regulatory clock starts at classification
        ctx["reg_clock_started"] = now
        ctx["reg_deadline"] = now + config.REG_REPORT_HOURS * 3600
    inc_id = "INC-" + uuid.uuid4().hex[:8].upper()
    steps = []
    for s in pb["steps"]:
        st = {**s, "state": "pending", "result": None, "actor": None, "ts": None}
        if s["mode"] == "auto":
            gap = _precondition_gap(s, ctx)
            if gap:
                st["mode"] = "approve"
                st["downgraded"] = f"not auto-executed: {gap} (IR-3.2 needs unambiguous evidence)"
        steps.append(st)
    conn.execute(
        "INSERT INTO incidents(id, playbook_id, alert_id, opened_by, opened_at, status, context, steps, severity) VALUES (?,?,?,?,?,?,?,?,?)",
        (inc_id, playbook_id, ref, opened_by, now, "open", json.dumps(ctx), json.dumps(steps), severity),
    )
    conn.commit()
    db.audit(conn, opened_by, "incident.open", {"incident": inc_id, "playbook": playbook_id, "alert": alert_id, "finding": finding_id,
                                                "severity": severity, "evidence": ctx.get("evidence")})
    for s in steps:  # pre-approved steps run immediately
        if s["mode"] == "auto":
            _execute_step(conn, inc_id, s["id"], actor="system:auto", reason="IR-3.2 pre-approved; evidence unambiguous")
    if alert_id:
        conn.execute("UPDATE alerts SET status='in_progress', ack_by=COALESCE(ack_by, ?), ack_at=COALESCE(ack_at, ?) WHERE id=? AND status!='closed'",
                     (opened_by, now, alert_id))
        conn.commit()
    return get_incident(conn, inc_id)


def get_incident(conn: sqlite3.Connection, inc_id: str) -> dict:
    r = conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
    if not r:
        raise KeyError(inc_id)
    d = dict(r)
    d["context"] = json.loads(d["context"])
    d["steps"] = json.loads(d["steps"])
    return d


def _save_steps(conn, inc: dict, steps: list[dict]) -> None:
    done = all(s["state"] in ("done", "rejected") for s in steps)
    conn.execute("UPDATE incidents SET steps=?, status=?, closed_at=? WHERE id=?",
                 (json.dumps(steps), "closed" if done else "open", time.time() if done else None, inc["id"]))
    if done and inc.get("alert_id"):
        conn.execute("UPDATE alerts SET status='closed', disposition=COALESCE(disposition, 'true_positive') WHERE id=?", (inc["alert_id"],))
    conn.commit()


def _find_step(inc: dict, step_id: str) -> dict:
    step = next((s for s in inc["steps"] if s["id"] == step_id), None)
    if step is None:
        raise KeyError(step_id)
    return step


def _execute_step(conn, inc_id: str, step_id: str, actor: str, reason: str) -> dict:
    inc = get_incident(conn, inc_id)
    step = _find_step(inc, step_id)
    try:
        result = ACTIONS[step["action"]](conn, inc["context"])
    except Exception as e:  # an action blowing up must not leave the incident half-written
        conn.rollback()
        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    ok = bool(result.get("ok"))
    step.update({"state": "done" if ok else "failed", "result": result, "actor": actor, "ts": time.time(), "reason": reason})
    _save_steps(conn, inc, inc["steps"])
    db.audit(conn, actor, "incident.step.execute" if ok else "incident.step.failed",
             {"incident": inc_id, "step": step_id, "action": step["action"], "result": result, "reason": reason})
    return step


def _authorise(conn, inc: dict, step: dict, p: Principal, verb: str) -> None:
    if not p.can_see_project(inc["context"].get("project", "")):
        raise KeyError(inc["id"])
    needed = "incident.approve" if step["mode"] == "approve" else "incident.step"
    if not p.can(needed):
        db.audit(conn, p.user, "incident.step.denied", {"incident": inc["id"], "step": step["id"], "role": p.role, "verb": verb})
        raise PermissionError(f"role '{p.role}' may not {verb} containment actions (IR-3.1)")
    if verb == "approve" and step["mode"] == "approve" and config.FOUR_EYES and p.user == inc["opened_by"]:
        db.audit(conn, p.user, "incident.step.denied", {"incident": inc["id"], "step": step["id"], "why": "four-eyes"})
        raise PermissionError("four-eyes control: the person who opened the incident cannot approve its containment (IAM-2.2)")


def approve_step(conn: sqlite3.Connection, inc_id: str, step_id: str, approver: str, role: str | None = None, reason: str = "",
                 principal: Principal | None = None) -> dict:
    # `role` is accepted for backwards compatibility and deliberately ignored: authority comes
    # from the resolved identity, never from what the caller says its role is.
    p = principal or resolve(approver)
    inc = get_incident(conn, inc_id)
    step = _find_step(inc, step_id)
    if step["state"] not in ("pending", "failed"):
        return step
    _authorise(conn, inc, step, p, "approve")
    return _execute_step(conn, inc_id, step_id, actor=p.user, reason=reason or f"approved by {p.role}")


def reject_step(conn: sqlite3.Connection, inc_id: str, step_id: str, actor: str, reason: str, principal: Principal | None = None) -> dict:
    p = principal or resolve(actor)
    inc = get_incident(conn, inc_id)
    step = _find_step(inc, step_id)
    if step["state"] not in ("pending", "failed"):
        return step
    _authorise(conn, inc, step, p, "reject")
    step.update({"state": "rejected", "actor": p.user, "ts": time.time(), "reason": reason})
    _save_steps(conn, inc, inc["steps"])
    db.audit(conn, p.user, "incident.step.reject", {"incident": inc_id, "step": step_id, "reason": reason})
    return step


def incident_report_md(conn: sqlite3.Connection, inc_id: str) -> str:
    """Post-incident review skeleton (IR-4.2): what fired, what was done, by whom, on what evidence."""
    inc = get_incident(conn, inc_id)
    ctx = inc["context"]
    ts = lambda t: time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t)) if t else "—"
    lines = [f"# Post-incident review — {inc['id']}", "",
             f"- Playbook: {inc['playbook_id']} (SOP {ctx.get('sop') or '—'})",
             f"- Severity: {inc['severity']}   Status: {inc['status']}",
             f"- Opened: {ts(inc['opened_at'])} by {inc['opened_by']}   Closed: {ts(inc.get('closed_at'))}",
             f"- Trigger: {ctx.get('alert_title') or ctx.get('finding_title') or '—'}",
             f"- Scope: {ctx.get('project', '—')} / {ctx.get('principal') or ctx.get('asset_name') or ctx.get('asset_id') or '—'}",
             f"- Policy clauses: {', '.join(ctx.get('controls', [])) or '—'}"]
    if ctx.get("reg_deadline"):
        lines.append(f"- Regulatory clock (IR-1.2): started {ts(ctx['reg_clock_started'])}, report due {ts(ctx['reg_deadline'])} (REG-DIG-7)")
    lines += ["", "## Triggering evidence", "```json", json.dumps(ctx.get("evidence", {}), indent=2), "```", "", "## Actions", "",
              "| Step | Mode | State | Actor | When | Reason / result |", "|---|---|---|---|---|---|"]
    for s in inc["steps"]:
        res = json.dumps(s["result"]) if s.get("result") else ""
        lines.append(f"| {s['title']} | {s['mode']} | {s['state']} | {s.get('actor') or '—'} | {ts(s.get('ts'))} | {s.get('reason') or ''} {res} |")
    lines += ["", "## To complete within ten business days (IR-4.2)", "", "- Control that failed:", "- Control that detected the incident:",
              "- Data exposure assessment and reportability decision:", ""]
    return "\n".join(lines)
