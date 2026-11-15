"""FastAPI surface for the analyst console and for automation.

Identity
  BANKSHIELD_AUTH=header (default, demo): the `X-User` header names a simulated user.
  BANKSHIELD_AUTH=token: `Authorization: Bearer <HS256 JWT>` is required.
  Either way an unknown or missing identity is a 401 — there is no default user.

Authorisation is checked server-side on every route, three ways: a role permission
(config.ROLE_PERMISSIONS), project visibility, and policy clearance inside the RAG pipeline.
Something a caller may not see is reported as 404, never 403, so its existence does not leak.
"""

from __future__ import annotations

import csv
import io
import json
import threading
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__, auth, config, db, governance, insights
from ..detection import compute_attack_paths, correlate, remediation_for, rule_index, run_log_detections, scan_assets
from ..detection import mitre as mitre_mod
from ..playbooks import IncidentError, approve_step, get_incident, incident_report_md, load_playbooks, open_incident, playbooks_for, reject_step
from ..rag import ask
from ..rag.clearance import Principal, resolve
from ..rag.retriever import get_index
from ..reports import compliance_report, regulatory_gap, report_markdown, residency_evidence
from ..simulator import SCENARIOS, run_attack_scenario

app = FastAPI(title="BankShield", version=__version__,
              description="Bank Cloud Security Intelligence Platform — RAG over policy and live cloud state")
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")
MAX_BODY_BYTES = 64 * 1024


@app.middleware("http")
async def security_headers(request: Request, call_next):
    rid = uuid.uuid4().hex[:12]
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "request body too large"}, status_code=413, headers={"X-Request-ID": rid})
    resp = await call_next(request)
    resp.headers["X-Request-ID"] = rid
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    if not request.url.path.startswith(_DOCS_PATHS):   # Swagger UI loads its assets from a CDN
        resp.headers["Content-Security-Policy"] = _CSP
    return resp


# ---------------------------------------------------------------- identity, rate limit, permissions

_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()


def _rate_limit(user: str) -> None:
    limit = config.RATE_LIMIT_PER_MIN
    if limit <= 0:
        return
    now = time.monotonic()
    with _hits_lock:
        q = _hits[user]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(int(60 - (now - q[0])) + 1)})
        q.append(now)


def principal(x_user: str | None = Header(default=None), authorization: str | None = Header(default=None)) -> Principal:
    if config.AUTH_MODE == "token":
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "bearer token required", headers={"WWW-Authenticate": "Bearer"})
        try:
            user = auth.verify_token(authorization.split(" ", 1)[1].strip())
        except auth.AuthError as e:
            raise HTTPException(401, str(e), headers={"WWW-Authenticate": "Bearer"})
    else:
        user = x_user or ""
    if user not in config.USERS:
        raise HTTPException(401, "unknown or missing identity")
    _rate_limit(user)
    return resolve(user)


def need(permission: str):
    def dep(p: Principal = Depends(principal)) -> Principal:
        if not p.can(permission):
            raise HTTPException(403, f"role '{p.role}' lacks permission '{permission}'")
        return p
    return dep


def conn():
    c = db.connect()
    try:
        yield c
    finally:
        c.close()


def _guard(fn, *a, **kw):
    """Run a domain call and translate its exceptions to HTTP once, consistently."""
    try:
        return fn(*a, **kw)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except (KeyError, StopIteration):
        raise HTTPException(404, "not found")
    except (IncidentError, governance.GovernanceError) as e:
        raise HTTPException(409, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


# ---------------------------------------------------------------- console & health

@app.get("/", include_in_schema=False)
def console():
    return FileResponse(STATIC / "index.html", media_type="text/html")


@app.get("/healthz")
def healthz(c=Depends(conn)):
    chunks = c.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    return JSONResponse({"status": "ok" if chunks else "unseeded", "version": __version__}, status_code=200 if chunks else 503)


@app.get("/api/whoami")
def whoami(p: Principal = Depends(principal)):
    return {"user": p.user, "role": p.role, "clearance": p.clearance, "projects": p.projects, "permissions": sorted(p.permissions),
            "users": list(config.USERS) if config.AUTH_MODE == "header" else [p.user], "auth_mode": config.AUTH_MODE,
            "four_eyes": config.FOUR_EYES, "version": __version__}


@app.get("/api/users", include_in_schema=False)
def users():
    """Demo identities for the console's user switcher. Disabled outside header mode."""
    if config.AUTH_MODE != "header":
        raise HTTPException(404, "not found")
    return [{"user": u, "role": v["role"]} for u, v in config.USERS.items()]


# ---------------------------------------------------------------- RAG

class AskBody(BaseModel):
    question: str = Field(min_length=1, max_length=config.MAX_QUESTION_LEN)


@app.post("/api/ask")
def api_ask(body: AskBody, p: Principal = Depends(need("ask")), c=Depends(conn)):
    if not body.question.strip():
        raise HTTPException(400, "empty question")
    return ask(c, body.question.strip(), principal=p).to_dict()


@app.get("/api/clauses/{clause_id}")
def clause(clause_id: str, p: Principal = Depends(need("read")), c=Depends(conn)):
    ch = get_index(c).visible(clause_id, p.clearance)
    if not ch:
        raise HTTPException(404, "not found")   # same answer for "no such clause" and "not cleared"
    return ch


# ---------------------------------------------------------------- overview, posture, attack paths

@app.get("/api/overview")
def api_overview(p: Principal = Depends(need("read")), c=Depends(conn)):
    return insights.overview(c, p)


def _decorate(f: dict[str, Any]) -> dict[str, Any]:
    f["playbooks"] = [pb["id"] for pb in playbooks_for(f["rule_id"])]
    f["mitre"] = [mitre_mod.describe(t) for t in f["mitre"]]
    return f


@app.get("/api/findings")
def findings(status: str = "open", severity: str | None = None, project: str | None = None, q: str | None = None,
             p: Principal = Depends(need("read")), c=Depends(conn)):
    if status not in ("open", "excepted", "resolved"):
        raise HTTPException(400, "status must be open, excepted or resolved")
    out = insights._visible_findings(c, p, status)
    if severity:
        out = [f for f in out if f["severity"] == severity]
    if project:
        out = [f for f in out if f["project"] == project]
    if q:
        ql = q.lower()
        out = [f for f in out if ql in f"{f['title']} {f['asset_name']} {f['rule_id']} {f['project']} {' '.join(f['controls'])}".lower()]
    return [_decorate(f) for f in out]


@app.get("/api/findings.csv", response_class=PlainTextResponse)
def findings_csv(p: Principal = Depends(need("read")), c=Depends(conn)):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "rule_id", "severity", "risk", "project", "asset", "asset_type", "title", "controls", "first_seen_utc", "sla_breached"])
    for f in insights._visible_findings(c, p):
        w.writerow([f["id"], f["rule_id"], f["severity"], f["risk"], f["project"], _csv_safe(f["asset_name"]), f["asset_type"], _csv_safe(f["title"]),
                    " ".join(f["controls"]), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(f["first_seen"])), f["sla_breached"]])
    db.audit(c, p.user, "findings.export", {"format": "csv"})
    return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=bankshield-findings.csv"})


def _csv_safe(v: Any) -> str:
    """Neutralise spreadsheet formula injection (a resource can be named `=cmd|...`)."""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: str, p: Principal = Depends(need("read")), c=Depends(conn)):
    for status in ("open", "excepted", "resolved"):
        f = next((x for x in insights._visible_findings(c, p, status) if x["id"] == finding_id), None)
        if f:
            break
    else:
        raise HTTPException(404, "not found")
    rule = rule_index().get(f["rule_id"], {})
    index = get_index(c)
    f["remediation"] = remediation_for(rule, {"name": f["asset_name"], "project": f["project"]}) if rule else {}
    f["clauses"] = [{"clause_id": ch["clause_id"], "heading": ch["heading"], "text": ch["text"], "doc_title": ch["doc_title"]}
                    for cid in f["controls"] if (ch := index.visible(cid, p.clearance))]
    f["exceptions"] = [e for e in governance.list_exceptions(c, p) if e["rule_id"] == f["rule_id"] and e["asset_id"] == f["asset_id"]]
    f["attack_paths"] = [{"id": ap["id"], "title": ap["title"], "score": ap["score"]} for ap in compute_attack_paths(c, p.visible_projects())
                         if any(x["id"] == finding_id for x in ap["findings"])]
    return _decorate(f)


@app.get("/api/assets")
def assets(p: Principal = Depends(need("read")), c=Depends(conn)):
    counts: dict[str, dict[str, Any]] = defaultdict(lambda: {"open": 0, "max_risk": 0.0, "worst": None})
    for f in insights._visible_findings(c, p):
        cnt = counts[f["asset_id"]]
        cnt["open"] += 1
        if f["risk"] > cnt["max_risk"]:
            cnt["max_risk"], cnt["worst"] = f["risk"], f["severity"]
    out = []
    for r in c.execute("SELECT id, project, type, name, region, sensitivity, owner FROM assets ORDER BY project, type, name"):
        if p.can_see_project(r["project"]):
            out.append({**dict(r), **counts[r["id"]]})
    return out


@app.get("/api/attack-paths")
def attack_paths(p: Principal = Depends(need("read")), c=Depends(conn)):
    paths = compute_attack_paths(c, p.visible_projects())
    for ap in paths:
        ap["mitre"] = [mitre_mod.describe(t) for t in ap["mitre"]]
    return paths


@app.get("/api/mitre")
def mitre(p: Principal = Depends(need("read")), c=Depends(conn)):
    return insights.mitre_matrix(c, p)


@app.post("/api/scan")
def scan(p: Principal = Depends(need("scan")), c=Depends(conn)):
    res = {"posture": scan_assets(c), "detections": run_log_detections(c)}
    db.audit(c, p.user, "scan.run", res)
    return res


@app.post("/api/simulate/{scenario}")
def simulate(scenario: str, p: Principal = Depends(need("simulate")), c=Depends(conn)):
    if scenario not in SCENARIOS:
        raise HTTPException(404, f"unknown scenario; choose from {sorted(SCENARIOS)}")
    n = run_attack_scenario(c, scenario)
    det = run_log_detections(c)
    db.audit(c, p.user, "simulate.attack", {"scenario": scenario, "log_rows": n, **det})
    return {"scenario": scenario, "log_rows": n, **det}


@app.get("/api/scenarios")
def scenarios(p: Principal = Depends(need("read"))):
    return sorted(SCENARIOS)


# ---------------------------------------------------------------- alerts & cases

@app.get("/api/alerts")
def alerts(p: Principal = Depends(need("read")), c=Depends(conn)):
    out = insights.visible_alerts(c, p)
    for a in out:
        a["playbooks"] = [pb["id"] for pb in playbooks_for(a["detection_id"])]
        a["mitre"] = [mitre_mod.describe(t) for t in a["mitre"]]
    return out


class TriageBody(BaseModel):
    disposition: str = Field(max_length=32)
    note: str = Field(default="", max_length=1000)


@app.post("/api/alerts/{alert_id}/triage")
def alert_triage(alert_id: str, body: TriageBody, p: Principal = Depends(need("alert.triage")), c=Depends(conn)):
    return _guard(governance.triage_alert, c, p, alert_id, body.disposition, body.note)


@app.get("/api/cases")
def cases(p: Principal = Depends(need("read")), c=Depends(conn)):
    return correlate(c, p.visible_projects())


# ---------------------------------------------------------------- incidents

class OpenBody(BaseModel):
    playbook_id: str = Field(max_length=64)
    alert_id: str | None = Field(default=None, max_length=64)
    finding_id: str | None = Field(default=None, max_length=64)


class StepBody(BaseModel):
    reason: str = Field(default="", max_length=1000)


def _incident_visible(c, inc_id: str, p: Principal) -> dict:
    try:
        inc = get_incident(c, inc_id)
    except KeyError:
        raise HTTPException(404, "not found")
    if not p.can_see_project(inc["context"].get("project", "")):
        raise HTTPException(404, "not found")
    return inc


@app.get("/api/playbooks")
def playbooks(p: Principal = Depends(need("read"))):
    return list(load_playbooks().values())


@app.get("/api/incidents")
def incidents(p: Principal = Depends(need("read")), c=Depends(conn)):
    out = []
    for r in c.execute("SELECT id FROM incidents ORDER BY opened_at DESC"):
        inc = get_incident(c, r["id"])
        if p.can_see_project(inc["context"].get("project", "")):
            out.append(inc)
    return out


@app.post("/api/incidents")
def incidents_open(body: OpenBody, p: Principal = Depends(need("incident.open")), c=Depends(conn)):
    if not (body.alert_id or body.finding_id):
        raise HTTPException(400, "an incident must be opened from an alert or a finding")
    return _guard(open_incident, c, body.playbook_id, p.user, alert_id=body.alert_id, finding_id=body.finding_id, principal=p)


@app.post("/api/incidents/{inc_id}/steps/{step_id}/approve")
def step_approve(inc_id: str, step_id: str, body: StepBody, p: Principal = Depends(principal), c=Depends(conn)):
    _incident_visible(c, inc_id, p)
    return _guard(approve_step, c, inc_id, step_id, p.user, reason=body.reason, principal=p)


@app.post("/api/incidents/{inc_id}/steps/{step_id}/reject")
def step_reject(inc_id: str, step_id: str, body: StepBody, p: Principal = Depends(principal), c=Depends(conn)):
    _incident_visible(c, inc_id, p)
    return _guard(reject_step, c, inc_id, step_id, p.user, body.reason or "rejected", principal=p)


@app.get("/api/incidents/{inc_id}/report.md", response_class=PlainTextResponse)
def incident_report(inc_id: str, p: Principal = Depends(need("read")), c=Depends(conn)):
    _incident_visible(c, inc_id, p)
    db.audit(c, p.user, "incident.report", {"incident": inc_id})
    return PlainTextResponse(incident_report_md(c, inc_id), media_type="text/markdown")


# ---------------------------------------------------------------- exception register

class ExceptionBody(BaseModel):
    finding_id: str = Field(max_length=64)
    reason: str = Field(max_length=1000)
    compensating_control: str = Field(max_length=1000)
    expires_in_days: int = Field(ge=1, le=config.MAX_EXCEPTION_DAYS)


class DecisionBody(BaseModel):
    note: str = Field(default="", max_length=1000)


@app.get("/api/exceptions")
def exceptions(p: Principal = Depends(need("read")), c=Depends(conn)):
    return governance.list_exceptions(c, p)


@app.post("/api/exceptions")
def exception_request(body: ExceptionBody, p: Principal = Depends(need("exception.request")), c=Depends(conn)):
    return _guard(governance.request_exception, c, p, body.finding_id, body.reason, body.compensating_control, body.expires_in_days)


@app.post("/api/exceptions/{exc_id}/{verb}")
def exception_decide(exc_id: str, verb: str, body: DecisionBody, p: Principal = Depends(need("exception.approve")), c=Depends(conn)):
    if verb not in ("approve", "reject", "revoke"):
        raise HTTPException(404, "not found")
    if verb == "revoke":
        return _guard(governance.revoke_exception, c, p, exc_id, body.note)
    return _guard(governance.decide_exception, c, p, exc_id, verb == "approve", body.note)


# ---------------------------------------------------------------- reports & audit

@app.get("/api/report/compliance")
def report(doc: str | None = None, p: Principal = Depends(need("read")), c=Depends(conn)):
    rep = compliance_report(c, projects=p.visible_projects(), doc_filter=doc)
    db.audit(c, p.user, "report.compliance", {"doc": doc, **rep["summary"]})
    return rep


@app.get("/api/report/compliance.md", response_class=PlainTextResponse)
def report_md(doc: str | None = None, p: Principal = Depends(need("read")), c=Depends(conn)):
    rep = compliance_report(c, projects=p.visible_projects(), doc_filter=doc)
    db.audit(c, p.user, "report.compliance.export", {"doc": doc, **rep["summary"]})
    return PlainTextResponse(report_markdown(rep), media_type="text/markdown")


@app.get("/api/report/residency")
def residency(p: Principal = Depends(need("read")), c=Depends(conn)):
    return [r for r in residency_evidence(c) if p.can_see_project(r["project"])]


class GapBody(BaseModel):
    requirements: list[dict[str, Any]] = Field(max_length=200)


@app.post("/api/report/gap")
def gap(body: GapBody, p: Principal = Depends(need("read")), c=Depends(conn)):
    return regulatory_gap(c, body.requirements, projects=p.visible_projects())


@app.get("/api/audit")
def audit_log(limit: int = 100, action: str | None = None, actor: str | None = None,
              p: Principal = Depends(need("audit.read")), c=Depends(conn)):
    limit = max(1, min(limit, 500))
    detail = db.verify_audit_detail(c)
    where, params = [], []
    if action:
        where.append("action LIKE ?"); params.append(action + "%")
    if actor:
        where.append("actor = ?"); params.append(actor)
    sql = "SELECT seq, ts, actor, action, payload, hash FROM audit" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY seq DESC LIMIT ?"
    recs = db.rows(c, sql, tuple(params) + (limit,))
    for r in recs:
        r["payload"] = json.loads(r["payload"])
    return {"chain_ok": detail["ok"], "records": detail["records"], "broken_at": detail["broken_at"], "keyed": detail["keyed"],
            "checkpoint": detail["checkpoint"], "checkpoint_ok": detail["checkpoint_ok"], "head": detail["head"], "entries": recs}


@app.post("/api/audit/checkpoint")
def audit_checkpoint(p: Principal = Depends(need("audit.checkpoint")), c=Depends(conn)):
    cp = db.audit_checkpoint(c, p.user)
    db.audit(c, p.user, "audit.checkpoint", {"seq": cp["seq"], "hash": cp["hash"]})
    return cp


@app.get("/api/metrics", response_class=PlainTextResponse)
def metrics(p: Principal = Depends(need("audit.read")), c=Depends(conn)):
    return PlainTextResponse(insights.prometheus(c), media_type="text/plain; version=0.0.4")
