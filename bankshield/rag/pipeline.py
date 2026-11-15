"""The ask() pipeline — the core of the platform.

    question ─► screen (injection) ─► route ─► clearance-first hybrid retrieval ─► relevance gate
             ─► scrub (injection in evidence)
             ─► live-state join: findings + alerts for the retrieved clauses, project-scoped;
                for a named asset, its findings pull in the clauses they violate
             ─► LLM (falls back to the extractive composer if the backend errors)
             ─► citation enforcement ─► output DLP ─► audit record ─► Answer
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field, asdict
from typing import Any

from .. import config, db
from ..detection.log_detections import alerts_for_controls
from ..detection.rules import findings_for_asset, findings_for_controls, remediation_for, rule_index
from . import guard
from .clearance import Principal, resolve
from .llm import SYSTEM_PROMPT, ExtractiveLLM, get_llm
from .retriever import get_index
from .router import route


@dataclass
class Answer:
    question: str
    answer: str
    citations: list[str]
    refused: bool
    refusal_reason: str | None
    route: str
    retrieved: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    suspicious_chunks: list[str] = field(default_factory=list)
    user: str = ""
    role: str = ""
    latency_ms: int = 0
    audit_hash: str = ""
    alerts: list[dict[str, Any]] = field(default_factory=list)
    remediation: list[dict[str, Any]] = field(default_factory=list)
    intents: list[str] = field(default_factory=list)
    confidence: str = "none"
    coverage: float = 0.0
    backend: str = ""
    redactions: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_LLM = None


def _llm():
    global _LLM
    if _LLM is None:
        _LLM = get_llm()
    return _LLM


def reset_llm() -> None:
    global _LLM
    _LLM = None


def _chunk_view(c: dict[str, Any], **extra: Any) -> tuple[dict[str, Any], bool]:
    text, bad = guard.scrub(c["text"])
    return {**c, "text": text, **extra}, bad


def ask(conn: sqlite3.Connection, question: str, user: str = "asha.analyst", principal: Principal | None = None,
        k: int | None = None) -> Answer:
    t0 = time.time()
    p = principal or resolve(user)
    question = guard.normalise(question).strip()[: config.MAX_QUESTION_LEN]
    r = route(question)
    base = dict(question=question, citations=[], route=r.mode, user=p.user, role=p.role, intents=sorted(r.intents))

    hit = guard.screen_question(question)
    if hit:
        ans = Answer(answer="I can't act on that. The question contains an instruction to override how this assistant works; "
                            "it has been logged. Ask the security or policy question directly.",
                     refused=True, refusal_reason="prompt_injection", retrieved=[], findings=[], notes=[f"matched: {hit[:60]}"], **base)
        return _finish(conn, ans, t0)

    index = get_index(conn)
    res = index.search_ex(question, k=k, max_clearance=p.clearance)
    retrieved, suspicious = [], []
    for h in res.hits:
        view, bad = _chunk_view(h.chunk, score=round(h.score, 4), bm25=round(h.bm25, 3), vector=round(h.vector, 3), source="retrieval")
        if bad:
            suspicious.append(h.chunk["id"])
        retrieved.append(view)

    # A named asset: its own open findings are the evidence, and they bring their clauses with them.
    notes: list[str] = []
    asset_findings: list[dict] = []
    if r.asset_ids:
        asset_findings = findings_for_asset(conn, r.asset_ids, projects=p.visible_projects())
        seen_assets = {f["asset_id"] for f in asset_findings}
        known = {row["id"] for row in conn.execute(
            f"SELECT id, project FROM assets WHERE id IN ({','.join('?' * len(r.asset_ids))})", tuple(r.asset_ids))
            if p.can_see_project(row["project"])}
        for a in r.asset_ids:
            if a not in known:
                notes.append(f"{a} is not a resource in a project you can see.")
            elif a not in seen_assets:
                notes.append(f"{a} has no open findings.")
        if not known:
            # Same answer whether the asset does not exist or sits in a project the caller cannot see.
            ans = Answer(answer="I can't find " + ", ".join(r.asset_ids) + " among the resources in the projects you can see.",
                         refused=True, refusal_reason="asset_not_visible", retrieved=[], findings=[], notes=notes, **base)
            return _finish(conn, ans, t0)
        asset_names = [row["name"] for row in conn.execute(
            f"SELECT name FROM assets WHERE id IN ({','.join('?' * len(known))})", tuple(known))]
        have = {c["clause_id"] for c in retrieved}
        extra = []
        for f in asset_findings:
            for cid in f["controls"]:
                c = index.visible(cid, p.clearance)
                if c and cid not in have and len(extra) < 4:
                    have.add(cid)
                    view, bad = _chunk_view(c, score=1.0, bm25=0.0, vector=0.0, source="asset")
                    if bad:
                        suspicious.append(c["id"])
                    extra.append(view)
        retrieved = extra + retrieved   # the clauses the asset actually violates lead

    relevant = res.relevant() or bool(asset_findings)
    if not retrieved or not relevant:
        msg = "I can't answer that from the policy corpus available to you. No sufficiently relevant clause was retrieved."
        ans = Answer(answer=" ".join([msg] + notes), refused=True, refusal_reason="low_retrieval_score", retrieved=retrieved, findings=[],
                     suspicious_chunks=suspicious, coverage=res.coverage, notes=notes, **base)
        return _finish(conn, ans, t0)

    clause_ids = [c["clause_id"] for c in retrieved]
    findings: list[dict] = []
    alerts: list[dict] = []
    remediation: list[dict] = []
    state_checked = False
    if r.mode in ("both", "state"):
        state_checked = True
        if r.asset_ids:
            findings = asset_findings
        else:
            # Join on the clauses that actually answer the question, not on every retrieved neighbour.
            top = retrieved[0]["score"] or 1.0
            join_ids = [c["clause_id"] for c in retrieved if c["score"] >= 0.6 * top] or clause_ids[:1]
            findings = findings_for_controls(conn, join_ids, projects=p.visible_projects())
            if not findings:
                findings = findings_for_controls(conn, clause_ids, projects=p.visible_projects())
        if r.asset_ids:
            # Only alerts that concern the named resource: its own identity, or evidence that mentions it.
            import json as _json
            alerts = [a for a in alerts_for_controls(conn, clause_ids, projects=p.visible_projects())
                      if any((a["principal"] or "").startswith(n + "@") or n in _json.dumps(a["evidence"]) for n in asset_names)]
        else:
            alerts = alerts_for_controls(conn, clause_ids if "alerts" in r.intents else clause_ids[:2], projects=p.visible_projects())
            if "alerts" not in r.intents:
                alerts = alerts[:3]
        if "remediate" in r.intents and findings:
            rules = rule_index()
            done = set()
            for f in findings:
                rule = rules.get(f["rule_id"])
                if not rule or (f["rule_id"], f["asset_id"]) in done:
                    continue
                done.add((f["rule_id"], f["asset_id"]))
                rem = remediation_for(rule, {"name": f["asset_name"], "project": f["project"]})
                remediation.append({"rule_id": f["rule_id"], "asset": f"{f['project']}/{f['asset_name']}", "finding_id": f["id"],
                                    "controls": f["controls"], **rem})

    # Build the prompt. Evidence is wrapped as data.
    evidence = "\n\n".join(guard.wrap_as_data(c["clause_id"], c["text"]) for c in retrieved)
    if findings:
        rows = "\n".join(f"- {f['project']}/{f['asset_name']} [{f['asset_type']}] {f['title']} | risk={f.get('risk')} | evidence={f['evidence']} | controls={f['controls']}" for f in findings[:25])
        evidence += "\n\n" + guard.wrap_as_data("LIVE-FINDINGS", rows)
    if alerts:
        rows = "\n".join(f"- {a['project']} {a['principal']} [{a['severity']}/{a['status']}] {a['title']} | controls={a['controls']}" for a in alerts[:10])
        evidence += "\n\n" + guard.wrap_as_data("LIVE-ALERTS", rows)
    if remediation:
        rows = "\n".join(f"- {x['asset']} ({x['rule_id']}): {x['guidance']} | command: {x['fix']} | controls={x['controls']}" for x in remediation[:10])
        evidence += "\n\n" + guard.wrap_as_data("REMEDIATION", rows)
    user_msg = f"Question: {question}\n\nEvidence:\n{evidence}\n\nAnswer with citations."
    llm_ctx = {"question": question, "clauses": retrieved, "findings": findings, "alerts": alerts, "remediation": remediation,
               "state_checked": state_checked, "exact_refs": res.exact_refs}

    backend = _llm()
    try:
        raw = backend.generate(SYSTEM_PROMPT, user_msg, context=llm_ctx)
        backend_name = backend.name
    except Exception as e:  # model outage must not take the console down — degrade to the offline composer
        raw = ExtractiveLLM().generate(SYSTEM_PROMPT, user_msg, context=llm_ctx)
        backend_name = "extractive(fallback)"
        notes.append(f"LLM backend unavailable ({type(e).__name__}); answered with the offline extractive composer.")

    allowed = set(clause_ids) | {c for f in findings for c in f["controls"]} | {c for a in alerts for c in a["controls"]}
    ok, valid, invalid = guard.enforce_citations(raw, allowed)
    common = dict(retrieved=retrieved, findings=findings, alerts=alerts, remediation=remediation, suspicious_chunks=suspicious,
                  coverage=res.coverage, backend=backend_name, notes=notes)
    if not ok:
        reason = f"invalid_citations:{','.join(invalid)}" if invalid else "uncited_answer"
        ans = Answer(answer="I can't give a reliable answer: the generated response did not cite retrieved policy clauses, so it was withheld.",
                     refused=True, refusal_reason=reason, **{**base, "citations": valid}, **common)
        return _finish(conn, ans, t0)

    text, n_red = guard.redact_secrets(raw)
    if notes:
        text += "\n\n" + "\n".join(f"Note: {n}" for n in notes)
    confidence = "high" if (res.coverage >= 0.75 or res.exact_refs or asset_findings) and not suspicious else "medium"
    ans = Answer(answer=text, refused=False, refusal_reason=None, confidence=confidence, redactions=n_red,
                 **{**base, "citations": valid}, **common)
    return _finish(conn, ans, t0)


def _finish(conn: sqlite3.Connection, ans: Answer, t0: float) -> Answer:
    ans.latency_ms = int((time.time() - t0) * 1000)
    ans.audit_hash = db.audit(conn, ans.user, "rag.ask", {
        "question": ans.question, "role": ans.role, "route": ans.route, "intents": ans.intents, "refused": ans.refused,
        "reason": ans.refusal_reason, "citations": ans.citations, "confidence": ans.confidence, "coverage": ans.coverage,
        "retrieved": [c["id"] for c in ans.retrieved], "findings": [f["id"] for f in ans.findings],
        "alerts": [a["id"] for a in ans.alerts], "suspicious": ans.suspicious_chunks, "redactions": ans.redactions,
        "backend": ans.backend, "latency_ms": ans.latency_ms,
    })
    return ans
