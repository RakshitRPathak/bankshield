"""Authentication, authorisation, isolation and input-handling tests."""
import time

import pytest

from bankshield import auth, config
from bankshield.detection.safe_expr import UnsafeExpression, compile_rule, evaluate

VARS = {"cfg", "asset", "ALLOWED_REGIONS"}


# ------------------------------------------------------------------ rule sandbox

@pytest.mark.parametrize("expr", [
    "().__class__.__mro__[1].__subclasses__()",          # the classic eval-sandbox escape
    "cfg.__class__",
    "__import__('os').system('id')",
    "open('/etc/passwd').read()",
    "(lambda: 1)()",
    "cfg.get('x').__globals__",
    "getattr(cfg, '__class__')",
    "[x for x in ().__class__.__bases__]",
    "cfg.pop('public')",                                  # mutation is not on the allow-list
    "f'{cfg}'",
    "(y := 1)",
    "exec('1')",
    "'__class__' in cfg",
])
def test_rule_sandbox_rejects_escapes(expr):
    with pytest.raises(UnsafeExpression):
        compile_rule(expr, VARS)


def test_rule_sandbox_evaluates_legitimate_rules():
    code = compile_rule("any(k.get('age_days', 0) > cfg.get('max', 90) for k in cfg.get('keys', []))", VARS)
    assert evaluate(code, {"cfg": {"keys": [{"age_days": 120}], "max": 100}, "asset": {}, "ALLOWED_REGIONS": set()}) is True
    code = compile_rule("asset['region'] not in ALLOWED_REGIONS and asset['sensitivity'] == 'restricted'", VARS)
    assert evaluate(code, {"cfg": {}, "asset": {"region": "us-central1", "sensitivity": "restricted"}, "ALLOWED_REGIONS": {"asia-south1"}})


def test_every_shipped_rule_passes_the_sandbox_and_has_remediation():
    from bankshield.detection import load_rules
    rules = load_rules()
    assert len(rules) == 33 and len({r["id"] for r in rules}) == 33
    for r in rules:
        assert r["remediation"] and r["fix"], r["id"]
        assert r["controls"], r["id"]


# ------------------------------------------------------------------ tokens

def test_token_roundtrip_and_tampering(restore_config):
    config.SECRET_KEY = "unit-test-secret-0123456789"
    tok = auth.issue_token("ravi.senior")
    assert auth.verify_token(tok) == "ravi.senior"
    head, body, sig = tok.split(".")
    forged_body = auth._b64(b'{"sub":"meera.ciso","iat":1,"exp":9999999999,"iss":"bankshield"}')
    with pytest.raises(auth.AuthError):
        auth.verify_token(f"{head}.{forged_body}.{sig}")                # claims swapped, old signature
    none_head = auth._b64(b'{"alg":"none","typ":"JWT"}')
    with pytest.raises(auth.AuthError):
        auth.verify_token(f"{none_head}.{forged_body}.")                # alg=none downgrade
    with pytest.raises(auth.AuthError):
        auth.verify_token(auth.issue_token("ravi.senior", ttl_s=10, now=time.time() - 3600))  # expired
    config.SECRET_KEY = "another-secret-0123456789"
    with pytest.raises(auth.AuthError):
        auth.verify_token(tok)                                          # signed with a different key
    config.SECRET_KEY = ""
    with pytest.raises(auth.AuthError):
        auth.issue_token("ravi.senior")                                 # refuses to sign with no secret


def test_token_mode_requires_bearer(client, restore_config):
    config.AUTH_MODE, config.SECRET_KEY = "token", "unit-test-secret-0123456789"
    assert client.get("/api/whoami", headers={"X-User": "meera.ciso"}).status_code == 401   # header is ignored
    assert client.get("/api/whoami", headers={"Authorization": "Bearer nonsense"}).status_code == 401
    r = client.get("/api/whoami", headers={"Authorization": f"Bearer {auth.issue_token('asha.analyst')}"})
    assert r.status_code == 200 and r.json()["user"] == "asha.analyst" and r.json()["users"] == ["asha.analyst"]
    assert client.get("/api/users").status_code == 404


# ------------------------------------------------------------------ API identity & permissions

def test_no_identity_is_rejected_everywhere(client):
    for path in ["/api/whoami", "/api/findings", "/api/alerts", "/api/overview", "/api/attack-paths", "/api/audit", "/api/incidents"]:
        assert client.get(path).status_code == 401, path
        assert client.get(path, headers={"X-User": "mallory"}).status_code == 401, path
    assert client.post("/api/ask", json={"question": "Is MFA required?"}).status_code == 401
    assert client.post("/api/scan").status_code == 401


@pytest.mark.parametrize("user,method,path,body,expected", [
    ("asha.analyst", "post", "/api/simulate/leaked_key", None, 403),
    ("ext.auditor", "post", "/api/scan", None, 403),
    ("ext.auditor", "post", "/api/incidents", {"playbook_id": "PB-PUBLIC-STORAGE", "finding_id": "x"}, 403),
    ("asha.analyst", "get", "/api/audit", None, 403),
    ("asha.analyst", "get", "/api/metrics", None, 403),
    ("ravi.senior", "post", "/api/audit/checkpoint", None, 403),
    ("asha.analyst", "post", "/api/exceptions", {"finding_id": "x", "reason": "r" * 12, "compensating_control": "c" * 12, "expires_in_days": 30}, 403),
    ("ravi.senior", "post", "/api/exceptions/EXC-1/approve", {"note": ""}, 403),
    ("ravi.senior", "post", "/api/simulate/leaked_key", None, 200),
    ("ext.auditor", "get", "/api/audit", None, 200),
])
def test_role_permissions(client, user, method, path, body, expected):
    r = getattr(client, method)(path, headers={"X-User": user}, **({"json": body} if body is not None else {}))
    assert r.status_code == expected, r.text


def test_project_isolation(client, conn, as_user):
    other = conn.execute("SELECT id FROM findings WHERE project='core-banking-prod' AND rule_id='BS-020'").fetchone()["id"]
    a = as_user("asha.analyst")
    assert client.get(f"/api/findings/{other}", headers=a).status_code == 404
    # cannot open an incident on a finding outside her projects (previously possible)
    assert client.post("/api/incidents", json={"playbook_id": "PB-PRIV-ESC", "finding_id": other}, headers=a).status_code == 404
    # an incident in a project she cannot see is invisible and untouchable
    inc = client.post("/api/incidents", json={"playbook_id": "PB-PRIV-ESC", "finding_id": other}, headers=as_user("ravi.senior")).json()
    assert inc["id"] not in {i["id"] for i in client.get("/api/incidents", headers=a).json()}
    assert client.post(f"/api/incidents/{inc['id']}/steps/diff_changes/approve", json={"reason": "x"}, headers=a).status_code == 404
    assert client.get(f"/api/incidents/{inc['id']}/report.md", headers=a).status_code == 404
    for path in ["/api/alerts", "/api/assets", "/api/report/residency", "/api/exceptions"]:
        assert {x["project"] for x in client.get(path, headers=a).json()} <= {"payments-prod", "shared-services"}, path
    for ap in client.get("/api/attack-paths", headers=a).json():
        assert set(ap["projects"]) <= {"payments-prod", "shared-services"}
    for case in client.get("/api/cases", headers=a).json():
        assert set(case["projects"]) <= {"payments-prod", "shared-services"}


def test_clause_endpoint_respects_clearance(client, as_user):
    assert client.get("/api/clauses/IR-2.1", headers=as_user("asha.analyst")).status_code == 404
    assert client.get("/api/clauses/NOPE-9.9", headers=as_user("asha.analyst")).status_code == 404   # indistinguishable
    assert client.get("/api/clauses/IR-2.1", headers=as_user("ravi.senior")).status_code == 200


def test_security_headers_and_limits(client, as_user):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "onclick=" not in r.text and "<script>" not in r.text          # nothing inline for the CSP to block
    r = client.get("/api/whoami", headers=as_user("meera.ciso"))
    assert r.headers["cache-control"] == "no-store" and r.headers["x-request-id"]
    assert client.post("/api/ask", json={"question": "x" * 5000}, headers=as_user("meera.ciso")).status_code == 422
    assert client.post("/api/ask", json={"question": "   "}, headers=as_user("meera.ciso")).status_code == 400
    big = client.post("/api/report/gap", content=b"x" * 70000, headers={**as_user("meera.ciso"), "Content-Type": "application/json"})
    assert big.status_code == 413


def test_rate_limit(client, as_user, restore_config):
    config.RATE_LIMIT_PER_MIN = 3
    codes = [client.get("/api/whoami", headers=as_user("asha.analyst")).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert client.get("/api/whoami", headers=as_user("meera.ciso")).status_code == 200   # per identity


def test_csv_export_neutralises_formulas(client, conn, as_user):
    conn.execute("UPDATE assets SET name='=HYPERLINK(\"http://evil\")' WHERE id='pay-gcs-exports'")
    conn.commit()
    text = client.get("/api/findings.csv", headers=as_user("meera.ciso")).text
    assert "'=HYPERLINK" in text and "\n=HYPERLINK" not in text and ",=HYPERLINK" not in text


def test_health_is_open_and_minimal(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and set(r.json()) == {"status", "version"}
