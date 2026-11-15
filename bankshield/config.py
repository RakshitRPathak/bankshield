"""Central configuration. Everything is overridable via environment variables."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("BANKSHIELD_DATA_DIR", ROOT / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.getenv("BANKSHIELD_DB", DATA_DIR / "bankshield.db"))
POLICY_DIR = Path(os.getenv("BANKSHIELD_POLICY_DIR", ROOT / "policies"))
RULES_PATH = Path(os.getenv("BANKSHIELD_RULES", ROOT / "bankshield" / "detection" / "rules.yaml"))
PLAYBOOK_DIR = Path(os.getenv("BANKSHIELD_PLAYBOOKS", ROOT / "bankshield" / "playbooks" / "library"))

# LLM backend: "extractive" (offline, deterministic), "openai", or "vertex".
LLM_BACKEND = os.getenv("BANKSHIELD_LLM", "extractive")
OPENAI_MODEL = os.getenv("BANKSHIELD_OPENAI_MODEL", "gpt-4o-mini")
VERTEX_MODEL = os.getenv("BANKSHIELD_VERTEX_MODEL", "gemini-1.5-flash")
VERTEX_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT", "")
VERTEX_LOCATION = os.getenv("BANKSHIELD_VERTEX_LOCATION", "asia-south1")

# Embedding backend: "tfidf" (offline), "lsa" (offline, dense latent-semantic vectors) or
# "sentence-transformers" (needs a model download).
EMBEDDING_BACKEND = os.getenv("BANKSHIELD_EMBEDDINGS", "tfidf")
ST_MODEL = os.getenv("BANKSHIELD_ST_MODEL", "all-MiniLM-L6-v2")

# Retrieval
TOP_K = int(os.getenv("BANKSHIELD_TOP_K", "6"))
MIN_RETRIEVAL_SCORE = float(os.getenv("BANKSHIELD_MIN_SCORE", "0.12"))  # raw cosine (tf-idf)
MIN_BM25 = float(os.getenv("BANKSHIELD_MIN_BM25", "4.0"))                 # raw BM25 top score
MIN_COVERAGE = float(os.getenv("BANKSHIELD_MIN_COVERAGE", "0.40"))        # idf-weighted share of the question the evidence covers
# A strong lexical AND vector match answers even when the question is phrased in words the corpus lacks.
STRONG_BM25 = float(os.getenv("BANKSHIELD_STRONG_BM25", "8.0"))
STRONG_COSINE = float(os.getenv("BANKSHIELD_STRONG_COSINE", "0.20"))
HYBRID_ALPHA = float(os.getenv("BANKSHIELD_HYBRID_ALPHA", "0.5"))  # weight of vector vs BM25
MAX_QUESTION_LEN = int(os.getenv("BANKSHIELD_MAX_QUESTION_LEN", "600"))

# Data residency: regions the bank is allowed to store data in.
ALLOWED_REGIONS = {"asia-south1", "asia-south2"}

# ------------------------------------------------------------------ identity & access
# AUTH_MODE "header": the X-User header names a simulated user (demo console).
# AUTH_MODE "token":  a signed bearer token is required (HS256, see bankshield/auth.py).
# Production: replace both with IAP / OIDC; the Principal contract stays the same.
AUTH_MODE = os.getenv("BANKSHIELD_AUTH", "header")
SECRET_KEY = os.getenv("BANKSHIELD_SECRET", "")           # signs tokens; REQUIRED in token mode
AUDIT_HMAC_KEY = os.getenv("BANKSHIELD_AUDIT_KEY", "")    # if set, the audit chain is keyed (HMAC-SHA256)
TOKEN_TTL_S = int(os.getenv("BANKSHIELD_TOKEN_TTL", "3600"))
RATE_LIMIT_PER_MIN = int(os.getenv("BANKSHIELD_RATE_LIMIT", "240"))  # per identity; 0 disables
FOUR_EYES = os.getenv("BANKSHIELD_FOUR_EYES", "1") != "0"  # approver must differ from the incident opener

# Clearance levels. Users may only retrieve material at or below their level.
CLEARANCE = {"public": 0, "internal": 1, "restricted": 2, "ciso": 3}
ROLE_CLEARANCE = {"analyst": 1, "senior_analyst": 2, "ciso": 3, "auditor": 2}

# Role → permissions. Every API route checks exactly one of these.
_READ = {"ask", "read"}
ROLE_PERMISSIONS = {
    "analyst": _READ | {"scan", "incident.open", "incident.step", "alert.triage"},
    "senior_analyst": _READ | {"scan", "simulate", "incident.open", "incident.step", "incident.approve",
                               "alert.triage", "exception.request", "audit.read"},
    "ciso": _READ | {"scan", "simulate", "incident.open", "incident.step", "incident.approve", "alert.triage",
                     "exception.request", "exception.approve", "audit.read", "audit.checkpoint"},
    "auditor": _READ | {"audit.read"},  # read-only by design (IAM-2.2: cannot both act and audit)
}

# Simulated users for the console. Real deployment: map from IdP groups.
USERS = {
    "asha.analyst": {"role": "analyst", "projects": ["payments-prod", "shared-services"]},
    "ravi.senior": {"role": "senior_analyst", "projects": ["core-banking-prod", "payments-prod", "data-lake", "shared-services"]},
    "meera.ciso": {"role": "ciso", "projects": ["*"]},
    "ext.auditor": {"role": "auditor", "projects": ["*"]},
}

# ------------------------------------------------------------------ risk & SLAs
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_BASE = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 2.0}
# Remediation SLA per severity (hours from first detection).
SLA_HOURS = {"critical": 24, "high": 72, "medium": 14 * 24, "low": 30 * 24}
ALERT_ACK_MINUTES = {"critical": 15, "high": 60, "medium": 240, "low": 1440}  # LOG-2.3
REG_REPORT_HOURS = 6            # REG-DIG-7: regulator reporting window for Sev 1/2
MAX_EXCEPTION_DAYS = 365        # DRS-3.2: exceptions expire within 12 months
