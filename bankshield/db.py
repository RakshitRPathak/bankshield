"""SQLite persistence + tamper-evident audit trail.

In production this maps to Cloud SQL (Postgres + pgvector) and BigQuery; SQLite keeps the
prototype dependency-free. Every table is created idempotently and older databases are
migrated in place (see _MIGRATIONS).

Audit trail integrity, in layers:
  1. append-only   — SQLite triggers abort UPDATE/DELETE on the audit table;
  2. hash chain    — each record commits to the previous record's hash, over a
                     length-prefixed encoding (no delimiter ambiguity);
  3. keyed chain   — with BANKSHIELD_AUDIT_KEY set the chain is HMAC-SHA256, so someone with
                     database write access but not the key cannot re-forge it;
  4. checkpoints   — the chain head is anchored outside the table (a file here, a WORM bucket
                     in production), which is what detects truncation of the tail.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    region TEXT,
    sensitivity TEXT NOT NULL DEFAULT 'internal',
    owner TEXT,
    config TEXT NOT NULL  -- JSON
);
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    project TEXT NOT NULL,
    principal TEXT NOT NULL,
    method TEXT NOT NULL,
    resource TEXT,
    source_ip TEXT,
    country TEXT,
    status TEXT NOT NULL DEFAULT 'OK',
    extra TEXT  -- JSON
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS idx_logs_principal ON logs(principal);
CREATE INDEX IF NOT EXISTS idx_logs_method ON logs(method);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    project TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT NOT NULL,  -- JSON
    controls TEXT NOT NULL,  -- JSON list of clause ids
    status TEXT NOT NULL DEFAULT 'open',   -- open | excepted | resolved
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    risk REAL NOT NULL DEFAULT 0,
    due_at REAL,
    mitre TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    detection_id TEXT NOT NULL,
    project TEXT NOT NULL,
    principal TEXT,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT NOT NULL,  -- JSON
    controls TEXT NOT NULL,  -- JSON
    ts REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',   -- open | acknowledged | in_progress | closed
    created_at REAL,
    mitre TEXT NOT NULL DEFAULT '[]',
    ack_by TEXT,
    ack_at REAL,
    disposition TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    playbook_id TEXT NOT NULL,
    alert_id TEXT,
    opened_by TEXT NOT NULL,
    opened_at REAL NOT NULL,
    status TEXT NOT NULL,
    context TEXT NOT NULL,  -- JSON
    steps TEXT NOT NULL,     -- JSON list with per-step state
    severity INTEGER NOT NULL DEFAULT 3,
    closed_at REAL
);
CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL,
    doc_title TEXT NOT NULL,
    clause_id TEXT NOT NULL,
    heading TEXT,
    text TEXT NOT NULL,
    clearance TEXT NOT NULL,
    regulator TEXT,
    version TEXT
);
CREATE TABLE IF NOT EXISTS exceptions (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    project TEXT NOT NULL,
    reason TEXT NOT NULL,
    compensating_control TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected | revoked
    decided_by TEXT,
    decided_at REAL,
    decision_note TEXT
);
CREATE TABLE IF NOT EXISTS posture_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    score REAL NOT NULL,
    open INTEGER NOT NULL,
    critical INTEGER NOT NULL,
    high INTEGER NOT NULL,
    medium INTEGER NOT NULL,
    low INTEGER NOT NULL,
    excepted INTEGER NOT NULL DEFAULT 0,
    by_project TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit trail is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit trail is append-only'); END;
"""

# Columns added after v0.1 — applied to databases created by an older build.
_MIGRATIONS: dict[str, dict[str, str]] = {
    "findings": {"risk": "REAL NOT NULL DEFAULT 0", "due_at": "REAL", "mitre": "TEXT NOT NULL DEFAULT '[]'"},
    "alerts": {"created_at": "REAL", "mitre": "TEXT NOT NULL DEFAULT '[]'", "ack_by": "TEXT", "ack_at": "REAL",
               "disposition": "TEXT", "note": "TEXT"},
    "incidents": {"severity": "INTEGER NOT NULL DEFAULT 3", "closed_at": "REAL"},
}
_initialised: set[str] = set()


def _migrate(conn: sqlite3.Connection) -> None:
    for table, cols in _MIGRATIONS.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if not have:
            continue
        for col, ddl in cols.items():
            if col not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")


def connect(path=None) -> sqlite3.Connection:
    p = str(path or config.DB_PATH)
    conn = sqlite3.connect(p, check_same_thread=False, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    ready = p in _initialised and conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='audit_no_delete'").fetchone()
    if not ready:
        _migrate(conn)          # old tables first, so the indexes/triggers below apply cleanly
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
        _initialised.add(p)
    return conn


@contextmanager
def session(path=None) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def reset(path=None) -> None:
    p = Path(path or config.DB_PATH)
    _initialised.discard(str(p))
    for suffix in ("", "-wal", "-shm", ".anchor"):
        f = p.parent / (p.name + suffix)
        if f.exists():
            f.unlink()


# ---------------------------------------------------------------- audit chain

def _hash(prev: str, ts: float, actor: str, action: str, payload: str) -> str:
    """Hash of one record. Fields are length-prefixed so no field can smuggle a delimiter."""
    parts = [prev, f"{ts:.6f}", actor, action, payload]
    msg = b"".join(len(b).to_bytes(8, "big") + b for b in (s.encode() for s in parts))
    if config.AUDIT_HMAC_KEY:
        return hmac.new(config.AUDIT_HMAC_KEY.encode(), msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


def audit(conn: sqlite3.Connection, actor: str, action: str, payload: dict[str, Any]) -> str:
    """Append a hash-chained audit record. Returns the new record hash.

    The read-of-head and the insert happen under one write lock (BEGIN IMMEDIATE), so two
    concurrent requests cannot both chain onto the same predecessor.
    """
    body = json.dumps(payload, sort_keys=True, default=str)
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else "GENESIS"
        ts = round(time.time(), 6)
        h = _hash(prev, ts, actor, action, body)
        conn.execute(
            "INSERT INTO audit(ts, actor, action, payload, prev_hash, hash) VALUES (?,?,?,?,?,?)",
            (ts, actor, action, body, prev, h),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return h


def _anchor_path() -> Path:
    return config.DB_PATH.parent / (config.DB_PATH.name + ".anchor")


def audit_checkpoint(conn: sqlite3.Connection, actor: str = "system") -> dict[str, Any]:
    """Anchor the current chain head outside the database (production: object-lock bucket)."""
    row = conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    cp = {"seq": row["seq"] if row else 0, "hash": row["hash"] if row else "GENESIS", "ts": time.time(), "by": actor}
    with open(_anchor_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(cp) + "\n")
    return cp


def last_checkpoint() -> dict[str, Any] | None:
    p = _anchor_path()
    if not p.exists():
        return None
    lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return json.loads(lines[-1]) if lines else None


def verify_audit_detail(conn: sqlite3.Connection) -> dict[str, Any]:
    """Recompute the chain and compare against the last external checkpoint."""
    prev, n, broken_at = "GENESIS", 0, None
    by_seq: dict[int, str] = {}
    for r in conn.execute("SELECT * FROM audit ORDER BY seq"):
        expected = _hash(prev, r["ts"], r["actor"], r["action"], r["payload"])
        if expected != r["hash"] or r["prev_hash"] != prev:
            broken_at = r["seq"]
            break
        prev = r["hash"]
        by_seq[r["seq"]] = r["hash"]
        n += 1
    cp = last_checkpoint()
    anchored = None
    if cp and cp["seq"]:
        anchored = by_seq.get(cp["seq"]) == cp["hash"]   # False ⇒ tail truncated or history rewritten
    ok = broken_at is None and anchored is not False
    return {"ok": ok, "records": n, "broken_at": broken_at, "head": prev, "keyed": bool(config.AUDIT_HMAC_KEY),
            "checkpoint": cp, "checkpoint_ok": anchored}


def verify_audit_chain(conn: sqlite3.Connection) -> tuple[bool, int]:
    """Recompute the chain. Returns (ok, number_of_valid_records)."""
    d = verify_audit_detail(conn)
    return d["ok"], d["records"]


def rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]
