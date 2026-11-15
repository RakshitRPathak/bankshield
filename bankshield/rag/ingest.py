"""Clause-aware ingestion of policy markdown.

Chunk = one numbered clause (e.g. `### CSP-3.1 No public storage` + its body). Keeping the
clause as the unit means every citation maps to something an auditor can look up, and the
clause ID is exactly what the detection rules reference.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import yaml

from .. import config

_FRONT = re.compile(r"^---\n(.*?)\n---\n", re.S)
_CLAUSE = re.compile(r"^(#{2,3})\s+([A-Z][A-Z-]*-\d+(?:\.\d+)?)\s+(.*)$", re.M)


def parse_policy(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    m = _FRONT.match(text)
    meta = yaml.safe_load(m.group(1)) if m else {}
    body = text[m.end():] if m else text
    doc_id = str(meta.get("doc_id", path.stem))
    chunks = []
    matches = list(_CLAUSE.finditer(body))
    for i, mm in enumerate(matches):
        level, clause_id, heading = mm.group(1), mm.group(2), mm.group(3).strip()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        content = body[mm.end():end].strip()
        # Drop section-level headers (## X-1) whose body is just subsections.
        if level == "##" and any(c.group(2).startswith(clause_id + ".") for c in matches[i + 1:i + 6]):
            continue
        if not content:
            continue
        chunks.append({
            "id": f"{doc_id}:{clause_id}",
            "doc_id": doc_id,
            "doc_title": str(meta.get("title", path.stem)),
            "clause_id": clause_id,
            "heading": heading,
            "text": f"{clause_id} {heading}. {content}",
            "clearance": str(meta.get("clearance", "internal")),
            "regulator": str(meta.get("regulator", "internal")),
            "version": str(meta.get("version", "")),
        })
    return chunks


def ingest_policies(conn: sqlite3.Connection, policy_dir: Path | None = None) -> int:
    policy_dir = policy_dir or config.POLICY_DIR
    conn.execute("DELETE FROM chunks")
    n = 0
    for path in sorted(policy_dir.glob("*.md")):
        for c in parse_policy(path):
            conn.execute(
                "INSERT INTO chunks(id, doc_id, doc_title, clause_id, heading, text, clearance, regulator, version) VALUES (?,?,?,?,?,?,?,?,?)",
                (c["id"], c["doc_id"], c["doc_title"], c["clause_id"], c["heading"], c["text"], c["clearance"], c["regulator"], c["version"]),
            )
            n += 1
    conn.commit()
    return n
