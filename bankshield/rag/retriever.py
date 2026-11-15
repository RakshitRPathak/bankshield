"""Hybrid retriever: BM25 (lexical) + vector (semantic), fused by weighted min-max scores.

Clearance is applied FIRST: scores are normalised and the relevance gate is computed over the
chunks the caller may see, and nothing else. (Gating on the whole corpus would let a junior
analyst learn that a restricted clause matches their question from the fact that the system
answered at all.) A search returns its own SearchResult — nothing about a query is stored on
the shared index, so concurrent requests cannot read each other's gate.

Three independent relevance signals feed the gate:
  cosine    raw TF-IDF cosine of the best visible chunk
  bm25      raw BM25 score of the best visible chunk
  coverage  idf-weighted share of the question's content words found in the retrieved
            evidence — "write me a poem about clouds" hits `cloud` but covers ~1/3 of itself
"""

from __future__ import annotations

import re
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from rank_bm25 import BM25Okapi

from .. import config
from .embeddings import TfidfEmbedder, get_embedder

_TOKEN = re.compile(r"[a-z0-9][a-z0-9.\-]*")
_CLAUSE_REF = re.compile(r"\b([A-Z]{2,4}(?:-[A-Z]{2,4})?-\d+(?:\.\d+)?)\b")

# Words that carry no topic: never counted for or against coverage.
_STOP = set("""a an and are as at be been being but by can could did do does doing for from had has have having how i if in into is
it its just may me might must my no not of on or our out over shall should so than that the their them then there these they this
those to too under up us was we were what when where which who whom why will with would you your about above after again all also
am any because before between both each few more most other own same some such only very s t now right currently please tell show
list give me say says said explain summarise summarize describe need needs needed required require requires allowed permitted
many much long often there's what's it's get got like want know happen happens acceptable okay ok""".split())
try:  # the standard English stop list (someone, anyone, nobody, whenever, …) when scikit-learn is present
    from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS as _SK_STOP
    _STOP |= set(_SK_STOP) - {"system", "bill", "fire", "detail", "interest", "found", "move", "side", "top", "front", "back", "call", "amount", "cry", "mill", "sincere", "thick", "thin", "fill", "describe", "full", "empty", "serious", "keep", "name", "part", "put", "show", "take", "give", "go", "see", "made", "find", "done"} | {"show", "give", "describe"}
except Exception:  # pragma: no cover
    pass


def _stem(t: str) -> str:
    """Small suffix stemmer, applied identically to corpus and query: buckets→bucket,
    policies→policy, exporting/exported→export, logging→log, rotate/rotating→rotat."""
    if len(t) < 4 or any(ch.isdigit() for ch in t):
        return t
    if t.endswith("ies") and len(t) > 4:
        t = t[:-3] + "y"
    elif t.endswith("s") and not t.endswith(("ss", "us", "is")):
        t = t[:-1]
    for suf in ("ing", "ed"):
        if t.endswith(suf) and len(t) - len(suf) >= 3:
            t = t[:-len(suf)]
            if len(t) > 3 and t[-1] == t[-2] and t[-1] not in "ls":   # logg→log, but install stays
                t = t[:-1]
            break
    if t.endswith("ly") and len(t) > 5:
        t = t[:-2]
    if t.endswith("e") and len(t) > 4:
        t = t[:-1]
    return t


_EXPAND = {
    "mfa": ["multi", "factor", "authentication"], "2fa": ["multi", "factor", "authentication"],
    "cmek": ["customer", "managed", "encryption", "key"], "sa": ["service", "account"],
    "vm": ["compute", "instance"], "vms": ["compute", "instance"], "gcs": ["bucket", "storage"],
    "bq": ["bigquery", "dataset"], "sql": ["database"], "k8s": ["kubernetes", "gke"],
    "pii": ["restricted", "customer", "data"], "ssh": ["22"], "rdp": ["3389"],
    "vpc-sc": ["vpc", "service", "control", "perimeter"], "dr": ["disaster", "recovery"],
    "db": ["database"], "dbs": ["database"], "creds": ["credential"], "prod": ["production"],
    "admin": ["administrative"], "admins": ["administrative"], "encrypted": ["encryption"], "encrypt": ["encryption"],
    "rotated": ["rotate"], "rotation": ["rotate"], "logins": ["authentication", "login"], "login": ["authentication"],
    "overseas": ["outside", "india"], "abroad": ["outside", "india"], "offshore": ["outside", "india"],
    "internet": ["0.0.0.0", "public"], "exposed": ["public"], "localisation": ["residency", "india"],
    "localization": ["residency", "india"], "residency": ["region", "india"], "sovereignty": ["residency"],
    "hacked": ["compromised"], "breach": ["incident", "compromise"], "leak": ["leaked"], "stolen": ["leaked", "compromised"],
    "firewall": ["firewall", "port"], "kubernetes": ["gke"], "passwords": ["secret", "credential"], "password": ["secret", "credential"],
}


def _tok(s: str) -> list[str]:
    out = []
    for t in _TOKEN.findall(s.lower()):
        t = t.rstrip(".-")
        if not t:
            continue
        out.append(_stem(t))
        out.extend(_stem(e) for e in _EXPAND.get(t, ()))
    return out


def _content_terms(s: str) -> list[tuple[str, list[str]]]:
    """(stemmed term, its expansions) for each content word of a question."""
    out, seen = [], set()
    for t in _TOKEN.findall(s.lower()):
        t = t.rstrip(".-")
        st = _stem(t)
        if not t or t in _STOP or st in _STOP or st in seen:
            continue
        seen.add(st)
        out.append((st, [_stem(e) for e in _EXPAND.get(t, ())]))
    return out


def _doc_text(c: dict[str, Any]) -> str:
    # Heading repeated so the clause title carries extra weight (auditors ask by title).
    return f"{c.get('heading', '')}. {c.get('heading', '')}. {c['text']}"


@dataclass
class Hit:
    chunk: dict[str, Any]
    score: float
    bm25: float
    vector: float


@dataclass
class SearchResult:
    hits: list[Hit] = field(default_factory=list)
    bm25_max: float = 0.0
    cosine_max: float = 0.0
    coverage: float = 0.0
    exact_refs: list[str] = field(default_factory=list)

    def relevant(self, min_cosine: float | None = None, min_bm25: float | None = None, min_coverage: float | None = None) -> bool:
        """Absolute-relevance gate (min-max fusion always has a '1.0', so it can't be used)."""
        if not self.hits:
            return False
        if self.exact_refs:
            return True
        min_cosine = config.MIN_RETRIEVAL_SCORE if min_cosine is None else min_cosine
        min_bm25 = config.MIN_BM25 if min_bm25 is None else min_bm25
        min_coverage = config.MIN_COVERAGE if min_coverage is None else min_coverage
        if self.bm25_max >= config.STRONG_BM25 and self.cosine_max >= config.STRONG_COSINE and self.coverage >= min_coverage / 2:
            return True
        return (self.cosine_max >= min_cosine or self.bm25_max >= min_bm25) and self.coverage >= min_coverage


class HybridIndex:
    def __init__(self, chunks: list[dict[str, Any]]):
        self.chunks = chunks
        self.tokens = [_tok(_doc_text(c)) for c in chunks]
        self.token_sets = [set(t) for t in self.tokens]
        self.bm25 = BM25Okapi(self.tokens)
        joined = [" ".join(t) for t in self.tokens]
        self.lexical = TfidfEmbedder()                      # always present: drives the relevance gate
        self.lex_matrix = self.lexical.fit(joined)
        self.embedder = get_embedder()                      # ranking channel; may be dense
        self.matrix = self.lex_matrix if isinstance(self.embedder, TfidfEmbedder) else self.embedder.fit(joined)
        if isinstance(self.embedder, TfidfEmbedder):
            self.embedder = self.lexical
        self.levels = np.array([config.CLEARANCE.get(c["clearance"], 1) for c in chunks])
        self.by_clause = {c["clause_id"]: c for c in chunks}
        self._max_idf = max(self.bm25.idf.values()) if self.bm25.idf else 1.0
        self._local = threading.local()

    # -- backwards-compatible gate for callers that used index.search() then index.relevant()
    def relevant(self, min_cosine: float = None, min_bm25: float = None) -> bool:
        res = getattr(self._local, "last", None)
        return bool(res and res.relevant(min_cosine, min_bm25))

    def search(self, query: str, k: int = None, alpha: float = None, max_clearance: int = 1,
               exact_boost: float = 0.35) -> list[Hit]:
        res = self.search_ex(query, k=k, alpha=alpha, max_clearance=max_clearance, exact_boost=exact_boost)
        self._local.last = res
        return res.hits

    def visible(self, clause_id: str, max_clearance: int) -> dict[str, Any] | None:
        c = self.by_clause.get(clause_id)
        return c if c and config.CLEARANCE.get(c["clearance"], 1) <= max_clearance else None

    def search_ex(self, query: str, k: int = None, alpha: float = None, max_clearance: int = 1,
                  exact_boost: float = 0.35) -> SearchResult:
        k = k or config.TOP_K
        alpha = config.HYBRID_ALPHA if alpha is None else alpha
        vis = np.flatnonzero(self.levels <= max_clearance)   # clearance filter happens BEFORE anything is scored
        if len(vis) == 0:
            return SearchResult()
        q_toks = _tok(query)
        q_text = " ".join(q_toks)
        b = np.asarray(self.bm25.get_scores(q_toks), dtype=float)[vis]
        lex = (self.lex_matrix[vis] @ self.lexical.encode([q_text])[0]).astype(float)
        v = lex if self.embedder is self.lexical else (self.matrix[vis] @ self.embedder.encode([q_text])[0]).astype(float)
        fused = alpha * _minmax(v) + (1 - alpha) * _minmax(b)
        b_n, v_n = _minmax(b), _minmax(v)
        # Exact clause references in the question are a strong signal (auditors ask "what does CSP-4.1 say").
        refs = [r for r in dict.fromkeys(_CLAUSE_REF.findall(query))]
        exact = []
        for ref in refs:
            for pos, i in enumerate(vis):
                if self.chunks[i]["clause_id"] == ref:
                    fused[pos] += exact_boost + 1.0
                    exact.append(ref)
        hits: list[Hit] = []
        for pos in np.argsort(-fused, kind="stable"):
            if fused[pos] <= 0:
                break
            i = vis[pos]
            hits.append(Hit(chunk=self.chunks[i], score=float(min(fused[pos], 1.0 + exact_boost)), bm25=float(b_n[pos]), vector=float(v_n[pos])))
            if len(hits) >= k:
                break
        return SearchResult(hits=hits, bm25_max=float(b.max()), cosine_max=float(lex.max()),
                            coverage=self._coverage(query, hits), exact_refs=exact)

    def _coverage(self, query: str, hits: list[Hit]) -> float:
        terms = _content_terms(query)
        if not terms or not hits:
            return 0.0
        idx = {id(h.chunk): n for n, h in enumerate(hits)}
        pool: set[str] = set()
        for n, c in enumerate(self.chunks):
            if id(c) in idx:
                pool |= self.token_sets[n]
        got = total = 0.0
        for term, expansions in terms:
            w = self.bm25.idf.get(term)
            if w is None or w <= 0:
                w = max((self.bm25.idf.get(e, 0.0) for e in expansions), default=0.0) or self._max_idf
            total += w
            if term in pool or (expansions and all(e in pool for e in expansions)):
                got += w
        return round(got / total, 3) if total else 0.0


def _minmax(x: np.ndarray) -> np.ndarray:
    if len(x) == 0:
        return x
    lo, hi = float(x.min()), float(x.max())
    if hi - lo < 1e-9:
        return np.zeros_like(x)
    return (x - lo) / (hi - lo)


_CACHE: dict[str, HybridIndex] = {}
_CACHE_LOCK = threading.Lock()


def get_index(conn: sqlite3.Connection, refresh: bool = False) -> HybridIndex:
    key = f"{config.DB_PATH}|{config.EMBEDDING_BACKEND}"
    with _CACHE_LOCK:
        if refresh or key not in _CACHE:
            chunks = [dict(r) for r in conn.execute("SELECT * FROM chunks ORDER BY id")]
            if not chunks:
                raise RuntimeError("no policy chunks ingested — run scripts/seed.py")
            _CACHE[key] = HybridIndex(chunks)
        return _CACHE[key]


def invalidate() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
