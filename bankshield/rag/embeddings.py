"""Pluggable embeddings. All expose fit(texts) and encode(texts) -> ndarray with
L2-normalised rows, so cosine similarity is a dot product.

  tfidf                  offline, deterministic, lexical (default)
  lsa                    offline, deterministic, dense: TF-IDF projected onto latent topics
                         (truncated SVD) — matches paraphrases that share no exact term
  sentence-transformers  neural; needs a model download, falls back to tfidf if blocked
"""

from __future__ import annotations

import numpy as np

from .. import config


class TfidfEmbedder:
    name = "tfidf"

    def __init__(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english", min_df=1)
        self._fitted = False

    def fit(self, texts: list[str]) -> np.ndarray:
        X = self.vec.fit_transform(texts)
        self._fitted = True
        return _norm(X.toarray())

    def encode(self, texts: list[str]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("fit() first")
        return _norm(self.vec.transform(texts).toarray())


class LsaEmbedder:
    name = "lsa"

    def __init__(self, dims: int = 64) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english", min_df=1)
        self.dims = dims
        self.svd = None

    def fit(self, texts: list[str]) -> np.ndarray:
        from sklearn.decomposition import TruncatedSVD
        X = self.vec.fit_transform(texts)
        self.svd = TruncatedSVD(n_components=max(2, min(self.dims, X.shape[0] - 1, X.shape[1] - 1)), random_state=7)
        return _norm(self.svd.fit_transform(X))

    def encode(self, texts: list[str]) -> np.ndarray:
        if self.svd is None:
            raise RuntimeError("fit() first")
        return _norm(self.svd.transform(self.vec.transform(texts)))


class SentenceTransformerEmbedder:
    name = "sentence-transformers"

    def __init__(self, model: str | None = None) -> None:
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model or config.ST_MODEL)

    def fit(self, texts: list[str]) -> np.ndarray:
        return self.encode(texts)

    def encode(self, texts: list[str]) -> np.ndarray:
        return _norm(np.asarray(self.model.encode(texts, convert_to_numpy=True)))


def _norm(X: np.ndarray) -> np.ndarray:
    n = np.linalg.norm(X, axis=1, keepdims=True)
    n[n == 0] = 1.0
    return X / n


def get_embedder(backend: str | None = None):
    backend = backend or config.EMBEDDING_BACKEND
    if backend == "sentence-transformers":
        try:
            return SentenceTransformerEmbedder()
        except Exception:  # model download blocked, etc. — degrade gracefully
            pass
    if backend == "lsa":
        return LsaEmbedder()
    return TfidfEmbedder()
