from __future__ import annotations
import math
import re
import zlib
from collections import Counter

import numpy as np


def _tokens(text: str):
    out = []
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text):
        low = ident.lower()
        parts = [p.lower() for p in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", ident)]
        if len(low) > 2:
            out.append(low)
        out.extend(p for p in parts if len(p) > 1)
        out.extend(f"{a}_{b}" for a, b in zip(parts, parts[1:]))
    return out


class HashingEmbedder:
    """Dependency-free, fully offline embedder (signed feature hashing over identifier sub-words).
    Good enough for code/identifier retrieval; swap for BGE/E5 via SCR_EMBED_BACKEND=st."""
    name = "hash-768"

    def __init__(self, dim: int = 768):
        self.dim = dim

    def _vec(self, text: str):
        v = np.zeros(self.dim, dtype=np.float32)
        for tok, tf in Counter(_tokens(text)).items():
            h = zlib.crc32(tok.encode())
            v[h % self.dim] += (1 if zlib.crc32(tok.encode() + b"#") & 1 else -1) * (1 + math.log(tf))
        n = np.linalg.norm(v)
        return v / n if n else v

    def embed_docs(self, texts):
        return np.vstack([self._vec(t) for t in texts]) if texts else np.zeros((0, self.dim), np.float32)

    def embed_query(self, text):
        return self._vec(text)


class SentenceTransformerEmbedder:
    """BGE / E5 / any sentence-transformers model. Point `model` at a LOCAL directory so nothing is downloaded."""

    def __init__(self, model: str):
        from sentence_transformers import SentenceTransformer  # lazy import
        self.model = SentenceTransformer(model)
        self.name = f"st:{model}"

    def embed_docs(self, texts):
        return np.asarray(self.model.encode(texts, normalize_embeddings=True), dtype=np.float32)

    def embed_query(self, text):
        q = "Represent this sentence for searching relevant passages: " + text
        return np.asarray(self.model.encode([q], normalize_embeddings=True)[0], dtype=np.float32)


def make_embedder(settings):
    if settings.embed_backend == "st":
        return SentenceTransformerEmbedder(settings.embed_model)
    return HashingEmbedder()
