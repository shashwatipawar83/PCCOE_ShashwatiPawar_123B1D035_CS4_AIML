from __future__ import annotations
import json
import re
import threading
from pathlib import Path

import numpy as np


class VectorStore:
    """Persistent, per-collection cosine-similarity store (numpy). Same surface as FAISS/Chroma wrappers:
    replace() / search(). Authorization is applied as a *pre-filter* so unauthorised chunks can never be
    retrieved, ranked or sent to a model."""

    def __init__(self, directory: Path, embedder):
        self.dir, self.embedder = Path(directory), embedder
        self.dir.mkdir(parents=True, exist_ok=True)
        self._cache, self._lock = {}, threading.RLock()

    def _paths(self, name):
        safe = re.sub(r"[^\w.-]", "_", name)
        return self.dir / f"{safe}.npy", self.dir / f"{safe}.json"

    def replace(self, collection: str, items: list[dict]):
        vecs = self.embedder.embed_docs([i["text"] for i in items])
        npy, js = self._paths(collection)
        with self._lock:
            np.save(npy, vecs)
            js.write_text(json.dumps([{"text": i["text"], "meta": i["meta"]} for i in items]))
            self._cache[collection] = (vecs, [{"text": i["text"], "meta": i["meta"]} for i in items])
        return len(items)

    def _load(self, collection):
        with self._lock:
            if collection not in self._cache:
                npy, js = self._paths(collection)
                if not (npy.exists() and js.exists()):
                    return np.zeros((0, 1), np.float32), []
                self._cache[collection] = (np.load(npy), json.loads(js.read_text()))
            return self._cache[collection]

    def search(self, collection: str, query: str, k: int = 5, predicate=None):
        vecs, docs = self._load(collection)
        if not docs:
            return []
        idx = [i for i, d in enumerate(docs) if predicate is None or predicate(d["meta"])]
        if not idx:
            return []
        scores = vecs[idx] @ self.embedder.embed_query(query)
        order = np.argsort(-scores)[:k]
        return [(float(scores[o]), docs[idx[o]]["meta"], docs[idx[o]]["text"]) for o in order]

    def count(self, collection):
        return len(self._load(collection)[1])
