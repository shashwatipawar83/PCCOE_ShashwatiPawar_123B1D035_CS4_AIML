from __future__ import annotations
import re

from .analyzers.rules import CATALOGUE


class Guidelines:
    """Internal coding-standard knowledge: rule catalogue + organisation markdown files, indexed for RAG."""
    COLLECTION = "guidelines"

    def __init__(self, directory, store):
        self.dir, self.store, self.by_id = directory, store, {}
        self.reload()

    def reload(self):
        self.by_id = {r.id: {"id": r.id, "title": r.title, "text": f"{r.title}. {r.description} Remedy: {r.fix} ({r.ref})"}
                      for r in CATALOGUE.values()}
        if self.dir.exists():
            for f in sorted(self.dir.glob("*.md")):
                for sec in re.split(r"^## ", f.read_text(), flags=re.M)[1:]:
                    head, _, body = sec.partition("\n")
                    rid, _, title = head.strip().partition(" ")
                    self.by_id[rid] = {"id": rid, "title": title.strip(), "text": f"{title.strip()}. {body.strip()}",
                                       "source": f.name}
        self.store.replace(self.COLLECTION, [
            {"text": g["text"], "meta": {"id": g["id"], "title": g["title"]}} for g in self.by_id.values()])

    def lookup(self, rid):
        return self.by_id.get(rid)

    def related(self, query, exclude=None, k=2, min_score=0.2):
        hits = self.store.search(self.COLLECTION, query, k=k + 1)
        return [{"id": m["id"], "title": m["title"], "score": round(s, 2)} for s, m, _ in hits
                if m["id"] != exclude and s >= min_score][:k]
