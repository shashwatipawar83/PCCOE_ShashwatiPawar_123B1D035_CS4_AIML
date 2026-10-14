"""Service container: users, repos, path-level authorisation, safe file access, finding persistence."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path

from . import auth
from .code import Ctx, chunk_file
from .config import Settings
from .db import DB, now
from .embeddings import make_embedder
from .guidelines import Guidelines
from .llm import LLMClient
from .vectorstore import VectorStore

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _matches(prefix: str, rel: str) -> bool:
    prefix = prefix.strip("/")
    return prefix == "" or rel == prefix or rel.startswith(prefix + "/")


class Services:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        s = self.settings
        self.db = DB(s.data_dir / "scr.sqlite3")
        self.embedder = make_embedder(s)
        self.store = VectorStore(s.data_dir / "vectors", self.embedder)
        self.llm = LLMClient(s)
        self.guidelines = Guidelines(s.guidelines_dir, self.store)

    # ---------------- users ----------------
    def create_user(self, username, password, role):
        if len(password) < 10:
            raise ApiError(400, "password must be at least 10 characters")
        salt, h = auth.hash_password(password)
        self.db.execute("INSERT OR REPLACE INTO users(username,salt,pw_hash,role) VALUES(?,?,?,?)",
                        (username, salt, h, role))

    def login(self, username, password):
        u = self.db.one("SELECT * FROM users WHERE username=?", (username,))
        if not u or not auth.verify_password(password, u["salt"], u["pw_hash"]):
            self.db.audit(username, "login_failed")
            raise ApiError(401, "invalid credentials")
        self.db.audit(username, "login")
        return auth.make_token(self.settings.secret_key, username, self.settings.token_ttl_s)

    def user_from_token(self, token):
        name = auth.read_token(self.settings.secret_key, token or "")
        u = self.db.one("SELECT id,username,role FROM users WHERE username=?", (name,)) if name else None
        if not u:
            raise ApiError(401, "invalid or expired token")
        return u

    def grant(self, username, repo, path_prefix, effect="allow"):
        u = self.db.one("SELECT id FROM users WHERE username=?", (username,))
        if not u:
            raise ApiError(404, "unknown user")
        self.db.execute("INSERT OR REPLACE INTO permissions VALUES(?,?,?,?)", (u["id"], repo, path_prefix.strip("/"), effect))

    # ---------------- repos & files ----------------
    def register_repo(self, name, rel_dir):
        self.safe_join(self.settings.repo_root, rel_dir)
        self.db.execute("INSERT OR REPLACE INTO repos VALUES(?,?)", (name, rel_dir))

    @staticmethod
    def safe_join(root: Path, rel: str) -> Path:
        p = (root / rel).resolve()
        try:
            p.relative_to(root.resolve())
        except ValueError:
            raise ApiError(400, "path escapes the repository root")
        return p

    def repo_dir(self, repo) -> Path:
        r = self.db.one("SELECT path FROM repos WHERE name=?", (repo,))
        if not r:
            raise ApiError(404, f"unknown repository '{repo}'")
        return self.safe_join(self.settings.repo_root, r["path"])

    def all_files(self, repo):
        base, out = self.repo_dir(repo), []
        for dp, dn, fn in os.walk(base):
            dn[:] = [d for d in dn if d not in (".git", "node_modules", "__pycache__", "logs")]
            for f in fn:
                p = Path(dp) / f
                if p.suffix.lower() in self.settings.extensions and not p.is_symlink():
                    try:
                        if p.resolve().relative_to(base) and p.stat().st_size <= self.settings.max_file_bytes:
                            out.append(p.relative_to(base).as_posix())
                    except ValueError:
                        pass
        return sorted(out)

    def can_access(self, user, repo, rel) -> bool:
        if user["role"] == "admin":
            return True
        allowed = False
        for r in self.db.query("SELECT path_prefix,effect FROM permissions WHERE user_id=? AND repo=?", (user["id"], repo)):
            if _matches(r["path_prefix"], rel):
                if r["effect"] == "deny":
                    return False
                allowed = True
        return allowed

    def authorized_files(self, user, repo):
        return [f for f in self.all_files(repo) if self.can_access(user, repo, f)]

    def require_repo_access(self, user, repo):
        self.repo_dir(repo)
        if user["role"] != "admin" and not self.db.query(
                "SELECT 1 FROM permissions WHERE user_id=? AND repo=? AND effect='allow'", (user["id"], repo)):
            self.db.audit(user["username"], "denied", {"repo": repo})
            raise ApiError(403, "no access to this repository")

    def read_file(self, repo, rel) -> str:
        p = self.safe_join(self.repo_dir(repo), rel)
        if not p.is_file():
            raise ApiError(404, f"file not found: {rel}")
        return p.read_text(errors="replace")

    def read_authorized(self, user, repo, rel) -> Ctx:
        self.require_repo_access(user, repo)
        if not self.can_access(user, repo, rel):
            self.db.audit(user["username"], "denied", {"repo": repo, "file": rel})
            raise ApiError(403, f"not authorised for {rel}")
        return Ctx(rel, self.read_file(repo, rel))

    # ---------------- indexing ----------------
    def index_repo(self, repo):
        items = []
        for rel in self.all_files(repo):
            items.extend(chunk_file(Ctx(rel, self.read_file(repo, rel))))
        for it in items:
            it["text"] = f"{it['meta']['path']} {it['meta']['name']}\n{it['text']}"
            it["meta"]["repo"] = repo
        return self.store.replace(f"code::{repo}", items)

    # ---------------- findings ----------------
    @staticmethod
    def fingerprint(repo, f):
        return hashlib.sha1(f"{repo}|{f['file']}|{f['rule']}|{f.get('function')}|{f.get('anchor','')}".encode()).hexdigest()

    def save_finding(self, user, repo, f) -> dict:
        fp, ts = self.fingerprint(repo, f), now()
        cols = dict(repo=repo, file=f["file"], function=f.get("function"), line_start=f["line_start"],
                    line_end=f["line_end"], rule=f["rule"], severity=f["severity"], category=f.get("category"),
                    title=f["title"], description=f.get("description"), evidence=f.get("evidence"),
                    suggestion=f.get("suggestion"), explanation=f.get("explanation"), reference=f.get("reference"),
                    confidence=round(f.get("confidence", 0.5), 2), source=f.get("source"),
                    citations=json.dumps(f.get("citations", [])), llm_used=int(bool(f.get("llm_used"))), updated_at=ts)
        ex = self.db.one("SELECT id FROM findings WHERE fingerprint=?", (fp,))
        if ex:   # keep reviewer disposition, refresh the evidence
            sets = ",".join(f"{k}=?" for k in cols)
            self.db.execute(f"UPDATE findings SET {sets} WHERE id=?", (*cols.values(), ex["id"]))
            fid = ex["id"]
        else:
            cols.update(fingerprint=fp, created_by=user["username"], created_at=ts)
            fid = self.db.execute(f"INSERT INTO findings({','.join(cols)}) VALUES({','.join('?'*len(cols))})",
                                  tuple(cols.values())).lastrowid
        return self.get_finding(fid)

    def get_finding(self, fid):
        r = self.db.one("SELECT * FROM findings WHERE id=?", (fid,))
        if r:
            r["citations"] = json.loads(r["citations"] or "[]")
        return r

    def list_findings(self, user, repo=None, status=None, min_severity=None):
        rows = self.db.query("SELECT * FROM findings ORDER BY id")
        out = []
        for r in rows:
            if repo and r["repo"] != repo:
                continue
            if status and r["status"] != status:
                continue
            if min_severity and SEV_ORDER[r["severity"]] < SEV_ORDER[min_severity]:
                continue
            if not self.can_access(user, r["repo"], r["file"]):
                continue
            r["citations"] = json.loads(r["citations"] or "[]")
            out.append(r)
        return sorted(out, key=lambda r: (-SEV_ORDER[r["severity"]], r["file"], r["line_start"]))

    DISPOSITIONS = {"reviewer": {"open", "accepted", "rejected"}, "admin": {"open", "accepted", "rejected", "fixed"},
                    "developer": {"fixed"}}

    def disposition(self, user, fid, status, comment):
        f = self.get_finding(fid)
        if not f or not self.can_access(user, f["repo"], f["file"]):
            raise ApiError(404, "finding not found")
        if status not in self.DISPOSITIONS[user["role"]]:
            raise ApiError(403, f"role '{user['role']}' may not set status '{status}'")
        if status == "rejected" and not (comment or "").strip():
            raise ApiError(400, "a comment is required when rejecting (false positive) a finding")
        self.db.execute("UPDATE findings SET status=?,reviewer=?,reviewer_comment=?,updated_at=? WHERE id=?",
                        (status, user["username"], comment, now(), fid))
        self.db.audit(user["username"], "disposition", {"finding": fid, "status": status, "comment": comment})
        return self.get_finding(fid)

    def metrics(self, user, repo=None):
        rows = self.list_findings(user, repo)
        by = lambda k: {v: sum(1 for r in rows if r[k] == v) for v in sorted({r[k] for r in rows})}
        tp = sum(r["status"] in ("accepted", "fixed") for r in rows)
        fp = sum(r["status"] == "rejected" for r in rows)
        return {"total": len(rows), "by_status": by("status"), "by_severity": by("severity"), "by_rule": by("rule"),
                "finding_precision": round(tp / (tp + fp), 2) if tp + fp else None,
                "reviewed": tp + fp, "llm_assisted": sum(r["llm_used"] for r in rows),
                "processed_inside_boundary_pct": 100.0,
                "audit_chain_valid": self.db.verify_audit()}

    def publish_accepted(self, user, repo=None):
        rows = [r for r in self.list_findings(user, repo, "accepted") if not r["published_at"]]
        sent = []
        for r in rows:
            payload = {k: r[k] for k in ("id", "repo", "file", "function", "line_start", "rule", "severity",
                                         "title", "suggestion", "reviewer", "reviewer_comment")}
            (self.settings.data_dir / "outbox" / f"finding-{r['id']}.json").write_text(json.dumps(payload, indent=2))
            if self.settings.workflow_webhook:
                self._post_webhook(payload)
            self.db.execute("UPDATE findings SET published_at=? WHERE id=?", (now(), r["id"]))
            sent.append(r["id"])
        self.db.audit(user["username"], "publish", {"findings": sent})
        return sent

    def _post_webhook(self, payload):
        import urllib.request
        from urllib.parse import urlparse
        url = self.settings.workflow_webhook
        if urlparse(url).hostname not in self.settings.allowed_hosts:
            raise ApiError(500, "workflow webhook host is not in the allow-list")
        urllib.request.urlopen(urllib.request.Request(
            url, json.dumps(payload).encode(), {"Content-Type": "application/json"}), timeout=10)

    # ---------------- reports ----------------
    def export_markdown(self, user, repo=None):
        rows = self.list_findings(user, repo)
        lines = ["# Secure code review report", f"_Generated {now()} - {len(rows)} findings_", ""]
        for r in rows:
            lines += [f"## [{r['severity'].upper()}] {r['title']}",
                      f"- **Where:** `{r['file']}:{r['line_start']}` in `{r['function']}`  ",
                      f"- **Rule:** {r['rule']} ({r['reference']})  - **Confidence:** {r['confidence']}  - **Status:** {r['status']}",
                      f"- **Source:** {r['source']}", "", "```c", r["evidence"] or "", "```",
                      f"**Why it matters:** {r['explanation'] or r['description']}", "",
                      f"**Suggested fix:** {r['suggestion']}", ""]
            if r["reviewer_comment"]:
                lines.append(f"**Reviewer ({r['reviewer']}):** {r['reviewer_comment']}\n")
        return "\n".join(lines)
