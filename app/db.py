from __future__ import annotations
import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
  salt TEXT NOT NULL, pw_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','reviewer','developer')));
CREATE TABLE IF NOT EXISTS repos(name TEXT PRIMARY KEY, path TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS permissions(
  user_id INTEGER NOT NULL, repo TEXT NOT NULL, path_prefix TEXT NOT NULL,
  effect TEXT NOT NULL CHECK(effect IN ('allow','deny')),
  PRIMARY KEY(user_id, repo, path_prefix));
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT UNIQUE NOT NULL,
  repo TEXT NOT NULL, file TEXT NOT NULL, function TEXT, line_start INTEGER, line_end INTEGER,
  rule TEXT NOT NULL, severity TEXT NOT NULL, category TEXT, title TEXT NOT NULL,
  description TEXT, evidence TEXT, suggestion TEXT, explanation TEXT, reference TEXT,
  confidence REAL, source TEXT, citations TEXT, llm_used INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open', reviewer TEXT, reviewer_comment TEXT,
  created_by TEXT, created_at TEXT, updated_at TEXT, published_at TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, user TEXT, action TEXT NOT NULL,
  detail TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DB:
    def __init__(self, path):
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def execute(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def query(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # --- tamper-evident audit log (hash chain) ---------------------------------
    @staticmethod
    def _h(prev, ts, user, action, detail):
        return hashlib.sha256(f"{prev}|{ts}|{user}|{action}|{detail}".encode()).hexdigest()

    def audit(self, user, action, detail=None):
        detail = detail if isinstance(detail, str) else json.dumps(detail or {}, default=str, sort_keys=True)
        with self.lock:
            last = self.conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else "0" * 64
            ts = now()
            self.conn.execute(
                "INSERT INTO audit(ts,user,action,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)",
                (ts, user, action, detail, prev, self._h(prev, ts, user, action, detail)))
            self.conn.commit()

    def verify_audit(self) -> bool:
        prev = "0" * 64
        for r in self.query("SELECT * FROM audit ORDER BY id"):
            if r["prev_hash"] != prev or r["hash"] != self._h(prev, r["ts"], r["user"], r["action"], r["detail"]):
                return False
            prev = r["hash"]
        return True
