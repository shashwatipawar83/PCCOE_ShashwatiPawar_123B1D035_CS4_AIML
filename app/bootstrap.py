from __future__ import annotations
import os
import secrets

from .services import Services


def bootstrap_demo(svc: Services, admin_pw=None, user_pw=None):
    """Create demo roles + register and index the sample repository. Returns credentials."""
    admin_pw = admin_pw or os.getenv("SCR_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    user_pw = user_pw or os.getenv("SCR_DEMO_PASSWORD") or secrets.token_urlsafe(12)
    svc.create_user("admin", admin_pw, "admin")
    svc.create_user("alice", user_pw, "developer")   # developer: whole repo except calib/
    svc.create_user("bob", user_pw, "reviewer")      # reviewer: whole repo
    svc.register_repo("ecu_demo", "ecu_demo")
    svc.grant("alice", "ecu_demo", "", "allow")
    svc.grant("alice", "ecu_demo", "src/calib", "deny")
    svc.grant("bob", "ecu_demo", "", "allow")
    n = svc.index_repo("ecu_demo")
    svc.db.audit("system", "bootstrap", {"indexed_chunks": n})
    return {"admin": admin_pw, "alice": user_pw, "bob": user_pw}
