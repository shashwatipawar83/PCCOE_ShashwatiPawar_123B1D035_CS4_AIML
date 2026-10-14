from __future__ import annotations
from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from .config import Settings
from .engine import Engine
from .services import ApiError, Services


class LoginIn(BaseModel):
    username: str
    password: str

class UserIn(BaseModel):
    username: str
    password: str
    role: str = "developer"

class RepoIn(BaseModel):
    name: str
    path: str

class PermIn(BaseModel):
    username: str
    repo: str
    path_prefix: str = ""
    effect: str = "allow"

class ReviewIn(BaseModel):
    repo: str
    paths: list[str] | None = None
    build_log: str | None = None
    cppcheck_xml: str | None = None
    use_llm: bool = True

class AskIn(BaseModel):
    repo: str
    question: str
    use_llm: bool = True

class DebugIn(BaseModel):
    repo: str
    log: str
    use_llm: bool = True

class SummIn(BaseModel):
    repo: str
    path: str
    function: str | None = None
    use_llm: bool = True

class DispIn(BaseModel):
    status: str
    comment: str | None = None


def create_app(settings: Settings | None = None) -> FastAPI:
    svc = Services(settings)
    eng = Engine(svc)
    app = FastAPI(title="Secure Code Debugging & Review Assistant", version="1.0")
    app.state.svc, app.state.engine = svc, eng

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, e: ApiError):
        return JSONResponse({"detail": e.message}, status_code=e.status)

    def current_user(authorization: str = Header(default="")):
        return svc.user_from_token(authorization.removeprefix("Bearer ").strip())

    def admin(user=Depends(current_user)):
        if user["role"] != "admin":
            raise ApiError(403, "admin only")
        return user

    @app.get("/health")
    def health():
        return {"status": "ok", "llm_backend": svc.llm.backend, "embedder": svc.embedder.name}

    @app.post("/auth/login")
    def login(b: LoginIn):
        return {"access_token": svc.login(b.username, b.password), "token_type": "bearer"}

    @app.get("/me")
    def me(user=Depends(current_user)):
        return user

    # ---- administration
    @app.post("/admin/users")
    def add_user(b: UserIn, user=Depends(admin)):
        if b.role not in ("admin", "reviewer", "developer"):
            raise ApiError(400, "invalid role")
        svc.create_user(b.username, b.password, b.role)
        svc.db.audit(user["username"], "create_user", {"user": b.username, "role": b.role})
        return {"ok": True}

    @app.post("/admin/repos")
    def add_repo(b: RepoIn, user=Depends(admin)):
        svc.register_repo(b.name, b.path)
        svc.db.audit(user["username"], "register_repo", b.model_dump() if hasattr(b, "model_dump") else b.dict())
        return {"ok": True}

    @app.post("/admin/permissions")
    def add_perm(b: PermIn, user=Depends(admin)):
        if b.effect not in ("allow", "deny"):
            raise ApiError(400, "effect must be allow|deny")
        svc.grant(b.username, b.repo, b.path_prefix, b.effect)
        svc.db.audit(user["username"], "grant", {"to": b.username, "repo": b.repo, "prefix": b.path_prefix, "effect": b.effect})
        return {"ok": True}

    @app.post("/admin/repos/{repo}/index")
    def index(repo: str, user=Depends(admin)):
        n = svc.index_repo(repo)
        svc.db.audit(user["username"], "index", {"repo": repo, "chunks": n})
        return {"repo": repo, "chunks": n}

    @app.get("/admin/audit")
    def audit(limit: int = 100, user=Depends(admin)):
        return {"chain_valid": svc.db.verify_audit(),
                "entries": svc.db.query("SELECT id,ts,user,action,detail FROM audit ORDER BY id DESC LIMIT ?", (limit,))}

    # ---- repos / analysis
    @app.get("/repos")
    def repos(user=Depends(current_user)):
        out = []
        for r in svc.db.query("SELECT name FROM repos ORDER BY name"):
            files = svc.authorized_files(user, r["name"])
            if files:
                out.append({"name": r["name"], "files": files})
        return out

    @app.post("/review")
    def review(b: ReviewIn, user=Depends(current_user)):
        return eng.review(user, b.repo, b.paths, b.build_log, b.cppcheck_xml, b.use_llm)

    @app.post("/ask")
    def ask(b: AskIn, user=Depends(current_user)):
        return eng.ask(user, b.repo, b.question, use_llm=b.use_llm)

    @app.post("/summarize")
    def summarize(b: SummIn, user=Depends(current_user)):
        return eng.summarize(user, b.repo, b.path, b.function, b.use_llm)

    @app.post("/debug")
    def debug(b: DebugIn, user=Depends(current_user)):
        return eng.debug(user, b.repo, b.log, b.use_llm)

    # ---- findings workflow
    @app.get("/findings")
    def findings(repo: str | None = None, status: str | None = None, min_severity: str | None = None,
                 user=Depends(current_user)):
        return svc.list_findings(user, repo, status, min_severity)

    @app.patch("/findings/{fid}")
    def dispose(fid: int, b: DispIn, user=Depends(current_user)):
        return svc.disposition(user, fid, b.status, b.comment)

    @app.post("/findings/publish")
    def publish(repo: str | None = None, user=Depends(current_user)):
        if user["role"] not in ("reviewer", "admin"):
            raise ApiError(403, "reviewer/admin only")
        return {"published": svc.publish_accepted(user, repo)}

    @app.get("/findings/export", response_class=PlainTextResponse)
    def export(repo: str | None = None, user=Depends(current_user)):
        return svc.export_markdown(user, repo)

    @app.get("/metrics")
    def metrics(repo: str | None = None, user=Depends(current_user)):
        return svc.metrics(user, repo)

    return app


def app_factory() -> FastAPI:   # uvicorn app.main:app_factory --factory
    return create_app()
