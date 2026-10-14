from __future__ import annotations
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    """All settings come from SCR_* environment variables unless passed explicitly."""
    data_dir: Path | None = None
    repo_root: Path | None = None
    guidelines_dir: Path | None = None
    secret_key: str | None = None
    token_ttl_s: int = 8 * 3600
    llm_backend: str | None = None        # offline | ollama | openai_compat
    llm_url: str | None = None
    llm_model: str | None = None
    llm_timeout_s: int = 120
    allowed_hosts: tuple | None = None    # hosts the LLM / webhook may live on
    embed_backend: str | None = None      # hash | st
    embed_model: str | None = None
    workflow_webhook: str | None = None
    max_file_bytes: int = 1_000_000
    max_llm_findings: int = 25
    extensions: tuple = (".c", ".h", ".cpp", ".hpp", ".cc", ".py")

    def __post_init__(self):
        e = os.getenv
        self.data_dir = Path(self.data_dir or e("SCR_DATA_DIR", BASE_DIR / "data")).resolve()
        self.repo_root = Path(self.repo_root or e("SCR_REPO_ROOT", BASE_DIR / "sample_repos")).resolve()
        self.guidelines_dir = Path(self.guidelines_dir or e("SCR_GUIDELINES_DIR", BASE_DIR / "guidelines")).resolve()
        self.llm_backend = self.llm_backend or e("SCR_LLM_BACKEND", "offline")
        self.llm_url = self.llm_url or e("SCR_LLM_URL", "http://127.0.0.1:11434")
        self.llm_model = self.llm_model or e("SCR_LLM_MODEL", "llama3.1:8b")
        hosts = e("SCR_ALLOWED_HOSTS", "127.0.0.1,localhost,ollama,llm")
        self.allowed_hosts = tuple(self.allowed_hosts or [h.strip() for h in hosts.split(",") if h.strip()])
        self.embed_backend = self.embed_backend or e("SCR_EMBED_BACKEND", "hash")
        self.embed_model = self.embed_model or e("SCR_EMBED_MODEL", "BAAI/bge-small-en-v1.5")
        self.workflow_webhook = self.workflow_webhook or e("SCR_WORKFLOW_WEBHOOK") or None
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "outbox").mkdir(exist_ok=True)
        if not self.secret_key:
            self.secret_key = e("SCR_SECRET_KEY") or self._persisted_secret()

    def _persisted_secret(self) -> str:
        f = self.data_dir / "secret.key"
        if not f.exists():
            f.write_text(secrets.token_hex(32))
            try:
                f.chmod(0o600)
            except OSError:
                pass
        return f.read_text().strip()
