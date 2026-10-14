"""Local-only LLM client. Backends: ollama, openai_compat (vLLM / llama.cpp server), offline (no model)."""
from __future__ import annotations
import json
import re
import urllib.request
from urllib.parse import urlparse


class LLMUnavailable(Exception):
    pass


class LLMClient:
    def __init__(self, settings):
        self.backend, self.url = settings.llm_backend, settings.llm_url.rstrip("/")
        self.model, self.timeout = settings.llm_model, settings.llm_timeout_s
        if self.backend != "offline":
            host = urlparse(self.url).hostname
            if host not in settings.allowed_hosts:   # control: no external transmission of source code
                raise ValueError(f"LLM host '{host}' is not in SCR_ALLOWED_HOSTS {settings.allowed_hosts}")

    @property
    def available(self) -> bool:
        return self.backend != "offline"

    def complete(self, system: str, user: str, max_tokens: int = 700) -> str:
        if not self.available:
            raise LLMUnavailable("offline mode")
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        try:
            if self.backend == "ollama":
                body = {"model": self.model, "messages": msgs, "stream": False,
                        "options": {"temperature": 0.1, "num_predict": max_tokens}}
                path, pick = "/api/chat", lambda r: r["message"]["content"]
            else:
                body = {"model": self.model, "messages": msgs, "temperature": 0.1, "max_tokens": max_tokens}
                path, pick = "/v1/chat/completions", lambda r: r["choices"][0]["message"]["content"]
            req = urllib.request.Request(self.url + path, json.dumps(body).encode(),
                                         {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return pick(json.loads(resp.read()))
        except Exception as e:  # network, timeout, schema
            raise LLMUnavailable(str(e)) from e

    def complete_json(self, system: str, user: str, keys: tuple, max_tokens: int = 700) -> dict:
        raw = self.complete(system, user, max_tokens)
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            raise LLMUnavailable("no JSON in model output")
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError as e:
            raise LLMUnavailable("invalid JSON") from e
        if not all(k in data and isinstance(data[k], str) for k in keys):
            raise LLMUnavailable("JSON missing required keys")
        return data
