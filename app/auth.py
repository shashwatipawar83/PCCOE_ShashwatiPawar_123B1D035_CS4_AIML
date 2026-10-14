from __future__ import annotations
import base64
import hashlib
import hmac
import json
import secrets
import time

ITER = 200_000


def hash_password(password: str, salt: str | None = None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITER).hex()
    return salt, h


def verify_password(password: str, salt: str, expected: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt)[1], expected)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_token(secret: str, username: str, ttl_s: int) -> str:
    payload = _b64(json.dumps({"u": username, "exp": int(time.time()) + ttl_s}).encode())
    sig = _b64(hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def read_token(secret: str, token: str) -> str | None:
    try:
        payload, sig = token.split(".", 1)
        good = _b64(hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return data["u"] if data["exp"] > time.time() else None
    except Exception:
        return None
