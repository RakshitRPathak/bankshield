"""Signed bearer tokens (HS256 JWT, standard library only).

The demo console uses the `X-User` header (BANKSHIELD_AUTH=header). Setting
BANKSHIELD_AUTH=token makes every API call require `Authorization: Bearer <jwt>` signed with
BANKSHIELD_SECRET. In production the same Principal is built from an IAP / OIDC assertion
instead; nothing downstream changes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from . import config


class AuthError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key() -> bytes:
    if len(config.SECRET_KEY) < 16:
        raise AuthError("BANKSHIELD_SECRET must be set (>=16 chars) to issue or verify tokens")
    return config.SECRET_KEY.encode()


def issue_token(user: str, ttl_s: int | None = None, now: float | None = None) -> str:
    if user not in config.USERS:
        raise AuthError(f"unknown user {user!r}")
    now = time.time() if now is None else now
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"sub": user, "iat": int(now), "exp": int(now + (ttl_s or config.TOKEN_TTL_S)), "iss": "bankshield"}
    body = _b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_key(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def verify_token(token: str, now: float | None = None) -> str:
    """Return the subject if the token is authentic and unexpired, else raise AuthError."""
    try:
        header, body, sig = token.split(".")
        head = json.loads(_unb64(header))
    except Exception as e:
        raise AuthError("malformed token") from e
    if head.get("alg") != "HS256":           # never trust the header to pick the algorithm ("alg: none")
        raise AuthError("unsupported algorithm")
    expected = _b64(hmac.new(_key(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, sig):
        raise AuthError("bad signature")
    try:
        claims = json.loads(_unb64(body))
    except Exception as e:
        raise AuthError("malformed claims") from e
    if claims.get("iss") != "bankshield" or float(claims.get("exp", 0)) < (time.time() if now is None else now):
        raise AuthError("token expired or wrong issuer")
    sub = claims.get("sub")
    if sub not in config.USERS:
        raise AuthError("unknown subject")
    return sub
