# app/main.py
from __future__ import annotations

import hmac
import os
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import get_default_provider, get_settings
from .models import ProviderInfo, ProviderResolveRequest, ProviderResolveResponse
from .services import resolve_provider

# --- Optional dependency: PyJWT ---
try:
    import jwt  # PyJWT
except Exception as e:  # pragma: no cover
    jwt = None
    _jwt_import_error = e


# ---------------------------
# Settings access (robust)
# ---------------------------
def _settings_get(key: str, default: Any = None) -> Any:
    """
    get_settings() might return a pydantic object OR (in some states) a dict.
    This accessor avoids AttributeError footguns.
    """
    s = get_settings()
    if isinstance(s, dict):
        return s.get(key, default)
    return getattr(s, key, default)


# ---------------------------
# Admin gate (critical hardening)
# ---------------------------
def _admin_token() -> str:
    # Prefer TVC-specific token; fall back to shared ADMIN_TOKEN if you want unified ops.
    tok = (os.getenv("STEGTV_ADMIN_TOKEN") or os.getenv("ADMIN_TOKEN") or "").strip()
    if not tok:
        # Fail closed in prod if not configured.
        raise HTTPException(status_code=500, detail="Missing STEGTV_ADMIN_TOKEN (or ADMIN_TOKEN).")
    return tok


def require_admin(x_admin_token: str = Header(default="", alias="X-Admin-Token")) -> None:
    expected = _admin_token()
    provided = (x_admin_token or "").strip()
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


def _public_resolve_enabled() -> bool:
    return os.getenv("STEGTV_PUBLIC_RESOLVE", "").strip().lower() in {"1", "true", "yes"}


def require_admin_unless_public_resolve(request: Request) -> None:
    """
    Protect /providers/resolve by default.
    If STEGTV_PUBLIC_RESOLVE=1, it becomes public.
    """
    if _public_resolve_enabled():
        return
    # Enforce admin if not public
    x_admin = request.headers.get("X-Admin-Token", "")
    expected = _admin_token()
    if not x_admin or not hmac.compare_digest(x_admin.strip(), expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


# ---------------------------
# Lightweight in-memory rate limiting
# ---------------------------
_RATE_BUCKET: Dict[str, tuple[int, int]] = {}  # ip -> (window_start_epoch, count)


def rate_limit(max_per_minute: int = 60):
    def _dep(request: Request) -> None:
        # Best-effort IP detection. (Behind proxies, you may want X-Forwarded-For parsing later.)
        ip = request.client.host if request.client else "unknown"
        now = int(time.time())
        window = now - (now % 60)

        ws, cnt = _RATE_BUCKET.get(ip, (window, 0))
        if ws != window:
            ws, cnt = window, 0

        cnt += 1
        _RATE_BUCKET[ip] = (ws, cnt)

        if cnt > max_per_minute:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return _dep


# ---------------------------
# JWT helpers
# ---------------------------
def _require_jwt() -> None:
    if jwt is None:
        raise HTTPException(
            status_code=500,
            detail=(
                "PyJWT is not installed. Add `PyJWT==2.10.1` to requirements.txt. "
                f"Import error: {_jwt_import_error}"
            ),
        )


def _jwt_secret() -> str:
    secret = os.getenv("STEGTV_JWT_SECRET", "").strip()
    if not secret:
        raise HTTPException(status_code=500, detail="Missing env var STEGTV_JWT_SECRET (required for /tokens/*).")
    if len(secret) < 16:
        raise HTTPException(status_code=500, detail="STEGTV_JWT_SECRET is too short (min 16 chars recommended).")
    return secret


def _jwt_issuer() -> str:
    return "stegverse:tvc"


def _jwt_audience() -> str:
    # You can change this later (e.g. "stegverse:scw") but keep it stable across consumers.
    return os.getenv("STEGTV_JWT_AUD", "stegverse:scw").strip() or "stegverse:scw"


# In-memory revocation epoch (v0.1). Bump it to invalidate all existing tokens.
# NOTE: For multi-instance deployments, move this to a shared store (Redis/db) later.
_REV_EPOCH: int = 0


def _now() -> int:
    return int(time.time())


def _clamp_ttl(ttl_seconds: int) -> int:
    # Ephemeral means minutes, not hours.
    if ttl_seconds <= 0:
        return 120
    return max(10, min(ttl_seconds, 300))


# ---------------------------
# Token models
# ---------------------------
class TokenIssueRequest(BaseModel):
    sub: str = Field(..., description="Subject identifier (user/workload).")
    action: str = Field(..., description="Machine-readable action name, e.g. 'deploy', 'write_repo'.")
    scope: str = Field(..., description="Resource scope, e.g. 'repo:StegVerse-Labs/TVC'.")
    ttl_seconds: int = Field(120, description="Token TTL seconds (clamped 10..300).")

    ctx_hash: Optional[str] = Field(None, description="Optional context hash (bind token to request payload/env).")
    bundle_hash: Optional[str] = Field(None, description="Optional policy bundle hash/digest (bind token to policy version).")

    mode: str = Field("assisted", description="manual|assisted|autonomous|degraded|frozen")
    extra: Optional[Dict[str, Any]] = Field(None, description="Optional extra claims dict (namespaced under x).")


class TokenIssueResponse(BaseModel):
    token: str
    exp: int
    jti: str
    rev: int


class TokenVerifyRequest(BaseModel):
    token: str


class TokenVerifyResponse(BaseModel):
    valid: bool
    claims: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


class TokenRevokeResponse(BaseModel):
    rev: int


# ---------------------------
# App init (optionally disable docs in prod)
# ---------------------------
ENV = (os.getenv("ENV") or os.getenv("STEGTV_ENV") or "prod").strip().lower()
_disable_docs = ENV in {"prod", "production"}

app = FastAPI(
    title="StegTVC Core",
    description="StegVerse Token Vault Config / AI Provider Router (Core v1.0, option C).",
    version=str(_settings_get("version", "0.1.0")),
    docs_url=None if _disable_docs else "/docs",
    redoc_url=None if _disable_docs else "/redoc",
    openapi_url=None if _disable_docs else "/openapi.json",
)


# ---------------------------
# Routes
# ---------------------------
@app.get("/health", summary="Basic health check")
async def health() -> JSONResponse:
    provider = get_default_provider()
    payload = {
        "status": "ok",
        "service": str(_settings_get("service_name", "stegtvc")),
        "version": str(_settings_get("version", "0.1.0")),
        "public_url": str(_settings_get("public_url", "")),
        # Intentionally omit provider endpoint in health to reduce intel leakage
        "default_provider": {
            "name": getattr(provider, "name", None),
            "model": getattr(provider, "model", None),
        },
        "ephemeral_security": {
            "token_ttl_max_seconds": 300,
            "revocation_epoch": _REV_EPOCH,
            # Intentionally omit algorithm/secret details from health
        },
    }
    return JSONResponse(payload)


@app.post(
    "/providers/resolve",
    response_model=ProviderResolveResponse,
    summary="Resolve which provider/model/config to use for a given use-case.",
    dependencies=[Depends(require_admin_unless_public_resolve), Depends(rate_limit(120))],
)
async def providers_resolve(body: ProviderResolveRequest) -> ProviderResolveResponse:
    return resolve_provider(body)


@app.get(
    "/providers/default",
    response_model=ProviderInfo,
    summary="Return the currently configured default provider/model.",
    dependencies=[Depends(require_admin), Depends(rate_limit(120))],
)
async def providers_default() -> ProviderInfo:
    base = get_default_provider()
    return ProviderInfo(
        name=base.name,
        model=base.model,
        endpoint=base.endpoint,
        notes=getattr(base, "notes", None),
    )


# ---------- Ephemeral tokens (ADMIN-GATED) ----------
@app.post(
    "/tokens/issue",
    response_model=TokenIssueResponse,
    summary="Issue an ephemeral, action-scoped StegVerse token.",
    dependencies=[Depends(require_admin), Depends(rate_limit(30))],
)
async def tokens_issue(body: TokenIssueRequest) -> TokenIssueResponse:
    _require_jwt()
    secret = _jwt_secret()

    ttl = _clamp_ttl(body.ttl_seconds)
    iat = _now()
    exp = iat + ttl
    jti = str(uuid.uuid4())

    claims: Dict[str, Any] = {
        "iss": _jwt_issuer(),
        "aud": _jwt_audience(),
        "sub": body.sub,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "act": body.action,
        "scope": body.scope,
        "mode": body.mode,
        "rev": _REV_EPOCH,
    }

    if body.ctx_hash:
        claims["ctxh"] = body.ctx_hash
    if body.bundle_hash:
        claims["bnd"] = body.bundle_hash
    if body.extra:
        claims["x"] = body.extra

    token = jwt.encode(claims, secret, algorithm="HS256")
    return TokenIssueResponse(token=token, exp=exp, jti=jti, rev=_REV_EPOCH)


@app.post(
    "/tokens/verify",
    response_model=TokenVerifyResponse,
    summary="Verify a StegVerse token and return claims.",
    dependencies=[Depends(require_admin), Depends(rate_limit(60))],
)
async def tokens_verify(body: TokenVerifyRequest) -> TokenVerifyResponse:
    _require_jwt()
    secret = _jwt_secret()

    try:
        claims = jwt.decode(
            body.token,
            secret,
            algorithms=["HS256"],
            audience=_jwt_audience(),
            issuer=_jwt_issuer(),
            options={"require": ["exp", "iat", "iss", "aud", "jti"]},
            leeway=10,  # small clock skew tolerance
        )
    except Exception as e:
        return TokenVerifyResponse(valid=False, claims=None, reason=f"decode_failed: {e}")

    token_rev = int(claims.get("rev", -1))
    if token_rev != _REV_EPOCH:
        return TokenVerifyResponse(
            valid=False,
            claims=claims,
            reason=f"revoked: token_rev={token_rev} current_rev={_REV_EPOCH}",
        )

    return TokenVerifyResponse(valid=True, claims=claims, reason=None)


@app.post(
    "/tokens/revoke",
    response_model=TokenRevokeResponse,
    summary="Revoke all previously issued tokens (bump epoch).",
    dependencies=[Depends(require_admin), Depends(rate_limit(10))],
)
async def tokens_revoke() -> TokenRevokeResponse:
    global _REV_EPOCH
    _REV_EPOCH += 1
    return TokenRevokeResponse(rev=_REV_EPOCH)
