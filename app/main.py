from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .models import ProviderResolveRequest, ProviderResolveResponse, ProviderInfo
from .services import resolve_provider
from .config import get_settings  # your existing config.py

# --- Optional dependency: PyJWT ---
try:
    import jwt  # PyJWT
except Exception as e:  # pragma: no cover
    jwt = None
    _jwt_import_error = e

# --- Redis (async) ---
try:
    import redis.asyncio as redis  # type: ignore
except Exception as e:  # pragma: no cover
    redis = None
    _redis_import_error = e


# ----------------------------
# Env / toggles
# ----------------------------
def _env() -> str:
    return (os.getenv("ENV", "prod") or "prod").strip().lower()


def _is_dev() -> bool:
    return _env() in {"dev", "development", "local"}


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
    secret = (os.getenv("STEGTV_JWT_SECRET", "") or "").strip()
    if not secret:
        raise HTTPException(status_code=500, detail="Missing env var STEGTV_JWT_SECRET.")
    if len(secret) < 16:
        raise HTTPException(status_code=500, detail="STEGTV_JWT_SECRET too short (min 16 chars recommended).")
    return secret


def _admin_token() -> str:
    # You set STEGTV_ADMIN_TOKEN on Render — good. Keep ADMIN_TOKEN as fallback.
    tok = (os.getenv("STEGTV_ADMIN_TOKEN") or os.getenv("ADMIN_TOKEN") or "").strip()
    if not tok:
        raise HTTPException(status_code=500, detail="Missing env var STEGTV_ADMIN_TOKEN (or ADMIN_TOKEN).")
    return tok


def _jwt_leeway_seconds() -> int:
    # Sliding-window grace for exp checks (internal flows). Keep small.
    try:
        v = int(os.getenv("JWT_LEEWAY_SECONDS", "10"))
    except Exception:
        v = 10
    return max(0, min(v, 60))


def _redis_url() -> str:
    # Render Redis typically provides REDIS_URL or you can set it manually.
    # Use whichever you prefer; we accept either.
    return (os.getenv("REDIS_URL") or os.getenv("STEGTV_REDIS_URL") or "").strip()


def _now() -> int:
    return int(time.time())


def _clamp_ttl(ttl_seconds: int) -> int:
    # Ephemeral means minutes, not hours.
    if ttl_seconds <= 0:
        return 120
    return max(10, min(ttl_seconds, 300))


# ----------------------------
# Redis helpers (revocation + rate limit)
# ----------------------------
_R: Optional["redis.Redis"] = None  # lazy singleton


async def _get_redis() -> "redis.Redis":
    global _R
    if redis is None:
        raise HTTPException(
            status_code=500,
            detail=f"redis package not installed. Add `redis` to requirements.txt. Import error: {_redis_import_error}",
        )

    url = _redis_url()
    if not url:
        raise HTTPException(status_code=500, detail="Missing REDIS_URL (or STEGTV_REDIS_URL).")

    if _R is None:
        _R = redis.from_url(url, decode_responses=True)
    return _R


async def _get_rev_epoch(r: "redis.Redis") -> int:
    key = "stegtvc:rev_epoch"
    val = await r.get(key)
    if val is None:
        # initialize safely
        await r.set(key, "0", nx=True)
        return 0
    try:
        return int(val)
    except Exception:
        # if corrupted, reset to 0 (safe default)
        await r.set(key, "0")
        return 0


async def _bump_rev_epoch(r: "redis.Redis") -> int:
    key = "stegtvc:rev_epoch"
    # Atomic increment
    new_val = await r.incr(key)
    return int(new_val)


async def _rate_limit_or_429(
    request: Request,
    r: "redis.Redis",
    *,
    bucket: str,
    limit: int,
    window_seconds: int,
) -> None:
    """
    Redis-backed fixed window limiter:
      key = steg:rl:{bucket}:{client_ip}:{window_start}
    """
    # Determine client ip (Render/Cloudflare: x-forwarded-for typically present)
    xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    client_ip = xff or (request.client.host if request.client else "unknown")

    now = _now()
    window_start = now - (now % window_seconds)
    key = f"stegtvc:rl:{bucket}:{client_ip}:{window_start}"

    # INCR + EXPIRE is a standard pattern; small race on expire is acceptable.
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, window_seconds)

    if count > limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")


# ----------------------------
# Admin auth dependency (X-Admin-Token)
# ----------------------------
async def require_admin(x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token")) -> None:
    tok = _admin_token()
    if not x_admin_token or x_admin_token.strip() != tok:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ----------------------------
# Models
# ----------------------------
class TokenIssueRequest(BaseModel):
    sub: str = Field(..., description="Subject identifier (user/workload).")
    action: str = Field(..., description="Machine-readable action name, e.g. 'deploy'.")
    scope: str = Field(..., description="Resource scope, e.g. 'repo:StegVerse-Labs/TVC'.")
    ttl_seconds: int = Field(120, description="Token TTL seconds (clamped 10..300).")
    ctx_hash: Optional[str] = Field(None, description="Optional context hash binding.")
    bundle_hash: Optional[str] = Field(None, description="Optional policy bundle hash/digest.")
    mode: str = Field("assisted", description="manual|assisted|autonomous|degraded|frozen")
    extra: Optional[Dict[str, Any]] = Field(None, description="Optional extra claims dict (namespaced).")


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


# ----------------------------
# FastAPI app (docs off in prod)
# ----------------------------
_docs_url = "/docs" if _is_dev() else None
_redoc_url = "/redoc" if _is_dev() else None
_openapi_url = "/openapi.json" if _is_dev() else None

app = FastAPI(
    title="StegTVC Core",
    description="StegVerse Token Vault Config / AI Provider Router (Core v0.1.x).",
    version=get_settings().version,
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
)

# Add APIKey security scheme so Swagger “Authorize” sets X-Admin-Token
if _is_dev():
    from fastapi.openapi.utils import get_openapi

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["AdminToken"] = {
            "type": "apiKey",
            "in": "header",
            "name": "X-Admin-Token",
        }
        # Apply globally to admin-tagged ops only (we’ll set per-route below)
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi  # type: ignore


# ----------------------------
# Routes
# ----------------------------
@app.get("/health", summary="Basic health check")
async def health() -> JSONResponse:
    settings = get_settings()
    payload: Dict[str, Any] = {
        "status": "ok",
        "env": _env(),
        "service": (os.getenv("APP_NAME") or settings.name or "stegtvc").lower(),
        "version": settings.version,
    }

    # In dev only, show richer info (never leak this in prod)
    if _is_dev():
        try:
            r = await _get_redis()
            rev = await _get_rev_epoch(r)
            payload["security"] = {
                "docs_enabled": True,
                "admin_header": "X-Admin-Token",
                "token_ttl_max_seconds": 300,
                "revocation_epoch": rev,
                "jwt_signing": "HS256 (env: STEGTV_JWT_SECRET)",
                "jwt_leeway_seconds": _jwt_leeway_seconds(),
                "redis": "configured",
            }
        except Exception as e:
            payload["security"] = {
                "docs_enabled": True,
                "redis": f"error: {e}",
            }

    return JSONResponse(payload)


@app.post(
    "/providers/resolve",
    response_model=ProviderResolveResponse,
    summary="Resolve which provider/model/config to use for a given use-case.",
)
async def providers_resolve(body: ProviderResolveRequest) -> ProviderResolveResponse:
    return resolve_provider(body)


@app.get(
    "/providers/default",
    response_model=ProviderInfo,
    summary="Return the currently configured default provider/model.",
)
async def providers_default() -> ProviderInfo:
    settings = get_settings()
    base = settings.default_provider  # dict in your config.py
    return ProviderInfo(
        name=base.get("name", ""),
        model=base.get("model", ""),
        endpoint=base.get("endpoint", ""),
        notes=base.get("notes"),
    )


# ----------------------------
# Admin-protected token endpoints
# ----------------------------
@app.post(
    "/tokens/issue",
    response_model=TokenIssueResponse,
    summary="Issue an ephemeral, action-scoped StegVerse token.",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
async def tokens_issue(request: Request, body: TokenIssueRequest) -> TokenIssueResponse:
    _require_jwt()
    secret = _jwt_secret()

    r = await _get_redis()
    await _rate_limit_or_429(request, r, bucket="tokens_issue", limit=30, window_seconds=60)

    ttl = _clamp_ttl(body.ttl_seconds)
    iat = _now()
    exp = iat + ttl
    jti = str(uuid.uuid4())

    rev_epoch = await _get_rev_epoch(r)

    claims: Dict[str, Any] = {
        "iss": "stegverse:tvc",
        "sub": body.sub,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "act": body.action,
        "scope": body.scope,
        "mode": body.mode,
        "rev": rev_epoch,
    }

    if body.ctx_hash:
        claims["ctxh"] = body.ctx_hash
    if body.bundle_hash:
        claims["bnd"] = body.bundle_hash
    if body.extra:
        claims["x"] = body.extra

    token = jwt.encode(claims, secret, algorithm="HS256")
    return TokenIssueResponse(token=token, exp=exp, jti=jti, rev=rev_epoch)


@app.post(
    "/tokens/verify",
    response_model=TokenVerifyResponse,
    summary="Verify a StegVerse token and return claims.",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
async def tokens_verify(request: Request, body: TokenVerifyRequest) -> TokenVerifyResponse:
    _require_jwt()
    secret = _jwt_secret()

    r = await _get_redis()
    await _rate_limit_or_429(request, r, bucket="tokens_verify", limit=120, window_seconds=60)

    leeway = _jwt_leeway_seconds()

    try:
        claims = jwt.decode(body.token, secret, algorithms=["HS256"], leeway=leeway)
    except Exception as e:
        return TokenVerifyResponse(valid=False, claims=None, reason=f"decode_failed: {e}")

    try:
        token_rev = int(claims.get("rev", -1))
    except Exception:
        token_rev = -1

    current_rev = await _get_rev_epoch(r)
    if token_rev != current_rev:
        return TokenVerifyResponse(
            valid=False,
            claims=claims,
            reason=f"revoked: token_rev={token_rev} current_rev={current_rev}",
        )

    return TokenVerifyResponse(valid=True, claims=claims, reason=None)


@app.post(
    "/tokens/revoke",
    response_model=TokenRevokeResponse,
    summary="Revoke all previously issued tokens (bump epoch).",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)
async def tokens_revoke(request: Request) -> TokenRevokeResponse:
    r = await _get_redis()
    await _rate_limit_or_429(request, r, bucket="tokens_revoke", limit=10, window_seconds=60)

    new_rev = await _bump_rev_epoch(r)
    return TokenRevokeResponse(rev=new_rev)
