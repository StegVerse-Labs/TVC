from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import get_settings, get_default_provider
from .models import ProviderResolveRequest, ProviderResolveResponse, ProviderInfo
from .services import resolve_provider

# --- Optional dependency: PyJWT ---
try:
    import jwt  # PyJWT
except Exception as e:  # pragma: no cover
    jwt = None
    _jwt_import_error = e

# --- Optional dependency: Redis (async) ---
try:
    import redis.asyncio as redis_async
except Exception:
    redis_async = None


# ------------------------
# Helpers / Settings
# ------------------------
def _now() -> int:
    return int(time.time())


def _clamp_ttl(ttl_seconds: int) -> int:
    # Ephemeral means minutes.
    if ttl_seconds <= 0:
        return 120
    return max(10, min(ttl_seconds, 300))


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
        raise HTTPException(status_code=500, detail="Missing env var STEGTV_JWT_SECRET.")
    if len(secret) < 16:
        raise HTTPException(status_code=500, detail="STEGTV_JWT_SECRET too short (min 16 chars).")
    return secret


def _admin_token() -> str:
    # Prefer STEGTV_ADMIN_TOKEN, allow legacy ADMIN_TOKEN fallback.
    tok = (os.getenv("STEGTV_ADMIN_TOKEN") or os.getenv("ADMIN_TOKEN") or "").strip()
    if not tok:
        raise HTTPException(status_code=500, detail="Missing env var STEGTV_ADMIN_TOKEN (or ADMIN_TOKEN).")
    return tok


def _env() -> str:
    # Your config.py uses ENV already; keep consistent.
    return (os.getenv("ENV") or "production").strip().lower()


def _docs_enabled() -> bool:
    # Only enable docs in dev-like envs.
    return _env() in ("dev", "development", "local")


def _public_url() -> str:
    return (os.getenv("PUBLIC_URL") or os.getenv("STEGTV_PUBLIC_URL") or "").strip()


def _redis_url() -> str:
    return (os.getenv("REDIS_URL") or "").strip()


def _verify_grace_seconds() -> int:
    # Sliding window for internal flows (admin-only).
    raw = (os.getenv("STEGTV_VERIFY_GRACE_SECONDS") or "30").strip()
    try:
        v = int(raw)
    except Exception:
        v = 30
    return max(0, min(v, 300))


# ------------------------
# Redis wiring (optional)
# ------------------------
_redis: Optional["redis_async.Redis"] = None


async def _get_redis() -> Optional["redis_async.Redis"]:
    global _redis
    if _redis is not None:
        return _redis

    url = _redis_url()
    if not url:
        return None
    if redis_async is None:
        # redis lib not installed; just act like redis is absent.
        return None

    # decode_responses=True returns strings instead of bytes
    _redis = redis_async.from_url(url, decode_responses=True)
    return _redis


async def _get_rev_epoch() -> int:
    r = await _get_redis()
    if r is None:
        return int(os.getenv("STEGTV_REV_EPOCH", "0") or 0)

    try:
        v = await r.get("tvc:rev_epoch")
        if v is None:
            await r.set("tvc:rev_epoch", "0")
            return 0
        return int(v)
    except Exception:
        # If redis is flaky, fall back to process env epoch.
        return int(os.getenv("STEGTV_REV_EPOCH", "0") or 0)


async def _bump_rev_epoch() -> int:
    r = await _get_redis()
    if r is None:
        # Process-local fallback (not shared across instances).
        cur = int(os.getenv("STEGTV_REV_EPOCH", "0") or 0) + 1
        os.environ["STEGTV_REV_EPOCH"] = str(cur)
        return cur

    try:
        v = await r.incr("tvc:rev_epoch")
        return int(v)
    except Exception:
        cur = int(os.getenv("STEGTV_REV_EPOCH", "0") or 0) + 1
        os.environ["STEGTV_REV_EPOCH"] = str(cur)
        return cur


# ------------------------
# Auth dependency
# ------------------------
async def require_admin(x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token")) -> None:
    expected = _admin_token()
    presented = (x_admin_token or "").strip()
    if not presented or presented != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ------------------------
# Models
# ------------------------
class TokenIssueRequest(BaseModel):
    sub: str = Field(..., description="Subject identifier (user/workload).")
    action: str = Field(..., description="Action name, e.g. 'deploy', 'write_repo'.")
    scope: str = Field(..., description="Resource scope, e.g. 'repo:StegVerse-Labs/TVC'.")
    ttl_seconds: int = Field(120, description="Token TTL seconds (clamped 10..300).")
    ctx_hash: Optional[str] = Field(None, description="Optional context hash (bind token to request context).")
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


# ------------------------
# App init (docs toggle)
# ------------------------
settings = get_settings()

app = FastAPI(
    title="StegTVC Core",
    description="StegVerse Token Vault Config / AI Provider Router (Core v1.0, option C).",
    version=settings.version,
    docs_url="/docs" if _docs_enabled() else None,
    redoc_url="/redoc" if _docs_enabled() else None,
    openapi_url="/openapi.json" if _docs_enabled() else None,
)


# ------------------------
# Routes
# ------------------------
@app.get("/", summary="Root (avoid Render HEAD / 404 noise)")
async def root() -> Dict[str, Any]:
    return {"status": "ok", "service": "stegtvc", "env": _env(), "version": settings.version}


@app.get("/health", summary="Basic health check")
async def health() -> Dict[str, Any]:
    provider = get_default_provider()

    # Redis status should never crash health.
    redis_ok = False
    redis_configured = bool(_redis_url())
    if redis_configured:
        r = await _get_redis()
        if r is not None:
            try:
                pong = await r.ping()
                redis_ok = bool(pong)
            except Exception:
                redis_ok = False

    payload = {
        "status": "ok",
        "env": _env(),
        "service": "stegtvc",
        "version": settings.version,
        "public_url": _public_url() or settings.default_provider.get("endpoint", ""),
        "default_provider": {
            "name": provider.get("name"),
            "model": provider.get("model"),
            "endpoint": provider.get("endpoint"),
        },
        "security": {
            "admin_header": "X-Admin-Token",
            "docs_enabled": _docs_enabled(),
            "token_ttl_max_seconds": 300,
            "revocation_epoch": await _get_rev_epoch(),
            "jwt_signing": "HS256 (env: STEGTV_JWT_SECRET)",
            "verify_grace_seconds": _verify_grace_seconds(),
        },
        "redis": {
            "configured": redis_configured,
            "ok": redis_ok,
        },
    }
    return payload


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
    base = get_default_provider()
    return ProviderInfo(
        name=base["name"],
        model=base["model"],
        endpoint=base.get("endpoint"),
        notes=base.get("notes"),
    )


# ------------------------
# Ephemeral tokens (admin protected)
# ------------------------
@app.post(
    "/tokens/issue",
    response_model=TokenIssueResponse,
    summary="Issue an ephemeral, action-scoped StegVerse token.",
    dependencies=[Depends(require_admin)],
)
async def tokens_issue(body: TokenIssueRequest) -> TokenIssueResponse:
    _require_jwt()
    secret = _jwt_secret()

    ttl = _clamp_ttl(body.ttl_seconds)
    iat = _now()
    exp = iat + ttl
    jti = str(uuid.uuid4())
    rev = await _get_rev_epoch()

    claims: Dict[str, Any] = {
        "iss": "stegverse:tvc",
        "sub": body.sub,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "act": body.action,
        "scope": body.scope,
        "mode": body.mode,
        "rev": rev,
    }
    if body.ctx_hash:
        claims["ctxh"] = body.ctx_hash
    if body.bundle_hash:
        claims["bnd"] = body.bundle_hash
    if body.extra:
        claims["x"] = body.extra

    token = jwt.encode(claims, secret, algorithm="HS256")
    return TokenIssueResponse(token=token, exp=exp, jti=jti, rev=rev)


@app.post(
    "/tokens/verify",
    response_model=TokenVerifyResponse,
    summary="Verify a StegVerse token and return claims.",
    dependencies=[Depends(require_admin)],
)
async def tokens_verify(body: TokenVerifyRequest) -> TokenVerifyResponse:
    _require_jwt()
    secret = _jwt_secret()

    # Normal verify path
    try:
        claims = jwt.decode(body.token, secret, algorithms=["HS256"])
    except Exception as e:
        # Sliding-window path: allow slight expiry for internal flows (admin-only).
        grace = _verify_grace_seconds()
        if grace > 0:
            try:
                claims2 = jwt.decode(
                    body.token,
                    secret,
                    algorithms=["HS256"],
                    options={"verify_exp": False},
                )
                exp = int(claims2.get("exp", 0) or 0)
                if exp and _now() <= exp + grace:
                    # Still must satisfy revocation epoch.
                    cur_rev = await _get_rev_epoch()
                    tok_rev = int(claims2.get("rev", -1))
                    if tok_rev != cur_rev:
                        return TokenVerifyResponse(
                            valid=False,
                            claims=claims2,
                            reason=f"revoked: token_rev={tok_rev} current_rev={cur_rev}",
                        )
                    return TokenVerifyResponse(
                        valid=True,
                        claims=claims2,
                        reason=f"expired_but_within_grace:{grace}s",
                    )
            except Exception:
                pass

        return TokenVerifyResponse(valid=False, claims=None, reason=f"decode_failed: {e}")

    # Revocation check
    cur_rev = await _get_rev_epoch()
    tok_rev = int(claims.get("rev", -1))
    if tok_rev != cur_rev:
        return TokenVerifyResponse(
            valid=False,
            claims=claims,
            reason=f"revoked: token_rev={tok_rev} current_rev={cur_rev}",
        )

    return TokenVerifyResponse(valid=True, claims=claims, reason=None)


@app.post(
    "/tokens/revoke",
    response_model=TokenRevokeResponse,
    summary="Revoke all previously issued tokens (bump epoch).",
    dependencies=[Depends(require_admin)],
)
async def tokens_revoke() -> TokenRevokeResponse:
    new_rev = await _bump_rev_epoch()
    return TokenRevokeResponse(rev=new_rev)
