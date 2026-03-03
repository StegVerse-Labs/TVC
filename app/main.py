from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, Optional, Tuple

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


# -------------------------
# Environment + app wiring
# -------------------------

def _env_name() -> str:
    # You are using ENV=dev / ENV=prod
    return (os.getenv("ENV", "") or os.getenv("APP_ENV", "") or "production").strip().lower()


ENV_NAME = _env_name()
DOCS_ENABLED = ENV_NAME in ("dev", "development", "local", "test")


def _safe_settings_value(obj: Any, *names: str, default: Any = None) -> Any:
    for n in names:
        if hasattr(obj, n):
            v = getattr(obj, n)
            if v is not None:
                return v
    return default


# -------------------------
# Minimal hardening helpers
# -------------------------

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
        raise HTTPException(
            status_code=500,
            detail="Missing env var STEGTV_JWT_SECRET (required for /tokens/*).",
        )
    if len(secret) < 16:
        raise HTTPException(
            status_code=500,
            detail="STEGTV_JWT_SECRET is too short (min 16 chars recommended).",
        )
    return secret


def _admin_token() -> str:
    # You set STEGTV_ADMIN_TOKEN in Render
    tok = os.getenv("STEGTV_ADMIN_TOKEN", "").strip()
    if not tok:
        raise HTTPException(
            status_code=500,
            detail="Missing env var STEGTV_ADMIN_TOKEN (required for admin endpoints).",
        )
    return tok


def _is_prod() -> bool:
    return ENV_NAME in ("prod", "production")


# -------------------------
# In-memory rate limiting
# -------------------------
# Simple fixed-window limiter per IP+route.
# Good enough to reduce random internet noise until Redis-based limiter arrives.

_RL_BUCKET: Dict[Tuple[str, str, int], int] = {}
_RL_WINDOW_SECONDS = int(os.getenv("STEGTV_RL_WINDOW_SECONDS", "60"))
_RL_MAX_PER_WINDOW = int(os.getenv("STEGTV_RL_MAX_PER_WINDOW", "60"))  # per IP per route per window


def _client_ip(request: Request) -> str:
    # Prefer Render/Cloudflare/Proxy header if present, fallback to client host.
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # first IP is original client
        return xff.split(",")[0].strip()
    xrip = request.headers.get("x-real-ip", "").strip()
    if xrip:
        return xrip
    return getattr(request.client, "host", "unknown")


def rate_limit(request: Request) -> None:
    ip = _client_ip(request)
    route = request.url.path
    now = int(time.time())
    window = now // max(1, _RL_WINDOW_SECONDS)
    key = (ip, route, window)
    _RL_BUCKET[key] = _RL_BUCKET.get(key, 0) + 1
    if _RL_BUCKET[key] > _RL_MAX_PER_WINDOW:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


# -------------------------
# Admin auth dependency
# -------------------------

def require_admin(x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token")) -> None:
    expected = _admin_token()
    if not x_admin_token or x_admin_token.strip() != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


# -------------------------
# Token controls
# -------------------------

# In-memory revocation epoch (v0.1). Bump it to invalidate all existing tokens.
# NOTE: For multi-instance deployments, move this to a shared store (Redis/db) later.
_REV_EPOCH: int = 0


def _now() -> int:
    return int(time.time())


def _clamp_ttl(ttl_seconds: int) -> int:
    # Keep this tight by default: ephemeral means minutes, not hours.
    if ttl_seconds <= 0:
        return 120
    return max(10, min(ttl_seconds, 300))


def _jwt_leeway_seconds() -> int:
    # Default small clock-skew leeway
    return max(0, min(int(os.getenv("STEGTV_JWT_LEEWAY_SECONDS", "5")), 60))


def _internal_leeway_seconds() -> int:
    # Sliding window for *internal flows* ONLY (admin gated) — bounded.
    return max(0, min(int(os.getenv("STEGTV_INTERNAL_LEEWAY_SECONDS", "30")), 120))


# ---------- Token models ----------
class TokenIssueRequest(BaseModel):
    sub: str = Field(..., description="Subject identifier (user/workload).")
    action: str = Field(..., description="Machine-readable action name, e.g. 'deploy', 'write_repo'.")
    scope: str = Field(..., description="Resource scope, e.g. 'repo:StegVerse-Labs/TVC'.")
    ttl_seconds: int = Field(120, description="Token TTL seconds (clamped 10..300).")

    ctx_hash: Optional[str] = Field(None, description="Optional context hash (bind token to request payload/environment).")
    bundle_hash: Optional[str] = Field(None, description="Optional policy bundle hash / digest (bind token to policy version).")

    mode: str = Field("assisted", description="manual|assisted|autonomous|degraded|frozen")
    extra: Optional[Dict[str, Any]] = Field(None, description="Optional extra claims dict.")


class TokenIssueResponse(BaseModel):
    token: str
    exp: int
    jti: str
    rev: int


class TokenVerifyRequest(BaseModel):
    token: str
    # Optional: request a bounded internal sliding-window verify (admin-gated).
    # If true, token can be accepted if it expired within INTERNAL_LEEWAY seconds.
    internal_window: bool = False


class TokenVerifyResponse(BaseModel):
    valid: bool
    claims: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


class TokenRevokeResponse(BaseModel):
    rev: int


# -------------------------
# FastAPI app
# -------------------------

settings = get_settings()
app_name = _safe_settings_value(settings, "service_name", "service", "name", default="stegtvc")
app_version = _safe_settings_value(settings, "version", default="0.1.0")

app = FastAPI(
    title="StegTVC Core",
    description="StegVerse Token Vault Config / AI Provider Router (Core v1.0, option C).",
    version=str(app_version),
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url="/redoc" if DOCS_ENABLED else None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
)


# -------------------------
# Endpoints
# -------------------------

@app.get("/health", summary="Basic health check")
async def health(request: Request) -> JSONResponse:
    # Light rate limiting even here (stops cheap floods)
    rate_limit(request)

    s = get_settings()
    env_val = _safe_settings_value(s, "env", default=ENV_NAME)

    base = {
        "status": "ok",
        "env": env_val if env_val else ENV_NAME,
        "service": _safe_settings_value(s, "service_name", "service", "name", default=app_name),
        "version": _safe_settings_value(s, "version", default=app_version),
    }

    # Only expose internals in dev/test
    if not _is_prod():
        try:
            provider = get_default_provider()
            # provider might be dict or object depending on your config implementation
            prov_name = provider.get("name") if isinstance(provider, dict) else getattr(provider, "name", None)
            prov_model = provider.get("model") if isinstance(provider, dict) else getattr(provider, "model", None)
            prov_ep = provider.get("endpoint") if isinstance(provider, dict) else getattr(provider, "endpoint", None)
        except Exception:
            prov_name = prov_model = prov_ep = None

        base.update(
            {
                "docs_enabled": DOCS_ENABLED,
                "security": {
                    "admin_header": "X-Admin-Token",
                    "revocation_epoch": _REV_EPOCH,
                    "token_ttl_max_seconds": 300,
                    "jwt_signing": "HS256",
                    "jwt_leeway_seconds": _jwt_leeway_seconds(),
                    "internal_window_seconds": _internal_leeway_seconds(),
                    "rate_limit": {
                        "window_seconds": _RL_WINDOW_SECONDS,
                        "max_per_window": _RL_MAX_PER_WINDOW,
                    },
                },
                "default_provider": {
                    "name": prov_name,
                    "model": prov_model,
                    "endpoint": prov_ep,
                },
            }
        )

    return JSONResponse(base)


@app.post(
    "/providers/resolve",
    response_model=ProviderResolveResponse,
    summary="Resolve which provider/model/config to use for a given use-case.",
)
async def providers_resolve(request: Request, body: ProviderResolveRequest) -> ProviderResolveResponse:
    rate_limit(request)
    return resolve_provider(body)


@app.get(
    "/providers/default",
    response_model=ProviderInfo,
    summary="Return the currently configured default provider/model.",
)
async def providers_default(request: Request) -> ProviderInfo:
    rate_limit(request)
    base = get_default_provider()
    if isinstance(base, dict):
        return ProviderInfo(
            name=base.get("name"),
            model=base.get("model"),
            endpoint=base.get("endpoint"),
            notes=base.get("notes"),
        )
    return ProviderInfo(
        name=getattr(base, "name", None),
        model=getattr(base, "model", None),
        endpoint=getattr(base, "endpoint", None),
        notes=getattr(base, "notes", None),
    )


# ---------- Ephemeral tokens (ADMIN PROTECTED) ----------
@app.post(
    "/tokens/issue",
    response_model=TokenIssueResponse,
    summary="Issue an ephemeral, action-scoped StegVerse token.",
    dependencies=[Depends(require_admin)],
)
async def tokens_issue(request: Request, body: TokenIssueRequest) -> TokenIssueResponse:
    rate_limit(request)
    _require_jwt()
    secret = _jwt_secret()

    ttl = _clamp_ttl(body.ttl_seconds)
    iat = _now()
    exp = iat + ttl
    jti = str(uuid.uuid4())

    claims: Dict[str, Any] = {
        "iss": "stegverse:tvc",
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
    dependencies=[Depends(require_admin)],
)
async def tokens_verify(request: Request, body: TokenVerifyRequest) -> TokenVerifyResponse:
    rate_limit(request)
    _require_jwt()
    secret = _jwt_secret()

    # Normal path: small leeway for clock skew
    leeway = _jwt_leeway_seconds()

    # Internal sliding-window path (bounded) — only if requested AND admin-auth already passed
    if body.internal_window:
        leeway = max(leeway, _internal_leeway_seconds())

    try:
        claims = jwt.decode(body.token, secret, algorithms=["HS256"], leeway=leeway)
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
    dependencies=[Depends(require_admin)],
)
async def tokens_revoke(request: Request) -> TokenRevokeResponse:
    rate_limit(request)
    global _REV_EPOCH
    _REV_EPOCH += 1
    return TokenRevokeResponse(rev=_REV_EPOCH)


# -------------------------
# Fallback root
# -------------------------
@app.get("/", include_in_schema=not _is_prod())
async def root(request: Request) -> JSONResponse:
    rate_limit(request)
    # Keep it boring in prod.
    if _is_prod():
        return JSONResponse({"status": "ok"})
    return JSONResponse({"status": "ok", "docs": "/docs" if DOCS_ENABLED else None})
