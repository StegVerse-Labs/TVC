from __future__ import annotations

import os
import time
import uuid
import hmac
import secrets
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
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


# -----------------------------
# Environment / hardening
# -----------------------------
def _env() -> str:
    # Render: add ENV=dev (temporary) to enable docs
    # Default to "prod" to be conservative.
    return (os.getenv("ENV", "prod") or "prod").strip().lower()


IS_DEV = _env() in {"dev", "development", "local", "staging", "test"}


def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    # get_settings() should return an object, but we defensively support dict too.
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


# -----------------------------
# Admin token auth (X-Admin-Token)
# -----------------------------
ADMIN_HEADER_NAME = "X-Admin-Token"
_admin_header = APIKeyHeader(name=ADMIN_HEADER_NAME, auto_error=False)


def _admin_secret() -> str:
    # You added STEGTV_ADMIN_TOKEN in Render env vars — this is where it's used.
    secret = (os.getenv("STEGTV_ADMIN_TOKEN", "") or "").strip()
    if not secret:
        raise HTTPException(
            status_code=500,
            detail="Missing env var STEGTV_ADMIN_TOKEN (required for admin-protected routes).",
        )
    if len(secret) < 24:
        # Not fatal, but strongly discouraged — keep it long and random.
        # You can remove this check if you prefer.
        raise HTTPException(
            status_code=500,
            detail="STEGTV_ADMIN_TOKEN is too short (recommend 24+ chars).",
        )
    return secret


def _require_admin(x_admin_token: Optional[str]) -> None:
    expected = _admin_secret()

    if not x_admin_token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    provided = x_admin_token.strip()

    # Constant-time comparison
    if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Unauthorized")


def require_admin(
    # This makes Swagger aware of the header and shows it in the UI flows.
    x_admin_token: Optional[str] = Depends(_admin_header),
) -> None:
    _require_admin(x_admin_token)


# -----------------------------
# JWT helpers
# -----------------------------
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
        raise HTTPException(
            status_code=500,
            detail="Missing env var STEGTV_JWT_SECRET (required for /tokens/*).",
        )
    if len(secret) < 32:
        raise HTTPException(
            status_code=500,
            detail="STEGTV_JWT_SECRET is too short (recommend 32+ chars).",
        )
    return secret


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


# ---------- Token models ----------
class TokenIssueRequest(BaseModel):
    sub: str = Field(..., description="Subject identifier (user/workload).")
    action: str = Field(..., description="Machine-readable action name, e.g. 'deploy', 'write_repo'.")
    scope: str = Field(..., description="Resource scope, e.g. 'repo:StegVerse-Labs/TVC'.")
    ttl_seconds: int = Field(120, description="Token TTL seconds (clamped 10..300).")

    ctx_hash: Optional[str] = Field(None, description="Optional context hash binding (recommended).")
    bundle_hash: Optional[str] = Field(None, description="Optional policy bundle hash/digest binding (recommended).")

    mode: str = Field("assisted", description="manual|assisted|autonomous|degraded|frozen")
    extra: Optional[Dict[str, Any]] = Field(None, description="Optional extra claims dict (discouraged).")


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


# -----------------------------
# FastAPI app with prod docs toggle
# -----------------------------
_settings = get_settings()

app = FastAPI(
    title="StegTVC Core",
    description="StegVerse Token Vault Config / AI Provider Router (Core v1.0, option C).",
    version=str(_safe_getattr(_settings, "version", "0.1.0")),
    docs_url="/docs" if IS_DEV else None,
    redoc_url="/redoc" if IS_DEV else None,
    openapi_url="/openapi.json" if IS_DEV else None,
)

# Expose an "Authorize" flow in Swagger for X-Admin-Token
# (Swagger UI will show a global auth control).
app.openapi_tags = [{"name": "admin", "description": "Admin-protected endpoints"}]
app.swagger_ui_init_oauth = {}  # harmless; keeps UI config explicit
app.openapi_schema = None  # let FastAPI build on demand


@app.get("/health", summary="Basic health check")
async def health() -> JSONResponse:
    settings = get_settings()
    provider = get_default_provider()

    payload = {
        "status": "ok",
        "env": _env(),
        "service": _safe_getattr(settings, "service_name", "tvc"),
        "version": _safe_getattr(settings, "version", "0.1.0"),
        "public_url": _safe_getattr(settings, "public_url", None),
        "default_provider": {
            "name": provider.name,
            "model": provider.model,
            "endpoint": provider.endpoint,
        },
        "security": {
            "admin_header": ADMIN_HEADER_NAME,
            "docs_enabled": bool(IS_DEV),
            "token_ttl_max_seconds": 300,
            "revocation_epoch": _REV_EPOCH,
            "jwt_signing": "HS256 (env: STEGTV_JWT_SECRET)",
        },
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
    base = get_default_provider()
    return ProviderInfo(
        name=base.name,
        model=base.model,
        endpoint=base.endpoint,
        notes=base.notes,
    )


# ---------- Ephemeral tokens (admin-protected) ----------
@app.post(
    "/tokens/issue",
    response_model=TokenIssueResponse,
    summary="Issue an ephemeral, action-scoped StegVerse token.",
    tags=["admin"],
)
async def tokens_issue(
    body: TokenIssueRequest,
    _admin: None = Depends(require_admin),
) -> TokenIssueResponse:
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
    tags=["admin"],
)
async def tokens_verify(
    body: TokenVerifyRequest,
    _admin: None = Depends(require_admin),
) -> TokenVerifyResponse:
    _require_jwt()
    secret = _jwt_secret()

    try:
        claims = jwt.decode(body.token, secret, algorithms=["HS256"])
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
    tags=["admin"],
)
async def tokens_revoke(
    _admin: None = Depends(require_admin),
) -> TokenRevokeResponse:
    global _REV_EPOCH
    _REV_EPOCH += 1
    return TokenRevokeResponse(rev=_REV_EPOCH)
