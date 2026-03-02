from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
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


# ---------- Token models ----------
class TokenIssueRequest(BaseModel):
    # Who/what is requesting issuance (caller-supplied for now; later bind to mTLS/SPIFFE identity)
    sub: str = Field(..., description="Subject identifier (user/workload).")

    # Execution intent
    action: str = Field(..., description="Machine-readable action name, e.g. 'deploy', 'write_repo'.")
    scope: str = Field(..., description="Resource scope, e.g. 'repo:StegVerse-Labs/TVC'.")

    # Ephemeral controls
    ttl_seconds: int = Field(120, description="Token TTL seconds (clamped 10..300).")

    # Optional bindings (recommended)
    ctx_hash: Optional[str] = Field(
        None,
        description="Optional context hash (bind token to request payload/environment).",
    )
    bundle_hash: Optional[str] = Field(
        None,
        description="Optional policy bundle hash / digest (bind token to policy version).",
    )

    # Autonomy mode: keep simple for now
    mode: str = Field("assisted", description="manual|assisted|autonomous|degraded|frozen")

    # Optional extra claims (discouraged unless necessary)
    extra: Optional[Dict[str, Any]] = Field(None, description="Optional extra claims dict.")


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


# ---------- App ----------
app = FastAPI(
    title="StegTVC Core",
    description="StegVerse Token Vault Config / AI Provider Router (Core v1.0, option C).",
    version=get_settings().version,
)


@app.get("/health", summary="Basic health check")
async def health() -> JSONResponse:
    settings = get_settings()
    provider = get_default_provider()

    payload = {
        "status": "ok",
        "service": settings.service_name,
        "version": settings.version,
        "public_url": settings.public_url,
        "default_provider": {
            "name": provider.name,
            "model": provider.model,
            "endpoint": provider.endpoint,
        },
        "ephemeral_security": {
            "token_ttl_max_seconds": 300,
            "revocation_epoch": _REV_EPOCH,
            "signing": "HS256 (env: STEGTV_JWT_SECRET)",
        },
    }
    return JSONResponse(payload)


@app.post(
    "/providers/resolve",
    response_model=ProviderResolveResponse,
    summary="Resolve which provider/model/config to use for a given use-case.",
)
async def providers_resolve(body: ProviderResolveRequest) -> ProviderResolveResponse:
    """
    Main integration point for SCW / StegCore / hybrid-collab-bridge.

    Callers send a high-level description of the task, and receive:
      - provider.name  (e.g. 'github_models')
      - provider.model (e.g. 'openai/gpt-4.1-mini')
      - provider.endpoint (optional)
      - constraints (max_tokens, temperature, etc.)
    """
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


# ---------- Ephemeral tokens ----------
@app.post("/tokens/issue", response_model=TokenIssueResponse, summary="Issue an ephemeral, action-scoped StegVerse token.")
async def tokens_issue(body: TokenIssueRequest) -> TokenIssueResponse:
    _require_jwt()
    secret = _jwt_secret()

    ttl = _clamp_ttl(body.ttl_seconds)
    iat = _now()
    exp = iat + ttl
    jti = str(uuid.uuid4())

    # Minimal, mechanical claims for boundary-conditioned authority.
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
        # Keep extras namespaced to avoid collisions with core claims.
        claims["x"] = body.extra

    token = jwt.encode(claims, secret, algorithm="HS256")
    return TokenIssueResponse(token=token, exp=exp, jti=jti, rev=_REV_EPOCH)


@app.post("/tokens/verify", response_model=TokenVerifyResponse, summary="Verify a StegVerse token and return claims.")
async def tokens_verify(body: TokenVerifyRequest) -> TokenVerifyResponse:
    _require_jwt()
    secret = _jwt_secret()

    try:
        claims = jwt.decode(body.token, secret, algorithms=["HS256"])
    except Exception as e:
        return TokenVerifyResponse(valid=False, claims=None, reason=f"decode_failed: {e}")

    # Revocation epoch check: if token was issued before the last revoke bump, it's invalid.
    token_rev = int(claims.get("rev", -1))
    if token_rev != _REV_EPOCH:
        return TokenVerifyResponse(
            valid=False,
            claims=claims,
            reason=f"revoked: token_rev={token_rev} current_rev={_REV_EPOCH}",
        )

    return TokenVerifyResponse(valid=True, claims=claims, reason=None)


@app.post("/tokens/revoke", response_model=TokenRevokeResponse, summary="Revoke all previously issued tokens (bump epoch).")
async def tokens_revoke() -> TokenRevokeResponse:
    global _REV_EPOCH
    _REV_EPOCH += 1
    return TokenRevokeResponse(rev=_REV_EPOCH)
