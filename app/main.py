from __future__ import annotations

import hmac
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

# --- Optional dependency: redis (async) ---
try:
    import redis.asyncio as redis  # type: ignore
except Exception:
    redis = None  # pragma: no cover


# ------------------------
# Helpers / Settings
# ------------------------
def _now() -> int:
    return int(time.time())


def _env() -> str:
    # Your config.py uses ENV; keep that canonical.
    return (os.getenv("ENV", "") or get_settings().env or "production").strip().lower()


def _is_prod() -> bool:
    return _env() in ("prod", "production")


def _docs_enabled() -> bool:
    # Default: enabled in dev, disabled in prod
    v = os.getenv("STEGTV_DOCS", "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return not _is_prod()


def _admin_token_value() -> str:
    # You added STEGTV_ADMIN_TOKEN in Render; support both for compatibility.
    return (
        os.getenv("STEGTV_ADMIN_TOKEN", "").strip()
        or os.getenv("ADMIN_TOKEN", "").strip()
        or get_settings().ADMIN_TOKEN.strip()
    )


def _const_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def require_admin(x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token")) -> None:
    expected = _admin_token_value()
    if not expected:
        # If you haven't set an admin token, do NOT allow token endpoints to function.
        raise HTTPException(status_code=503, detail="Admin token not configured (set STEGTV_ADMIN_TOKEN).")
    if not x_admin_token or not _const_time_eq(x_admin_token.strip(), expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


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
        raise HTTPException(status_code=500, detail="STEGTV_JWT_SECRET is too short (min 16 chars recommended).")
    return secret


def _clamp_ttl(ttl_seconds: int) -> int:
    # Ephemeral by default: minutes, not hours.
    if ttl_seconds <= 0:
        return 120
    return max(10, min(ttl_seconds, int(os.getenv("STEGTV_TTL_MAX", "300"))))


def _jwt_leeway_seconds() -> int:
    # Small clock skew tolerance
    try:
        return max(0, min(int(os.getenv("STEGTV_JWT_LEEWAY", "5")), 60))
    except Exception:
        return 5


def _sliding_enabled() -> bool:
    v = os.getenv("STEGTV_SLIDING_ENABLED", "true").strip().lower()
    return v in ("1", "true", "yes", "on")


def _sliding_grace_seconds() -> int:
    # Allow a brief post-expiration grace ONLY for internal flows.
    try:
        return max(0, min(int(os.getenv("STEGTV_SLIDING_GRACE", "30")), 300))
    except Exception:
        return 30


def _refresh_if_under_seconds() -> int:
    # If token is going to expire in <= N seconds, mint a refreshed token.
    try:
        return max(0, min(int(os.getenv("STEGTV_REFRESH_UNDER", "20")), 120))
    except Exception:
        return 20


def _redis_url() -> str:
    return os.getenv("REDIS_URL", "").strip() or os.getenv("STEGTV_REDIS_URL", "").strip()


async def _get_redis():
    if redis is None:
        return None
    url = _redis_url()
    if not url:
        return None
    try:
        r = redis.from_url(url, decode_responses=True)
        # quick ping
        await r.ping()
        return r
    except Exception:
        return None


# ------------------------
# Redis-backed rev epoch
# ------------------------
_REV_EPOCH_LOCAL: int = 0
REV_EPOCH_KEY = "stegtvc:rev_epoch"


async def _get_rev_epoch() -> int:
    r = await _get_redis()
    if not r:
        return _REV_EPOCH_LOCAL
    val = await r.get(REV_EPOCH_KEY)
    if not val:
        await r.set(REV_EPOCH_KEY, "0")
        return 0
    try:
        return int(val)
    except Exception:
        await r.set(REV_EPOCH_KEY, "0")
        return 0


async def _bump_rev_epoch() -> int:
    global _REV_EPOCH_LOCAL
    r = await _get_redis()
    if not r:
        _REV_EPOCH_LOCAL += 1
        return _REV_EPOCH_LOCAL
    # atomic increment
    return int(await r.incr(REV_EPOCH_KEY))


# ------------------------
# Request/Response models
# ------------------------
class TokenIssueRequest(BaseModel):
    sub: str = Field(..., description="Subject identifier (user/workload).")
    action: str = Field(..., description="Machine-readable action name, e.g. 'deploy'.")
    scope: str = Field(..., description="Resource scope, e.g. 'repo:StegVerse-Labs/TVC'.")
    ttl_seconds: int = Field(120, description="Token TTL seconds (clamped).")
    ctx_hash: Optional[str] = Field(None, description="Optional context hash binding.")
    bundle_hash: Optional[str] = Field(None, description="Optional policy bundle hash binding.")
    mode: str = Field("assisted", description="manual|assisted|autonomous|degraded|frozen")
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
    refreshed_token: Optional[str] = None
    refreshed_exp: Optional[int] = None


class TokenRevokeResponse(BaseModel):
    rev: int


# ------------------------
# App creation (docs toggle)
# ------------------------
docs_enabled = _docs_enabled()
app = FastAPI(
    title="StegTVC Core",
    description="StegVerse Token Vault Config / AI Provider Router (Core v1.0, option C).",
    version=get_settings().version,
    docs_url="/docs" if docs_enabled else None,
    redoc_url=None if _is_prod() else "/redoc",
    openapi_url="/openapi.json" if docs_enabled else None,
)


# ------------------------
# Minimal hardening middleware
# ------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # If you later serve HTML: add CSP.
    return resp


# Root route so Render/health checks don't spam 404 on HEAD /
@app.get("/", include_in_schema=False)
async def root() -> JSONResponse:
    return JSONResponse({"status": "ok"})


# ------------------------
# Health
# ------------------------
@app.get("/health", summary="Basic health check")
async def health() -> JSONResponse:
    s = get_settings()
    provider = get_default_provider(s.config)

    # provider is a dict per your config.py
    payload: Dict[str, Any] = {
        "status": "ok",
        "env": "prod" if _is_prod() else "dev",
        "service": "stegtvc",
        "version": s.version,
    }

    # In prod, keep health minimal (don’t leak endpoints/config).
    if not _is_prod():
        payload.update(
            {
                "public_url": os.getenv("PUBLIC_URL", "").strip() or "",
                "default_provider": {
                    "name": provider.get("name"),
                    "model": provider.get("model"),
                    "endpoint": provider.get("endpoint"),
                },
                "security": {
                    "admin_header": "X-Admin-Token",
                    "docs_enabled": docs_enabled,
                    "token_ttl_max_seconds": int(os.getenv("STEGTV_TTL_MAX", "300")),
                    "revocation_epoch": await _get_rev_epoch(),
                    "jwt_signing": "HS256 (env: STEGTV_JWT_SECRET)",
                    "sliding_enabled": _sliding_enabled(),
                    "sliding_grace_seconds": _sliding_grace_seconds(),
                },
                "redis": {"configured": bool(_redis_url()), "active": bool(await _get_redis())},
            }
        )

    return JSONResponse(payload)


# ------------------------
# Provider routes
# ------------------------
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
    s = get_settings()
    base = get_default_provider(s.config)
    return ProviderInfo(
        name=str(base.get("name", "")),
        model=str(base.get("model", "")),
        endpoint=base.get("endpoint"),
        notes=base.get("notes"),
    )


# ------------------------
# Token logic
# ------------------------
def _encode_token(claims: Dict[str, Any]) -> str:
    _require_jwt()
    secret = _jwt_secret()
    return jwt.encode(claims, secret, algorithm="HS256")


def _decode_token(token: str, verify_exp: bool = True) -> Dict[str, Any]:
    _require_jwt()
    secret = _jwt_secret()
    options = {"verify_exp": verify_exp}
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        options=options,
        leeway=_jwt_leeway_seconds(),
    )


@app.post(
    "/tokens/issue",
    response_model=TokenIssueResponse,
    summary="Issue an ephemeral, action-scoped StegVerse token.",
    dependencies=[Depends(require_admin)],
)
async def tokens_issue(body: TokenIssueRequest) -> TokenIssueResponse:
    ttl = _clamp_ttl(body.ttl_seconds)
    iat = _now()
    exp = iat + ttl
    jti = str(uuid.uuid4())
    rev = await _get_rev_epoch()

    claims: Dict[str, Any] = {
        "iss": "stegverse:tvc",
        "sub": body.sub,
        "iat": iat,
        "nbf": iat,
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

    token = _encode_token(claims)
    return TokenIssueResponse(token=token, exp=exp, jti=jti, rev=rev)


@app.post(
    "/tokens/verify",
    response_model=TokenVerifyResponse,
    summary="Verify a StegVerse token and return claims.",
    dependencies=[Depends(require_admin)],
)
async def tokens_verify(body: TokenVerifyRequest) -> TokenVerifyResponse:
    now = _now()
    grace = _sliding_grace_seconds()
    sliding = _sliding_enabled()

    # First attempt: strict decode (checks exp)
    try:
        claims = _decode_token(body.token, verify_exp=True)
    except Exception as e:
        # Sliding-window path: only if expired AND sliding enabled
        msg = str(e)
        if sliding and ("Signature has expired" in msg or "ExpiredSignatureError" in msg):
            try:
                # Decode without exp verification so we can evaluate grace window ourselves
                claims = _decode_token(body.token, verify_exp=False)
                exp = int(claims.get("exp", 0))
                if exp <= 0:
                    return TokenVerifyResponse(valid=False, claims=None, reason="decode_failed: missing exp")

                if now > exp + grace:
                    return TokenVerifyResponse(valid=False, claims=None, reason="expired_beyond_grace")

                # within grace, continue with normal checks below
            except Exception as e2:
                return TokenVerifyResponse(valid=False, claims=None, reason=f"decode_failed: {e2}")
        else:
            return TokenVerifyResponse(valid=False, claims=None, reason=f"decode_failed: {e}")

    # Revocation epoch check
    token_rev = int(claims.get("rev", -1))
    current_rev = await _get_rev_epoch()
    if token_rev != current_rev:
        return TokenVerifyResponse(
            valid=False,
            claims=claims,
            reason=f"revoked: token_rev={token_rev} current_rev={current_rev}",
        )

    # Optionally refresh token if it's nearing expiry (sliding window usability)
    exp = int(claims.get("exp", 0))
    refreshed_token: Optional[str] = None
    refreshed_exp: Optional[int] = None

    if sliding and exp > 0:
        under = _refresh_if_under_seconds()
        if (exp - now) <= under:
            # Mint a new token with same authority but a new exp/jti.
            # This gives you a "sliding window" without accepting long-lived tokens.
            ttl = _clamp_ttl(int(os.getenv("STEGTV_REFRESH_TTL", "120")))
            iat = now
            new_exp = now + ttl
            new_jti = str(uuid.uuid4())

            new_claims = dict(claims)
            new_claims["iat"] = iat
            new_claims["nbf"] = iat
            new_claims["exp"] = new_exp
            new_claims["jti"] = new_jti
            # keep same rev
            refreshed_token = _encode_token(new_claims)
            refreshed_exp = new_exp

    return TokenVerifyResponse(
        valid=True,
        claims=claims,
        reason=None,
        refreshed_token=refreshed_token,
        refreshed_exp=refreshed_exp,
    )


@app.post(
    "/tokens/revoke",
    response_model=TokenRevokeResponse,
    summary="Revoke all previously issued tokens (bump epoch).",
    dependencies=[Depends(require_admin)],
)
async def tokens_revoke() -> TokenRevokeResponse:
    new_rev = await _bump_rev_epoch()
    return TokenRevokeResponse(rev=new_rev)
