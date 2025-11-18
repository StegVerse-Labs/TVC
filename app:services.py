"""
app.services

Core services: token issuance, chainlog writing, and simple policy checks.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict

import jwt

from .config import load_policy_bundle, get_env
from .models import TokenIssueRequest, TokenIssueResponse, AIRequest, AIResponse
from .providers import route_ai_request

BASE_DIR = Path(__file__).resolve().parents[1]
CHAINLOG_PATH = BASE_DIR / "data" / "runtime_chainlog.jsonl"

JWT_SECRET = get_env("STEGTV_JWT_SECRET", default="dev-only-secret")
JWT_ALG = "HS256"


def _append_chainlog(event: Dict[str, Any]) -> None:
    CHAINLOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    event.setdefault("ts", time.time())
    if not CHAINLOG_PATH.exists():
        CHAINLOG_PATH.write_text("", encoding="utf-8")
    with CHAINLOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def issue_token(req: TokenIssueRequest) -> TokenIssueResponse:
    now = int(time.time())
    exp = now + req.ttl_seconds

    payload = {
        "sub": req.subject,
        "role": req.role,
        "aud": req.audience,
        "iat": now,
        "exp": exp,
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

    _append_chainlog(
        {
            "kind": "token_issued",
            "subject": req.subject,
            "role": req.role,
            "audience": req.audience,
            "expires_at": exp,
        }
    )

    return TokenIssueResponse(
        token=token,
        expires_in=req.ttl_seconds,
        role=req.role,
        subject=req.subject,
    )


async def execute_ai(req: AIRequest) -> AIResponse:
    trace_id = str(uuid.uuid4())
    output = await route_ai_request(req)

    _append_chainlog(
        {
            "kind": "ai_invocation",
            "provider": req.provider,
            "model": req.model,
            "trace_id": trace_id,
            "trace_tag": req.trace_tag,
        }
    )

    return AIResponse(
        provider=req.provider,
        model=req.model,
        output=output,
        trace_id=trace_id,
    )


def build_health_status() -> Dict[str, Any]:
    try:
        bundle = load_policy_bundle()
        status = {
            "status": "ok",
            "message": "StegTVC core is running.",
            "bundle_version": bundle.version,
            "bundle_path": str(bundle.path),
            "integrity": bundle.integrity,
        }
    except Exception as e:  # noqa: BLE001
        status = {
            "status": "error",
            "message": f"Failed to load policy bundle: {e}",
        }

    return status
