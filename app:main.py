"""
app.main

StegTVC Core v1.0 FastAPI application.

Endpoints:
- GET  /health          → basic status + bundle version
- GET  /config/status   → more detailed bundle info
- POST /tokens/issue    → issue a signed StegVerse token
- POST /ai/route        → route AI request via configured provider(s)
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .config import load_policy_bundle
from .models import HealthStatus, TokenIssueRequest, TokenIssueResponse, AIRequest, AIResponse
from .services import issue_token, execute_ai, build_health_status

app = FastAPI(
    title="StegTVC Core",
    description="StegVerse Token Vault runtime and AI router",
    version="1.0.0",
)


@app.get("/health", response_model=HealthStatus)
def health() -> HealthStatus:
    data = build_health_status()
    return HealthStatus(
        status=data.get("status", "error"),
        message=data.get("message", ""),
        bundle_version=data.get("bundle_version"),
    )


@app.get("/config/status")
def config_status() -> JSONResponse:
    try:
        bundle = load_policy_bundle()
        return JSONResponse(
            {
                "bundle_version": bundle.version,
                "bundle_path": str(bundle.path),
                "integrity": bundle.integrity,
                "source": bundle.raw.get("source"),
            }
        )
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/tokens/issue", response_model=TokenIssueResponse)
def issue_token_endpoint(req: TokenIssueRequest) -> TokenIssueResponse:
    return issue_token(req)


@app.post("/ai/route", response_model=AIResponse)
async def ai_route_endpoint(req: AIRequest) -> AIResponse:
    try:
        return await execute_ai(req)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(e)) from e
