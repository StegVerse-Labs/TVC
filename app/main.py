from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .config import get_settings, get_default_provider
from .models import ProviderResolveRequest, ProviderResolveResponse, ProviderInfo
from .services import resolve_provider

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