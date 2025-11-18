"""
app.providers

Abstraction over AI providers. For now we support GitHub Models only.
"""

from __future__ import annotations

import json
from typing import Dict, Any

import httpx

from .config import get_env


class ProviderError(RuntimeError):
    pass


async def call_github_models(
    model: str,
    prompt: str,
    system_prompt: str | None = None,
    max_tokens: int = 512,
    temperature: float = 0.2,
) -> str:
    token = get_env("GITHUB_MODELS_TOKEN", required=True)
    api_url = "https://models.github.ai/inference/chat/completions"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }

    messages: list[Dict[str, Any]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(api_url, headers=headers, content=json.dumps(payload))

    if resp.status_code >= 400:
        raise ProviderError(f"GitHub Models error {resp.status_code}: {resp.text}")

    data = resp.json()
    content = (
        data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    return content


async def route_ai_request(payload: "AIRequest") -> str:
    if payload.provider == "github_models":
        return await call_github_models(
            model=payload.model,
            prompt=payload.prompt,
            system_prompt=payload.system_prompt,
            max_tokens=payload.max_tokens,
            temperature=payload.temperature,
        )
    raise ProviderError(f"Unsupported provider: {payload.provider}")
