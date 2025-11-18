"""
app.models

Shared Pydantic models for StegTVC core.
"""

from __future__ import annotations

from typing import Optional, Literal
from pydantic import BaseModel, Field


class HealthStatus(BaseModel):
    status: Literal["ok", "degraded", "error"]
    message: str
    bundle_version: Optional[int] = None


class TokenIssueRequest(BaseModel):
    subject: str = Field(..., description="Entity ID (human or AI)")
    role: str = Field(..., description="Role name (e.g., guardian_ai, stegcore)")
    ttl_seconds: int = Field(3600, description="Token lifetime in seconds")
    audience: str = Field("stegverse", description="Intended audience")


class TokenIssueResponse(BaseModel):
    token: str
    expires_in: int
    role: str
    subject: str


class AIRequest(BaseModel):
    provider: Literal["github_models"] = Field(
        "github_models", description="Initial provider; more later"
    )
    model: str = Field(
        "openai/gpt-4.1",
        description="GitHub Models model ID (e.g., openai/gpt-4.1)",
    )
    prompt: str
    system_prompt: str | None = None
    max_tokens: int = 512
    temperature: float = 0.2
    trace_tag: str | None = Field(
        None, description="Optional tag for chainlog correlation"
    )


class AIResponse(BaseModel):
    provider: str
    model: str
    output: str
    trace_id: str
