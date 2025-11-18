from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ProviderInfo(BaseModel):
    """Concrete provider/model details other repos can act on."""

    name: str = Field(..., description="Provider identifier, e.g. 'github_models' or 'openai'.")
    model: str = Field(..., description="Model identifier, e.g. 'openai/gpt-4.1-mini'.")
    endpoint: Optional[str] = Field(
        None,
        description="Optional HTTP endpoint. Many callers can rely on their own defaults.",
    )
    notes: Optional[str] = Field(
        None,
        description="Human-readable notes or caveats about this provider.",
    )


class ProviderResolveRequest(BaseModel):
    """
    Input sent from other StegVerse components to decide which
    provider/model/config to use.
    """

    use_case: str = Field(
        "generic-text-review",
        description="High-level purpose: 'generic-text-review', 'code-review', etc.",
    )
    repo: Optional[str] = Field(
        None,
        description="GitHub repo name (e.g. 'StegVerse/StegCore') for future policy routing.",
    )
    module: Optional[str] = Field(
        None,
        description="Logical module name, e.g. 'SCW', 'TV', 'StegCore', 'StegTalk'.",
    )
    importance: str = Field(
        "normal",
        description="Hint for cost/speed: 'low', 'normal', 'high', 'critical'.",
    )
    extra: Dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form metadata; ignored by current v1.0 implementation.",
    )


class ProviderResolveResponse(BaseModel):
    """Result returned from StegTVC to a caller."""

    provider: ProviderInfo
    use_case: str = Field(..., description="Echo of requested use_case for traceability.")
    constraints: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional constraints like max_tokens, temperature, etc.",
    )
    steward: str = Field(
        "StegTVC",
        description="Name of the steward service that produced this decision.",
    )