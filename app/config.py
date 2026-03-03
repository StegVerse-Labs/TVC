# app/config.py
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(HERE, "stegtv_config.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "providers": [
        {
            "name": "GitHub-Models",
            "model": "gpt-4.1-mini",
            "endpoint": "https://models.github.ai/inference/chat/completions",
            "priority": 1,
            "notes": "Default provider from stegtv_config.json",
        }
    ]
}


def load_stegtv_config() -> Dict[str, Any]:
    """
    Returns parsed config if file exists, otherwise writes & returns DEFAULT_CONFIG.

    NOTE: On Render this file lives in the code workspace and may be ephemeral.
    That's fine for v0.1; later you can move config into Redis/DB.
    """
    if not os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "w") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
        except Exception:
            # If the filesystem is read-only for any reason, just fall back in-memory.
            return DEFAULT_CONFIG
        return DEFAULT_CONFIG

    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG


@dataclass(frozen=True)
class Provider:
    name: str
    model: str
    endpoint: Optional[str] = None
    notes: Optional[str] = None


def _providers_from_cfg(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    providers: List[Dict[str, Any]] = (cfg.get("providers", []) or [])
    return [p for p in providers if isinstance(p, dict)]


def get_default_provider(cfg: Optional[Dict[str, Any]] = None) -> Provider:
    cfg = cfg or load_stegtv_config()
    providers = _providers_from_cfg(cfg)

    if not providers:
        p0 = DEFAULT_CONFIG["providers"][0]
        return Provider(
            name=str(p0.get("name", "default")),
            model=str(p0.get("model", "unknown")),
            endpoint=p0.get("endpoint"),
            notes=p0.get("notes"),
        )

    providers_sorted = sorted(providers, key=lambda p: int(p.get("priority", 9999)))
    p = providers_sorted[0]
    return Provider(
        name=str(p.get("name", "default")),
        model=str(p.get("model", "unknown")),
        endpoint=p.get("endpoint"),
        notes=p.get("notes"),
    )


@dataclass(frozen=True)
class Settings:
    # app identity
    service_name: str = "stegtvc"
    version: str = "0.1.0"

    # environment mode (controls docs, etc.)
    # prefer STEGTV_ENV, but accept legacy ENV
    env: str = "prod"

    # public URL (Render external URL if present)
    public_url: Optional[str] = None

    # config + provider
    config: Dict[str, Any] = None  # type: ignore
    default_provider: Provider = None  # type: ignore

    # secrets (do not block boot here; endpoints may enforce at runtime)
    STEGTV_JWT_SECRET: str = ""
    STEGTV_ADMIN_TOKEN: str = ""
    GITHUB_MODELS_TOKEN: str = ""


def _get_env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _infer_public_url() -> Optional[str]:
    # Render commonly exposes an external URL. If not available, use PUBLIC_URL if you set it.
    for k in ("RENDER_EXTERNAL_URL", "PUBLIC_URL", "APP_PUBLIC_URL"):
        v = _get_env(k, "")
        if v:
            return v
    return None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    cfg = load_stegtv_config()
    provider = get_default_provider(cfg)

    # Version can be overridden without touching code
    version = _get_env("APP_VERSION", "0.1.0")
    service_name = _get_env("APP_NAME", "stegtvc")

    # Prefer new env var names, but accept legacy to avoid breaking you mid-rollout.
    env = _get_env("STEGTV_ENV", "")
    if not env:
        env = _get_env("ENV", "prod")
    env = env.lower()

    admin_tok = _get_env("STEGTV_ADMIN_TOKEN", "")
    if not admin_tok:
        # legacy fallback (what your old file used)
        admin_tok = _get_env("ADMIN_TOKEN", "")

    return Settings(
        service_name=service_name,
        version=version,
        env=env,
        public_url=_infer_public_url(),
        config=cfg,
        default_provider=provider,
        STEGTV_JWT_SECRET=_get_env("STEGTV_JWT_SECRET", ""),
        STEGTV_ADMIN_TOKEN=admin_tok,
        GITHUB_MODELS_TOKEN=_get_env("GITHUB_MODELS_TOKEN", ""),
    )
