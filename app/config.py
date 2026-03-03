# app/config.py
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
        }
    ]
}


def load_stegtv_config() -> Dict[str, Any]:
    """
    Returns parsed config if file exists,
    otherwise writes & returns the DEFAULT_CONFIG.
    """
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG

    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


def get_default_provider(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = cfg or load_stegtv_config()
    providers: List[Dict[str, Any]] = cfg.get("providers", []) or []
    if not providers:
        return DEFAULT_CONFIG["providers"][0]

    providers_sorted = sorted(providers, key=lambda p: int(p.get("priority", 9999)))
    return providers_sorted[0]


@dataclass(frozen=True)
class Settings:
    # app identity
    name: str = "TVC"
    version: str = "0.1.0"
    env: str = "production"

    # config + provider
    config: Dict[str, Any] = None  # type: ignore
    default_provider: Dict[str, Any] = None  # type: ignore

    # secrets (optional; don’t block boot)
    STEGTV_JWT_SECRET: str = ""
    GITHUB_MODELS_TOKEN: str = ""
    ADMIN_TOKEN: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    cfg = load_stegtv_config()
    provider = get_default_provider(cfg)

    # version can be overridden from env without touching code
    version = os.getenv("APP_VERSION", "0.1.0")

    return Settings(
        name=os.getenv("APP_NAME", "TVC"),
        version=version,
        env=os.getenv("ENV", "production"),
        config=cfg,
        default_provider=provider,
        STEGTV_JWT_SECRET=os.getenv("STEGTV_JWT_SECRET", ""),
        GITHUB_MODELS_TOKEN=os.getenv("GITHUB_MODELS_TOKEN", ""),
        ADMIN_TOKEN=os.getenv("ADMIN_TOKEN", ""),
    )
