# app/config.py
import json
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "stegtv_config.json")

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
    """
    Returns the highest-priority provider from config.
    """
    cfg = cfg or load_stegtv_config()
    providers: List[Dict[str, Any]] = cfg.get("providers", []) or []
    if not providers:
        return DEFAULT_CONFIG["providers"][0]

    # lowest priority number wins; missing priority defaults to 9999
    providers_sorted = sorted(providers, key=lambda p: int(p.get("priority", 9999)))
    return providers_sorted[0]


@lru_cache(maxsize=1)
def get_settings() -> Dict[str, Any]:
    """
    Lightweight "settings" object (dict) so main.py can import get_settings().
    We keep it simple: config from file + relevant env vars.
    """
    cfg = load_stegtv_config()
    return {
        "config": cfg,
        "default_provider": get_default_provider(cfg),
        # Optional secrets (don’t require them to boot)
        "STEGTV_JWT_SECRET": os.getenv("STEGTV_JWT_SECRET", ""),
        "GITHUB_MODELS_TOKEN": os.getenv("GITHUB_MODELS_TOKEN", ""),
        "ADMIN_TOKEN": os.getenv("ADMIN_TOKEN", ""),
        "ENV": os.getenv("ENV", "production"),
    }
