"""
StegTVC resolver

Given a use_case + module, pick the right provider/model based on
data/tv_config.json. Supports wildcard rules and a global fallback.
"""

import json
import os
from pathlib import Path


class StegTVCResolutionError(Exception):
    """Raised when no suitable rule/provider can be found."""


def _load_config() -> dict:
    """
    Load StegTVC config.

    Priority:
      1. STEGTVC_CONFIG_PATH env var (local file path)
      2. ./data/tv_config.json (repo default)
    """
    env_path = os.getenv("STEKTVC_CONFIG_PATH") or os.getenv("STEGTVC_CONFIG_PATH")
    cfg_path: Path

    if env_path:
        cfg_path = Path(env_path)
    else:
        # default: repo-local config
        cfg_path = Path(__file__).resolve().parent.parent / "data" / "tv_config.json"

    if not cfg_path.is_file():
        raise StegTVCResolutionError(
            f"Config file not found at: {cfg_path}"
        )

    with cfg_path.open("r", encoding="utf-8") as f:
        cfg = json.load(f)

    if "providers" not in cfg:
        raise StegTVCResolutionError("Config missing 'providers' list")

    # Ensure keys exist even if omitted
    cfg.setdefault("rules", [])
    return cfg


def _index_providers(cfg: dict) -> dict:
    """Return a dict name -> provider dict."""
    providers = {}
    for p in cfg.get("providers", []):
        name = p.get("name")
        if name:
            providers[name] = p
    return providers


def stegtvc_resolve(use_case: str, module: str, importance: str = "normal") -> dict:
    """
    Resolve a provider/model for the given use_case + module.

    Matching strategy (in order):

    1. Exact match:   use_case == rule.use_case AND module == rule.module
    2. Wildcard mod:  use_case == rule.use_case AND rule.module == "*"
    3. Wildcard case: rule.use_case == "*" AND module == rule.module
    4. Global '*','*' fallback, if present.

    Returns:
        {
          "use_case": ...,
          "module": ...,
          "provider": { ... full provider dict ... },
          "rule": { ... the rule that matched ... },
        }
    """
    cfg = _load_config()
    providers = _index_providers(cfg)
    rules = cfg.get("rules", [])

    requested = {"use_case": use_case, "module": module}

    # Helper to check / pick rule
    exact_match = None
    wildcard_module = None
    wildcard_use_case = None
    global_fallback = None

    for rule in rules:
        uc = rule.get("use_case", "*")
        mod = rule.get("module", "*")

        if uc == use_case and mod == module:
            exact_match = rule
            break  # strongest match; we can stop

        if uc == use_case and mod == "*":
            if wildcard_module is None:
                wildcard_module = rule

        if uc == "*" and mod == module:
            if wildcard_use_case is None:
                wildcard_use_case = rule

        if uc == "*" and mod == "*":
            # keep the *last* defined global fallback
            global_fallback = rule

    chosen_rule = exact_match or wildcard_module or wildcard_use_case or global_fallback

    if not chosen_rule:
        raise StegTVCResolutionError(
            f"No match found for use_case='{use_case}' module='{module}'"
        )

    provider_name = chosen_rule.get("provider")
    provider = providers.get(provider_name)

    if not provider:
        raise StegTVCResolutionError(
            f"Rule selected provider '{provider_name}', "
            f"but no provider with that name exists in config."
        )

    return {
        "use_case": use_case,
        "module": module,
        "importance": importance,
        "provider": provider,
        "rule": chosen_rule,
        "config_path": str(
            os.getenv("STEKTVC_CONFIG_PATH")
            or os.getenv("STEGTVC_CONFIG_PATH")
            or (Path(__file__).resolve().parent.parent / "data" / "tv_config.json")
        ),
    }
