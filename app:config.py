"""
app.config

Loads the StegTV policy bundle exported from StegVerse/TV and exposes
simple accessors for roles / issuers. StegTVC is the core runtime.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE_PATH = BASE_DIR / "policy_bundle.json"


class PolicyBundle:
    def __init__(self, raw: Dict[str, Any], path: Path) -> None:
        self.raw = raw
        self.path = path

    @property
    def version(self) -> int | None:
        return self.raw.get("version")

    @property
    def integrity(self) -> Dict[str, Any]:
        return self.raw.get("integrity", {})

    @property
    def roles_yaml(self) -> str:
        return self.raw.get("content", {}).get("roles_yaml", "")

    @property
    def issuers_yaml(self) -> str:
        return self.raw.get("content", {}).get("issuers_yaml", "")

    @property
    def rotation_markdown(self) -> str:
        return self.raw.get("content", {}).get("rotation_markdown", "")


def load_policy_bundle(path: str | Path | None = None) -> PolicyBundle:
    bundle_path = Path(
        os.getenv("STEGTV_POLICY_BUNDLE_PATH", str(path or DEFAULT_BUNDLE_PATH))
    )

    if not bundle_path.exists():
        raise FileNotFoundError(
            f"StegTV policy bundle not found at {bundle_path}. "
            "Copy exports/stegtv_policy_bundle.json from the TV repo and "
            "place it as policy_bundle.json (or set STEGTV_POLICY_BUNDLE_PATH)."
        )

    raw = json.loads(bundle_path.read_text(encoding="utf-8"))
    return PolicyBundle(raw=raw, path=bundle_path)


def get_env(name: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.getenv(name, default)
    if required and not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value
