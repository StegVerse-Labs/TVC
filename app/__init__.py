# StegTVC Core v1 — initializer
from .config import load_stegtv_config
from .resolver import stegtvc_resolve

__all__ = ["load_stegtv_config", "stegtv_resolve"]
