import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "stegtv_config.json")

DEFAULT_CONFIG = {
    "providers": [
        {
            "name": "GitHub-Models",
            "model": "gpt-4.1-mini",
            "endpoint": "https://models.github.ai/inference/chat/completions",
            "priority": 1
        }
    ]
}

def load_stegtv_config():
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
