# app/resolver.py

import json
import urllib.request

CONFIG_URL = (
    "https://raw.githubusercontent.com/StegVerse-Labs/StegTVC/main/data/stegtvc_config.json"
)

class StegTVError(Exception):
    pass

def stegtvc_resolve(use_case: str, module: str, importance: str = "normal"):
    """
    Resolve which provider/model to use based on the StegTVC config JSON.
    """
    try:
        with urllib.request.urlopen(CONFIG_URL, timeout=10) as response:
            config_data = json.loads(response.read().decode("utf-8"))
    except Exception as e:
        raise StegTVError(f"Failed to fetch StegTVC config: {e}")

    for rule in config_data.get("rules", []):
        if (
            rule["use_case"] == use_case
            and rule["module"] == module
            and rule.get("importance", "normal") == importance
        ):
            return rule["provider"]

    raise StegTVError(
        f"No matching resolver rule for use_case={use_case} module={module}"
    )
