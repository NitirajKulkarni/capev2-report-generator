"""
Persistent Configuration & Settings Manager for CAPEv2 Report Generator.
Saves and loads user preferences (Analyst Name, Organization, Report Title, etc.)
so they are remembered across application restarts.
"""

import os
import json
from typing import Dict, Any

def get_config_dir() -> str:
    """Get the persistent configuration directory for the user."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        conf_dir = os.path.join(base, "cape_report_generator")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        conf_dir = os.path.join(base, "cape_report_generator")
    os.makedirs(conf_dir, exist_ok=True)
    return conf_dir

def get_config_file() -> str:
    return os.path.join(get_config_dir(), "settings.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "analyst_name": "",
    "organization": "",
    "report_title": "CAPEv2 Sandbox Malware Analysis Report",
    "classification": "",
    "output_dir": "",
    "defang_iocs": True,
}

def load_settings() -> Dict[str, Any]:
    """Load settings from disk or return defaults."""
    cfg_file = get_config_file()
    if os.path.isfile(cfg_file):
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                res = DEFAULT_CONFIG.copy()
                res.update(data)
                return res
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()

def save_settings(settings: Dict[str, Any]) -> bool:
    """Save user settings to disk."""
    cfg_file = get_config_file()
    try:
        current = load_settings()
        current.update(settings)
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[!] Warning: Could not save settings: {e}")
        return False
