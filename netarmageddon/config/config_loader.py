from pathlib import Path
from typing import Any, Dict

import yaml


def load_config(config_path: str = "config/default.yaml") -> Dict[str, Any]:
    """Load YAML configuration file."""
    path = Path(__file__).parent.parent / config_path
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data
            return {}
    except FileNotFoundError:
        return {}
