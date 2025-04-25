import yaml
from pathlib import Path
from typing import Dict, Any

def load_config(config_path: str = "config/default.yaml") -> Dict[str, Any]:
    """Load YAML configuration file."""
    path = Path(__file__).parent.parent / config_path
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}