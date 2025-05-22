from pathlib import Path
from typing import Any, Optional, cast

import yaml

DEFAULT_VALUES_F_NAME = "default.yaml"


class ConfigLoader:
    _config: Optional[dict[str, Any]] = None

    @classmethod
    def _load_config(cls) -> dict[str, Any]:
        if cls._config is None:
            cfg_path = Path(__file__).parent / f"{DEFAULT_VALUES_F_NAME}"
            with cfg_path.open() as f:
                cls._config = yaml.safe_load(f)
        return cast(dict[str, Any], cls._config)

    @classmethod
    def get(
        cls,
        section: str,
        attack: Optional[str] = None,
        key: Optional[str] = None,
        default: Any = None,
    ) -> Any:
        """
        Get config value with fallback.

        Examples:
            get("attacks", "dhcp", "default_num_devices")
            get("attacks", "dhcp", "default_interface")
        Fallback:
            if key not found in attacks.dhcp, it tries attacks.default_interface
        """
        cfg = cls._load_config()

        try:
            if section and attack and key:
                return cfg[section].get(attack, {}).get(key) or cfg[section].get(key) or default
            elif section and key:
                return cfg[section].get(key, default)
            else:
                return default
        except (KeyError, AttributeError):
            return default
