from pathlib import Path

from netarmageddon.config.config_loader import ConfigLoader


def test_config_loading() -> None:
    config = ConfigLoader._load_config()

    assert "attacks" in config
    assert ConfigLoader.get("attacks", "dummy", "default_interface") == "lo"
    assert ConfigLoader.get("attacks", "dhcp", "default_num_devices") <= 255
    assert ConfigLoader.get("attacks", "arp", "default_base_ip").startswith("192.168.")
    assert ConfigLoader.get("attacks", "arp", "default_base_ip").endswith(".")

    assert isinstance(
        ConfigLoader.get("attacks", "dhcp", "default_client_src", default=[]), list
    )


def test_missing_config(monkeypatch) -> None:
    def fake_path(*args, **kwargs):
        return Path("nonexistent.yaml")

    monkeypatch.setattr("netarmageddon.config.config_loader.Path", fake_path)
    ConfigLoader._config = None
    try:
        ConfigLoader._load_config()
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        assert True
