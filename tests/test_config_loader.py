import pytest
from netarmageddon.config import config_loader

def test_config_loading():
    config = config_loader.load_config()
    assert "attacks" in config
    assert config["attacks"]["dhcp"]["max_pps"] == 100
    assert config["attacks"]["dhcp"]["default_devices"] <= 255
    assert config["attacks"]["arp"]["base_ip"][0:8] == "192.168."

def test_missing_config():
    config = config_loader.load_config("invalid_path.yaml")
    assert config == {}