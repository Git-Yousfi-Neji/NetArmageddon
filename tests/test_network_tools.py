from netarmageddon.utils import network_tools


def test_validate_ip() -> None:
    assert network_tools.validate_ip("192.168.1.1") is True
    assert network_tools.validate_ip("256.400.123.456") is False


def test_generate_random_ip() -> None:
    ip = network_tools.generate_random_ip("10.0.0.0/24")
    assert network_tools.validate_ip(ip)
    assert ip.startswith("10.0.0.")


def test_port_availability() -> None:
    assert network_tools.is_port_available(54321) is True
    # Test with occupied port (requires netcat: nc -l 54321)
    # assert network_tools.is_port_available(54321) is False


def test_default_gateway() -> None:
    gateway = network_tools.get_default_gateway()
    assert gateway is not None
    assert network_tools.validate_ip(gateway)
