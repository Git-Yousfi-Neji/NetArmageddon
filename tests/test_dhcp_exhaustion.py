import subprocess
import sys
from netarmageddon.cli import parse_option_range
import pytest
from unittest.mock import patch
import threading
from netarmageddon.core.dhcp_exhaustion import DHCPExhaustion
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


@pytest.fixture
def mock_interface(monkeypatch):
    # Ensure the interface validation passes
    monkeypatch.setattr('scapy.arch.get_if_list', lambda: ['lo', 'wlan0'])


@pytest.fixture
def dhcp_instance(mock_interface):
    return DHCPExhaustion(
        interface='lo',
        num_devices=5,
        request_options=[1, 3, 6],
        client_src=['00:11:22:33:44:55', '66-77-88-99-AA-BB'],
    )


def test_initialization_validation(mock_interface):
    with pytest.raises(ValueError) as exc:
        DHCPExhaustion(interface='invalid', num_devices=1)
    assert "Interface 'invalid' not found" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        DHCPExhaustion(interface='lo', num_devices=0)
    assert 'Number of devices must be at least 1' in str(exc.value)


def test_option_parsing() -> None:
    assert parse_option_range("1") == [1]
    assert parse_option_range("1-3") == [1, 2, 3]
    assert parse_option_range("1,3-5") == [1, 3, 4, 5]
    assert parse_option_range("6,10-12,15") == [6, 10, 11, 12, 15]


def test_invalid_options() -> None:
    # Empty input should error
    with pytest.raises(ValueError):
        parse_option_range("")

    # Non-numeric token
    with pytest.raises(ValueError):
        parse_option_range("a")

    # Missing end of range
    with pytest.raises(ValueError):
        parse_option_range("1-")

    # Missing start of range
    with pytest.raises(ValueError):
        parse_option_range("-3")

    # Descending range is invalid (start > end)
    with pytest.raises(ValueError):
        parse_option_range("5-3")

    # Double comma / empty segment
    with pytest.raises(ValueError):
        parse_option_range("1,,2")


def test_mac_validation(dhcp_instance):
    valid = [['aa:bb:cc:dd:ee:ff', 'AA-BB-CC-DD-EE-FF']]
    for macs in valid:
        normalized = dhcp_instance._validate_macs(macs)
        assert normalized == ['aa:bb:cc:dd:ee:ff', 'aa:bb:cc:dd:ee:ff']
    with pytest.raises(ValueError):
        dhcp_instance._validate_macs(['invalid_mac'])


def test_mac_generation_pool(dhcp_instance):
    # Cycle through provided MAC pool
    assert dhcp_instance._generate_mac() == '00:11:22:33:44:55'
    assert dhcp_instance._generate_mac() == '66:77:88:99:aa:bb'
    assert dhcp_instance._generate_mac() == '00:11:22:33:44:55'


def test_mac_generation_random(mock_interface):
    ex = DHCPExhaustion(interface='lo', num_devices=1)
    ex.mac_pool.clear()
    random_macs = set()
    for _ in range(5):
        mac = ex._generate_mac()
        assert mac.startswith('de:ad:')
        random_macs.add(mac)
    assert len(random_macs) == 5


@patch('netarmageddon.core.dhcp_exhaustion.sendp')
@patch('netarmageddon.core.dhcp_exhaustion.time.sleep', lambda x: None)
def test_send_loop(mock_sendp, dhcp_instance):
    dhcp_instance.num_devices = 3
    dhcp_instance.running = True
    dhcp_instance._send_loop()
    assert mock_sendp.call_count == 3


@patch('netarmageddon.core.dhcp_exhaustion.sendp')
@patch('netarmageddon.core.dhcp_exhaustion.time.sleep', lambda x: None)
def test_create_dhcp_packet(mock_sendp, dhcp_instance):
    pkt = dhcp_instance._create_dhcp_packet()
    for layer in (Ether, IP, UDP, BOOTP, DHCP):
        assert pkt.haslayer(layer)
    # BOOTP chaddr is bytes; strip nulls
    chaddr = pkt[BOOTP].chaddr.replace(b'\x00', b'')
    assert chaddr == b'00:11:22:33:44:55'
    # Extract DHCP options safely
    opts = {}
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and len(opt) == 2:
            opts[opt[0]] = opt[1]
    assert opts['message-type'] == 'discover'
    assert opts['client_id'] == '00:11:22:33:44:55'


def test_rate_limit_and_warning(dhcp_instance, caplog):
    assert dhcp_instance._rate_limit(50) == 50
    caplog.set_level('WARNING')
    capped = dhcp_instance._rate_limit(DHCPExhaustion.MAX_PPS + 10)
    assert capped == DHCPExhaustion.MAX_PPS
    assert 'exceeds safety limit' in caplog.text


def test_thread_lifecycle(mock_interface):
    # Verify thread creation and eventual stop without asserting mid-run state
    with (
        patch('netarmageddon.core.dhcp_exhaustion.sendp'),
        patch('netarmageddon.core.dhcp_exhaustion.time.sleep', lambda x: None),
    ):
        ex = DHCPExhaustion(interface='lo', num_devices=1)
        ex.start()
        assert isinstance(ex.thread, threading.Thread)
        # Allow thread to finish
        ex.thread.join(timeout=1)
        assert ex.running is False


def test_context_manager(mock_interface):
    with (
        patch('netarmageddon.core.dhcp_exhaustion.sendp'),
        patch('netarmageddon.core.dhcp_exhaustion.time.sleep', lambda x: None),
    ):
        with DHCPExhaustion(interface='lo', num_devices=2) as instance:
            assert hasattr(instance, 'thread') and isinstance(instance.thread, threading.Thread)
        assert instance.running is False


def test_exception_handling(dhcp_instance):
    errors = []
    dhcp_instance.logger.error = lambda msg: errors.append(msg)
    dhcp_instance.running = True
    with patch.object(dhcp_instance, '_create_dhcp_packet', side_effect=Exception('Test error')):
        dhcp_instance._send_loop()
    assert errors and 'DHCP loop error: Test error' in errors[0]


def test_user_abort(dhcp_instance):
    dhcp_instance.running = True
    dhcp_instance.thread = threading.current_thread()
    dhcp_instance.user_abort()
    assert dhcp_instance.running is False


def test_help_without_root_privileges(capsys):
    cmd = [sys.executable, "-m", "netarmageddon", "dhcp", "-i", "dummy_intf"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert "This script requires root privileges" in result.stdout
