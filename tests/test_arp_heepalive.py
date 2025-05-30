# Updated tests for ARPKeepAlive to align with implementation
import subprocess
import sys
import pytest
import threading
import random
from unittest.mock import patch
from netarmageddon.core.arp_keepalive import ARPKeepAlive
from scapy.layers.l2 import ARP, Ether


@pytest.fixture
def mock_interface(monkeypatch):
    # Stub interface list to include 'eth0' and 'lo'
    monkeypatch.setattr('scapy.arch.get_if_list', lambda: ['eth0', 'lo'])


@pytest.fixture
def arp_instance(mock_interface):
    # Base IP with trailing dot
    return ARPKeepAlive(
        interface='lo',
        base_ip='192.168.1.',
        num_devices=3,
        mac_prefix='de:ad:00',
        interval=0.01,
        cycles=2,
    )


def test_ip_validation() -> None:
    """Test base IP validation"""
    with pytest.raises(ValueError) as exc:
        ARPKeepAlive("lo", "192.168.1")  # Missing trailing dot
    assert 'Use format like' in str(exc.value)

    with pytest.raises(ValueError) as exc:
        ARPKeepAlive("lo", "192.168.1.100.")  # Extra dot
    assert 'Use format like' in str(exc.value)


def test_arp_initialization() -> None:
    """Test ARPKeepAlive class initialization"""
    arp = ARPKeepAlive("lo", "192.168.1.")
    assert arp.base_ip == "192.168.1."
    assert arp.num_devices == 50


@pytest.mark.parametrize('base_ip', ['192.168.1', 'abc.def.ghi.'])
def test_validate_ip_failure(mock_interface, base_ip):
    with pytest.raises(ValueError) as exc:
        ARPKeepAlive(interface='lo', base_ip=base_ip)
    # Validation message changed to guidance format
    assert 'Use format like' in str(exc.value)


@pytest.mark.parametrize('prefix', ['de:ad', 'gh:00:11', '00:11:22:33'])
def test_validate_mac_prefix_failure(mock_interface, prefix):
    with pytest.raises(ValueError) as exc:
        ARPKeepAlive(interface='lo', base_ip='10.0.0.', mac_prefix=prefix)
    assert 'Use format like' in str(exc.value)


def test_generate_mac_deterministic(arp_instance):
    # Seed random for reproducibility
    random.seed(0)
    mac1 = arp_instance._generate_mac(1)
    random.seed(0)
    mac2 = arp_instance._generate_mac(1)
    assert mac1 == mac2
    assert mac1.startswith('de:ad:00:01:')


def test_generate_arp_packet(arp_instance):
    pkt = arp_instance._generate_arp_packet(5)
    assert pkt.haslayer(Ether)
    assert pkt.haslayer(ARP)
    ether = pkt.getlayer(Ether)
    arp = pkt.getlayer(ARP)
    assert arp.psrc == '192.168.1.5'
    # MAC in hwsrc matches Ether src
    assert ether.src == arp.hwsrc


@patch('netarmageddon.core.arp_keepalive.sendp', side_effect=PermissionError('perm'))
@patch('netarmageddon.core.arp_keepalive.time.sleep', lambda x: None)
def test_send_arp_announcements_permission_error(mock_send, arp_instance):
    # Run announcements to trigger PermissionError
    arp_instance.running = True
    arp_instance.cycles = 1
    arp_instance.num_devices = 1
    arp_instance._send_arp_announcements()
    # After PermissionError, ARPKeepAlive should stop running
    assert not arp_instance.running


def test_thread_start_stop(mock_interface):
    # Patch sendp and sleep to avoid real network ops
    with (
        patch('netarmageddon.core.arp_keepalive.sendp'),
        patch('netarmageddon.core.arp_keepalive.time.sleep', lambda x: None),
    ):
        ka = ARPKeepAlive(interface='lo', base_ip='10.0.0.', num_devices=1, cycles=1)
        ka.start()
        # Thread should be created
        assert isinstance(ka.thread, threading.Thread)
        # Wait for thread to finish
        ka.thread.join(timeout=1)
        # After execution, running flag is reset
        assert not ka.running
        # stop should not error
        ka.stop()


def test_user_abort(mock_interface):
    ka = ARPKeepAlive(interface='lo', base_ip='192.168.0.', num_devices=1, cycles=1)
    ka.running = True
    ka.thread = threading.current_thread()
    ka.user_abort()
    assert not ka.running


def test_context_manager(mock_interface):
    with (
        patch('netarmageddon.core.arp_keepalive.sendp'),
        patch('netarmageddon.core.arp_keepalive.time.sleep', lambda x: None),
    ):
        with ARPKeepAlive(interface='lo', base_ip='172.16.0.', num_devices=1, cycles=1) as ka:
            # Context manager should set up thread attribute
            assert hasattr(ka, 'thread') and isinstance(ka.thread, threading.Thread)
        assert not ka.running


def test_help_without_root_privileges(capsys):
    # Simulate running module without root
    cmd = [sys.executable, "-m", "netarmageddon", "traffic", "-i", "dummy_intf"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert "This script requires root privileges" in result.stdout
