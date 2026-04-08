# Updated tests for ARPKeepAlive to align with implementation
import random
import subprocess
import sys
import threading
from unittest.mock import patch

import pytest
from scapy.layers.l2 import ARP, Ether

from netarmageddon.core.arp_keepalive import ARPKeepAlive


@pytest.fixture
def mock_interface(monkeypatch):
    # Stub interface list to include 'eth0' and 'lo'
    monkeypatch.setattr("scapy.arch.get_if_list", lambda: ["eth0", "lo"])


@pytest.fixture
def arp_instance(mock_interface):
    # Base IP with trailing dot
    return ARPKeepAlive(
        interface="lo",
        base_ip="192.168.1.",
        num_devices=3,
        mac_prefix="de:ad:00",
        interval=0.01,
        cycles=2,
    )


def test_ip_validation() -> None:
    """Test base IP validation"""
    with pytest.raises(ValueError) as exc:
        ARPKeepAlive("lo", "192.168.1")  # Missing trailing dot
    assert "Use format like" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        ARPKeepAlive("lo", "192.168.1.100.")  # Extra dot
    assert "Use format like" in str(exc.value)


def test_arp_initialization() -> None:
    """Test ARPKeepAlive class initialization"""
    arp = ARPKeepAlive("lo", "192.168.1.")
    assert arp.base_ip == "192.168.1."
    assert arp.num_devices == 50


@pytest.mark.parametrize("base_ip", ["192.168.1", "abc.def.ghi."])
def test_validate_ip_failure(mock_interface, base_ip):
    with pytest.raises(ValueError) as exc:
        ARPKeepAlive(interface="lo", base_ip=base_ip)
    # Validation message changed to guidance format
    assert "Use format like" in str(exc.value)


@pytest.mark.parametrize("prefix", ["de:ad", "gh:00:11", "00:11:22:33"])
def test_validate_mac_prefix_failure(mock_interface, prefix):
    with pytest.raises(ValueError) as exc:
        ARPKeepAlive(interface="lo", base_ip="10.0.0.", mac_prefix=prefix)
    assert "Use format like" in str(exc.value)


def test_generate_mac_deterministic(arp_instance):
    # Seed random for reproducibility
    random.seed(0)
    mac1 = arp_instance._generate_mac(1)
    random.seed(0)
    mac2 = arp_instance._generate_mac(1)
    assert mac1 == mac2
    assert mac1.startswith("de:ad:00:01:")


def test_generate_arp_packet(arp_instance):
    pkt = arp_instance._generate_arp_packet(5)
    assert pkt.haslayer(Ether)
    assert pkt.haslayer(ARP)
    ether = pkt.getlayer(Ether)
    arp = pkt.getlayer(ARP)
    assert arp.psrc == "192.168.1.5"
    # MAC in hwsrc matches Ether src
    assert ether.src == arp.hwsrc


@patch("netarmageddon.core.arp_keepalive.sendp", side_effect=PermissionError("perm"))
@patch("netarmageddon.core.arp_keepalive.time.sleep", lambda x: None)
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
        patch("netarmageddon.core.arp_keepalive.sendp"),
        patch("netarmageddon.core.arp_keepalive.time.sleep", lambda x: None),
    ):
        ka = ARPKeepAlive(interface="lo", base_ip="10.0.0.", num_devices=1, cycles=1)
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
    ka = ARPKeepAlive(interface="lo", base_ip="192.168.0.", num_devices=1, cycles=1)
    ka.running = True
    ka.thread = threading.current_thread()
    ka.user_abort()
    assert not ka.running


def test_context_manager(mock_interface):
    with (
        patch("netarmageddon.core.arp_keepalive.sendp"),
        patch("netarmageddon.core.arp_keepalive.time.sleep", lambda x: None),
    ):
        with ARPKeepAlive(interface="lo", base_ip="172.16.0.", num_devices=1, cycles=1) as ka:
            # Context manager should set up thread attribute
            assert hasattr(ka, "thread") and isinstance(ka.thread, threading.Thread)
        assert not ka.running


@pytest.mark.skipif(
    sys.version_info >= (3, 11), reason="scapy subprocess import broken on Python 3.11+ in this env"
)
def test_help_without_root_privileges(capsys):
    # Simulate running module without root
    cmd = [sys.executable, "-m", "netarmageddon", "traffic", "-i", "dummy_intf"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert "This script requires root privileges" in result.stdout


# ── target_macs tests ─────────────────────────────────────────────────────────


def test_target_macs_sets_num_devices(mock_interface):
    """When target_macs is provided, num_devices should equal len(target_macs)."""
    macs = ["de:ad:be:ef:00:01", "de:ad:be:ef:00:02", "de:ad:be:ef:00:03"]
    ka = ARPKeepAlive(interface="lo", base_ip="10.0.0.", target_macs=macs)
    assert ka.num_devices == 3
    assert ka.target_macs == macs


def test_target_macs_generate_mac_returns_exact(mock_interface):
    """_generate_mac should return the explicit MAC, not a random one."""
    macs = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    ka = ARPKeepAlive(interface="lo", base_ip="10.0.0.", target_macs=macs)
    assert ka._generate_mac(1) == "aa:bb:cc:dd:ee:01"
    assert ka._generate_mac(2) == "aa:bb:cc:dd:ee:02"


def test_target_macs_arp_packet_uses_exact_mac(mock_interface):
    """ARP packet hwsrc and Ether src should match the given target MAC."""
    macs = ["ca:fe:ba:be:00:01"]
    ka = ARPKeepAlive(interface="lo", base_ip="192.168.1.", target_macs=macs)
    pkt = ka._generate_arp_packet(1)
    assert pkt.getlayer(Ether).src == "ca:fe:ba:be:00:01"
    assert pkt.getlayer(ARP).hwsrc == "ca:fe:ba:be:00:01"
    assert pkt.getlayer(ARP).psrc == "192.168.1.1"


def test_target_macs_invalid_mac_raises(mock_interface):
    """A malformed MAC in target_macs should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid MAC"):
        ARPKeepAlive(interface="lo", base_ip="10.0.0.", target_macs=["not-a-mac"])


def test_target_macs_empty_list_raises(mock_interface):
    """An empty target_macs list should raise ValueError."""
    with pytest.raises(ValueError, match="must not be empty"):
        ARPKeepAlive(interface="lo", base_ip="10.0.0.", target_macs=[])


@patch("netarmageddon.core.arp_keepalive.sendp")
@patch("netarmageddon.core.arp_keepalive.time.sleep", lambda x: None)
def test_target_macs_sends_correct_packets(mock_send, mock_interface):
    """With target_macs, sendp must be called with the explicit MACs."""
    macs = ["11:22:33:44:55:01", "11:22:33:44:55:02"]
    ka = ARPKeepAlive(interface="lo", base_ip="10.1.2.", target_macs=macs, cycles=1, interval=0)
    ka.running = True
    ka._send_arp_announcements()

    assert mock_send.call_count == len(macs)
    sent_macs = [call.args[0].getlayer(Ether).src for call in mock_send.call_args_list]
    assert sent_macs == macs


def test_target_macs_normalises_case(mock_interface):
    """MAC addresses in target_macs should be stored lower-case."""
    macs = ["AA:BB:CC:DD:EE:FF"]
    ka = ARPKeepAlive(interface="lo", base_ip="10.0.0.", target_macs=macs)
    assert ka.target_macs == ["aa:bb:cc:dd:ee:ff"]
