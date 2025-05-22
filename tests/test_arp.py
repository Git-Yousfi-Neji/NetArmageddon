import time
from unittest.mock import MagicMock, patch

import pytest
from netarmageddon.core.arp_keepalive import ARPKeepAlive
from scapy.layers.l2 import ARP, Ether


def test_arp_initialization() -> None:
    """Test ARPKeepAlive class initialization"""
    arp = ARPKeepAlive("lo", "192.168.1.")
    assert arp.base_ip == "192.168.1."
    assert arp.num_devices == 50


def test_ip_validation() -> None:
    """Test base IP validation"""
    with pytest.raises(ValueError):
        ARPKeepAlive("lo", "192.168.1")  # Missing trailing dot

    with pytest.raises(ValueError):
        ARPKeepAlive("lo", "192.168.1.100.")  # Extra dot


def test_arp_packet_generation() -> None:
    """Test ARP packet structure"""
    arp = ARPKeepAlive("lo", "10.0.0.", num_devices=1)
    packet = arp._generate_arp_packet(1)

    assert packet.haslayer(Ether)
    assert packet.haslayer(ARP)
    assert packet[ARP].op == 1  # ARP who-has
    assert packet[ARP].psrc == "10.0.0.1"
    assert packet[ARP].pdst == "10.0.0.1"
    assert packet[Ether].dst == "ff:ff:ff:ff:ff:ff"


@patch("netarmageddon.core.arp_keepalive.sendp")
def test_arp_announcements(mock_sendp: MagicMock) -> None:
    """Test ARP announcement sending"""
    arp = ARPKeepAlive("lo", "127.0.0.", num_devices=20)
    arp.start()
    time.sleep(0.5)  # Allow time for one cycle
    arp.stop()

    # Verify at least 2 packets sent (one for each device)
    assert mock_sendp.call_count >= 2
    first_packet = mock_sendp.call_args_list[0][0][0]
    assert first_packet[ARP].psrc.startswith("127.0.0.")


def test_thread_management() -> None:
    """Test ARP thread start/stop"""
    arp = ARPKeepAlive("lo", "127.0.0.")
    arp.start()
    assert arp.running is True
    assert arp.thread is not None
    assert arp.thread.is_alive()

    arp.stop()
    assert arp.running is False
    assert not arp.thread.is_alive()


@patch("netarmageddon.core.arp_keepalive.sendp")
def test_arp_cycles(mock_sendp: MagicMock) -> None:
    """Test ARP announcement cycles"""
    arp = ARPKeepAlive("lo", "127.0.0.", num_devices=2, interval=0.1, cycles=2)
    arp.start()
    assert arp.thread is not None
    arp.thread.join()  # Wait for the thread to finish

    # Expecting 2 cycles * 2 devices = 4 packets
    assert mock_sendp.call_count == 4


def test_arp_cycles_count_and_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Given num_devices=2 and cycles=3, ARPKeepAlive should send exactly
    2*3 = 6 packets, then stop running.
    We patch both sendp and _rate_limit to ensure all sends happen.
    """
    sent = []
    (NUM_DEVICES, CYCLES) = (2, 3)

    # 1) Patch sendp so no real sockets are opened
    monkeypatch.setattr(
        "netarmageddon.core.arp_keepalive.sendp",
        lambda pkt, iface=None, verbose=False: sent.append(pkt.psrc),
    )

    # 2) Patch rate limiter to return a very high pps (so delay is nearly zero)
    monkeypatch.setattr(ARPKeepAlive, "_rate_limit", lambda self, pps: pps * 100)

    # Create with 2 devices, 3 cycles, tiny interval
    arp = ARPKeepAlive(
        interface="lo",
        base_ip="192.168.0.",
        num_devices=NUM_DEVICES,
        interval=0.01,
        cycles=CYCLES,
    )

    arp.start()
    # Wait up to 1s for thread to finish
    assert arp.thread is not None
    arp.thread.join(timeout=1)

    # Should have sent exactly 6 ARP packets
    assert len(sent) == NUM_DEVICES * CYCLES, f"Expected {2*3} packets, got {len(sent)}"

    # The thread must be done and running=False
    assert not arp.running
    if arp.thread is not None:
        assert not arp.thread.is_alive()
