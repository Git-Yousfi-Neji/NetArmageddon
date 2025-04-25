import pytest
from netarmageddon.core.dhcp_exhaustion import DHCPExhaustion

def test_dhcp_initialization():
    """Test DHCPExhaustion class initialization"""
    dhcp = DHCPExhaustion("lo", 10)  # Using loopback interface
    assert dhcp.num_devices == 10
    assert dhcp.interface == "lo"

def test_mac_generation():
    """Test MAC address generation uniqueness"""
    dhcp = DHCPExhaustion("lo", 100)
    macs = set()
    for _ in range(100):
        mac = dhcp._generate_mac()
        assert mac not in macs
        macs.add(mac)

def test_packet_creation():
    """Test DHCP packet structure"""
    dhcp = DHCPExhaustion("lo", 1)
    packet = dhcp._create_dhcp_packet()
    assert packet.haslayer(DHCP)
    assert packet[DHCP].options[0][1] == 1  # DHCP Discover