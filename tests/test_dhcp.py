import pytest
from netarmageddon.core.dhcp_exhaustion import DHCPExhaustion
from scapy.all import DHCP
from scapy.layers.dhcp import IP, DHCP, BOOTP
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether

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
    
    assert packet.haslayer(Ether)
    assert packet.haslayer(IP)
    assert packet.haslayer(UDP)
    assert packet.haslayer(BOOTP)
    assert packet.haslayer(DHCP)
    
    # Verify DHCP Discover message type
    dhcp_layer = packet[DHCP]
    discover_option = [opt for opt in dhcp_layer.options if opt[0] == 'message-type']
    assert discover_option[0][1] == 'discover'  # Use string value