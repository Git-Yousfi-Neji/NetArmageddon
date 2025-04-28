import pytest
from netarmageddon.core.dhcp_exhaustion import DHCPExhaustion
from netarmageddon.cli import parse_option_range
from scapy.all import DHCP
from scapy.layers.dhcp import IP, DHCP, BOOTP
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether

def test_dhcp_initialization():
    """Test DHCPExhaustion class initialization"""
    dhcp = DHCPExhaustion("lo", 10)  # Using loopback interface
    assert dhcp.num_devices == 10
    assert dhcp.interface == "lo"

def test_option_parsing():
    assert parse_option_range("1") == [1]
    assert parse_option_range("1-3") == [1,2,3]
    assert parse_option_range("1,3-5") == [1,3,4,5]
    assert parse_option_range("6,10-12,15") == [6,10,11,12,15]

def test_dhcp_packet_options():
    # Test custom options
    attack = DHCPExhaustion("lo", request_options=[1,3,6])
    packet = attack._create_dhcp_packet()
    dhcp_layer = packet[DHCP]

    param_req = next(opt for opt in dhcp_layer.options if opt[0] == 'param_req_list')
    assert param_req[1] == [1,3,6]

def test_invalid_options():
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