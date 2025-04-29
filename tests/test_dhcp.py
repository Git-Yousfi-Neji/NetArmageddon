import time
import pytest
from netarmageddon.core.dhcp_exhaustion import DHCPExhaustion
from netarmageddon.cli import parse_option_range
from netarmageddon.cli import parse_mac_address
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

def test_mac_validation():
    # Valid MACs
    valid_macs = ["00:11:22:33:44:55", "aa-bb-cc-dd-ee-ff", "FF:EE:DD:CC:BB:AA"]
    attack = DHCPExhaustion("lo", client_src=valid_macs)
    assert attack.client_src == ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "ff:ee:dd:cc:bb:aa"]

    # Invalid MAC
    with pytest.raises(ValueError):
        DHCPExhaustion("lo", client_src=["invalid"])

def test_device_limit():
    """Verify attack stops after specified number of devices"""
    attack = DHCPExhaustion("lo", num_devices=3)
    attack.start()
    time.sleep(1)  # Allow thread to start
    attack.thread.join(timeout=2)  # Wait for completion

    assert not attack.thread.is_alive()
    assert attack.running is False

def test_device_count_limit():
    """Verify attack stops after specified device count"""
    attack = DHCPExhaustion("lo", num_devices=30)
    attack.start()
    time.sleep(2)  # Allow time for execution
    assert not attack.running, "Attack should auto-stop after 3 devices"

def test_device_limit_with_two_macs(monkeypatch):
    """
    When num_devices=3 but only two MACs are given,
    DHCPExhaustion should send exactly three packets,
    cycling through those two MACs.
    """
    sent_srcs = []

    # Patch sendp to capture the packet.src instead of actually sending
    def fake_sendp(pkt, iface=None, verbose=False):
        sent_srcs.append(pkt.src)

    # Monkey-patch the sendp function in our module
    monkeypatch.setattr(
        'netarmageddon.core.dhcp_exhaustion.sendp',
        fake_sendp,
        raising=True
    )  # :contentReference[oaicite:0]{index=0}

    # Provide exactly two MACs but request three devices
    macs = ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
    attack = DHCPExhaustion(
        interface="lo",
        num_devices=3,
        client_src=macs
    )

    # Start and wait for completion
    attack.start()
    attack.thread.join(timeout=2)  # ensure the thread has time to finish

    # It should have sent exactly 3 packets
    assert len(sent_srcs) == 3, "Should send exactly 3 packets"  # :contentReference[oaicite:1]{index=1}

    # And the sequence should be MAC1, MAC2, MAC1
    expected = [macs[0], macs[1], macs[0]]
    assert sent_srcs == expected, f"Expected cycling {expected}, got {sent_srcs}"

def test_mac_cycling():
    macs = ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
    attack = DHCPExhaustion("lo", client_src=macs, num_devices=3)

    generated = [attack._generate_mac() for _ in range(4)]
    assert generated == ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff",
                        "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]

def test_cli_mac_parsing():
    args = parse_mac_address(["-s", "00:11:22:33:44:55,aa-bb-cc-dd-ee-ff , de:ad:22:33:44:55"])
    assert args.client_src == ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "de:ad:22:33:44:55"]

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