import pytest
from scapy.packet import Packet
from scapy.layers.dot11 import Dot11AssoResp, Dot11ReassoResp, Dot11QoS

from netarmageddon.core.deauth import Interceptor


# Reset abort flag
@pytest.fixture(autouse=True)
def reset_abort():
    Interceptor._ABORT = False
    yield
    Interceptor._ABORT = False


# Parsing utilities


def test_parse_custom_ssid_name_none():
    assert Interceptor.parse_custom_ssid_name(None) is None


@pytest.mark.parametrize("ssid", ["network", "myssid"])
def test_parse_custom_ssid_name_valid(ssid):
    assert Interceptor.parse_custom_ssid_name(ssid) == ssid


def test_parse_custom_ssid_name_empty():
    with pytest.raises(Exception):
        Interceptor.parse_custom_ssid_name("")


# MAC verification


def test_verify_mac_addr_valid():
    valid = "aa:bb:cc:dd:ee:ff"
    assert Interceptor.verify_mac_addr(valid) == valid


@pytest.mark.parametrize("mac", ["invalid"])
def test_verify_mac_addr_invalid(mac):
    with pytest.raises(Exception):
        Interceptor.verify_mac_addr(mac)


# Parse custom BSSID


def test_parse_custom_bssid_addr_none():
    assert Interceptor.parse_custom_bssid_addr(None) is None


@pytest.mark.parametrize("bssid,expect_exc", [("aa:bb:cc:dd:ee:ff", False), ("badmac", True)])
def test_parse_custom_bssid_addr(bssid, expect_exc):
    if expect_exc:
        with pytest.raises(Exception):
            Interceptor.parse_custom_bssid_addr(bssid)
    else:
        assert Interceptor.parse_custom_bssid_addr(bssid) == bssid


# Parse custom client MACs


def test_parse_custom_client_mac_none():
    assert Interceptor.parse_custom_client_mac(None) == []


def test_parse_custom_client_mac_valid():
    macs = "aa:bb:cc:dd:ee:ff"
    result = Interceptor.parse_custom_client_mac(macs)
    assert result == [macs]


def test_parse_custom_client_mac_invalid():
    with pytest.raises(Exception):
        Interceptor.parse_custom_client_mac("badmac")


# Parse custom channels via direct method call


def make_interceptor():
    # minimal instance: skip monitor, no parsing side-effects on init
    inst = Interceptor(
        net_iface='lo',
        skip_monitor_mode_setup=True,
        kill_networkmanager=False,
        ssid_name=None,
        bssid_addr=None,
        custom_client_macs=None,
        custom_channels=None,
        deauth_all_channels=False,
        autostart=False,
        debug_mode=False,
    )
    return inst


def test_parse_custom_channels_success():
    inst = make_interceptor()
    inst._channel_range = {1: {}, 6: {}, 11: {}, 36: {}}
    assert inst.parse_custom_channels("1,6,11") == [1, 6, 11]


def test_parse_custom_channels_invalid_format():
    inst = make_interceptor()
    inst._channel_range = {1: {}, 2: {}}
    with pytest.raises(Exception):
        inst.parse_custom_channels("a,b")


def test_parse_custom_channels_unsupported():
    inst = make_interceptor()
    inst._channel_range = {1: {}, 3: {}}
    with pytest.raises(Exception):
        inst.parse_custom_channels("1,2")


# Packet confirms client


def make_pkt(layer, **attrs):
    # Dummy packet with haslayer and getlayer
    class DummyLayer:
        pass

    dummy = DummyLayer()
    for k, v in attrs.items():
        setattr(dummy, k, v)
    pkt = Packet()
    pkt.haslayer = lambda lay: lay == layer
    pkt.getlayer = lambda lay: dummy if lay == layer else None
    return pkt


@pytest.mark.parametrize(
    "layer,attrs",
    [(Dot11AssoResp, {'status': 0}), (Dot11ReassoResp, {'status': 0}), (Dot11QoS, {})],
)
def test_packet_confirms_client_positive(layer, attrs):
    pkt = make_pkt(layer, **attrs)
    assert Interceptor._packet_confirms_client(pkt)


def test_packet_confirms_client_negative():
    pkt = Packet()
    pkt.haslayer = lambda lay: False
    assert not Interceptor._packet_confirms_client(pkt)


# Init channels generator without triggering parse_custom channels


def test_init_channels_generator():
    inst = make_interceptor()
    inst._channel_range = {1: {}, 2: {}, 3: {}}
    inst._deauth_all_channels = True
    gen = inst._init_channels_generator()
    seq = [next(gen) for _ in range(5)]
    assert seq == [1, 2, 3, 1, 2]


# Abort run raises SystemExit


def test_abort_run(monkeypatch):
    monkeypatch.setattr('builtins.exit', lambda code=0: (_ for _ in ()).throw(SystemExit(code)))
    with pytest.raises(SystemExit) as exc:
        Interceptor.abort_run("msg")
    assert exc.value.code == 0
    assert Interceptor._ABORT
