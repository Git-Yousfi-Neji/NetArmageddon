# API Reference (Work in Progress)

## Core Modules

### `DHCPExhaustion`
```python
class DHCPExhaustion(BaseAttack):
    def __init__(self, interface: str, num_devices: int = 50)
    def start(self) -> None
    def stop(self) -> None
```

### `ARPKeepAlive`
```python
class ARPKeepAlive(BaseAttack):
    def __init__(self, interface: str, base_ip: str, num_devices: int = 50)
    def start(self) -> None
    def stop(self) -> None
```

### `TrafficLogger`
```python
class TrafficLogger(BaseAttack):
    def __init__(
        self,
        interface: str,
        bpf_filter: str,
        output_file: str,
        duration: int = 0,
        count: int = 0,
        snaplen: int = 65535,
        promisc: bool = False,
    )
    def start(self) -> None
    def stop(self) -> None

    """
    Captures live network traffic into a PCAP file.

    Args:
        interface: Name of the network interface (e.g., "eth0").
        bpf_filter: BPF filter string (e.g., "tcp port 80").
        output_file: Path to write the .pcap file.
        duration: Max capture time in seconds (0 = unlimited).
        count: Max packet count (0 = unlimited).
        snaplen: Max bytes per packet.
        promisc: Enable interface promiscuous mode.
    """
```
### `Deauth`
```python
class Deauth(BaseAttack):
    def __init__(
        self,
        interface: str,
        *,
        clients: Optional[str] = None,
        skip_monitormode: bool = False,
        kill: bool = False,
        deauth_all_channels: bool = False,
        channels: Optional[str] = None,
        ssid: Optional[str] = None,
        bssid: Optional[str] = None,
        autostart: bool = False,
        dry_run: bool = False,
        debug: bool = False,
    ) -> None

    def run(self): -> None

    """
    Perform a Wi-Fi deauthentication attack against an AP or specific clients.

    Args:
        interface: Wireless interface in monitor mode (e.g., "wlan0mon").
        clients: Comma-separated list of client MAC addresses to target.
        skip_monitormode: Assume interface already in monitor mode.
        kill: Stop NetworkManager before attack.
        deauth_all_channels: Cycle through all channels for broadcast deauth.
        channels: Comma-separated list of specific channels to target.
        ssid: Custom SSID filter to attack only a named network.
        bssid: Custom BSSID filter to attack only a specific AP.
        autostart: Automatically select the only found AP without prompt.
        dry_run: Do not actually send packets; simulate only.
        debug: Enable verbose debug output.
    """
```
