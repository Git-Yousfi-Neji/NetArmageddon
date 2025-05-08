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
