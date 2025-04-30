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
