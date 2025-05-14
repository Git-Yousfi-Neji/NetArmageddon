from enum import Enum
from typing import List

BD_MACADDR = "ff:ff:ff:ff:ff:ff"


class BandType(Enum):
    T_24GHZ = "24GHZ"
    T_50GHZ = "50GHZ"


class SSID:
    def __init__(self, name: str, mac_addr: str, band_type: BandType) -> None:
        self.name: str = name
        self.mac_addr: str = mac_addr
        self.clients: List[str] = []
        self._band_type: BandType = band_type
        self._channel_list: List[int] = []

    def add_channel(self, ch: int) -> None:
        self._channel_list.append(ch)
        self._channel_list = sorted(self._channel_list)

    def add_client(self, mac_addr: str) -> None:
        self.clients.append(mac_addr)

    @property
    def channel(self) -> int:
        return (
            self._channel_list[len(self._channel_list) // 2]
            if len(self._channel_list) > 1
            else self._channel_list[0]
        )


def frequency_to_channel(freq: int) -> int:
    base = 5000 if freq // 1000 == 5 else 2407
    return (freq - base) // 5
