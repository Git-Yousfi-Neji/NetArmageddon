import random
import re
import logging
import threading
import time
from typing import Optional
from scapy.all import sendp
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.arch import get_if_list


class ARPKeepAlive:
    """Maintain fake devices in router's ARP table"""

    MAX_PPS: int = 100  # Safety limit for packets per second

    def __init__(
        self,
        interface: str,
        base_ip: str,
        num_devices: int = 50,
        mac_prefix: str = "de:ad:00",
        interval: float = 5.0,
        cycles: int = 1,
    ):
        self.interface = interface
        self.base_ip = base_ip
        self.num_devices = num_devices
        self.mac_prefix = mac_prefix
        self.interval = interval
        self.cycles = cycles
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger(self.__class__.__name__)

        self._validate_interface()
        self._validate_ip()
        self._validate_mac_prefix()

    def _validate_interface(self) -> None:
        """Verify network interface exists"""
        if self.interface not in get_if_list():
            raise ValueError(
                f"Interface '{self.interface}' not found. " f"Available: {get_if_list()}"
            )

    def _validate_ip(self) -> None:
        """Validate base IP format"""
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.$", self.base_ip):
            raise ValueError("Invalid base IP. Use format like '192.168.1.'")

    def _validate_mac_prefix(self) -> None:
        """Validate MAC prefix format"""
        if not re.match(r"^([0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}$", self.mac_prefix):
            raise ValueError("Invalid MAC prefix. Use format like 'de:ad:00'")

    def _rate_limit(self, pps: int) -> int:
        """Enforce packets-per-second safety limit"""
        if pps > self.MAX_PPS:
            self.logger.warning(f"Capping rate from {pps} to {self.MAX_PPS} pps " "(safety limit)")
            return self.MAX_PPS
        return pps

    def _generate_mac(self, ip_suffix: int) -> str:
        """Generate deterministic MAC based on IP suffix"""
        return (
            f"{self.mac_prefix}:"
            f"{ip_suffix:02x}:"
            f"{random.randint(0, 0xff):02x}:"
            f"{random.randint(0, 0xff):02x}"
        )

    def _generate_arp_packet(self, ip_suffix: int) -> Packet:
        """Create ARP announcement packet"""
        ip = f"{self.base_ip}{ip_suffix}"
        mac = self._generate_mac(ip_suffix)
        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac, psrc=ip, pdst=ip)

    def _send_arp_announcements(self) -> None:
        """Main ARP sending loop with rate limiting"""
        try:
            pps = max(1, self.num_devices)
            allowed_pps = self._rate_limit(pps)
            delay = 1.0 / allowed_pps

            for cycle in range(1, self.cycles + 1):
                if not self.running:
                    break

                for i in range(1, self.num_devices + 1):
                    if not self.running:
                        break
                    pkt = self._generate_arp_packet(i)
                    try:
                        sendp(pkt, iface=self.interface, verbose=False)
                        self.logger.info(f"Sent ARP for {pkt.psrc}")
                    except PermissionError as e:
                        self.logger.error(f"Permission error: {e}")
                    time.sleep(delay)

                if cycle < self.cycles and self.running:
                    time.sleep(self.interval)

        finally:
            self.running = False
            self.logger.info("ARP cycles completed")

    def start(self) -> None:
        """Start ARP maintenance thread"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(
                target=self._send_arp_announcements, name="ARPKeepAliveThread"
            )
            self.thread.start()
            self.logger.info(f"Started ARP keep-alive for {self.num_devices} devices")

    def stop(self) -> None:
        """Stop ARP maintenance safely"""
        self.running = False
        if self.thread and self.thread.is_alive():
            if threading.current_thread() is not self.thread:
                self.thread.join(timeout=5)
                if self.thread.is_alive():
                    self.logger.error("ARP thread failed to stop")
        self.logger.info("ARP keep-alive stopped")

    def user_abort(self) -> None:
        """Handle graceful shutdown from SIGINT"""
        self.logger.info("User requested ARP stop")
        self.stop()

    def __enter__(self) -> "ARPKeepAlive":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
