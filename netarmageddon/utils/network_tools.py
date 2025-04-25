import re
import socket
import subprocess
from ipaddress import IPv4Network, IPv4Address
from typing import Optional

def validate_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    try:
        IPv4Address(ip)
        return True
    except ValueError:
        return False

def generate_random_ip(network: str = "192.168.1.0/24") -> str:
    """Generate random IP within a network range."""
    net = IPv4Network(network, strict=False)
    host = net.hosts()
    return str(next(host))

def is_port_available(port: int, interface: str = "0.0.0.0") -> bool:
    """Check if TCP port is available."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((interface, port))
            return True
        except OSError:
            return False

def get_default_gateway() -> Optional[str]:
    """Get system's default gateway IP."""
    try:
        result = subprocess.check_output(["ip", "route", "show", "default"])
        return result.decode().split()[2]
    except (subprocess.CalledProcessError, IndexError):
        return None