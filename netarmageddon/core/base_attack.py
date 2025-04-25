import abc
import threading
import logging

class BaseAttack(abc.ABC):
    """Abstract base class for all network attack modules"""
    
    def __init__(self, interface: str):
        """
        Initialize base attack parameters
        
        :param interface: Network interface to use for attack
        """
        self.interface = interface
        self.running = False
        self.thread = None
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Safety limits
        self.MAX_PPS = 100  # Max packets per second
        self._validate_interface()

    def _validate_interface(self):
        """Verify network interface exists"""
        from scapy.arch import get_if_list
        if self.interface not in get_if_list():
            raise ValueError(f"Interface {self.interface} not found")

    @abc.abstractmethod
    def start(self):
        """Start the attack in a separate thread"""
        pass

    @abc.abstractmethod
    def stop(self):
        """Stop the attack and clean up resources"""
        pass

    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()

    def _rate_limit(self, pps: int):
        """Enforce packets-per-second limit"""
        if pps >= self.MAX_PPS:  # Changed from > to >=
            self.logger.warning(f"PPS {pps} exceeds safety limit {self.MAX_PPS}")
            return self.MAX_PPS
        return pps