import abc
import logging
import threading
from functools import wraps
from scapy.arch import get_if_list

class BaseAttack(abc.ABC):
    """Abstract base class for network attack modules.
    
    Provides common functionality for:
    - Thread management
    - Rate limiting
    - Interface validation
    - Safety controls
    - Context management
    
    Attributes:
        interface (str): Network interface to use
        running (bool): Attack status flag
        thread (threading.Thread): Attack thread
        logger (logging.Logger): Configured logger
        MAX_PPS (int): Maximum allowed packets per second (safety limit)
    """
    
    MAX_PPS = 100  # Class-wide safety limit
    
    def __init__(self, interface: str):
        """Initialize base attack parameters.
        
        Args:
            interface: Network interface name to use for attack
            
        Raises:
            ValueError: If interface doesn't exist
        """
        self.interface = interface
        self.running = False
        self.thread = None
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self._validate_interface()

    def _validate_interface(self):
        """Verify network interface exists."""
        if self.interface not in get_if_list():
            raise ValueError(f"Interface '{self.interface}' not found. "
                             f"Available interfaces: {get_if_list()}")

    def _rate_limit(self, pps: int) -> int:
        """Enforce packets-per-second safety limit.
        
        Args:
            pps: Requested packets per second
            
        Returns:
            int: Allowed packets per second
            
        Logs:
            Warning when exceeding safety limit
        """
        if pps > self.MAX_PPS:
            self.logger.warning(
                f"Requested {pps} pps exceeds safety limit {self.MAX_PPS}. "
                f"Capping at {self.MAX_PPS} pps."
            )
            return self.MAX_PPS
        return pps

    def requires_active_attack(func):
        """Decorator to ensure method is only called when attack is running."""
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if not self.running:
                raise RuntimeError("Attack must be running to use this method")
            return func(self, *args, **kwargs)
        return wrapper

    @abc.abstractmethod
    def start(self):
        """Start the attack in a background thread."""
        pass

    @abc.abstractmethod
    def stop(self):
        """Stop the attack and clean up resources."""
        pass

    def __enter__(self):
        """Context manager entry point."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit point."""
        self.stop()

    def _base_stop(self):
        """Common stop procedure for all attacks."""
        if self.running:
            self.running = False
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=5)
                if self.thread.is_alive():
                    self.logger.error("Failed to stop attack thread")
            self.logger.info("Attack stopped successfully")

    def validate_mac(self, mac: str) -> bool:
        """Validate MAC address format.
        
        Args:
            mac: MAC address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        parts = mac.split(':')
        return (
            len(parts) == 6 and
            all(0 <= int(p, 16) <= 255 for p in parts)
        )