import abc
import logging
import threading
from functools import wraps
from typing import Any, Callable, Optional, Type, TypeVar

from scapy.arch import get_if_list

F = TypeVar("F", bound=Callable[..., Any])


class BaseAttack(abc.ABC):
    """Abstract base class for network attack modules."""

    MAX_PPS: int = 100  # Class-wide safety limit

    def __init__(self, interface: str) -> None:
        """Initialize base attack parameters."""
        self.interface: str = interface
        self.running: bool = False
        self.thread: Optional[threading.Thread] = None
        self.logger: logging.Logger = logging.getLogger(self.__class__.__name__)
        self._validate_interface()

    def _validate_interface(self) -> None:
        """Verify network interface exists."""
        if self.interface not in get_if_list():
            raise ValueError(
                f"Interface '{self.interface}' not found. " f"Available interfaces: {get_if_list()}"
            )

    def _rate_limit(self, pps: int) -> int:
        """
        Enforce packets-per-second safety limit.

        Args:
            pps: Requested packets per second

        Returns:
            Allowed packets per second
        """
        if pps > self.MAX_PPS:
            self.logger.warning(
                f"Requested {pps} pps exceeds safety limit {self.MAX_PPS}. "
                f"Capping at {self.MAX_PPS} pps."
            )
            return self.MAX_PPS
        return pps

    @staticmethod
    def requires_active_attack(func: F) -> F:
        """
        Decorator to ensure method is only called when attack is running.
        Raises RuntimeError otherwise.
        """

        @wraps(func)
        def wrapper(self: "BaseAttack", *args: Any, **kwargs: Any) -> Any:
            if not self.running:
                raise RuntimeError("Attack must be running to use this method")
            return func(self, *args, **kwargs)

        return wrapper  # type: ignore

    @abc.abstractmethod
    def start(self) -> None:
        """Start the attack in a background thread."""
        ...

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop the attack and clean up resources."""
        ...

    def __enter__(self) -> "BaseAttack":
        """Context manager entry point."""
        self.start()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None:
        """Context manager exit point."""
        self.stop()

    def _base_stop(self) -> None:
        """Common stop procedure for all attacks."""
        if self.running:
            self.running = False
            if self.thread and self.thread.is_alive():
                try:
                    self.thread.join(timeout=5)
                except Exception as e:
                    self.logger.error(f"Thread join error: {e}")
                finally:
                    if self.thread.is_alive():
                        self.logger.error("Failed to stop attack thread")
            self.logger.info("Attack stopped successfully")

    def validate_mac(self, mac: str) -> bool:
        """Validate MAC address format."""
        try:
            parts = mac.split(":")
            if len(parts) != 6:
                return False
            return all(0 <= int(p, 16) <= 0xFF for p in parts)
        except ValueError:
            return False
