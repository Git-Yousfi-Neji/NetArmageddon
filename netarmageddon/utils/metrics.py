import time
from typing import Dict


class AttackMetrics:
    """Track attack performance metrics"""

    def __init__(self) -> None:
        self.start_time: float = 0
        self.packets_sent: int = 0
        self.errors: int = 0

    def start_timer(self) -> None:
        self.start_time = time.time()

    def increment_packets(self) -> None:
        self.packets_sent += 1

    def increment_errors(self) -> None:
        self.errors += 1

    def get_stats(self) -> Dict[str, float]:
        duration = time.time() - self.start_time
        return {
            "duration": duration,
            "packets_per_sec": (self.packets_sent / duration if duration > 0 else 0),
            "error_rate": (self.errors / self.packets_sent if self.packets_sent > 0 else 0),
        }
