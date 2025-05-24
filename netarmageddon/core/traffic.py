import ctypes
import logging
import threading
import time
from scapy.arch import get_if_list
from typing import Optional

from netarmageddon.core.mapper import TrafficCaptureConfig
from netarmageddon.core.mapper import _lib as _traffic_lib


class TrafficLogger:
    """Traffic capture implementation with proper signal handling."""

    def __init__(
        self,
        interface: str,
        bpf_filter: str,
        output_file: str,
        duration: int,
        count: int,
        snaplen: int,
        promisc: bool,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.output_file = output_file
        self.duration = duration
        self.count = count
        self.snaplen = snaplen
        self.promisc = promisc
        self.running = False
        self.logger = logging.getLogger(self.__class__.__name__)
        self.capture_thread: Optional[threading.Thread] = None
        self.timer_thread: Optional[threading.Thread] = None

        self._validate_interface()

    def _validate_interface(self) -> None:
        """Verify network interface exists."""
        if self.interface not in get_if_list():
            raise ValueError(
                f"Interface '{self.interface}' not found. " f"Available interfaces: {get_if_list()}"
            )

    def start(self) -> None:
        """Start capture threads."""
        if self.running:
            return
        self.running = True

        self.capture_thread = threading.Thread(
            target=self._run_capture, name="TrafficCaptureThread", daemon=True
        )
        self.capture_thread.start()
        self.logger.info("Traffic capture thread started")

        if self.duration > 0:
            self.timer_thread = threading.Thread(
                target=self._stop_after_delay, name="TrafficTimerThread", daemon=True
            )
            self.timer_thread.start()
            self.logger.info(f"Timer thread will stop capture in {self.duration}s")

    def _stop_after_delay(self) -> None:
        """Automatic stop after duration expires."""
        time.sleep(self.duration)
        self.stop()

    def _run_capture(self) -> None:
        """Main capture loop interacting with C library."""
        self.logger.info(
            f"Running capture with [iface={self.interface}] "
            f"[filter={self.bpf_filter}] [out={self.output_file}] "
            f"[duration={self.duration}] [max_packets={self.count}] "
            f"[snaplen={self.snaplen}] [promisc={self.promisc}]"
        )
        cfg = TrafficCaptureConfig(
            interface=self.interface.encode("utf-8"),
            bpf_filter=self.bpf_filter.encode("utf-8"),
            output_file=self.output_file.encode("utf-8"),
            duration=self.duration,
            max_packets=self.count,
            snaplen=self.snaplen,
            promisc=self.promisc,
        )
        ret = _traffic_lib.traffic_capture_start(ctypes.byref(cfg))
        if ret != 0:
            err = _traffic_lib.traffic_get_last_error()
            self.logger.error(f"Capture failed: {err.decode() if err else 'unknown error'}")
        self.running = False

    def stop(self) -> None:
        """Clean shutdown procedure."""
        if not self.running:
            return

        self.logger.info("Initiating traffic capture shutdown")
        _traffic_lib.traffic_capture_stop()

        # Join threads with timeout
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
            if self.capture_thread.is_alive():
                self.logger.error("Capture thread failed to terminate")

        if self.timer_thread and self.timer_thread.is_alive():
            self.timer_thread.join(timeout=1)

        self.running = False
        self.logger.info("Traffic capture fully stopped")

    def user_abort(self) -> None:
        """Public method for signal handlers."""
        self.logger.info("User requested graceful shutdown")
        self.stop()

    def __enter__(self) -> "TrafficLogger":
        try:
            self.start()
            return self
        except Exception as e:
            self.logger.error(f"Failed to start capture: {str(e)}")
            raise  # Re-raise for visibility

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            self.stop()
        except Exception as e:
            self.logger.error(f"Error during shutdown: {str(e)}")
