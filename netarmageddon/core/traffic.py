import ctypes
import sys
import threading
import time
from scapy.arch import get_if_list
from typing import Optional

from netarmageddon.core.mapper import TrafficCaptureConfig
from netarmageddon.core.mapper import _lib as _traffic_lib
from netarmageddon.utils.output_manager import HEAD, INFO, DEBUG, WARNING, ERROR, CMD, CLEAR


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
        self.capture_thread: Optional[threading.Thread] = None
        self.timer_thread: Optional[threading.Thread] = None
        self._stopped = False
        self.start_time = time.time()

        self._validate_interface()

        HEAD("Traffic Capture Configuration")
        CMD(f"┣ Interface: {interface}")
        CMD(f"┣ Filter: {bpf_filter}")
        CMD(f"┣ Output: {output_file}")
        CMD(f"┗ Duration: {duration}s | Max packets: {count}")

    def _validate_interface(self) -> None:
        """Verify network interface exists."""
        DEBUG(f"Validating interface: {self.interface}")
        if self.interface not in get_if_list():
            ERROR(f"Interface {self.interface} not found!")
            CMD(f"Available interfaces: {', '.join(get_if_list())}")
            raise ValueError(f"Interface '{self.interface}' not found")
        INFO("Network interface validated")

    def start(self) -> None:
        """Start capture threads."""
        if self.running:
            return

        self.running = True
        self._stopped = False

        self.capture_thread = threading.Thread(
            target=self._run_capture, name="TrafficCaptureThread", daemon=True
        )
        self.capture_thread.start()
        CMD("🚀 Traffic capture started")

        if self.duration > 0:
            self.timer_thread = threading.Thread(
                target=self._stop_after_delay, name="TrafficTimerThread", daemon=True
            )
            self.timer_thread.start()
            INFO(f"Auto-stop timer set for {self.duration}s")

    def _stop_after_delay(self) -> None:
        """Automatic stop after duration expires."""
        time.sleep(self.duration)
        self.stop()

    def _run_capture(self) -> None:
        """Main capture loop interacting with C library."""
        INFO("Initializing packet capture")
        DEBUG(
            f"Capture params: iface={self.interface} "
            f"filter={self.bpf_filter} "
            f"out={self.output_file} "
            f"max_pkts={self.count} "
            f"snaplen={self.snaplen} "
            f"promisc={self.promisc}"
        )

        try:
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

            # Add packet count completion check
            if ret == 0 and self.count > 0:
                INFO(f"Captured {self.count} packets - stopping")

        except Exception as e:
            ERROR(f"Capture error: {str(e)}")
        finally:
            self.stop()

    def stop(self) -> None:
        """Clean shutdown procedure."""
        if self._stopped or not self.running:
            return

        DEBUG("Initiating capture shutdown")
        self.running = False
        _traffic_lib.traffic_capture_stop()

        # Modified thread cleanup
        current_thread = threading.current_thread()

        if self.capture_thread and self.capture_thread.is_alive():
            if current_thread is not self.capture_thread:
                self.capture_thread.join(timeout=5)
                if self.capture_thread.is_alive():
                    WARNING("Capture thread termination delayed")
            else:
                DEBUG("Skipping self-join of capture thread")

        if self.timer_thread and self.timer_thread.is_alive():
            if current_thread is not self.timer_thread:
                self.timer_thread.join(timeout=1)

        if sys.stdout.isatty():
            CLEAR()

        duration = time.time() - self.start_time
        CMD(f"Capture duration: {duration:.1f}s")
        CMD("✔ Traffic capture stopped")
        self._stopped = True

    def user_abort(self) -> None:
        """Public method for signal handlers."""
        CLEAR()
        WARNING("User requested capture stop")
        self.stop()

    def __enter__(self) -> "TrafficLogger":
        try:
            self.start()
            return self
        except Exception as e:
            ERROR(f"Start failed: {str(e)}")
            raise

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self._stopped:
            self.stop()
