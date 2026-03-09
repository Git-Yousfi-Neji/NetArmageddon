import ctypes
import threading
import time
from typing import Optional

from scapy.arch import get_if_list

from netarmageddon.core.mapper import TrafficCaptureConfig
from netarmageddon.core.mapper import _lib as _traffic_lib
from netarmageddon.utils.output_manager import (
    HEAD,
    INFO,
    DEBUG,
    WARNING,
    ERROR,
    CMD,
    SUCCESS,
    BOLD,
    RESET,
    BRIGHT_GREEN,
    BRIGHT_CYAN,
    BRIGHT_WHITE,
    BRIGHT_YELLOW,
    THIN_DELIM,
)


class TrafficLogger:
    """Traffic capture implementation using the libpcap C backend."""

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

        HEAD("◈  Traffic Capture — Configuration")
        CMD(f"  {'Interface':<20} {BRIGHT_CYAN}{interface}{RESET}")
        CMD(f"  {'BPF Filter':<20} {BRIGHT_CYAN}{bpf_filter or '(none)'}{RESET}")
        CMD(f"  {'Output file':<20} {BRIGHT_CYAN}{output_file}{RESET}")
        CMD(f"  {'Duration':<20} {BRIGHT_CYAN}{f'{duration}s' if duration else 'unlimited'}{RESET}")
        CMD(f"  {'Max packets':<20} {BRIGHT_CYAN}{count if count else 'unlimited'}{RESET}")
        CMD(f"  {'Snap length':<20} {BRIGHT_CYAN}{snaplen} bytes{RESET}")
        CMD(f"  {'Promiscuous':<20} {BRIGHT_GREEN if promisc else BRIGHT_YELLOW}{promisc}{RESET}")
        CMD(THIN_DELIM)

    def _validate_interface(self) -> None:
        DEBUG(f"Validating interface: {self.interface}")
        if self.interface not in get_if_list():
            ERROR(f"Interface '{self.interface}' not found!")
            CMD(f"  Available: {BRIGHT_CYAN}{', '.join(get_if_list())}{RESET}")
            raise ValueError(f"Interface '{self.interface}' not found")
        INFO(f"Interface {BOLD}{BRIGHT_CYAN}{self.interface}{RESET} validated")

    def start(self) -> None:
        if self.running:
            return

        self.running = True
        self._stopped = False

        self.capture_thread = threading.Thread(
            target=self._run_capture, name="TrafficCaptureThread", daemon=True
        )
        self.capture_thread.start()
        INFO(f"🚀 Capture started → {BOLD}{BRIGHT_CYAN}{self.output_file}{RESET}")

        if self.duration > 0:
            self.timer_thread = threading.Thread(
                target=self._stop_after_delay, name="TrafficTimerThread", daemon=True
            )
            self.timer_thread.start()
            INFO(f"  Auto-stop in {BOLD}{BRIGHT_YELLOW}{self.duration}s{RESET}")

    def _stop_after_delay(self) -> None:
        time.sleep(self.duration)
        self.stop()

    def _run_capture(self) -> None:
        INFO("  Initialising pcap capture engine")
        DEBUG(
            f"  iface={self.interface} filter={self.bpf_filter!r} "
            f"out={self.output_file} max={self.count} snaplen={self.snaplen} promisc={self.promisc}"
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

            if ret != 0:
                err = _traffic_lib.traffic_get_last_error()
                msg = err.decode() if err else "unknown"
                ERROR(f"Capture error from C backend: {msg}")
            elif self.count > 0:
                SUCCESS(f"Packet limit of {self.count} reached")

        except Exception as e:
            ERROR(f"Capture exception: {str(e)}")
        finally:
            self.stop()

    def stop(self) -> None:
        if self._stopped or not self.running:
            return

        DEBUG("Initiating capture shutdown")
        self.running = False
        _traffic_lib.traffic_capture_stop()

        current = threading.current_thread()

        if self.capture_thread and self.capture_thread.is_alive():
            if current is not self.capture_thread:
                self.capture_thread.join(timeout=5)
                if self.capture_thread.is_alive():
                    WARNING("Capture thread shutdown delayed")

        if self.timer_thread and self.timer_thread.is_alive():
            if current is not self.timer_thread:
                self.timer_thread.join(timeout=1)

        duration = time.time() - self.start_time
        INFO(f"  Total duration: {BOLD}{BRIGHT_WHITE}{duration:.1f}s{RESET}")
        SUCCESS(f"Traffic capture complete → {BOLD}{BRIGHT_CYAN}{self.output_file}{RESET}")
        self._stopped = True

    def user_abort(self) -> None:
        WARNING("User requested capture stop")
        self.stop()

    def __enter__(self) -> "TrafficLogger":
        self.start()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if not self._stopped:
            self.stop()
