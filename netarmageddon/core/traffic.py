import ctypes
import threading
import time

from netarmageddon.core.base_attack import BaseAttack
from netarmageddon.core.mapper import TrafficCaptureConfig
from netarmageddon.core.mapper import _lib as _traffic_lib


class TrafficLogger(BaseAttack):
    """
    TrafficLogger runs the C-based PCAP dump in a background thread,
    stopping cleanly on Ctrl+C via pcap_breakloop().
    """

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
        super().__init__(interface)
        self.bpf_filter = bpf_filter
        self.output_file = output_file
        self.duration = duration
        self.count = count
        self.snaplen = snaplen
        self.promisc = promisc
        self.capture_thread: threading.Thread
        self.timer_thread: threading.Thread

    def start(self) -> None:
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
        time.sleep(self.duration)
        if self.running:
            self.logger.info(f"Duration {self.duration}s elapsed; stopping capture")
            self.stop()

    def _run_capture(self) -> None:
        self.logger.info(
            f"Running capture with [iface={self.interface}] "
            f"[filter={self.bpf_filter}] [out={self.output_file}] "
            f"[duration={self.duration}] [max_packets={self.count}] "
            f"[snaplen={self.snaplen}] [promisc={self.promisc}]"
        )
        # build the C struct
        cfg = TrafficCaptureConfig(
            interface=self.interface.encode("utf-8"),
            bpf_filter=self.bpf_filter.encode("utf-8"),
            output_file=self.output_file.encode("utf-8"),
            duration=self.duration,
            max_packets=self.count,
            snaplen=self.snaplen,
            promisc=self.promisc,
        )
        self.logger.info("TrafficLogger started in _run_capture")
        ret = _traffic_lib.traffic_capture_start(ctypes.byref(cfg))
        if ret != 0:
            err = _traffic_lib.traffic_get_last_error()
            self.logger.error(f"Capture failed: {err.decode() if err else 'unknown error'}")
        else:
            self.logger.info("Capture finished")
        # ensure we mark stopped
        self.running = False

    def stop(self) -> None:
        if not self.running:
            return
        self.logger.info("TrafficLogger stop is called")
        # interrupt the C-level pcap_next_ex()
        _traffic_lib.traffic_capture_stop()
        # wait for thread to exit (because daemon=False)
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                self.logger.error("TrafficLogger thread failed to stop in 5s")
        self.running = False
        self.logger.info("TrafficLogger stopped successfully")
