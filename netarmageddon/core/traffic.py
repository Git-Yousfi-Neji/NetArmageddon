import argparse
import ctypes
import os

# load the shared lib
_lib = ctypes.CDLL(
    os.path.join(os.path.dirname(__file__), "traffic_logger_c", "libtraffic.so")
)


# match the C struct:
class TrafficCaptureConfig(ctypes.Structure):
    _fields_ = [
        ("interface", ctypes.c_char_p),
        ("bpf_filter", ctypes.c_char_p),
        ("output_file", ctypes.c_char_p),
        ("duration", ctypes.c_int),
        ("max_packets", ctypes.c_int),
        ("snaplen", ctypes.c_int),
        ("promisc", ctypes.c_bool),
    ]


# prototypes
_lib.traffic_capture_start.argtypes = [ctypes.POINTER(TrafficCaptureConfig)]
_lib.traffic_capture_start.restype = ctypes.c_int

_lib.traffic_capture_stop.argtypes = []
_lib.traffic_capture_stop.restype = None

_lib.traffic_get_last_error.argtypes = []
_lib.traffic_get_last_error.restype = ctypes.c_char_p


# helper to fire it up from argparse args
def start_capture_from_args(args: argparse.Namespace) -> None:
    cfg = TrafficCaptureConfig(
        interface=args.interface.encode("utf-8"),
        bpf_filter=args.filter.encode("utf-8"),
        output_file=args.output.encode("utf-8"),
        duration=args.duration,
        max_packets=args.count,
        snaplen=args.snaplen,
        promisc=bool(args.promisc),
    )
    ret = _lib.traffic_capture_start(ctypes.byref(cfg))
    if ret != 0:
        err = _lib.traffic_get_last_error()
        raise RuntimeError(f"Capture failed: {err.decode('utf-8')}")
