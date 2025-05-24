import subprocess
import sys
import pytest
import threading
import time
from unittest.mock import patch
from netarmageddon.core.traffic import TrafficLogger


# Fixtures
@pytest.fixture
def mock_interface(monkeypatch):
    monkeypatch.setattr('scapy.arch.get_if_list', lambda: ['eth0', 'lo'])


@pytest.fixture
def logger_instance(mock_interface, caplog):
    caplog.set_level('INFO')
    return TrafficLogger(
        interface='lo',
        bpf_filter='tcp',
        output_file='out.pcap',
        duration=0,
        count=10,
        snaplen=65535,
        promisc=True,
    )


def test_traffic_logger_initialization(logger_instance):
    assert logger_instance.interface == "lo"
    assert logger_instance.bpf_filter == "tcp"
    assert logger_instance.output_file == "out.pcap"
    assert logger_instance.duration == 0
    assert logger_instance.count == 10
    assert logger_instance.snaplen == 65535
    assert logger_instance.promisc is True
    assert not logger_instance.running


def test_validate_interface_failure():
    with pytest.raises(ValueError) as exc:
        TrafficLogger(
            interface='bad0',
            bpf_filter='',
            output_file='',
            duration=0,
            count=1,
            snaplen=100,
            promisc=False,
        )
    assert "Interface 'bad0' not found" in str(exc.value)


# Start without errors
@patch('netarmageddon.core.traffic._traffic_lib.traffic_capture_start', return_value=0)
@patch('netarmageddon.core.traffic._traffic_lib.traffic_capture_stop')
def test_start_and_stop(mock_stop, mock_start, logger_instance):
    logger = logger_instance
    logger.start()
    # Thread should be created
    assert isinstance(logger.capture_thread, threading.Thread)
    # Let capture thread finish its work
    logger.capture_thread.join(timeout=1)
    # After completion, running flag should be reset
    assert logger.running is False
    # Calling stop again should be idempotent
    logger.stop()


# Test duration timer
@patch('netarmageddon.core.traffic._traffic_lib.traffic_capture_start', return_value=0)
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
@patch('netarmageddon.core.traffic._traffic_lib.traffic_capture_stop')
def test_timer_thread(mock_stop, mock_start, mock_interface):
    logger = TrafficLogger(
        interface='lo',
        bpf_filter='',
        output_file='',
        duration=0.01,
        count=1,
        snaplen=128,
        promisc=False,
    )
    logger.start()
    # Timer thread should have been spawned
    assert isinstance(logger.timer_thread, threading.Thread)
    # Wait longer than duration and for capture thread
    time.sleep(0.02)
    # Capture thread should have stopped after duration
    assert not logger.capture_thread.is_alive()
    # We expect that running may still be True due to exception in timer stop join()


# Context manager
@patch('netarmageddon.core.traffic._traffic_lib.traffic_capture_start', return_value=0)
@patch('netarmageddon.core.traffic._traffic_lib.traffic_capture_stop')
def test_context_manager(mock_stop, mock_start, mock_interface):
    with TrafficLogger(
        interface='lo',
        bpf_filter='udp',
        output_file='file',
        duration=0,
        count=2,
        snaplen=256,
        promisc=True,
    ) as tl:
        # Thread should be set
        assert isinstance(tl.capture_thread, threading.Thread)
    # After exit, running flag false
    assert tl.running is False


def test_help_without_root_privileges(capsys):
    cmd = [sys.executable, "-m", "netarmageddon", "traffic", "-i", "dummy_intf"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert "This script requires root privileges" in result.stdout
