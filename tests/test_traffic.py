import threading
from unittest.mock import MagicMock, patch

import pytest

from netarmageddon.core.traffic import TrafficLogger


@pytest.fixture
def mock_ctypes():
    with patch("ctypes.CDLL") as mock_cdll:
        mock_lib = MagicMock()
        mock_cdll.return_value = mock_lib
        yield mock_lib


@pytest.fixture
def traffic_logger():
    return TrafficLogger(
        interface="lo",
        bpf_filter="tcp port 80",
        output_file="test.pcap",
        duration=10,
        count=100,
        snaplen=65535,
        promisc=True,
    )


def test_traffic_logger_initialization(traffic_logger):
    assert traffic_logger.interface == "lo"
    assert traffic_logger.bpf_filter == "tcp port 80"
    assert traffic_logger.output_file == "test.pcap"
    assert traffic_logger.duration == 10
    assert traffic_logger.count == 100
    assert traffic_logger.snaplen == 65535
    assert traffic_logger.promisc is True
    assert not traffic_logger.running


def test_traffic_start_stop(traffic_logger):
    mock_lib = MagicMock()
    # Use an event to simulate blocking capture
    capture_block = threading.Event()

    def capture_side_effect(cfg):
        # Block until test completion
        capture_block.wait(timeout=0.5)
        return 0

    mock_lib.traffic_capture_start.side_effect = capture_side_effect

    with patch("netarmageddon.core.traffic._traffic_lib", mock_lib):
        traffic_logger.start()

        # Verify initial state
        assert traffic_logger.running
        assert traffic_logger.capture_thread.is_alive()

        # Stop capture
        traffic_logger.stop()
        capture_block.set()  # Release the capture thread

        # Clean up
        traffic_logger.capture_thread.join(timeout=1)

        # Verify final state
        mock_lib.traffic_capture_stop.assert_called_once()
        assert not traffic_logger.running


def test_traffic_capture_error(traffic_logger, caplog):
    """Test error handling when C library returns an error"""
    # Mock the C library interface used by TrafficLogger
    with patch("netarmageddon.core.traffic._traffic_lib") as mock_lib:
        mock_lib.traffic_capture_start.return_value = -1
        mock_lib.traffic_get_last_error.return_value = b"Mocked error"

        traffic_logger.start()
        # Wait for capture thread to complete
        traffic_logger.capture_thread.join(timeout=1)

        # Verify error logging
        assert "Capture failed: Mocked error" in caplog.text
        mock_lib.traffic_capture_start.assert_called_once()
        mock_lib.traffic_get_last_error.assert_called_once()


def test_duration_handling(traffic_logger):
    with patch("netarmageddon.core.traffic._traffic_lib") as mock_lib, patch(
        "time.sleep"
    ) as mock_sleep:
        # 1) Block the capture thread so running=True persists
        done = threading.Event()
        mock_lib.traffic_capture_start.side_effect = (
            lambda cfg: done.wait(timeout=5) or 0
        )

        traffic_logger.duration = 1
        traffic_logger.start()

        # 2) Clear any prior sleep calls
        mock_sleep.reset_mock()

        # 3) Invoke the timer logic
        traffic_logger._stop_after_delay()

        # 4) Now exactly one sleep should have occurred
        mock_sleep.assert_called_once_with(1)
        mock_lib.traffic_capture_stop.assert_called_once()

        # 5) Clean up
        done.set()
        traffic_logger.capture_thread.join(timeout=1)
        assert not traffic_logger.running
