# tests/test_base_attack.py

import logging
import threading
import time
from typing import Generator, cast
from unittest.mock import patch

import pytest
from scapy.arch import get_if_list

from netarmageddon.core.base_attack import BaseAttack

# --- Concrete Attack Implementations for Testing ---


class StuckAttack(BaseAttack):
    def start(self) -> None:
        self.running = True
        # Daemon thread that never exits
        self.thread = threading.Thread(target=self._infinite_loop, daemon=True)
        self.thread.start()

    def _infinite_loop(self) -> None:
        """Truly infinite loop for failure scenarios"""
        while True:
            time.sleep(0.1)

    def stop(self) -> None:
        # use base stop to test error handling
        self._base_stop()


class MockAttack(BaseAttack):
    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._mock_loop)
        self.thread.start()

    def _mock_loop(self) -> None:
        """Controlled loop that respects running flag"""
        while self.running:
            time.sleep(0.1)

    def stop(self) -> None:
        self._base_stop()


# --- Fixtures ---


def valid_interface() -> str:
    """Return a valid interface name for tests."""
    return cast(str, get_if_list()[0])


def stuck_attack(valid_interface: str) -> Generator[StuckAttack, None, None]:
    """Provide a StuckAttack instance."""
    yield StuckAttack(valid_interface)


def mock_attack(valid_interface: str) -> Generator[MockAttack, None, None]:
    """Provide a MockAttack instance."""
    yield MockAttack(valid_interface)


# --- Tests ---


def test_base_attack_initialization(valid_interface: str) -> None:
    """Test base attack initialization with valid interface."""
    attack = MockAttack(valid_interface)
    assert attack.interface == valid_interface
    assert attack.running is False
    assert attack.thread is None


def test_invalid_interface_initialization() -> None:
    """Test initialization with invalid interface raises error."""
    with pytest.raises(ValueError) as excinfo:
        MockAttack("nonexistent0")
    assert "not found" in str(excinfo.value)


def test_rate_limiting(caplog: pytest.LogCaptureFixture) -> None:
    """Test rate limiting functionality."""
    attack = MockAttack("lo")
    # Below limit
    assert attack._rate_limit(50) == 50
    # At limit
    assert attack._rate_limit(attack.MAX_PPS) == attack.MAX_PPS
    # Above limit
    with caplog.at_level(logging.WARNING):
        capped = attack._rate_limit(attack.MAX_PPS + 10)
        assert capped == attack.MAX_PPS
    assert "exceeds safety limit" in caplog.text


def test_mac_address_validation() -> None:
    """Test MAC address validation helper."""
    attack = MockAttack("lo")
    # Valid
    assert attack.validate_mac("00:11:22:33:44:55") is True
    # Invalid hex
    assert attack.validate_mac("00:11:22:33:44:zz") is False
    # Too short
    assert attack.validate_mac("00:11:22:33:44") is False


def test_context_manager(mock_attack: MockAttack) -> None:
    """Test context manager start/stop functionality."""
    with mock_attack as a:
        assert a.running is True
        assert a.thread is not None
        assert a.thread.is_alive()
    assert mock_attack.running is False
    assert mock_attack.thread is not None
    assert not mock_attack.thread.is_alive()


def test_requires_active_attack_decorator(mock_attack: MockAttack) -> None:
    """Test method decorator enforces running attack."""

    @BaseAttack.requires_active_attack
    def test_method(self: BaseAttack) -> bool:
        return True

    # Should fail when not running
    with pytest.raises(RuntimeError):
        test_method(mock_attack)

    # Should work when running
    with mock_attack:
        assert test_method(mock_attack) is True


def test_base_stop_mechanism(mock_attack: MockAttack) -> None:
    """Test common stop procedure stops thread."""
    mock_attack.start()
    mock_attack.stop()
    assert mock_attack.running is False
    assert mock_attack.thread is not None
    assert not mock_attack.thread.is_alive()


def test_thread_cleanup_on_failure(
    mock_attack: MockAttack, caplog: pytest.LogCaptureFixture
) -> None:
    """Test thread cleanup when stop() encounters join error."""
    mock_attack.start()
    time.sleep(0.1)  # Give thread time to start

    # Force is_alive() True and join() to raise
    with (
        patch.object(mock_attack.thread, "is_alive", return_value=True),
        patch.object(
            mock_attack.thread, "join", side_effect=RuntimeError("Thread stuck")
        ),
    ):
        mock_attack.stop()

    assert "Thread join error: Thread stuck" in caplog.text
    assert "Failed to stop attack thread" in caplog.text


def test_logging_configuration(caplog: pytest.LogCaptureFixture) -> None:
    """Test class-specific logger name and level."""
    with caplog.at_level(logging.INFO):
        attack = MockAttack("lo")
        attack.logger.info("Test message")
        assert "Test message" in caplog.text
        assert attack.__class__.__name__ in caplog.text


def test_stuck_attack_stop(
    stuck_attack: StuckAttack, caplog: pytest.LogCaptureFixture
) -> None:
    """Test that StuckAttack._base_stop logs an error if thread won't join."""
    attack = stuck_attack
    attack.start()
    time.sleep(0.1)
    with caplog.at_level(logging.ERROR):
        attack.stop()
    assert (
        "Thread join error" in caplog.text
        or "Failed to stop attack thread" in caplog.text
    )
