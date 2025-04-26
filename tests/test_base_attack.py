# tests/test_base_attack.py
import pytest
import time
from unittest.mock import patch
import logging
import threading
from netarmageddon.core.base_attack import BaseAttack
from scapy.arch import get_if_list

# New test class for failed cleanup scenarios
class StuckAttack(BaseAttack):
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._infinite_loop, daemon=True)
        self.thread.start()

    def _infinite_loop(self):
        """Truly infinite loop for failure scenarios"""
        while True:
            time.sleep(0.1)

@pytest.fixture
def stuck_attack(valid_interface):
    return StuckAttack(valid_interface)

def test_thread_cleanup_on_failure(stuck_attack, caplog):
    """Test thread cleanup when stop fails"""
    stuck_attack.start()
    time.sleep(0.1)
    
    with patch.object(stuck_attack.thread, 'join', side_effect=RuntimeError("Thread stuck")):
        stuck_attack.stop()
    
    assert "Thread join error: Thread stuck" in caplog.text
    assert "Failed to stop attack thread" in caplog.text

# Mock concrete class for testing abstract methods
class MockAttack(BaseAttack):
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._mock_loop)
        self.thread.start()

    def _mock_loop(self):
        """Controlled loop that respects running flag"""
        while self.running:
            time.sleep(0.1)  # Regular check interval

    def stop(self):
        self._base_stop()

@pytest.fixture
def valid_interface():
    return get_if_list()[0]  # Use first available interface

@pytest.fixture
def mock_attack(valid_interface):
    return MockAttack(valid_interface)

def test_base_attack_initialization(valid_interface):
    """Test base attack initialization with valid interface"""
    attack = MockAttack(valid_interface)
    assert attack.interface == valid_interface
    assert attack.running is False
    assert attack.thread is None

def test_invalid_interface_initialization():
    """Test initialization with invalid interface raises error"""
    with pytest.raises(ValueError) as excinfo:
        MockAttack("invalid_interface0")
    assert "not found" in str(excinfo.value)

def test_rate_limiting(caplog):
    """Test rate limiting functionality"""
    attack = MockAttack("lo")
    
    # Below limit
    assert attack._rate_limit(50) == 50
    
    # At limit
    assert attack._rate_limit(100) == 100
    
    # Above limit
    with caplog.at_level(logging.WARNING):
        assert attack._rate_limit(150) == 100
    assert "exceeds safety limit" in caplog.text

def test_mac_address_validation():
    """Test MAC address validation helper"""
    attack = MockAttack("lo")
    
    valid_mac = "00:11:22:33:44:55"
    assert attack.validate_mac(valid_mac) is True
    
    invalid_mac = "00:11:22:33:44:zz"  # Invalid hex
    assert attack.validate_mac(invalid_mac) is False
    
    short_mac = "00:11:22:33:44"  # Too short
    assert attack.validate_mac(short_mac) is False

def test_context_manager(mock_attack):
    """Test context manager start/stop functionality"""
    with mock_attack:
        assert mock_attack.running is True
        assert mock_attack.thread.is_alive()
    
    assert mock_attack.running is False
    assert not mock_attack.thread.is_alive()

def test_requires_active_attack_decorator(mock_attack):
    """Test method decorator enforces running attack"""
    
    # Create decorated test method
    @BaseAttack.requires_active_attack
    def test_method(self):
        return True
    
    # Should fail when not running
    with pytest.raises(RuntimeError):
        test_method(mock_attack)
    
    # Should work when running
    with mock_attack:
        assert test_method(mock_attack) is True

def test_base_stop_mechanism(mock_attack):
    """Test common stop procedure"""
    mock_attack.start()
    mock_attack.stop()
    
    assert mock_attack.running is False
    assert not mock_attack.thread.is_alive()

def test_thread_cleanup_on_failure(mock_attack, caplog):
    """Test thread cleanup when stop fails"""
    mock_attack.start()
    time.sleep(0.1)  # Ensure thread starts
    
    # Force thread to appear alive and raise error on join
    with patch.object(mock_attack.thread, 'is_alive', return_value=True), \
         patch.object(mock_attack.thread, 'join', side_effect=RuntimeError("Thread stuck")):
        
        mock_attack.stop()
    
    assert "Thread join error: Thread stuck" in caplog.text
    assert "Failed to stop attack thread" in caplog.text

# tests/test_base_attack.py

def test_logging_configuration(caplog):
    """Test class-specific logging"""
    with caplog.at_level(logging.INFO):
        attack = MockAttack("lo")
        attack.logger.info("Test message")
        assert "Test message" in caplog.text
        assert attack.__class__.__name__ in caplog.text