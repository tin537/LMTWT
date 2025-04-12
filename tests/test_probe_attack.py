import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Add src directory to path so we can import lmtwt package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from lmtwt.attacks.probeattack import ProbeAttack


@pytest.fixture
def probe_attack():
    """Create a ProbeAttack instance for tests."""
    return ProbeAttack()


def test_probe_attack_initialization(probe_attack):
    """Test that ProbeAttack initializes correctly."""
    assert probe_attack is not None
    assert probe_attack.payload_generator is not None
    assert len(probe_attack.payload_categories) > 0


def test_generate_attack_sequence(probe_attack):
    """Test generating attack sequences."""
    # Test with default count
    attacks = probe_attack.generate_attack_sequence("test_model")
    assert len(attacks) == 5
    
    # Test with custom count
    attacks = probe_attack.generate_attack_sequence("test_model", count=3)
    assert len(attacks) == 3
    
    for attack in attacks:
        assert "payload" in attack
        assert "category" in attack
        assert "timestamp" in attack
        assert "target_model" in attack
        assert attack["target_model"] == "test_model"


def test_generate_adaptive_attack(probe_attack):
    """Test generating adaptive attacks based on previous results."""
    # Create mock previous results
    previous_results = [
        {"category": "dan", "success": True},
        {"category": "dan", "success": True},
        {"category": "injection", "success": False},
        {"category": "xss", "success": False}
    ]
    
    # Generate adaptive attack
    attack = probe_attack.generate_adaptive_attack(previous_results)
    
    assert attack is not None
    assert "payload" in attack
    assert "category" in attack
    assert "timestamp" in attack
    assert "adaptive" in attack
    assert attack["adaptive"] is True
    assert "previous_successes" in attack
    assert "success_rate" in attack
    
    # The dan category had 100% success rate, so it should be chosen
    assert attack["category"] == "dan"
    assert attack["previous_successes"] == 2
    assert attack["success_rate"] == 1.0


@patch('lmtwt.attacks.probeattack.ProbeAttack._check_success')
def test_execute_category_attack(mock_check_success, probe_attack):
    """Test executing category attacks."""
    # Mock target model
    target_model = MagicMock()
    target_model.protected_chat.return_value = "Test response"
    
    # Mock success check
    mock_check_success.return_value = True
    
    # Execute attack
    result = probe_attack.execute_category_attack("dan", target_model, iterations=2)
    
    assert result is not None
    assert "category" in result
    assert result["category"] == "dan"
    assert "iterations" in result
    assert result["iterations"] == 2
    assert "results" in result
    assert len(result["results"]) == 2
    assert "success_count" in result
    assert result["success_count"] == 2
    assert "error_count" in result
    assert result["error_count"] == 0
    assert "analysis" in result
    
    # Verify model was called
    assert target_model.protected_chat.call_count == 2 