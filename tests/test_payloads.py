import os
import sys
import pytest

# Add src directory to path so we can import lmtwt package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from lmtwt.attacks.payloads import PayloadGenerator


@pytest.fixture
def payload_generator():
    """Create a PayloadGenerator instance for tests."""
    return PayloadGenerator()


def test_payload_generator_initialization(payload_generator):
    """Test that PayloadGenerator initializes correctly."""
    assert payload_generator is not None
    categories = payload_generator.get_all_categories()
    assert len(categories) > 0
    assert "dan" in categories
    assert "injection" in categories


def test_get_dan_payload(payload_generator):
    """Test getting DAN payloads."""
    payload = payload_generator.get_dan_payload()
    assert payload is not None
    assert isinstance(payload, str)
    assert len(payload) > 0


def test_get_injection_payload(payload_generator):
    """Test getting injection payloads."""
    payload = payload_generator.get_injection_payload()
    assert payload is not None
    assert isinstance(payload, str)
    assert len(payload) > 0


def test_get_payloads_by_category(payload_generator):
    """Test getting payloads by category."""
    categories = ["dan", "injection", "xss"]
    
    for category in categories:
        payloads = payload_generator.get_payloads_by_category(category, count=2)
        assert len(payloads) == 2
        for payload in payloads:
            assert payload is not None
            assert isinstance(payload, str)
            assert len(payload) > 0


def test_get_random_payload(payload_generator):
    """Test getting random payloads."""
    for _ in range(5):
        payload = payload_generator.get_random_payload()
        assert payload is not None
        assert "category" in payload
        assert "payload" in payload
        assert payload["category"] in payload_generator.get_all_categories()
        assert isinstance(payload["payload"], str)
        assert len(payload["payload"]) > 0 