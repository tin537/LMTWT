import os
import sys
import pytest

# Add src directory to path so we can import lmtwt package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from lmtwt.attacks.templates import get_attack_template, list_attack_templates
from lmtwt.utils.config import load_config


def test_attack_templates():
    """Test that attack templates can be loaded."""
    templates = list_attack_templates()
    assert len(templates) > 0
    
    # Test getting a specific template
    template = get_attack_template("basic_prompt_injection")
    assert template is not None
    assert "name" in template
    assert "description" in template
    assert "instruction" in template


def test_config_loading():
    """Test that default config can be loaded."""
    config = load_config()
    assert config is not None
    assert "models" in config
    assert "attack_templates" in config 