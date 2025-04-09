import unittest
import os
import sys

# Add src directory to path so we can import lmtwt package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from lmtwt.attacks.templates import get_attack_template, list_attack_templates
from lmtwt.utils.config import load_config


class BasicTests(unittest.TestCase):
    def test_attack_templates(self):
        """Test that attack templates can be loaded."""
        templates = list_attack_templates()
        self.assertTrue(len(templates) > 0)
        
        # Test getting a specific template
        template = get_attack_template("basic_prompt_injection")
        self.assertIsNotNone(template)
        self.assertIn("name", template)
        self.assertIn("description", template)
        self.assertIn("instruction", template)
    
    def test_config_loading(self):
        """Test that default config can be loaded."""
        config = load_config()
        self.assertIsNotNone(config)
        self.assertIn("models", config)
        self.assertIn("attack_templates", config)
        

if __name__ == "__main__":
    unittest.main() 