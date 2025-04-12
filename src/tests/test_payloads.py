import unittest
from lmtwt.attacks.payloads import PayloadGenerator

class TestPayloadGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = PayloadGenerator()
    
    def test_get_dan_payload(self):
        payload = self.generator.get_dan_payload()
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 10)
        # Check for common DAN keywords
        self.assertTrue(any(keyword in payload.lower() for keyword in ['dan', 'do anything now', 'ignore', 'restriction']))
    
    def test_get_injection_payload(self):
        payload = self.generator.get_injection_payload()
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 10)
        # Check for common injection keywords
        self.assertTrue(any(keyword in payload.lower() for keyword in ['ignore', 'instruction', 'instead']))
    
    def test_get_xss_payload(self):
        payload = self.generator.get_xss_payload()
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 5)
        # Check for common XSS patterns
        self.assertTrue(any(pattern in payload for pattern in ['<script', 'javascript:', 'onerror=', '<img', '&lt;']))
    
    def test_get_glitch_prompt(self):
        payload = self.generator.get_glitch_prompt()
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 5)
    
    def test_get_misleading_payload(self):
        payload = self.generator.get_misleading_payload()
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 10)
    
    def test_get_malware_payload(self):
        payload = self.generator.get_malware_payload()
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 10)
        # Check for common malware keywords
        self.assertTrue(any(keyword in payload.lower() for keyword in ['malware', 'virus', 'ransomware', 'backdoor', 'exploit']))
    
    def test_get_forbidden_knowledge_payload(self):
        payload = self.generator.get_forbidden_knowledge_payload()
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 10)
    
    def test_get_encoding_attack(self):
        original = "Test message"
        payload = self.generator.get_encoding_attack(original)
        self.assertIsInstance(payload, str)
        self.assertNotEqual(payload, original)
        self.assertTrue(len(payload) > len(original))
    
    def test_get_snowball_payload(self):
        payload = self.generator.get_snowball_payload()
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 10)
    
    def test_get_random_payload(self):
        payload = self.generator.get_random_payload()
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 5)
    
    def test_get_payloads_by_category(self):
        # Test with valid category
        payloads = self.generator.get_payloads_by_category("dan", count=3)
        self.assertIsInstance(payloads, list)
        self.assertEqual(len(payloads), 3)
        for payload in payloads:
            self.assertIsInstance(payload, str)
            self.assertTrue(len(payload) > 10)
        
        # Test with invalid category
        with self.assertRaises(ValueError):
            self.generator.get_payloads_by_category("invalid_category")
    
    def test_get_all_categories(self):
        categories = self.generator.get_all_categories()
        expected_categories = [
            "dan", "injection", "xss", "glitch", 
            "misleading", "malware", "forbidden_knowledge", "snowball"
        ]
        self.assertListEqual(sorted(categories), sorted(expected_categories))

if __name__ == "__main__":
    unittest.main() 