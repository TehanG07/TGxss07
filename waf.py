# waf.py

import requests

class Waf_Detect:
    def __init__(self, url):
        self.url = url

    def waf_detect(self):
        # Placeholder for actual WAF detection logic
        result = self._simulate_waf_detection()  # Replace with actual method call

        # Ensure result is a string
        if isinstance(result, list):
            result = ' '.join(result)  # Join list items into a single string
        
        # Safely process the string
        result = result.lower()  # Now safe to call .lower()

        return result

    def _simulate_waf_detection(self):
        # This method simulates the WAF detection process and should be replaced with real implementation
        # Example of returning a list (change this according to actual implementation)
        return ["ExampleWAF"]
