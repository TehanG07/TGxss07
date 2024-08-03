#!/usr/bin/env python3

import os
import json
import requests
from waf import Waf_Detect

def load_payloads(payload_files):
    """Load payloads from multiple files (JSON or TXT)."""
    payloads = []
    for payload_file in payload_files:
        if payload_file.endswith('.json'):
            with open(payload_file, 'r') as f:
                payloads.extend(json.load(f))
        elif payload_file.endswith('.txt'):
            with open(payload_file, 'r') as f:
                payloads.extend(line.strip() for line in f)
    return payloads

def test_xss(url, payloads, result_dir):
    """Test for XSS vulnerabilities and save results."""
    # Ensure result directory exists
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)

    # Detect WAF
    waf = Waf_Detect(url).waf_detect()

    result_file = os.path.join(result_dir, 'xssbug.txt')

    for payload in payloads:
        try:
            response = requests.get(url, params={'param': payload})
            if payload in response.text:
                with open(result_file, 'a') as f:
                    f.write(f"URL: {url}\nParameter: param\nPayload: {payload}\n\n")
        except Exception as e:
            print(f"Error testing XSS with payload {payload}: {e}")

def main():
    import argparse

    parser = argparse.ArgumentParser(description="TGxss07 - XSS Vulnerability Finder")
    parser.add_argument('-u', '--url', required=True, help='URL to test for XSS vulnerabilities')
    parser.add_argument('-p', '--payloads', nargs='+', default=['payloads.json'], help='Files containing XSS payloads (JSON or TXT)')
    parser.add_argument('-r', '--results', default='./results', help='Directory to save results')
    
    args = parser.parse_args()

    url = args.url
    payload_files = args.payloads
    result_dir = args.results

    payloads = load_payloads(payload_files)
    test_xss(url, payloads, result_dir)

if __name__ == "__main__":
    main()
