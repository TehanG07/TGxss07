#!/usr/bin/env python3

import sys
import os
import json
import requests
from bs4 import BeautifulSoup
from termcolor import colored
import re
from urllib.parse import urlparse
from wafw00f.main import WAFW00F
from datetime import datetime
import shutil

# Define paths
PAYLOAD_JSON = 'payload.json'
PAYLOAD_TXT = 'payload.txt'
WAF_LIST = 'waf_list.txt'

# Generate a unique results directory based on the current timestamp
def generate_result_dir():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_dir = f'result_{timestamp}'
    return result_dir

class Waf_Detect:
    def __init__(self, url):
        self.url = url

    def waf_detect(self):
        wafw00f = WAFW00F(self.url)
        result = wafw00f.identwaf()
        if result:
            result = result[0].lower()
        else:
            return None
        wafs = self.fetch_names(WAF_LIST)
        for waf in wafs:
            if waf in result:
                return waf
        return None

    @staticmethod
    def fetch_names(filename):
        with open(filename, 'r') as waf_list:
            return waf_list.read().splitlines()

def get_valid_links(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for tag in soup.find_all(['a', 'form']):
            href = tag.get('href')
            action = tag.get('action')
            if href:
                href = requests.compat.urljoin(url, href)
                links.add(href)
            if action:
                action = requests.compat.urljoin(url, action)
                links.add(action)
        return links
    except requests.RequestException as e:
        print(colored(f"Error fetching {url}: {e}", 'red'))
        return set()

def find_xss_in_html(html_content, payloads):
    results = []
    for payload in payloads:
        if re.search(re.escape(payload), html_content, re.IGNORECASE):
            results.append(payload)
    return results

def test_xss(url, payloads, result_dir):
    waf = Waf_Detect(url).waf_detect()
    if waf:
        print(colored(f"Detected WAF: {waf}", 'yellow'))

    valid_links = get_valid_links(url)
    for link in valid_links:
        try:
            response = requests.get(link)
            if response.status_code == 200:
                xss_results = find_xss_in_html(response.text, payloads)
                for result in xss_results:
                    if result:
                        print(colored(f"Potential XSS found in {link}: {result}", 'yellow', attrs=['underline']))
                        save_result(result_dir, link, result)
                    else:
                        print(colored(f"No XSS found in {link}", 'green'))
        except requests.RequestException as e:
            print(colored(f"Error fetching {link}: {e}", 'red'))

def save_result(result_dir, url, payload):
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    result_file = os.path.join(result_dir, 'xssbug.txt')
    with open(result_file, 'a') as file:
        file.write(f"URL: {url}\nPayload: {payload}\n\n")

def load_payloads():
    payloads = []
    if os.path.exists(PAYLOAD_JSON):
        with open(PAYLOAD_JSON, 'r') as f:
            payloads.extend(json.load(f))
    if os.path.exists(PAYLOAD_TXT):
        with open(PAYLOAD_TXT, 'r') as f:
            payloads.extend(f.read().splitlines())
    return payloads

def main():
    if len(sys.argv) < 3:
        print("Usage: TGxss07.py -u <target_url> or TGxss07.py -l <list_of_targets> or TGxss07.py -dL <list_of_domains>")
        sys.exit(1)

    option = sys.argv[1]
    payloads = load_payloads()
    result_dir = generate_result_dir()

    if option == '-u':
        url = sys.argv[2]
        test_xss(url, payloads, result_dir)
    elif option == '-l':
        list_file = sys.argv[2]
        with open(list_file, 'r') as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()
                if url:
                    test_xss(url, payloads, result_dir)
    elif option == '-dL':
        domains_file = sys.argv[2]
        with open(domains_file, 'r') as file:
            domains = file.readlines()
            for domain in domains:
                domain = domain.strip()
                if domain:
                    url = f"http://{domain}"
                    test_xss(url, payloads, result_dir)
    else:
        print("Invalid option. Use -u, -l, or -dL.")

if __name__ == "__main__":
    main()
