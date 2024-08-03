#!/usr/bin/env python3

import sys
import os
import requests
from bs4 import BeautifulSoup
from termcolor import colored
import re
import json
from urllib.parse import urlparse

def load_payloads_from_json(json_file):
    try:
        with open(json_file, 'r') as file:
            payloads = json.load(file)
        return payloads
    except Exception as e:
        print(colored(f"Error loading JSON payloads: {e}", 'red'))
        return []

def load_payloads_from_txt(txt_file):
    try:
        with open(txt_file, 'r') as file:
            payloads = file.read().splitlines()
        return payloads
    except Exception as e:
        print(colored(f"Error loading TXT payloads: {e}", 'red'))
        return []

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

def check_xss_on_url(url, payloads):
    valid_links = get_valid_links(url)
    for link in valid_links:
        try:
            response = requests.get(link)
            if response.status_code == 200:
                xss_results = find_xss_in_html(response.text, payloads)
                for result in xss_results:
                    print(colored(f"Potential XSS payload found in {link}: {result}", 'red'))
        except requests.RequestException as e:
            print(colored(f"Error fetching {link}: {e}", 'red'))

def main():
    if len(sys.argv) < 4:
        print("Usage: TGxss07.py -u <target_url> -p <payload_file.json or payload_file.txt>")
        sys.exit(1)

    option = sys.argv[1]
    payload_file = sys.argv[3]
    
    if payload_file.endswith('.json'):
        payloads = load_payloads_from_json(payload_file)
    elif payload_file.endswith('.txt'):
        payloads = load_payloads_from_txt(payload_file)
    else:
        print("Invalid payload file format. Use .json or .txt.")
        sys.exit(1)

    if option == '-u':
        url = sys.argv[2]
        check_xss_on_url(url, payloads)
    elif option == '-l':
        list_file = sys.argv[2]
        with open(list_file, 'r') as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()
                if url:
                    check_xss_on_url(url, payloads)
    elif option == '-dL':
        domains_file = sys.argv[2]
        with open(domains_file, 'r') as file:
            domains = file.readlines()
            for domain in domains:
                domain = domain.strip()
                if domain:
                    url = f"http://{domain}"
                    check_xss_on_url(url, payloads)
    else:
        print("Invalid option. Use -u, -l, or -dL.")

if __name__ == "__main__":
    main()
