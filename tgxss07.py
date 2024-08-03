#!/usr/bin/env python3

import asyncio
import aiohttp
import os
import argparse
import time
from aiohttp import ClientSession
from asyncio import Semaphore
from bs4 import BeautifulSoup
import re

# Rate limiting semaphore for concurrency control
CONCURRENCY_LIMIT = 10  # Number of simultaneous requests
semaphore = Semaphore(CONCURRENCY_LIMIT)

# Introduce a delay between requests (in seconds)
REQUEST_DELAY = 0.0  # Set to 0 for no delay

async def fetch_html(session, url):
    async with semaphore:
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    print(f"Failed to fetch {url} with status code {response.status}")
        except Exception as e:
            print(f"Error fetching URL {url}: {e}")
        return None

async def crawl_domain(session, base_url):
    urls = set()
    html = await fetch_html(session, base_url)
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            # Handle relative URLs
            if not href.startswith(('http://', 'https://')):
                href = aiohttp.helpers.urljoin(base_url, href)
            if base_url in href and href not in urls:
                urls.add(href)
    return urls

async def test_xss(urls, payloads, result_dir):
    async with ClientSession(connector=aiohttp.TCPConnector(limit=None)) as session:
        tasks = []
        for url in urls:
            for payload in payloads:
                if payload.strip():  # Skip empty payloads
                    tasks.append(check_payload(session, url, payload, result_dir))
        await asyncio.gather(*tasks)

async def check_payload(session, url, payload, result_dir):
    async with semaphore:  # Rate limiting
        params = {'param': payload}
        print(f"Testing payload: {payload} on URL: {url}")  # Log payload being tested
        try:
            async with session.get(url, params=params) as response:
                print(f"Response status: {response.status} for payload: {payload}")  # Log response status
                content = await response.text()
                if payload in content:
                    parameter = 'param'  # Update this if you use different parameters
                    print("\033[31m" + "-" * 50)
                    print(f"Vulnerable URL: {url}")
                    print(f"Vulnerable Parameter: {parameter}")
                    print(f"Payload executed: {payload}")
                    print("-" * 50 + "\033[0m")
                    save_xss_bug(url, parameter, payload, result_dir)
                else:
                    print(f"\033[32mNo vulnerability found with payload: {payload}\033[0m")
        except Exception as e:
            print(f"Error with URL {url}: {e}")

        # Introduce delay between requests
        await asyncio.sleep(REQUEST_DELAY)

def save_xss_bug(url, parameter, payload, result_dir):
    file_path = os.path.join(result_dir, "xssbug.txt")
    with open(file_path, "a") as f:
        f.write(f"URL: {url}\nParameter: {parameter}\nPayload: {payload}\n\n")
    print(f"Saved vulnerable URL: {url} with parameter: {parameter} and payload: {payload}")  # Log saving operation

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-dL", "--domains", help="File containing list of domains/subdomains")
    parser.add_argument("-p", "--payload", required=True, help="Payload file (JSON or TXT)")
    parser.add_argument("-r", "--result", required=True, help="Result directory")
    args = parser.parse_args()

    urls = set()
    if args.url:
        urls.add(args.url)
    elif args.domains:
        with open(args.domains, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
            async def fetch_and_crawl():
                async with ClientSession(connector=aiohttp.TCPConnector(limit=None)) as session:
                    for domain in domains:
                        domain_urls = await crawl_domain(session, domain)
                        urls.update(domain_urls)
            asyncio.run(fetch_and_crawl())

    payload_file = args.payload
    result_dir = args.result

    if not urls:
        print("No URLs provided. Use -u for a single URL or -dL for a list of domains.")
        return

    if not os.path.exists(result_dir):
        os.makedirs(result_dir)

    with open(payload_file, "r") as f:
        payloads = f.read().splitlines()

    start_time = time.time()  # Start time
    print(f"Starting XSS testing on URLs with payloads from: {payload_file}")

    asyncio.run(test_xss(urls, payloads, result_dir))

    end_time = time.time()  # End time
    elapsed_time = end_time - start_time
    print(f"Total execution time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()
