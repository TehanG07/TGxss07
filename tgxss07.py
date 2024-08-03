#!/usr/bin/env python3

import asyncio
import aiohttp
import json
import os
import argparse
from colorama import Fore, Style

async def test_xss(session, url, payload, result_file):
    try:
        async with session.get(url, params={'param': payload}) as response:
            content = await response.text()
            if payload in content:
                # Found potential XSS vulnerability
                print(f"{Fore.RED}{url} vulnerable to {payload}{Style.RESET_ALL}")
                with open(result_file, 'a') as file:
                    file.write(f"URL: {url}\nParameter: param\nPayload: {payload}\n\n")
            else:
                # Not vulnerable
                print(f"{Fore.GREEN}{url} not vulnerable to {payload}{Style.RESET_ALL}")
    except Exception as e:
        print(f"Error testing XSS with payload {payload}: {e}")

async def main():
    parser = argparse.ArgumentParser(description='Test for XSS vulnerabilities.')
    parser.add_argument('-u', '--url', required=True, help='The URL to test.')
    parser.add_argument('-p', '--payload', required=True, help='File with payloads to test.')
    parser.add_argument('-r', '--result', required=True, help='Directory to store results.')

    args = parser.parse_args()

    # Ensure result directory exists
    os.makedirs(args.result, exist_ok=True)
    result_file = os.path.join(args.result, 'xssbug.txt')

    # Load payloads
    with open(args.payload, 'r') as f:
        payloads = f.readlines()

    async with aiohttp.ClientSession() as session:
        tasks = []
        for payload in payloads:
            payload = payload.strip()
            tasks.append(test_xss(session, args.url, payload, result_file))

        # Run tasks with limited concurrency
        await asyncio.gather(*tasks)

if __name__ == '__main__':
    asyncio.run(main())
