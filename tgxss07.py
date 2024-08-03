#!/usr/bin/env python3

import asyncio
import aiohttp
import os
import argparse
import time
from aiohttp import ClientSession
from asyncio import Semaphore

# Rate limiting semaphore
semaphore = Semaphore(2)  # Allow 2 requests per second

async def test_xss(url, payloads, result_dir):
    async with ClientSession() as session:
        tasks = []
        for payload in payloads:
            tasks.append(check_payload(session, url, payload, result_dir))
        await asyncio.gather(*tasks)

async def check_payload(session, url, payload, result_dir):
    async with semaphore:  # Rate limiting
        params = {'param': payload}
        try:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    content = await response.text()
                    if payload in content:
                        print(f"Vulnerable URL: {url}, Parameter: param, Payload: {payload}")
                        save_xss_bug(url, 'param', payload, result_dir)
        except Exception as e:
            print(f"Error with URL {url}: {e}")

def save_xss_bug(url, parameter, payload, result_dir):
    file_path = os.path.join(result_dir, "xssbug.txt")
    with open(file_path, "a") as f:
        f.write(f"URL: {url}, Parameter: {parameter}, Payload: {payload}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--payload", required=True, help="Payload file (JSON or TXT)")
    parser.add_argument("-r", "--result", required=True, help="Result directory")
    args = parser.parse_args()

    url = args.url
    payload_file = args.payload
    result_dir = args.result

    if not os.path.exists(result_dir):
        os.makedirs(result_dir)

    with open(payload_file, "r") as f:
        payloads = f.read().splitlines()

    start_time = time.time()  # Start time

    asyncio.run(test_xss(url, payloads, result_dir))

    end_time = time.time()  # End time
    elapsed_time = end_time - start_time
    print(f"Total execution time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()
