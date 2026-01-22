#!/usr/bin/env python3
"""Debug test to trace 413 error with large payloads."""

import socket
import ssl
import time
import sys

HOST = 'test.localhost'
PORT = 8443

def test_post(size, with_delay=False):
    """Send a POST request with specified body size."""
    body = b'X' * size

    headers = (
        f"POST /echo HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    print(f"\n{'='*60}")
    print(f"Testing {size} bytes {'WITH delay' if with_delay else 'all at once'}")
    print(f"Header size: {len(headers)} bytes")
    print(f"Total size: {len(headers) + len(body)} bytes")
    print(f"{'='*60}")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        ssl_sock = ctx.wrap_socket(sock, server_hostname=HOST)

        if with_delay:
            # Send header first
            ssl_sock.sendall(headers)
            time.sleep(0.01)  # 10ms delay
            # Then send body
            ssl_sock.sendall(body)
        else:
            # Send everything at once
            ssl_sock.sendall(headers + body)

        # Read response
        response = b''
        while True:
            chunk = ssl_sock.recv(8192)
            if not chunk:
                break
            response += chunk

        ssl_sock.close()

        # Parse status
        if b'HTTP/' in response:
            status_line = response.split(b'\r\n')[0].decode()
            status_code = int(status_line.split()[1])
            print(f"Response: {status_line}")

            if status_code == 200:
                # Check body
                if b'\r\n\r\n' in response:
                    resp_body = response.split(b'\r\n\r\n', 1)[1]
                    if len(resp_body) == size:
                        print(f"PASS: Got expected {size} bytes back")
                        return True
                    else:
                        print(f"FAIL: Expected {size} bytes, got {len(resp_body)}")
                        return False
            else:
                print(f"FAIL: Got status {status_code}")
                # Print error body if any
                if b'\r\n\r\n' in response:
                    err_body = response.split(b'\r\n\r\n', 1)[1]
                    if err_body:
                        print(f"Error body: {err_body[:200]}")
                return False
        else:
            print(f"FAIL: Invalid response")
            return False

    except Exception as e:
        print(f"FAIL: {e}")
        return False

def main():
    sizes = [10000, 32000, 33000, 40000, 50000]

    print("Testing without delay (all at once):")
    for size in sizes:
        test_post(size, with_delay=False)
        time.sleep(0.5)  # Give proxy time to log

    print("\n\nTesting WITH delay:")
    for size in [40000, 50000]:
        test_post(size, with_delay=True)
        time.sleep(0.5)

if __name__ == '__main__':
    main()
