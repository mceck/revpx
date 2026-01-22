#!/usr/bin/env python3
"""
Capture the exact error response from revpx for failing POST requests.
"""

import hashlib
import os
import socket
import ssl
import sys

PROXY_HTTPS_PORT = int(os.environ.get('PROXY_HTTPS_PORT', '8443'))


def create_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_raw_post(size):
    """Send raw POST request and capture full response."""
    body = os.urandom(size)

    request = (
        f'POST /echo HTTP/1.1\r\n'
        f'Host: test.localhost\r\n'
        f'Content-Type: application/octet-stream\r\n'
        f'Content-Length: {len(body)}\r\n'
        f'Connection: close\r\n'
        f'\r\n'
    ).encode() + body

    ctx = create_ssl_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect(('127.0.0.1', PROXY_HTTPS_PORT))
    ssl_sock = ctx.wrap_socket(sock, server_hostname='test.localhost')

    try:
        ssl_sock.sendall(request)
        response = b''
        while True:
            try:
                chunk = ssl_sock.recv(65536)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        return response
    finally:
        ssl_sock.close()


def main():
    print('Testing POST request error responses\n')

    # Test sizes around the failure point
    sizes = [
        50 * 1024,      # Should work
        60 * 1024,      # Check boundary
        63 * 1024,
        64 * 1024,      # Fails
        65 * 1024,
        100 * 1024,     # Fails
    ]

    for size in sizes:
        print(f'\n{"="*60}')
        print(f'Testing POST with {size} bytes ({size/1024:.1f}KB):')
        print(f'{"="*60}')

        response = make_raw_post(size)

        # Parse response
        if b'\r\n\r\n' in response:
            header_part, body_part = response.split(b'\r\n\r\n', 1)
            headers = header_part.decode('utf-8', errors='replace')
            body_preview = body_part[:500].decode('utf-8', errors='replace')

            print(f'\nHeaders:\n{headers}')
            print(f'\nBody preview ({len(body_part)} bytes):\n{body_preview}')
        else:
            print(f'\nRaw response ({len(response)} bytes):')
            print(response[:1000].decode('utf-8', errors='replace'))


if __name__ == '__main__':
    main()
