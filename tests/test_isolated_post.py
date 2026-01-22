#!/usr/bin/env python3
"""
Isolated POST request tests - each request on a fresh connection.
"""

import hashlib
import json
import os
import socket
import ssl
import sys
import time

PROXY_HTTPS_PORT = int(os.environ.get('PROXY_HTTPS_PORT', '8443'))


def create_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_post_request(size, use_connection_close=True):
    """Send a single POST request on a fresh connection."""
    body = os.urandom(size)
    expected_hash = hashlib.sha256(body).hexdigest()

    connection_header = 'Connection: close\r\n' if use_connection_close else ''

    request_header = (
        f'POST /echo HTTP/1.1\r\n'
        f'Host: test.localhost\r\n'
        f'Content-Type: application/octet-stream\r\n'
        f'Content-Length: {len(body)}\r\n'
        f'{connection_header}'
        f'\r\n'
    ).encode()

    ctx = create_ssl_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect(('127.0.0.1', PROXY_HTTPS_PORT))
    ssl_sock = ctx.wrap_socket(sock, server_hostname='test.localhost')

    try:
        # Send header and body separately to better understand timing
        ssl_sock.sendall(request_header)
        time.sleep(0.01)  # Small delay
        ssl_sock.sendall(body)

        response = b''
        while True:
            try:
                chunk = ssl_sock.recv(65536)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        # Parse response
        if not response:
            return False, 'Empty response', None

        if b'\r\n\r\n' in response:
            header_part, body_part = response.split(b'\r\n\r\n', 1)
            status_line = header_part.split(b'\r\n')[0].decode()

            if 'HTTP/1.1 200' in status_line or 'HTTP/1.0 200' in status_line:
                try:
                    data = json.loads(body_part)
                    if data.get('sha256') == expected_hash and data.get('received_length') == size:
                        return True, 'OK', None
                    else:
                        return False, f'Data mismatch: recv={data.get("received_length")}, sha={data.get("sha256")[:16]}', response
                except json.JSONDecodeError:
                    return False, 'JSON decode error', response
            else:
                return False, f'Status: {status_line}', response
        else:
            return False, 'No headers in response', response

    except Exception as e:
        return False, f'{type(e).__name__}: {e}', None
    finally:
        ssl_sock.close()


def main():
    print('Isolated POST Request Tests\n')
    print(f'{"Size":<12} {"Result":<8} {"Details"}')
    print('-' * 60)

    # Test each size multiple times to check for race conditions
    sizes = [
        32768,       # 32KB - buffer size
        40960,       # 40KB
        49152,       # 48KB
        51200,       # 50KB
        53248,       # 52KB
        55296,       # 54KB
        57344,       # 56KB
        59392,       # 58KB
        61440,       # 60KB
        63488,       # 62KB
        64512,       # 63KB
        65536,       # 64KB - 2*buffer
        66560,       # 65KB
        69632,       # 68KB
        73728,       # 72KB
        81920,       # 80KB
        98304,       # 96KB - 3*buffer
        102400,      # 100KB
    ]

    failed = []

    for size in sizes:
        results = []
        for i in range(3):  # Test each size 3 times
            time.sleep(0.1)  # Delay between tests
            passed, msg, _ = make_post_request(size)
            results.append(passed)

        success_rate = sum(results)
        if success_rate == 3:
            print(f'{size:<12} {"PASS":<8} All 3 attempts succeeded')
        elif success_rate == 0:
            print(f'{size:<12} {"FAIL":<8} All 3 attempts failed')
            failed.append(size)
        else:
            print(f'{size:<12} {"FLAKY":<8} {success_rate}/3 attempts succeeded')
            failed.append(size)

    print('\n' + '=' * 60)
    if failed:
        print(f'Failed/Flaky sizes: {failed}')

        # Try to identify the exact threshold
        print('\n--- Finding exact threshold ---')
        low = 32768
        high = 65536

        while high - low > 100:
            mid = (low + high) // 2
            results = [make_post_request(mid)[0] for _ in range(3)]
            if all(results):
                low = mid
                print(f'{mid}: PASS')
            else:
                high = mid
                print(f'{mid}: FAIL (or flaky)')

        print(f'\nThreshold appears to be around {low}-{high} bytes')
    else:
        print('All tests passed!')


if __name__ == '__main__':
    main()
