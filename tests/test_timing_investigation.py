#!/usr/bin/env python3
"""
Investigation of timing-related issues in POST requests.
"""

import hashlib
import json
import os
import socket
import ssl
import sys
import time

PROXY_HTTPS_PORT = int(os.environ.get('PROXY_HTTPS_PORT', '8443'))
RP_BUF_SIZE = 32768


def create_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'


def send_post(size, send_mode='all_at_once', keep_alive=False):
    """
    Send POST request with different modes.
    send_mode: 'all_at_once', 'header_then_body', 'chunked_body'
    """
    body = os.urandom(size)
    expected_hash = hashlib.sha256(body).hexdigest()

    connection_header = 'keep-alive' if keep_alive else 'close'
    request_header = (
        f'POST /echo HTTP/1.1\r\n'
        f'Host: test.localhost\r\n'
        f'Content-Type: application/octet-stream\r\n'
        f'Content-Length: {len(body)}\r\n'
        f'Connection: {connection_header}\r\n'
        f'\r\n'
    ).encode()

    ctx = create_ssl_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect(('127.0.0.1', PROXY_HTTPS_PORT))
    ssl_sock = ctx.wrap_socket(sock, server_hostname='test.localhost')

    try:
        if send_mode == 'all_at_once':
            ssl_sock.sendall(request_header + body)
        elif send_mode == 'header_then_body':
            ssl_sock.sendall(request_header)
            ssl_sock.sendall(body)
        elif send_mode == 'header_delay_body':
            ssl_sock.sendall(request_header)
            time.sleep(0.01)
            ssl_sock.sendall(body)
        elif send_mode == 'chunked_body':
            ssl_sock.sendall(request_header)
            chunk_size = 8192
            offset = 0
            while offset < len(body):
                chunk = body[offset:offset + chunk_size]
                ssl_sock.sendall(chunk)
                offset += chunk_size
                time.sleep(0.001)

        response = b''
        while True:
            try:
                chunk = ssl_sock.recv(65536)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        if not response:
            return False, 'Empty response'

        if b'\r\n\r\n' in response:
            header_part, body_part = response.split(b'\r\n\r\n', 1)
            status_line = header_part.split(b'\r\n')[0].decode()

            if '200' in status_line:
                try:
                    data = json.loads(body_part)
                    if data.get('sha256') == expected_hash:
                        return True, 'OK'
                    else:
                        return False, f'Hash mismatch'
                except:
                    return False, f'JSON error: {body_part[:100]}'
            else:
                # Check if it's the Python error
                if b'Large' in response:
                    return False, 'Body mixed with headers (Large error)'
                return False, f'Status: {status_line}'
        else:
            return False, 'No header separator'

    except Exception as e:
        return False, f'{type(e).__name__}: {e}'
    finally:
        ssl_sock.close()


def test_send_mode(mode, sizes):
    """Test a specific send mode with multiple sizes."""
    print(f'\n{Colors.YELLOW}Testing mode: {mode}{Colors.RESET}')
    results = {}

    for size in sizes:
        passed, msg = send_post(size, mode)
        results[size] = (passed, msg)
        status = f'{Colors.GREEN}PASS{Colors.RESET}' if passed else f'{Colors.RED}FAIL{Colors.RESET}'
        print(f'  {size//1024:>3}KB: [{status}] {msg}')
        time.sleep(0.05)

    return results


def test_rapid_fire(size, count=20):
    """Send many requests rapidly to check for race conditions."""
    print(f'\n{Colors.YELLOW}Rapid fire test: {count} requests of {size//1024}KB{Colors.RESET}')

    results = []
    for i in range(count):
        passed, msg = send_post(size, 'all_at_once')
        results.append(passed)
        if not passed:
            print(f'  Request {i+1}: {Colors.RED}FAIL{Colors.RESET} - {msg}')

    success = sum(results)
    if success == count:
        print(f'  {Colors.GREEN}All {count} requests succeeded{Colors.RESET}')
    else:
        print(f'  {Colors.RED}{count - success}/{count} requests failed{Colors.RESET}')

    return success == count


def test_pipelined_requests():
    """Send multiple requests on same connection (pipelining)."""
    print(f'\n{Colors.YELLOW}Testing pipelined requests{Colors.RESET}')

    ctx = create_ssl_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect(('127.0.0.1', PROXY_HTTPS_PORT))
    ssl_sock = ctx.wrap_socket(sock, server_hostname='test.localhost')

    sizes = [1024, 8192, 32768, 50000, 65536]
    success_count = 0

    try:
        for size in sizes:
            body = os.urandom(size)
            expected_hash = hashlib.sha256(body).hexdigest()

            request = (
                f'POST /echo HTTP/1.1\r\n'
                f'Host: test.localhost\r\n'
                f'Content-Type: application/octet-stream\r\n'
                f'Content-Length: {len(body)}\r\n'
                f'Connection: keep-alive\r\n'
                f'\r\n'
            ).encode() + body

            ssl_sock.sendall(request)

            # Read response
            response = b''
            content_length = None

            # Read headers
            while b'\r\n\r\n' not in response:
                response += ssl_sock.recv(4096)

            header_end = response.index(b'\r\n\r\n') + 4
            headers = response[:header_end].decode()

            for line in headers.split('\r\n'):
                if line.lower().startswith('content-length:'):
                    content_length = int(line.split(':')[1].strip())

            # Read body
            body_received = response[header_end:]
            while len(body_received) < content_length:
                body_received += ssl_sock.recv(4096)

            try:
                data = json.loads(body_received)
                if data.get('sha256') == expected_hash:
                    print(f'  {size//1024:>3}KB: {Colors.GREEN}PASS{Colors.RESET}')
                    success_count += 1
                else:
                    print(f'  {size//1024:>3}KB: {Colors.RED}FAIL{Colors.RESET} - hash mismatch')
            except:
                print(f'  {size//1024:>3}KB: {Colors.RED}FAIL{Colors.RESET} - {body_received[:50]}')

    except Exception as e:
        print(f'  {Colors.RED}Error: {e}{Colors.RESET}')
    finally:
        ssl_sock.close()

    return success_count == len(sizes)


def main():
    print(f'{Colors.YELLOW}=== Timing Investigation ==={Colors.RESET}')
    print(f'Proxy: https://127.0.0.1:{PROXY_HTTPS_PORT}')
    print(f'Buffer size: {RP_BUF_SIZE} bytes')

    sizes = [
        32 * 1024,   # 32KB
        48 * 1024,   # 48KB
        64 * 1024,   # 64KB - 2*buf
        80 * 1024,   # 80KB
        96 * 1024,   # 96KB - 3*buf
        100 * 1024,  # 100KB
        128 * 1024,  # 128KB - 4*buf
    ]

    # Test different send modes
    test_send_mode('all_at_once', sizes)
    test_send_mode('header_then_body', sizes)
    test_send_mode('header_delay_body', sizes)
    test_send_mode('chunked_body', sizes)

    # Rapid fire tests at problematic sizes
    test_rapid_fire(64 * 1024)
    test_rapid_fire(100 * 1024)

    # Pipelined requests
    test_pipelined_requests()


if __name__ == '__main__':
    main()
