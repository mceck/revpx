#!/usr/bin/env python3
"""
Targeted tests to investigate POST request issues in revpx.
"""

import hashlib
import http.client
import json
import os
import ssl
import sys
import time

PROXY_HOST = 'test.localhost'
PROXY_HTTPS_PORT = int(os.environ.get('PROXY_HTTPS_PORT', '8443'))
BACKEND_PORT = int(os.environ.get('BACKEND_PORT', '9999'))
RP_BUF_SIZE = 32768


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'


def create_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def test_post(size, description=''):
    """Test POST request with given body size."""
    body = os.urandom(size)
    expected_hash = hashlib.sha256(body).hexdigest()

    ctx = create_ssl_context()
    conn = http.client.HTTPSConnection(
        '127.0.0.1', PROXY_HTTPS_PORT,
        timeout=60,
        context=ctx
    )

    try:
        headers = {
            'Host': PROXY_HOST,
            'Content-Type': 'application/octet-stream',
            'Content-Length': str(len(body))
        }
        conn.request('POST', '/echo', body=body, headers=headers)
        response = conn.getresponse()
        response_body = response.read()

        if response.status != 200:
            return False, f'Status {response.status}'

        data = json.loads(response_body)
        if data['received_length'] != len(body):
            return False, f'Server received {data["received_length"]} bytes, sent {len(body)}'
        if data['sha256'] != expected_hash:
            return False, f'Checksum mismatch: got {data["sha256"][:16]}..., expected {expected_hash[:16]}...'

        return True, ''
    except http.client.RemoteDisconnected as e:
        return False, f'Remote disconnected: {e}'
    except Exception as e:
        return False, f'Error: {type(e).__name__}: {e}'
    finally:
        conn.close()


def test_post_chunked(size, chunk_size=8192, description=''):
    """Test POST with chunked transfer encoding."""
    body = os.urandom(size)
    expected_hash = hashlib.sha256(body).hexdigest()

    ctx = create_ssl_context()
    conn = http.client.HTTPSConnection(
        '127.0.0.1', PROXY_HTTPS_PORT,
        timeout=60,
        context=ctx
    )

    try:
        headers = {
            'Host': PROXY_HOST,
            'Content-Type': 'application/octet-stream',
            'Transfer-Encoding': 'chunked'
        }
        conn.request('POST', '/echo', headers=headers)

        # Send body in chunks
        offset = 0
        while offset < len(body):
            chunk = body[offset:offset + chunk_size]
            chunk_header = f'{len(chunk):x}\r\n'.encode()
            conn.sock.sendall(chunk_header + chunk + b'\r\n')
            offset += chunk_size
        conn.sock.sendall(b'0\r\n\r\n')

        response = conn.getresponse()
        response_body = response.read()

        if response.status != 200:
            return False, f'Status {response.status}'

        data = json.loads(response_body)
        if data['sha256'] != expected_hash:
            return False, 'Checksum mismatch'

        return True, ''
    except Exception as e:
        return False, f'{type(e).__name__}: {e}'
    finally:
        conn.close()


def test_direct_backend(size):
    """Test POST directly to backend (bypass proxy)."""
    body = os.urandom(size)
    expected_hash = hashlib.sha256(body).hexdigest()

    conn = http.client.HTTPConnection('127.0.0.1', BACKEND_PORT, timeout=60)
    try:
        conn.request('POST', '/echo', body=body)
        response = conn.getresponse()
        response_body = response.read()

        if response.status != 200:
            return False, f'Status {response.status}'

        data = json.loads(response_body)
        if data['received_length'] != len(body):
            return False, f'Server received {data["received_length"]} bytes'
        if data['sha256'] != expected_hash:
            return False, 'Checksum mismatch'

        return True, ''
    except Exception as e:
        return False, f'{type(e).__name__}: {e}'
    finally:
        conn.close()


def main():
    print(f'\n{Colors.YELLOW}=== POST Request Investigation ==={Colors.RESET}')
    print(f'Proxy: https://127.0.0.1:{PROXY_HTTPS_PORT}')
    print(f'Backend: http://127.0.0.1:{BACKEND_PORT}')
    print(f'Buffer size: {RP_BUF_SIZE} bytes\n')

    # First verify backend works directly
    print(f'{Colors.CYAN}--- Testing Direct Backend ---{Colors.RESET}')
    for size in [1024, 10240, 50*1024, 100*1024]:
        passed, details = test_direct_backend(size)
        status = f'{Colors.GREEN}PASS{Colors.RESET}' if passed else f'{Colors.RED}FAIL{Colors.RESET}'
        print(f'[{status}] Direct backend POST {size//1024}KB {details}')

    print(f'\n{Colors.CYAN}--- Testing POST Through Proxy ---{Colors.RESET}')

    # Test various sizes
    sizes = [
        (1024, '1KB'),
        (4096, '4KB'),
        (8192, '8KB'),
        (16384, '16KB'),
        (RP_BUF_SIZE - 1000, f'{RP_BUF_SIZE - 1000} (buf-1000)'),
        (RP_BUF_SIZE - 100, f'{RP_BUF_SIZE - 100} (buf-100)'),
        (RP_BUF_SIZE, f'{RP_BUF_SIZE} (buf)'),
        (RP_BUF_SIZE + 100, f'{RP_BUF_SIZE + 100} (buf+100)'),
        (RP_BUF_SIZE + 1000, f'{RP_BUF_SIZE + 1000} (buf+1000)'),
        (RP_BUF_SIZE * 2, f'{RP_BUF_SIZE * 2} (2*buf)'),
        (50 * 1024, '50KB'),
        (64 * 1024, '64KB'),
        (80 * 1024, '80KB'),
        (90 * 1024, '90KB'),
        (95 * 1024, '95KB'),
        (100 * 1024, '100KB'),
        (110 * 1024, '110KB'),
        (128 * 1024, '128KB'),
    ]

    passed_count = 0
    failed_count = 0
    failed_sizes = []

    for size, label in sizes:
        passed, details = test_post(size)
        if passed:
            status = f'{Colors.GREEN}PASS{Colors.RESET}'
            passed_count += 1
        else:
            status = f'{Colors.RED}FAIL{Colors.RESET}'
            failed_count += 1
            failed_sizes.append((size, label, details))
        print(f'[{status}] POST {label}: {details if not passed else "OK"}')
        time.sleep(0.1)  # Small delay between requests

    print(f'\n{Colors.CYAN}--- Testing POST with Keep-Alive ---{Colors.RESET}')

    # Test multiple POSTs on same connection
    ctx = create_ssl_context()
    conn = http.client.HTTPSConnection(
        '127.0.0.1', PROXY_HTTPS_PORT,
        timeout=60,
        context=ctx
    )

    keepalive_sizes = [1024, 4096, 16384, 32768, 50*1024]
    for i, size in enumerate(keepalive_sizes):
        try:
            body = os.urandom(size)
            expected_hash = hashlib.sha256(body).hexdigest()
            conn.request('POST', '/echo', body=body, headers={'Host': PROXY_HOST})
            response = conn.getresponse()
            response_body = response.read()
            data = json.loads(response_body)

            if response.status == 200 and data['sha256'] == expected_hash:
                print(f'{Colors.GREEN}[PASS]{Colors.RESET} Keep-alive POST #{i+1} ({size} bytes)')
            else:
                print(f'{Colors.RED}[FAIL]{Colors.RESET} Keep-alive POST #{i+1} ({size} bytes): Status {response.status}')
        except Exception as e:
            print(f'{Colors.RED}[FAIL]{Colors.RESET} Keep-alive POST #{i+1} ({size} bytes): {e}')
            # Connection might be broken, try to reconnect
            try:
                conn.close()
            except:
                pass
            conn = http.client.HTTPSConnection(
                '127.0.0.1', PROXY_HTTPS_PORT,
                timeout=60,
                context=ctx
            )

    conn.close()

    # Summary
    print(f'\n{Colors.YELLOW}=== Summary ==={Colors.RESET}')
    print(f'{Colors.GREEN}Passed: {passed_count}{Colors.RESET}')
    print(f'{Colors.RED}Failed: {failed_count}{Colors.RESET}')

    if failed_sizes:
        print(f'\n{Colors.RED}Failed sizes:{Colors.RESET}')
        for size, label, details in failed_sizes:
            print(f'  - {label} ({size} bytes): {details}')

    return 0 if failed_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
