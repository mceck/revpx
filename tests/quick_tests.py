#!/usr/bin/env python3
"""
Quick test script for revpx - simpler than full test suite.
Can be used for quick debugging and identifying specific issues.
"""

import hashlib
import http.client
import json
import os
import random
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
PROXY_HOST = 'test.localhost'
PROXY_HTTPS_PORT = int(os.environ.get('PROXY_HTTPS_PORT', '8443'))
PROXY_HTTP_PORT = int(os.environ.get('PROXY_HTTP_PORT', '8880'))
BACKEND_PORT = int(os.environ.get('BACKEND_PORT', '9999'))
RP_BUF_SIZE = 32768


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'


def create_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_request(path, method='GET', body=None, headers=None, timeout=30):
    """Make HTTPS request through proxy."""
    conn = http.client.HTTPSConnection(
        '127.0.0.1', PROXY_HTTPS_PORT,
        timeout=timeout,
        context=create_ssl_context()
    )
    req_headers = {'Host': PROXY_HOST}
    if headers:
        req_headers.update(headers)

    try:
        conn.request(method, path, body=body, headers=req_headers)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def verify_payload(body):
    """Verify payload with embedded SHA256 checksum."""
    if len(body) < 64:
        return False
    data = body[:-64]
    expected_checksum = body[-64:]
    actual_checksum = hashlib.sha256(data).hexdigest().encode()
    return expected_checksum == actual_checksum


def test_result(name, passed, details=''):
    """Print test result."""
    if passed:
        print(f'{Colors.GREEN}[PASS]{Colors.RESET} {name}')
    else:
        print(f'{Colors.RED}[FAIL]{Colors.RESET} {name}')
        if details:
            print(f'       {details}')
    return passed


def run_test(name, test_func):
    """Run a single test with error handling."""
    try:
        result, details = test_func()
        return test_result(name, result, details)
    except Exception as e:
        return test_result(name, False, str(e))


# Test functions
def test_health_check():
    status, headers, body = make_request('/health')
    if status != 200:
        return False, f'Status {status}'
    if body != b'OK':
        return False, f'Body: {body}'
    return True, ''


def test_small_payload():
    size = 1024
    status, headers, body = make_request(f'/payload?size={size}')
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_buffer_boundary_exact():
    """Test at exact buffer size."""
    size = RP_BUF_SIZE
    status, headers, body = make_request(f'/payload?size={size}')
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_buffer_boundary_plus_one():
    """Test at buffer size + 1."""
    size = RP_BUF_SIZE + 1
    status, headers, body = make_request(f'/payload?size={size}')
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_double_buffer():
    """Test at 2x buffer size."""
    size = RP_BUF_SIZE * 2
    status, headers, body = make_request(f'/payload?size={size}')
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_large_100kb():
    """Test 100KB payload."""
    size = 100 * 1024
    status, headers, body = make_request(f'/payload?size={size}', timeout=60)
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_large_500kb():
    """Test 500KB payload."""
    size = 500 * 1024
    status, headers, body = make_request(f'/payload?size={size}', timeout=60)
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_large_1mb():
    """Test 1MB payload."""
    size = 1024 * 1024
    status, headers, body = make_request(f'/payload?size={size}', timeout=120)
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_chunked_medium():
    """Test chunked transfer encoding."""
    size = RP_BUF_SIZE
    status, headers, body = make_request(f'/payload?size={size}&chunked=true')
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_chunked_large():
    """Test large chunked response."""
    size = RP_BUF_SIZE * 3
    status, headers, body = make_request(f'/payload?size={size}&chunked=true', timeout=60)
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_slow_response():
    """Test slow backend response."""
    size = 10240
    status, headers, body = make_request(f'/slow?size={size}&delay=0.05&chunk=1024', timeout=30)
    if status != 200:
        return False, f'Status {status}'
    if len(body) != size:
        return False, f'Length: {len(body)} != {size}'
    if not verify_payload(body):
        return False, 'Checksum mismatch'
    return True, ''


def test_post_echo():
    """Test POST request echo."""
    body = os.urandom(10240)
    expected_hash = hashlib.sha256(body).hexdigest()
    status, headers, response = make_request('/echo', method='POST', body=body)
    if status != 200:
        return False, f'Status {status}'
    data = json.loads(response)
    if data['received_length'] != len(body):
        return False, f'Received length: {data["received_length"]} != {len(body)}'
    if data['sha256'] != expected_hash:
        return False, 'Request body corrupted'
    return True, ''


def test_post_large():
    """Test large POST request."""
    body = os.urandom(100 * 1024)
    expected_hash = hashlib.sha256(body).hexdigest()
    status, headers, response = make_request('/echo', method='POST', body=body, timeout=60)
    if status != 200:
        return False, f'Status {status}'
    data = json.loads(response)
    if data['received_length'] != len(body):
        return False, f'Received length: {data["received_length"]} != {len(body)}'
    if data['sha256'] != expected_hash:
        return False, 'Request body corrupted'
    return True, ''


def test_keepalive():
    """Test multiple requests on same connection."""
    ctx = create_ssl_context()
    conn = http.client.HTTPSConnection(
        '127.0.0.1', PROXY_HTTPS_PORT,
        timeout=30, context=ctx
    )

    try:
        for i in range(5):
            size = 1024 * (i + 1)
            conn.request('GET', f'/payload?size={size}', headers={'Host': PROXY_HOST})
            response = conn.getresponse()
            body = response.read()

            if response.status != 200:
                return False, f'Request {i}: Status {response.status}'
            if len(body) != size:
                return False, f'Request {i}: Length {len(body)} != {size}'
            if not verify_payload(body):
                return False, f'Request {i}: Checksum mismatch'
    finally:
        conn.close()
    return True, ''


def test_concurrent_small():
    """Test concurrent small requests."""
    num = 20
    size = 4096

    def do_request(_):
        try:
            status, _, body = make_request(f'/payload?size={size}')
            return status == 200 and len(body) == size and verify_payload(body)
        except:
            return False

    with ThreadPoolExecutor(max_workers=5) as ex:
        results = list(ex.map(do_request, range(num)))

    success = sum(results)
    if success != num:
        return False, f'{num - success}/{num} failed'
    return True, ''


def test_concurrent_large():
    """Test concurrent large requests."""
    num = 10
    size = 100 * 1024

    def do_request(_):
        try:
            status, _, body = make_request(f'/payload?size={size}', timeout=60)
            return status == 200 and len(body) == size and verify_payload(body)
        except:
            return False

    with ThreadPoolExecutor(max_workers=3) as ex:
        results = list(ex.map(do_request, range(num)))

    success = sum(results)
    if success != num:
        return False, f'{num - success}/{num} failed'
    return True, ''


def test_boundary_scan():
    """Scan around buffer boundary for issues."""
    failed = []
    for offset in range(-10, 11):
        size = RP_BUF_SIZE + offset
        try:
            status, _, body = make_request(f'/payload?size={size}')
            if status != 200 or len(body) != size or not verify_payload(body):
                failed.append(offset)
        except Exception as e:
            failed.append(f'{offset}: {e}')

    if failed:
        return False, f'Failed at offsets: {failed}'
    return True, ''


def test_rapid_fire():
    """Rapid sequential requests."""
    failures = 0
    for i in range(50):
        try:
            status, _, body = make_request('/health')
            if status != 200:
                failures += 1
        except:
            failures += 1

    if failures > 0:
        return False, f'{failures}/50 failed'
    return True, ''


def test_mixed_sizes_concurrent():
    """Concurrent requests with mixed sizes."""
    sizes = [1024, 4096, RP_BUF_SIZE - 100, RP_BUF_SIZE, RP_BUF_SIZE + 100, 64 * 1024]

    def do_request(size):
        try:
            status, _, body = make_request(f'/payload?size={size}', timeout=60)
            if status != 200:
                return (False, size, f'Status {status}')
            if len(body) != size:
                return (False, size, f'Length {len(body)}')
            if not verify_payload(body):
                return (False, size, 'Checksum')
            return (True, size, '')
        except Exception as e:
            return (False, size, str(e))

    # Run each size 3 times
    all_sizes = sizes * 3
    random.shuffle(all_sizes)

    with ThreadPoolExecutor(max_workers=5) as ex:
        results = list(ex.map(do_request, all_sizes))

    failures = [(s, e) for ok, s, e in results if not ok]
    if failures:
        return False, f'Failures: {failures[:5]}'
    return True, ''


def main():
    print(f'\n{Colors.YELLOW}=== RevPx Quick Tests ==={Colors.RESET}')
    print(f'Proxy: https://127.0.0.1:{PROXY_HTTPS_PORT}')
    print(f'Backend: http://127.0.0.1:{BACKEND_PORT}')
    print(f'Buffer size: {RP_BUF_SIZE} bytes\n')

    tests = [
        ('Health check', test_health_check),
        ('Small payload (1KB)', test_small_payload),
        ('Buffer boundary exact (32KB)', test_buffer_boundary_exact),
        ('Buffer boundary + 1', test_buffer_boundary_plus_one),
        ('Double buffer (64KB)', test_double_buffer),
        ('Large payload (100KB)', test_large_100kb),
        ('Large payload (500KB)', test_large_500kb),
        ('Large payload (1MB)', test_large_1mb),
        ('Chunked medium (32KB)', test_chunked_medium),
        ('Chunked large (96KB)', test_chunked_large),
        ('Slow response', test_slow_response),
        ('POST echo', test_post_echo),
        ('POST large (100KB)', test_post_large),
        ('Keep-alive connection', test_keepalive),
        ('Concurrent small requests', test_concurrent_small),
        ('Concurrent large requests', test_concurrent_large),
        ('Boundary scan', test_boundary_scan),
        ('Rapid fire', test_rapid_fire),
        ('Mixed sizes concurrent', test_mixed_sizes_concurrent),
    ]

    passed = 0
    failed = 0

    for name, func in tests:
        if run_test(name, func):
            passed += 1
        else:
            failed += 1

    print(f'\n{Colors.YELLOW}=== Results ==={Colors.RESET}')
    print(f'{Colors.GREEN}Passed: {passed}{Colors.RESET}')
    print(f'{Colors.RED}Failed: {failed}{Colors.RESET}')

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
