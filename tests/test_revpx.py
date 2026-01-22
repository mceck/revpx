#!/usr/bin/env python3
"""
Comprehensive test suite for revpx reverse proxy.
Tests various scenarios that could cause content-length mismatches or body corruption.
"""

import hashlib
import json
import os
import random
import socket
import ssl
import string
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple

import urllib3

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Test configuration
PROXY_HOST = 'test.localhost'
PROXY_HTTPS_PORT = 8443
PROXY_HTTP_PORT = 8880
BACKEND_PORT = 9999
CERT_FILE = 'test.localhost.pem'
KEY_FILE = 'test.localhost-key.pem'

# Buffer size in revpx
RP_BUF_SIZE = 32768


class RevpxTestCase(unittest.TestCase):
    """Base test case with common utilities."""

    @classmethod
    def setUpClass(cls):
        """Start backend server and revpx."""
        cls.backend_process = None
        cls.revpx_process = None
        cls.start_servers()
        # Give servers time to start
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        """Stop all servers."""
        cls.stop_servers()

    @classmethod
    def start_servers(cls):
        """Start backend and revpx servers."""
        # Start backend server
        backend_cmd = [
            sys.executable,
            'tests/backend_server.py',
            '-p', str(BACKEND_PORT)
        ]
        cls.backend_process = subprocess.Popen(
            backend_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Start revpx
        revpx_cmd = [
            './build/revpx',
            '-p', str(PROXY_HTTPS_PORT),
            '-pp', str(PROXY_HTTP_PORT),
            PROXY_HOST, str(BACKEND_PORT), CERT_FILE, KEY_FILE
        ]
        cls.revpx_process = subprocess.Popen(
            revpx_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Wait for servers to be ready
        cls._wait_for_server('127.0.0.1', BACKEND_PORT, timeout=10)
        cls._wait_for_server('127.0.0.1', PROXY_HTTPS_PORT, timeout=10)

    @classmethod
    def stop_servers(cls):
        """Stop all servers."""
        if cls.revpx_process:
            cls.revpx_process.terminate()
            cls.revpx_process.wait(timeout=5)
        if cls.backend_process:
            cls.backend_process.terminate()
            cls.backend_process.wait(timeout=5)

    @classmethod
    def _wait_for_server(cls, host: str, port: int, timeout: float = 10):
        """Wait for a server to be ready."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((host, port))
                sock.close()
                return
            except (socket.error, ConnectionRefusedError):
                time.sleep(0.1)
        raise TimeoutError(f'Server {host}:{port} did not start in time')

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for HTTPS connections."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _make_request(self, path: str, method: str = 'GET', body: bytes = None,
                      headers: dict = None, timeout: float = 30) -> Tuple[int, dict, bytes]:
        """Make an HTTPS request through the proxy."""
        import http.client

        conn = http.client.HTTPSConnection(
            '127.0.0.1',
            PROXY_HTTPS_PORT,
            timeout=timeout,
            context=self._create_ssl_context()
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

    def _make_raw_request(self, request: bytes, timeout: float = 30) -> bytes:
        """Make a raw HTTPS request and return raw response."""
        ctx = self._create_ssl_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(('127.0.0.1', PROXY_HTTPS_PORT))
        ssl_sock = ctx.wrap_socket(sock, server_hostname=PROXY_HOST)

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

    def _verify_payload(self, body: bytes) -> bool:
        """Verify a payload with embedded checksum."""
        if len(body) < 64:
            return False
        data = body[:-64]
        expected_checksum = body[-64:]
        actual_checksum = hashlib.sha256(data).hexdigest().encode()
        return expected_checksum == actual_checksum


class TestBasicFunctionality(RevpxTestCase):
    """Test basic proxy functionality."""

    def test_health_check(self):
        """Test basic health check endpoint."""
        status, headers, body = self._make_request('/health')
        self.assertEqual(status, 200)
        self.assertEqual(body, b'OK')

    def test_header_forwarding(self):
        """Test that headers are properly forwarded."""
        status, headers, body = self._make_request(
            '/echo-headers',
            headers={'X-Custom-Header': 'test-value'}
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('X-Custom-Header'), 'test-value')
        # Check forwarded headers are added
        self.assertIn('X-Forwarded-For', data)
        self.assertIn('X-Real-IP', data)

    def test_http_to_https_redirect(self):
        """Test HTTP to HTTPS redirect."""
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', PROXY_HTTP_PORT, timeout=10)
        try:
            conn.request('GET', '/health', headers={'Host': PROXY_HOST})
            response = conn.getresponse()
            self.assertEqual(response.status, 301)
            location = response.getheader('Location')
            self.assertIn('https://', location)
        finally:
            conn.close()


class TestLargePayloads(RevpxTestCase):
    """Test large payload handling - main area of concern."""

    def test_payload_exact_buffer_size(self):
        """Test payload exactly at buffer size (32KB)."""
        status, headers, body = self._make_request(f'/payload?size={RP_BUF_SIZE}')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), RP_BUF_SIZE)
        self.assertTrue(self._verify_payload(body), 'Payload checksum mismatch')

    def test_payload_double_buffer_size(self):
        """Test payload at 2x buffer size (64KB)."""
        size = RP_BUF_SIZE * 2
        status, headers, body = self._make_request(f'/payload?size={size}')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body), 'Payload checksum mismatch')

    def test_payload_triple_buffer_size(self):
        """Test payload at 3x buffer size (96KB)."""
        size = RP_BUF_SIZE * 3
        status, headers, body = self._make_request(f'/payload?size={size}')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body), 'Payload checksum mismatch')

    def test_large_payload_100kb(self):
        """Test 100KB payload."""
        size = 100 * 1024
        status, headers, body = self._make_request(f'/payload?size={size}')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body), 'Payload checksum mismatch')

    def test_large_payload_256kb(self):
        """Test 256KB payload."""
        size = 256 * 1024
        status, headers, body = self._make_request(f'/payload?size={size}')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body), 'Payload checksum mismatch')

    def test_large_payload_512kb(self):
        """Test 512KB payload."""
        size = 512 * 1024
        status, headers, body = self._make_request(f'/payload?size={size}')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body), 'Payload checksum mismatch')

    def test_large_payload_1mb(self):
        """Test 1MB payload."""
        size = 1024 * 1024
        status, headers, body = self._make_request(f'/payload?size={size}', timeout=60)
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body), 'Payload checksum mismatch')

    def test_large_payload_5mb(self):
        """Test 5MB payload."""
        size = 5 * 1024 * 1024
        status, headers, body = self._make_request(f'/payload?size={size}', timeout=120)
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body), 'Payload checksum mismatch')


class TestBufferBoundaries(RevpxTestCase):
    """Test payloads at exact buffer boundaries."""

    def test_boundary_minus_1(self):
        """Test payload at buffer size - 1."""
        size = RP_BUF_SIZE - 1
        status, headers, body = self._make_request(f'/payload?size={size}')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body))

    def test_boundary_plus_1(self):
        """Test payload at buffer size + 1."""
        size = RP_BUF_SIZE + 1
        status, headers, body = self._make_request(f'/payload?size={size}')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body))

    def test_boundary_offsets(self):
        """Test various offsets around buffer boundary."""
        offsets = [-100, -10, -1, 0, 1, 10, 100, 1000]
        for offset in offsets:
            size = RP_BUF_SIZE + offset
            with self.subTest(offset=offset, size=size):
                status, headers, body = self._make_request(f'/payload?size={size}')
                self.assertEqual(status, 200)
                self.assertEqual(len(body), size, f'Content-Length mismatch at offset {offset}')
                self.assertTrue(self._verify_payload(body), f'Checksum mismatch at offset {offset}')

    def test_double_boundary_offsets(self):
        """Test various offsets around 2x buffer boundary."""
        base = RP_BUF_SIZE * 2
        offsets = [-100, -10, -1, 0, 1, 10, 100]
        for offset in offsets:
            size = base + offset
            with self.subTest(offset=offset, size=size):
                status, headers, body = self._make_request(f'/payload?size={size}')
                self.assertEqual(status, 200)
                self.assertEqual(len(body), size)
                self.assertTrue(self._verify_payload(body))


class TestChunkedTransfer(RevpxTestCase):
    """Test chunked transfer encoding."""

    def test_chunked_small(self):
        """Test small chunked response."""
        status, headers, body = self._make_request('/payload?size=1024&chunked=true')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), 1024)
        self.assertTrue(self._verify_payload(body))

    def test_chunked_medium(self):
        """Test medium chunked response (around buffer size)."""
        size = RP_BUF_SIZE
        status, headers, body = self._make_request(f'/payload?size={size}&chunked=true')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body))

    def test_chunked_large(self):
        """Test large chunked response (multiple buffer sizes)."""
        size = RP_BUF_SIZE * 4
        status, headers, body = self._make_request(f'/payload?size={size}&chunked=true')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body))

    def test_streaming_chunks(self):
        """Test streaming chunked response with delays."""
        status, headers, body = self._make_request(
            '/stream?chunks=20&chunk_size=4096&delay=0.01',
            timeout=60
        )
        self.assertEqual(status, 200)
        # Body size = chunks * chunk_size
        self.assertEqual(len(body), 20 * 4096)


class TestSlowResponses(RevpxTestCase):
    """Test handling of slow backend responses."""

    def test_slow_small_chunks(self):
        """Test slow response with small chunks."""
        size = 10240
        status, headers, body = self._make_request(
            f'/slow?size={size}&delay=0.05&chunk=512',
            timeout=30
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body))

    def test_slow_large_chunks(self):
        """Test slow response with large chunks."""
        size = 102400
        status, headers, body = self._make_request(
            f'/slow?size={size}&delay=0.01&chunk=8192',
            timeout=60
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body))


class TestConcurrency(RevpxTestCase):
    """Test concurrent request handling."""

    def test_concurrent_small_requests(self):
        """Test many concurrent small requests."""
        num_requests = 50
        size = 1024

        def make_request(_):
            try:
                status, headers, body = self._make_request(f'/payload?size={size}')
                return status == 200 and len(body) == size and self._verify_payload(body)
            except Exception as e:
                print(f'Request failed: {e}')
                return False

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            results = [f.result() for f in as_completed(futures)]

        success_count = sum(results)
        self.assertEqual(success_count, num_requests, f'{num_requests - success_count} requests failed')

    def test_concurrent_large_requests(self):
        """Test concurrent large requests."""
        num_requests = 20
        size = 100 * 1024

        def make_request(_):
            try:
                status, headers, body = self._make_request(f'/payload?size={size}', timeout=60)
                return status == 200 and len(body) == size and self._verify_payload(body)
            except Exception as e:
                print(f'Request failed: {e}')
                return False

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            results = [f.result() for f in as_completed(futures)]

        success_count = sum(results)
        self.assertEqual(success_count, num_requests, f'{num_requests - success_count} requests failed')

    def test_concurrent_mixed_sizes(self):
        """Test concurrent requests with mixed sizes."""
        sizes = [1024, 4096, 16384, 32768, 65536, 131072]
        num_per_size = 5

        def make_request(size):
            try:
                status, headers, body = self._make_request(f'/payload?size={size}', timeout=60)
                return status == 200 and len(body) == size and self._verify_payload(body)
            except Exception as e:
                print(f'Request failed for size {size}: {e}')
                return False

        requests = sizes * num_per_size
        random.shuffle(requests)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, size) for size in requests]
            results = [f.result() for f in as_completed(futures)]

        success_count = sum(results)
        total = len(requests)
        self.assertEqual(success_count, total, f'{total - success_count} requests failed')


class TestKeepAlive(RevpxTestCase):
    """Test keep-alive connection handling."""

    def test_multiple_requests_same_connection(self):
        """Test multiple requests on the same connection."""
        import http.client

        ctx = self._create_ssl_context()
        conn = http.client.HTTPSConnection(
            '127.0.0.1',
            PROXY_HTTPS_PORT,
            timeout=30,
            context=ctx
        )

        try:
            for i in range(10):
                size = 1024 * (i + 1)
                conn.request('GET', f'/payload?size={size}', headers={'Host': PROXY_HOST})
                response = conn.getresponse()
                body = response.read()

                self.assertEqual(response.status, 200, f'Request {i} failed with status {response.status}')
                self.assertEqual(len(body), size, f'Request {i} body length mismatch')
                self.assertTrue(self._verify_payload(body), f'Request {i} checksum mismatch')
        finally:
            conn.close()

    def test_keepalive_with_large_payloads(self):
        """Test keep-alive with large payloads."""
        import http.client

        ctx = self._create_ssl_context()
        conn = http.client.HTTPSConnection(
            '127.0.0.1',
            PROXY_HTTPS_PORT,
            timeout=60,
            context=ctx
        )

        sizes = [RP_BUF_SIZE - 100, RP_BUF_SIZE, RP_BUF_SIZE + 100, RP_BUF_SIZE * 2]

        try:
            for i, size in enumerate(sizes):
                conn.request('GET', f'/payload?size={size}', headers={'Host': PROXY_HOST})
                response = conn.getresponse()
                body = response.read()

                self.assertEqual(response.status, 200, f'Request {i} (size={size}) failed')
                self.assertEqual(len(body), size, f'Request {i} body length mismatch: got {len(body)}, expected {size}')
                self.assertTrue(self._verify_payload(body), f'Request {i} checksum mismatch')
        finally:
            conn.close()


class TestPostRequests(RevpxTestCase):
    """Test POST request handling with various body sizes."""

    def test_small_post(self):
        """Test small POST request."""
        body = os.urandom(1024)
        status, headers, response = self._make_request('/echo', method='POST', body=body)
        self.assertEqual(status, 200)
        data = json.loads(response)
        self.assertEqual(data['received_length'], len(body))
        self.assertTrue(data['match'])
        self.assertEqual(data['sha256'], hashlib.sha256(body).hexdigest())

    def test_large_post(self):
        """Test large POST request."""
        body = os.urandom(100 * 1024)
        status, headers, response = self._make_request('/echo', method='POST', body=body, timeout=60)
        self.assertEqual(status, 200)
        data = json.loads(response)
        self.assertEqual(data['received_length'], len(body))
        self.assertTrue(data['match'])
        self.assertEqual(data['sha256'], hashlib.sha256(body).hexdigest())

    def test_post_at_buffer_boundary(self):
        """Test POST with body at buffer boundary."""
        body = os.urandom(RP_BUF_SIZE)
        status, headers, response = self._make_request('/echo', method='POST', body=body, timeout=60)
        self.assertEqual(status, 200)
        data = json.loads(response)
        self.assertEqual(data['received_length'], len(body))
        self.assertTrue(data['match'])

    def test_mirror_large_body(self):
        """Test mirroring large body - response same size as request."""
        body = os.urandom(50 * 1024)
        expected_hash = hashlib.sha256(body).hexdigest()

        status, headers, response = self._make_request('/mirror', method='POST', body=body, timeout=60)
        self.assertEqual(status, 200)
        self.assertEqual(len(response), len(body))
        actual_hash = hashlib.sha256(response).hexdigest()
        self.assertEqual(actual_hash, expected_hash)


class TestEdgeCases(RevpxTestCase):
    """Test edge cases and potential problem areas."""

    def test_empty_response(self):
        """Test empty response body."""
        status, headers, body = self._make_request('/payload?size=64')  # Minimum for checksum
        self.assertEqual(status, 200)

    def test_very_large_headers(self):
        """Test request with many headers."""
        extra_headers = {f'X-Header-{i}': f'value-{i}' * 10 for i in range(50)}
        status, headers, body = self._make_request('/health', headers=extra_headers)
        self.assertEqual(status, 200)

    def test_rapid_sequential_requests(self):
        """Test rapid sequential requests."""
        for i in range(100):
            status, headers, body = self._make_request('/health')
            self.assertEqual(status, 200, f'Request {i} failed')

    def test_request_body_response_body_both_large(self):
        """Test large request and response body in same request."""
        request_body = os.urandom(50 * 1024)
        expected_hash = hashlib.sha256(request_body).hexdigest()

        status, headers, response = self._make_request(
            '/mirror', method='POST', body=request_body, timeout=60
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(response), len(request_body))
        self.assertEqual(hashlib.sha256(response).hexdigest(), expected_hash)

    def test_incremental_sizes(self):
        """Test incrementally increasing sizes to find exact failure point."""
        # Test every KB from 30KB to 40KB
        for kb in range(30, 40):
            size = kb * 1024
            with self.subTest(size_kb=kb):
                status, headers, body = self._make_request(f'/payload?size={size}')
                self.assertEqual(status, 200)
                self.assertEqual(len(body), size, f'Content-Length mismatch at {kb}KB')
                self.assertTrue(self._verify_payload(body), f'Checksum mismatch at {kb}KB')


class TestStressTest(RevpxTestCase):
    """Stress tests to trigger race conditions and edge cases."""

    def test_burst_requests(self):
        """Send burst of requests to trigger potential race conditions."""
        num_requests = 100

        def make_request(size):
            try:
                status, headers, body = self._make_request(f'/payload?size={size}', timeout=30)
                if status != 200:
                    return (False, f'Status {status}')
                if len(body) != size:
                    return (False, f'Length mismatch: got {len(body)}, expected {size}')
                if not self._verify_payload(body):
                    return (False, 'Checksum mismatch')
                return (True, None)
            except Exception as e:
                return (False, str(e))

        # Burst of requests with various sizes
        sizes = [random.randint(1024, 100 * 1024) for _ in range(num_requests)]

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request, size) for size in sizes]
            results = [f.result() for f in as_completed(futures)]

        failures = [(i, err) for i, (success, err) in enumerate(results) if not success]
        self.assertEqual(len(failures), 0, f'Failures: {failures[:10]}')  # Show first 10 failures

    def test_sustained_load(self):
        """Sustained load over time."""
        duration = 10  # seconds
        start_time = time.time()
        success_count = 0
        failure_count = 0
        failures = []

        while time.time() - start_time < duration:
            size = random.choice([1024, 4096, 16384, 32768, 65536])
            try:
                status, headers, body = self._make_request(f'/payload?size={size}', timeout=10)
                if status == 200 and len(body) == size and self._verify_payload(body):
                    success_count += 1
                else:
                    failure_count += 1
                    failures.append(f'Size {size}: status={status}, len={len(body)}')
            except Exception as e:
                failure_count += 1
                failures.append(f'Size {size}: {e}')

        total = success_count + failure_count
        print(f'\nSustained load: {success_count}/{total} successful ({failure_count} failures)')
        if failures:
            print(f'First failures: {failures[:5]}')
        self.assertEqual(failure_count, 0, f'{failure_count} failures during sustained load')


class TestSpecificBugScenarios(RevpxTestCase):
    """Tests targeting specific potential bugs identified in code review."""

    def test_partial_write_recovery(self):
        """Test recovery from partial writes by sending large payloads quickly."""
        sizes = [RP_BUF_SIZE + 1000, RP_BUF_SIZE * 2 + 500, RP_BUF_SIZE * 3 + 100]
        for size in sizes:
            with self.subTest(size=size):
                status, headers, body = self._make_request(f'/payload?size={size}')
                self.assertEqual(status, 200)
                self.assertEqual(len(body), size)
                self.assertTrue(self._verify_payload(body))

    def test_buffer_compaction_scenario(self):
        """Test scenarios that might trigger buffer compaction issues."""
        # Send requests that might cause buffer offset issues
        import http.client

        ctx = self._create_ssl_context()
        conn = http.client.HTTPSConnection(
            '127.0.0.1',
            PROXY_HTTPS_PORT,
            timeout=60,
            context=ctx
        )

        try:
            # First request: exactly buffer size
            conn.request('GET', f'/payload?size={RP_BUF_SIZE}', headers={'Host': PROXY_HOST})
            response = conn.getresponse()
            body = response.read()
            self.assertEqual(len(body), RP_BUF_SIZE)

            # Second request: slightly larger - should trigger compaction
            size2 = RP_BUF_SIZE + 1000
            conn.request('GET', f'/payload?size={size2}', headers={'Host': PROXY_HOST})
            response = conn.getresponse()
            body = response.read()
            self.assertEqual(len(body), size2)
            self.assertTrue(self._verify_payload(body))
        finally:
            conn.close()

    def test_chunked_body_boundary_crossing(self):
        """Test chunked responses that cross buffer boundaries."""
        # Request that will produce chunks crossing the 32KB boundary
        size = RP_BUF_SIZE + 5000
        status, headers, body = self._make_request(f'/payload?size={size}&chunked=true')
        self.assertEqual(status, 200)
        self.assertEqual(len(body), size)
        self.assertTrue(self._verify_payload(body))


def run_single_test(test_class, test_name):
    """Run a single test for debugging."""
    suite = unittest.TestLoader().loadTestsFromName(test_name, test_class)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)


if __name__ == '__main__':
    # Check if specific test is requested
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        # Run specific test
        test_name = sys.argv[1]
        sys.argv = sys.argv[:1]  # Remove test name from args

    # Run all tests
    unittest.main(verbosity=2)
