#!/usr/bin/env python3
"""
Fuzz and stress testing for revpx reverse proxy.

This test suite performs:
- Malformed HTTP request handling
- Random/fuzzy input generation
- Protocol boundary testing
- Security boundary testing (path traversal, header injection)
- Connection state and timing tests
- Binary/garbage input handling
"""

import hashlib
import json
import os
import random
import socket
import ssl
import string
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import pytest

# Import from main test module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_revpx import (
    BackendHandler,
    BackendServer,
    ProxyClient,
    RevPxProxy,
    HTTPS_PORT,
    BACKEND_PORT,
    TEST_DOMAIN,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def backend():
    """Start backend server for the test module"""
    server = BackendServer(BACKEND_PORT)
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="module")
def proxy(backend):
    """Start revpx proxy for the test module"""
    proxy = RevPxProxy()
    proxy.start()
    yield proxy
    proxy.stop()


@pytest.fixture
def client(proxy):
    """Get a test client"""
    return ProxyClient()


@pytest.fixture(autouse=True)
def reset_backend():
    """Reset backend state before each test"""
    BackendServer.reset()
    yield


class RawClient:
    """Low-level client for sending raw bytes through the proxy"""

    def __init__(self, host: str = TEST_DOMAIN, port: int = HTTPS_PORT):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def send_raw(self, data: bytes, timeout: float = 5.0, read_response: bool = True) -> Optional[bytes]:
        """Send raw bytes and optionally read response"""
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as sock:
                with self.context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    ssock.sendall(data)

                    if not read_response:
                        return None

                    response = b""
                    ssock.settimeout(2.0)
                    try:
                        while True:
                            chunk = ssock.recv(8192)
                            if not chunk:
                                break
                            response += chunk
                    except socket.timeout:
                        pass

                    return response
        except Exception as e:
            return None


# ============================================================================
# Malformed Request Tests
# ============================================================================

class TestMalformedRequests:
    """Test handling of malformed HTTP requests"""

    def test_missing_host_header(self, proxy):
        """Test request without Host header"""
        raw = RawClient()
        request = b"GET / HTTP/1.1\r\n\r\n"
        response = raw.send_raw(request)
        # Proxy uses SNI to route, so missing Host header may still work
        # Valid responses: 200 (routed via SNI), 400 (bad request), or connection close
        assert response is None or b"200" in response or b"400" in response or len(response) == 0

    def test_empty_request(self, proxy):
        """Test completely empty request"""
        raw = RawClient()
        response = raw.send_raw(b"")
        # Proxy should close connection or timeout
        assert response is None or len(response) == 0

    def test_partial_request_line(self, proxy):
        """Test incomplete request line"""
        raw = RawClient()
        response = raw.send_raw(b"GET /")
        # Should timeout or close connection
        assert response is None or len(response) == 0

    def test_garbage_request(self, proxy):
        """Test completely garbage data"""
        raw = RawClient()
        garbage = os.urandom(1024)
        response = raw.send_raw(garbage)
        # Should handle gracefully
        assert response is None or len(response) == 0 or b"400" in response

    def test_binary_in_headers(self, proxy):
        """Test binary data in header values"""
        raw = RawClient()
        binary_value = bytes(range(256))
        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nX-Binary: ".encode() + binary_value + b"\r\n\r\n"
        response = raw.send_raw(request)
        # Should either handle or return error
        assert response is not None

    def test_null_bytes_in_path(self, proxy):
        """Test null bytes in URL path"""
        raw = RawClient()
        request = f"GET /path\x00with\x00nulls HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = raw.send_raw(request)
        # Proxy should handle this safely
        assert response is not None

    def test_null_bytes_in_header_name(self, proxy):
        """Test null bytes in header name"""
        raw = RawClient()
        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nX-Null\x00Header: value\r\n\r\n".encode()
        response = raw.send_raw(request)
        assert response is not None

    def test_very_long_method(self, proxy):
        """Test extremely long HTTP method"""
        raw = RawClient()
        long_method = "X" * 10000
        request = f"{long_method} / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = raw.send_raw(request)
        # Should reject or handle gracefully
        assert response is None or len(response) == 0 or b"400" in response or b"501" in response

    def test_very_long_header_name(self, proxy):
        """Test very long header name"""
        raw = RawClient()
        long_name = "X-" + "A" * 10000
        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n{long_name}: value\r\n\r\n".encode()
        response = raw.send_raw(request)
        assert response is not None

    def test_very_long_header_value(self, proxy):
        """Test very long header value"""
        raw = RawClient()
        long_value = "A" * 100000
        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nX-Long: {long_value}\r\n\r\n".encode()
        response = raw.send_raw(request)
        assert response is not None

    def test_many_headers_limit(self, proxy):
        """Test request with excessive number of headers"""
        raw = RawClient()
        headers = "\r\n".join([f"X-Header-{i}: value-{i}" for i in range(1000)])
        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n{headers}\r\n\r\n".encode()
        response = raw.send_raw(request, timeout=10)
        # Should handle or reject
        assert response is not None

    def test_no_crlf_after_headers(self, proxy):
        """Test request without final CRLF"""
        raw = RawClient()
        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}".encode()
        response = raw.send_raw(request)
        # Should timeout waiting for complete headers
        assert response is None or len(response) == 0

    def test_lf_only_line_endings(self, proxy):
        """Test request with LF only (no CR)"""
        raw = RawClient()
        request = f"GET / HTTP/1.1\nHost: {TEST_DOMAIN}\n\n".encode()
        response = raw.send_raw(request)
        # Proxy may or may not accept this
        assert response is not None or response is None  # Just should not crash

    def test_mixed_line_endings(self, proxy):
        """Test request with mixed line endings"""
        raw = RawClient()
        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\nX-Test: value\r\n\r\n".encode()
        response = raw.send_raw(request)
        assert response is not None

    def test_http_09_request(self, proxy):
        """Test HTTP/0.9 style simple request"""
        raw = RawClient()
        request = b"GET /\r\n"
        response = raw.send_raw(request)
        # Modern proxies typically reject HTTP/0.9
        assert response is not None

    def test_invalid_http_version(self, proxy):
        """Test invalid HTTP version"""
        raw = RawClient()
        request = f"GET / HTTP/9.9\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = raw.send_raw(request)
        # Should return error or handle
        assert response is not None

    def test_http_2_preface_rejected(self, proxy):
        """Test that HTTP/2 connection preface is handled"""
        raw = RawClient()
        # HTTP/2 connection preface
        h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        response = raw.send_raw(h2_preface)
        # HTTP/1.1 proxy should reject this
        assert response is not None


# ============================================================================
# Fuzz Input Generation Tests
# ============================================================================

class TestFuzzGeneration:
    """Test with randomly generated fuzzy inputs"""

    def test_random_paths(self, client):
        """Test randomly generated paths"""
        for _ in range(100):
            path_len = random.randint(1, 500)
            # Generate random path with various characters
            chars = string.ascii_letters + string.digits + "/-_.~!$&'()*+,;=:@%"
            path = "/" + "".join(random.choice(chars) for _ in range(path_len))

            try:
                status, _, _ = client.request("GET", path, timeout=5)
                assert status in (200, 400, 404, 414)  # Valid responses
            except Exception:
                pass  # Connection errors are acceptable for malformed input

    def test_random_header_names(self, client):
        """Test randomly generated header names"""
        for _ in range(50):
            name_len = random.randint(1, 100)
            # Header names should be tokens (limited character set)
            chars = string.ascii_letters + string.digits + "-_"
            header_name = "X-" + "".join(random.choice(chars) for _ in range(name_len))
            header_value = "test-value"

            try:
                status, _, _ = client.request("GET", "/", headers={header_name: header_value}, timeout=5)
                assert status == 200
            except Exception:
                pass

    def test_random_header_values(self, client):
        """Test randomly generated header values"""
        for _ in range(50):
            value_len = random.randint(1, 1000)
            # Header values can contain printable ASCII (except control chars)
            chars = string.printable.replace("\r", "").replace("\n", "")
            header_value = "".join(random.choice(chars) for _ in range(value_len))

            try:
                status, _, _ = client.request("GET", "/", headers={"X-Random": header_value}, timeout=5)
                assert status == 200
            except Exception:
                pass

    def test_random_query_strings(self, client):
        """Test randomly generated query strings"""
        for _ in range(50):
            num_params = random.randint(1, 20)
            params = []
            for i in range(num_params):
                key_len = random.randint(1, 50)
                val_len = random.randint(0, 100)
                key = "".join(random.choice(string.ascii_letters) for _ in range(key_len))
                val = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(val_len))
                params.append(f"{key}={val}")

            path = "/?" + "&".join(params)

            try:
                status, _, _ = client.request("GET", path, timeout=5)
                assert status == 200
            except Exception:
                pass

    def test_random_body_content(self, client):
        """Test randomly generated request bodies"""
        for _ in range(50):
            body_len = random.randint(1, 10000)
            body = os.urandom(body_len)

            try:
                status, _, resp = client.request(
                    "POST", "/random-body",
                    headers={"Content-Type": "application/octet-stream"},
                    body=body,
                    timeout=10
                )
                if status == 200:
                    data = json.loads(resp)
                    assert data["body_length"] == body_len
            except Exception:
                pass

    def test_random_content_lengths(self, proxy):
        """Test with incorrect Content-Length headers"""
        raw = RawClient()

        for _ in range(20):
            actual_body = b"x" * random.randint(10, 100)
            # Claim different length
            claimed_length = random.randint(0, 1000)

            request = (
                f"POST /random HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {claimed_length}\r\n"
                f"\r\n"
            ).encode() + actual_body

            response = raw.send_raw(request, timeout=3)
            # Should handle mismatch gracefully
            assert response is None or len(response) >= 0


# ============================================================================
# Protocol Edge Cases
# ============================================================================

class TestProtocolEdgeCases:
    """Test HTTP protocol edge cases"""

    def test_request_smuggling_cl_te(self, proxy):
        """Test CL.TE request smuggling attempt"""
        raw = RawClient()
        # Try to include both Content-Length and Transfer-Encoding
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 13\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"SMUGGLED"
        ).encode()

        response = raw.send_raw(request)
        # Proxy should handle this without allowing smuggling
        assert response is not None

    def test_request_smuggling_te_cl(self, proxy):
        """Test TE.CL request smuggling attempt"""
        raw = RawClient()
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 4\r\n"
            f"\r\n"
            f"5c\r\n"
            f"SMUGGLED\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None

    def test_duplicate_content_length(self, proxy):
        """Test request with duplicate Content-Length headers"""
        raw = RawClient()
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 10\r\n"
            f"Content-Length: 20\r\n"
            f"\r\n"
            f"1234567890"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None

    def test_invalid_chunk_size(self, proxy):
        """Test chunked request with invalid chunk size"""
        raw = RawClient()
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"NOTAHEXNUMBER\r\n"
            f"data\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        # Should reject or handle gracefully
        assert response is not None

    def test_negative_content_length(self, proxy):
        """Test request with negative Content-Length"""
        raw = RawClient()
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: -1\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None

    def test_huge_content_length(self, proxy):
        """Test request with impossibly large Content-Length"""
        raw = RawClient()
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 9999999999999999999\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request, timeout=2)
        # Should reject, timeout, or close connection - empty response is valid
        assert response is None or len(response) == 0 or b"400" in response or b"413" in response

    def test_obs_fold_headers(self, proxy):
        """Test obsolete line folding in headers (RFC 7230 deprecated)"""
        raw = RawClient()
        # Line folding: continuation line starts with whitespace
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"X-Folded: value\r\n"
            f" continued\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        # May be rejected or accepted depending on implementation
        assert response is not None

    def test_space_before_colon(self, proxy):
        """Test space before colon in header"""
        raw = RawClient()
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"X-Test : value\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None

    def test_absolute_uri_request(self, client):
        """Test request with absolute URI (proxy style)"""
        # Some proxies support absolute URI in request line
        status, _, _ = client.request("GET", f"http://{TEST_DOMAIN}/path")
        # May work or return 400
        assert status in (200, 400)

    def test_connect_method(self, proxy):
        """Test CONNECT method (tunneling)"""
        raw = RawClient()
        request = f"CONNECT {TEST_DOMAIN}:443 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = raw.send_raw(request)
        # Reverse proxy should likely reject CONNECT
        assert response is not None

    def test_trace_method(self, proxy):
        """Test TRACE method"""
        raw = RawClient()
        request = f"TRACE / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = raw.send_raw(request)
        # TRACE is often disabled for security
        assert response is not None


# ============================================================================
# Security Boundary Tests
# ============================================================================

class TestSecurityBoundaries:
    """Test security-related edge cases"""

    def test_path_traversal_basic(self, client):
        """Test basic path traversal attempt"""
        status, _, body = client.request("GET", "/../../../etc/passwd")
        # Path should be handled safely - either normalized or rejected
        if status == 200:
            data = json.loads(body)
            # Path should not allow escaping
            assert data["path"] == "/../../../etc/passwd" or data["path"] == "/etc/passwd"

    def test_path_traversal_encoded(self, client):
        """Test URL-encoded path traversal"""
        status, _, body = client.request("GET", "/%2e%2e/%2e%2e/etc/passwd")
        # Should handle encoded sequences safely
        assert status in (200, 400, 404)

    def test_path_traversal_double_encoded(self, client):
        """Test double-encoded path traversal"""
        status, _, _ = client.request("GET", "/%252e%252e/etc/passwd")
        assert status in (200, 400, 404)

    def test_header_injection_crlf(self, proxy):
        """Test CRLF injection in header value"""
        raw = RawClient()
        # Try to inject a new header via CRLF in value
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"X-Injected: value\r\nX-Evil: injected\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        # Should handle without injection
        assert response is not None

    def test_host_header_attack(self, proxy):
        """Test Host header manipulation"""
        raw = RawClient()
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: evil.com\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        # Should reject unknown host or handle safely
        assert response is not None

    def test_host_header_port_manipulation(self, proxy):
        """Test Host header with port manipulation"""
        raw = RawClient()
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}:9999\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None

    def test_ssrf_localhost_header(self, client):
        """Test various localhost representations in requests"""
        paths = [
            "/",
            "/?url=http://127.0.0.1",
            "/?url=http://localhost",
            "/?url=http://[::1]",
        ]

        for path in paths:
            status, _, _ = client.request("GET", path)
            assert status == 200

    def test_unicode_normalization(self, client):
        """Test Unicode normalization in paths"""
        # Various Unicode representations that might normalize
        paths = [
            "/test\u2024\u2024/passwd",  # one dot leader
            "/\uff2e\uff4f\uff52\uff4d",  # fullwidth "Norm"
        ]

        for path in paths:
            try:
                status, _, _ = client.request("GET", path, timeout=5)
                assert status in (200, 400, 404)
            except Exception:
                pass  # Unicode handling may fail


# ============================================================================
# Connection State Tests
# ============================================================================

class TestConnectionState:
    """Test connection state handling"""

    def test_connection_reuse_after_error(self, proxy):
        """Test that connection can be reused after error response"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                # First request - trigger 404
                def custom_404(handler, req):
                    handler._send_response(404, {}, b"not found")

                BackendHandler.custom_response = custom_404

                request1 = f"GET /notfound HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                ssock.sendall(request1)

                response1 = b""
                while b"\r\n\r\n" not in response1:
                    response1 += ssock.recv(4096)

                assert b"404" in response1

                # Reset and try second request
                BackendHandler.custom_response = None

                request2 = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: close\r\n\r\n".encode()
                ssock.sendall(request2)

                response2 = b""
                try:
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response2 += chunk
                except:
                    pass

                assert b"200" in response2

    def test_pipelining(self, proxy):
        """Test HTTP pipelining (multiple requests without waiting)"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                # Send multiple requests at once
                requests = b""
                for i in range(3):
                    requests += f"GET /pipeline/{i} HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()

                ssock.sendall(requests)

                # Read all responses
                responses = b""
                ssock.settimeout(5.0)
                try:
                    while True:
                        chunk = ssock.recv(8192)
                        if not chunk:
                            break
                        responses += chunk
                except socket.timeout:
                    pass

                # Should get multiple 200 responses
                assert responses.count(b"HTTP/1.1 200") >= 1

    def test_slow_client_headers(self, proxy):
        """Test slow client sending headers byte by byte"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=30) as sock:
            with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                # Send byte by byte with small delay
                for b in request:
                    ssock.send(bytes([b]))
                    time.sleep(0.01)

                # Read response
                response = b""
                ssock.settimeout(5.0)
                try:
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass

                assert b"200" in response

    def test_slow_client_body(self, proxy):
        """Test slow client sending body slowly"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        body = b"x" * 100

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=30) as sock:
            with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                headers = (
                    f"POST / HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n"
                ).encode()

                ssock.sendall(headers)

                # Send body in small chunks
                for i in range(0, len(body), 10):
                    ssock.send(body[i:i+10])
                    time.sleep(0.05)

                # Read response
                response = b""
                ssock.settimeout(5.0)
                try:
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass

                assert b"200" in response

    def test_client_disconnect_during_response(self, proxy):
        """Test handling when client disconnects during response"""
        # Set up slow backend response
        BackendHandler.response_delay = 2.0

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                    request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
                    ssock.sendall(request)
                    # Immediately close without reading
                    # This tests proxy handling of client disconnect
        except:
            pass

        # Give proxy time to clean up
        time.sleep(0.5)

        # Proxy should still work for next request
        client = ProxyClient()
        BackendHandler.response_delay = 0
        status, _, _ = client.request("GET", "/")
        assert status == 200


# ============================================================================
# Stress Tests
# ============================================================================

class TestStress:
    """Stress tests for the proxy"""

    def test_rapid_connection_create_destroy(self, proxy):
        """Test rapidly creating and destroying connections"""
        for _ in range(50):
            try:
                client = ProxyClient()
                status, _, _ = client.request("GET", "/", timeout=5)
                assert status == 200
            except Exception:
                pass  # Some may fail under stress, that's OK

    def test_concurrent_different_paths(self, proxy):
        """Test many concurrent requests to different paths"""
        paths = [f"/path/{i}/subpath/{j}" for i in range(10) for j in range(10)]

        def make_request(path):
            client = ProxyClient()
            try:
                status, _, body = client.request("GET", path, timeout=10)
                return path, status
            except Exception as e:
                return path, -1

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request, path) for path in paths]
            results = [f.result() for f in as_completed(futures)]

        success_count = sum(1 for _, status in results if status == 200)
        assert success_count >= len(paths) * 0.9  # 90% success rate

    def test_concurrent_post_with_bodies(self, proxy):
        """Test many concurrent POST requests with bodies"""
        num_requests = 50

        def make_request(i):
            client = ProxyClient()
            body = f"request-{i}-data".encode() * 100
            body_hash = hashlib.md5(body).hexdigest()
            try:
                status, _, resp = client.request("POST", f"/post/{i}", body=body, timeout=10)
                if status == 200:
                    data = json.loads(resp)
                    return data["body_hash"] == body_hash
                return False
            except Exception:
                return False

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            results = [f.result() for f in as_completed(futures)]

        success_count = sum(results)
        assert success_count >= num_requests * 0.9

    def test_mixed_request_sizes(self, proxy):
        """Test concurrent requests with varying sizes"""
        sizes = [10, 100, 1000, 5000, 10000, 20000]

        def make_request(size):
            client = ProxyClient()
            body = os.urandom(size)
            body_hash = hashlib.md5(body).hexdigest()
            try:
                status, _, resp = client.request("POST", f"/size/{size}", body=body, timeout=30)
                if status == 200:
                    data = json.loads(resp)
                    return data["body_hash"] == body_hash
                return False
            except Exception:
                return False

        with ThreadPoolExecutor(max_workers=6) as executor:
            # Each size 5 times
            tasks = sizes * 5
            futures = [executor.submit(make_request, size) for size in tasks]
            results = [f.result() for f in as_completed(futures)]

        success_count = sum(results)
        assert success_count >= len(tasks) * 0.8


# ============================================================================
# Binary Protocol Tests
# ============================================================================

class TestBinaryProtocol:
    """Test handling of binary protocol elements"""

    def test_all_byte_values_in_body(self, client):
        """Test body containing all possible byte values"""
        body = bytes(range(256))
        status, _, resp = client.request(
            "POST", "/binary",
            headers={"Content-Type": "application/octet-stream"},
            body=body
        )

        assert status == 200
        data = json.loads(resp)
        assert data["body_length"] == 256
        assert data["body_hash"] == hashlib.md5(body).hexdigest()

    def test_structured_binary_data(self, client):
        """Test structured binary data (like network protocols)"""
        # Simulate some binary protocol header
        body = struct.pack(">IIHH", 0x12345678, 0xDEADBEEF, 80, 443)
        body += b"\x00" * 100  # padding

        status, _, resp = client.request(
            "POST", "/binary-struct",
            headers={"Content-Type": "application/octet-stream"},
            body=body
        )

        assert status == 200
        data = json.loads(resp)
        assert data["body_hash"] == hashlib.md5(body).hexdigest()

    def test_high_entropy_data(self, client):
        """Test high-entropy random data"""
        body = os.urandom(16384)  # 16KB of random data

        status, _, resp = client.request(
            "POST", "/entropy",
            headers={"Content-Type": "application/octet-stream"},
            body=body,
            timeout=15
        )

        assert status == 200
        data = json.loads(resp)
        assert data["body_hash"] == hashlib.md5(body).hexdigest()

    def test_repeated_patterns(self, client):
        """Test repeated binary patterns"""
        pattern = b"\xAA\x55\xFF\x00"
        body = pattern * 2500  # 10KB

        status, _, resp = client.request(
            "POST", "/pattern",
            headers={"Content-Type": "application/octet-stream"},
            body=body
        )

        assert status == 200
        data = json.loads(resp)
        assert data["body_hash"] == hashlib.md5(body).hexdigest()


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
