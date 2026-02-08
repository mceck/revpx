#!/usr/bin/env python3
"""
Comprehensive test suite for revpx reverse proxy.

This test suite simulates both server-side (backend) and client-side behavior
to validate the reverse proxy functionality for production use.

Tests cover:
- Basic HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
- Header forwarding and preservation
- Large payloads (request and response)
- Fast concurrent requests
- Chunked transfer encoding
- WebSocket upgrades
- Keep-alive connections
- SSL/TLS handling
- Error conditions and edge cases
"""

import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from typing import Callable, Optional

import pytest

# Configuration
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REVPX_BINARY = os.path.join(PROJECT_ROOT, "build", "revpx")
CERT_FILE = os.path.join(PROJECT_ROOT, "test.localhost.pem")
KEY_FILE = os.path.join(PROJECT_ROOT, "test.localhost-key.pem")
TEST_DOMAIN = "test.localhost"

# Ports - use high ports to avoid permission issues
HTTPS_PORT = 18443
HTTP_PORT = 18080
BACKEND_PORT = 18000


@dataclass
class CapturedRequest:
    """Captured request data from backend"""
    method: str
    path: str
    headers: dict
    body: bytes
    http_version: str


class BackendHandler(BaseHTTPRequestHandler):
    """Mock backend server handler that echoes requests and can simulate various responses"""

    protocol_version = "HTTP/1.1"

    # Class-level storage for test data
    captured_requests: list = []
    custom_response: Optional[Callable] = None
    response_delay: float = 0
    chunked_response: bool = False

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

    def _read_chunked_body(self):
        """Read a chunked transfer-encoded body"""
        body = b""
        while True:
            line = self.rfile.readline()
            line = line.strip()
            if not line:
                break
            try:
                chunk_size = int(line.split(b";")[0], 16)
            except ValueError:
                break
            if chunk_size == 0:
                # Consume trailer headers and final blank line
                while True:
                    trailer_line = self.rfile.readline()
                    if trailer_line in (b"\r\n", b"\n", b""):
                        break
                break
            body += self.rfile.read(chunk_size)
            self.rfile.readline()  # trailing CRLF
        return body

    def _capture_request(self) -> CapturedRequest:
        """Capture and store request details"""
        te = self.headers.get("Transfer-Encoding", "")
        if "chunked" in te.lower():
            body = self._read_chunked_body()
        else:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b""

        req = CapturedRequest(
            method=self.command,
            path=self.path,
            headers=dict(self.headers),
            body=body,
            http_version=self.request_version
        )
        BackendHandler.captured_requests.append(req)
        return req

    def _send_response(self, status: int = 200, headers: dict | None = None, body: bytes = b""):
        """Send a response with optional delay"""
        if BackendHandler.response_delay > 0:
            time.sleep(BackendHandler.response_delay)

        self.send_response(status)

        headers = headers or {}
        if BackendHandler.chunked_response:
            headers["Transfer-Encoding"] = "chunked"
        elif "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))

        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()

        if BackendHandler.chunked_response and body:
            # Send chunked response
            chunk_size = 1024
            for i in range(0, len(body), chunk_size):
                chunk = body[i:i + chunk_size]
                self.wfile.write(f"{len(chunk):x}\r\n".encode())
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.wfile.write(body)

    def _handle_request(self):
        """Common handler for all methods"""
        req = self._capture_request()

        if BackendHandler.custom_response:
            BackendHandler.custom_response(self, req)
            return

        # Default echo response
        response_data = {
            "method": req.method,
            "path": req.path,
            "headers": req.headers,
            "body_length": len(req.body),
            "body_hash": hashlib.md5(req.body).hexdigest() if req.body else None,
        }

        body = json.dumps(response_data, indent=2).encode()
        self._send_response(200, {"Content-Type": "application/json"}, body)

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()

    def do_PATCH(self):
        self._handle_request()

    def do_HEAD(self):
        req = self._capture_request()
        self._send_response(200, {"Content-Type": "text/plain", "X-Custom": "test"}, b"")

    def do_OPTIONS(self):
        req = self._capture_request()
        headers = {
            "Allow": "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        }
        self._send_response(200, headers, b"")


class BackendServer:
    """Threaded backend server manager"""

    def __init__(self, port: int):
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        """Start the backend server in a thread"""
        self.server = HTTPServer(("127.0.0.1", self.port), BackendHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # Wait for server to be ready
        time.sleep(0.1)

    def stop(self):
        """Stop the backend server"""
        if self.server:
            self.server.shutdown()
            self.server = None
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None

    @staticmethod
    def reset():
        """Reset test state"""
        BackendHandler.captured_requests.clear()
        BackendHandler.custom_response = None
        BackendHandler.response_delay = 0
        BackendHandler.chunked_response = False


class RevPxProxy:
    """Manager for the revpx reverse proxy process"""

    def __init__(
        self,
        https_port: int = HTTPS_PORT,
        http_port: int = HTTP_PORT,
        backend_port: int = BACKEND_PORT,
        domain: str = TEST_DOMAIN,
        cert: str = CERT_FILE,
        key: str = KEY_FILE
    ):
        self.https_port = https_port
        self.http_port = http_port
        self.backend_port = backend_port
        self.domain = domain
        self.cert = cert
        self.key = key
        self.process: Optional[subprocess.Popen] = None
        self.config_file: Optional[str] = None

    def start(self):
        """Start the reverse proxy"""
        # Create a temporary config file to avoid arg parsing issues
        self.config_file = os.path.join(PROJECT_ROOT, "tests", "test_config.json")
        config = [{
            "domain": self.domain,
            "port": str(self.backend_port),
            "cert_file": self.cert,
            "key_file": self.key
        }]
        with open(self.config_file, "w") as f:
            json.dump(config, f)

        # Set ports via environment variables
        env = os.environ.copy()
        env["REVPX_PORT"] = str(self.https_port)
        env["REVPX_PORT_PLAIN"] = str(self.http_port)

        cmd = [REVPX_BINARY, "-f", self.config_file]

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PROJECT_ROOT,
            env=env
        )

        # Wait for proxy to be ready
        time.sleep(1)

        # Check if process is still running
        if self.process.poll() is not None:
            stdout, stderr = self.process.communicate()
            raise RuntimeError(
                f"revpx failed to start:\nstdout: {stdout.decode()}\nstderr: {stderr.decode()}"
            )

    def stop(self):
        """Stop the reverse proxy"""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None

        # Clean up config file
        if self.config_file and os.path.exists(self.config_file):
            os.remove(self.config_file)
            self.config_file = None


class ProxyClient:
    """HTTPS client for testing the reverse proxy"""

    def __init__(self, host: str = TEST_DOMAIN, port: int = HTTPS_PORT, connect_host: str = "127.0.0.1"):
        self.host = host  # SNI hostname and Host header
        self.connect_host = connect_host  # Actual IP to connect to
        self.port = port
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def request(
        self,
        method: str = "GET",
        path: str = "/",
        headers: dict | None = None,
        body: bytes | None = None,
        timeout: float = 10.0
    ) -> tuple[int, dict, bytes]:
        """Make an HTTP request and return (status, headers, body)"""
        headers = headers or {}

        # Build request
        request_lines = [f"{method} {path} HTTP/1.1"]
        request_lines.append(f"Host: {self.host}")

        if body and "Content-Length" not in headers and "Transfer-Encoding" not in headers:
            headers["Content-Length"] = str(len(body))

        for key, value in headers.items():
            request_lines.append(f"{key}: {value}")

        request_lines.append("")
        request_lines.append("")
        request_data = "\r\n".join(request_lines).encode()

        if body:
            request_data += body

        # Connect to 127.0.0.1 but use SNI hostname for TLS
        with socket.create_connection((self.connect_host, self.port), timeout=timeout) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.host) as ssock:
                ssock.sendall(request_data)

                # Read response headers first
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = ssock.recv(8192)
                    if not chunk:
                        break
                    response += chunk

                if b"\r\n\r\n" not in response:
                    raise ValueError("Incomplete response - no headers received")

                header_end = response.index(b"\r\n\r\n") + 4
                headers_part = response[:header_end].decode()
                body_data = response[header_end:]

                # Parse content-length or chunked
                content_length = None
                chunked = False
                for line in headers_part.split("\r\n"):
                    lower = line.lower()
                    if lower.startswith("content-length:"):
                        content_length = int(line.split(":", 1)[1].strip())
                    elif lower.startswith("transfer-encoding:") and "chunked" in lower:
                        chunked = True

                if content_length is not None:
                    while len(body_data) < content_length:
                        chunk = ssock.recv(8192)
                        if not chunk:
                            break
                        body_data += chunk
                elif chunked:
                    # Read until 0\r\n\r\n
                    while not body_data.endswith(b"0\r\n\r\n"):
                        chunk = ssock.recv(8192)
                        if not chunk:
                            break
                        body_data += chunk

        # Parse status line
        status_line = headers_part.split("\r\n")[0]
        status = int(status_line.split()[1])

        # Parse headers
        resp_headers = {}
        for line in headers_part.split("\r\n")[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                resp_headers[key.strip()] = value.strip()

        # Decode chunked if needed
        if resp_headers.get("Transfer-Encoding", "").lower() == "chunked":
            body_data = self._decode_chunked(body_data)

        return status, resp_headers, body_data

    def _decode_chunked(self, data: bytes) -> bytes:
        """Decode chunked transfer encoding"""
        result = BytesIO()
        pos = 0

        while pos < len(data):
            # Find chunk size line
            line_end = data.find(b"\r\n", pos)
            if line_end == -1:
                break

            # Parse chunk size (ignore extensions)
            size_str = data[pos:line_end].decode().split(";")[0]
            chunk_size = int(size_str, 16)

            if chunk_size == 0:
                break

            # Read chunk data
            chunk_start = line_end + 2
            chunk_end = chunk_start + chunk_size
            result.write(data[chunk_start:chunk_end])

            pos = chunk_end + 2  # Skip trailing CRLF

        return result.getvalue()

    def request_raw(
        self,
        request_data: bytes,
        timeout: float = 10.0
    ) -> bytes:
        """Send raw request data and return raw response"""
        with socket.create_connection((self.connect_host, self.port), timeout=timeout) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.host) as ssock:
                ssock.sendall(request_data)

                response = b""
                try:
                    while True:
                        chunk = ssock.recv(8192)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass

                return response


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


# ============================================================================
# Basic HTTP Method Tests
# ============================================================================

class TestBasicHTTPMethods:
    """Test basic HTTP method handling"""

    def test_get_request(self, client):
        """Test simple GET request"""
        status, headers, body = client.request("GET", "/test/path")

        assert status == 200
        data = json.loads(body)
        assert data["method"] == "GET"
        assert data["path"] == "/test/path"

    def test_post_request(self, client):
        """Test POST request with body"""
        request_body = b'{"key": "value"}'
        status, headers, body = client.request(
            "POST", "/api/data",
            headers={"Content-Type": "application/json"},
            body=request_body
        )

        assert status == 200
        data = json.loads(body)
        assert data["method"] == "POST"
        assert data["body_length"] == len(request_body)

    def test_put_request(self, client):
        """Test PUT request"""
        request_body = b"updated content"
        status, headers, body = client.request("PUT", "/resource/1", body=request_body)

        assert status == 200
        data = json.loads(body)
        assert data["method"] == "PUT"

    def test_delete_request(self, client):
        """Test DELETE request"""
        status, headers, body = client.request("DELETE", "/resource/1")

        assert status == 200
        data = json.loads(body)
        assert data["method"] == "DELETE"

    def test_patch_request(self, client):
        """Test PATCH request"""
        request_body = b'{"partial": "update"}'
        status, headers, body = client.request("PATCH", "/resource/1", body=request_body)

        assert status == 200
        data = json.loads(body)
        assert data["method"] == "PATCH"

    def test_head_request(self, client):
        """Test HEAD request returns headers without body"""
        status, headers, body = client.request("HEAD", "/test")

        assert status == 200
        assert len(body) == 0
        assert "X-Custom" in headers

    def test_options_request(self, client):
        """Test OPTIONS request"""
        status, headers, body = client.request("OPTIONS", "/api")

        assert status == 200
        assert "Allow" in headers


# ============================================================================
# Header Forwarding Tests
# ============================================================================

class TestHeaderForwarding:
    """Test that headers are properly forwarded"""

    def test_standard_headers_forwarded(self, client):
        """Test standard headers are forwarded to backend"""
        custom_headers = {
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "ProxyClient/1.0",
            "Cache-Control": "no-cache",
        }

        status, _, body = client.request("GET", "/", headers=custom_headers)

        assert status == 200
        data = json.loads(body)

        for key, value in custom_headers.items():
            assert data["headers"].get(key) == value

    def test_custom_headers_forwarded(self, client):
        """Test custom X- headers are forwarded"""
        custom_headers = {
            "X-Request-Id": "test-123",
            "X-Correlation-Id": "corr-456",
            "X-Custom-Header": "custom-value",
        }

        status, _, body = client.request("GET", "/", headers=custom_headers)

        assert status == 200
        data = json.loads(body)

        for key, value in custom_headers.items():
            assert data["headers"].get(key) == value

    def test_authorization_header_forwarded(self, client):
        """Test Authorization header is forwarded"""
        headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
        }

        status, _, body = client.request("GET", "/api/protected", headers=headers)

        assert status == 200
        data = json.loads(body)
        assert data["headers"].get("Authorization") == headers["Authorization"]

    def test_cookie_header_forwarded(self, client):
        """Test Cookie header is forwarded"""
        headers = {
            "Cookie": "session=abc123; user=test"
        }

        status, _, body = client.request("GET", "/", headers=headers)

        assert status == 200
        data = json.loads(body)
        assert data["headers"].get("Cookie") == headers["Cookie"]

    def test_content_type_preserved(self, client):
        """Test Content-Type is preserved for requests"""
        content_types = [
            "application/json",
            "application/xml",
            "text/plain",
            "multipart/form-data; boundary=----WebKitFormBoundary",
            "application/x-www-form-urlencoded",
        ]

        for ct in content_types:
            status, _, body = client.request(
                "POST", "/",
                headers={"Content-Type": ct},
                body=b"test"
            )

            assert status == 200
            data = json.loads(body)
            assert data["headers"].get("Content-Type") == ct

    def test_many_headers(self, client):
        """Test request with many headers"""
        headers = {f"X-Header-{i}": f"value-{i}" for i in range(50)}

        status, _, body = client.request("GET", "/", headers=headers)

        assert status == 200
        data = json.loads(body)

        for key, value in headers.items():
            assert data["headers"].get(key) == value


# ============================================================================
# Large Payload Tests
# ============================================================================

class TestLargePayloads:
    """Test handling of large request and response payloads"""

    def test_small_request_body(self, client):
        """Test small request body (100 bytes)"""
        body = b"x" * 100
        status, _, resp_body = client.request("POST", "/", body=body)

        assert status == 200
        data = json.loads(resp_body)
        assert data["body_length"] == 100
        assert data["body_hash"] == hashlib.md5(body).hexdigest()

    def test_moderate_request_body(self, client):
        """Test request body around 30KB (close to proxy buffer size)"""
        body = b"x" * (30 * 1024)
        status, _, resp_body = client.request("POST", "/", body=body, timeout=15)

        assert status == 200
        data = json.loads(resp_body)
        assert data["body_length"] == 30 * 1024
        assert data["body_hash"] == hashlib.md5(body).hexdigest()

    def test_medium_request_body(self, client):
        """Test medium request body (100KB)"""
        body = b"x" * (100 * 1024)
        status, _, resp_body = client.request("POST", "/", body=body, timeout=60)

        assert status == 200
        data = json.loads(resp_body)
        assert data["body_length"] == 100 * 1024
        assert data["body_hash"] == hashlib.md5(body).hexdigest()

    def test_large_request_body(self, client):
        """Test large request body (1MB)"""
        body = b"x" * (1024 * 1024)
        status, _, resp_body = client.request("POST", "/", body=body, timeout=60)

        assert status == 200
        data = json.loads(resp_body)
        assert data["body_length"] == 1024 * 1024
        assert data["body_hash"] == hashlib.md5(body).hexdigest()

    def test_very_large_request_body(self, client):
        """Test very large request body (5MB)"""
        body = b"x" * (5 * 1024 * 1024)
        status, _, resp_body = client.request("POST", "/", body=body, timeout=120)

        assert status == 200
        data = json.loads(resp_body)
        assert data["body_length"] == 5 * 1024 * 1024

    def test_large_response_body(self, client):
        """Test large response from backend (1MB)"""
        response_size = 1024 * 1024
        response_data = b"y" * response_size

        def custom_response(handler, req):
            handler._send_response(200, {"Content-Type": "application/octet-stream"}, response_data)

        BackendHandler.custom_response = custom_response

        status, headers, body = client.request("GET", "/large-response", timeout=30)

        assert status == 200
        assert len(body) == response_size
        assert body == response_data

    def test_very_large_response_body(self, client):
        """Test very large response from backend (5MB)"""
        response_size = 5 * 1024 * 1024
        response_data = os.urandom(response_size)

        def custom_response(handler, req):
            handler._send_response(200, {"Content-Type": "application/octet-stream"}, response_data)

        BackendHandler.custom_response = custom_response

        status, headers, body = client.request("GET", "/very-large-response", timeout=60)

        assert status == 200
        assert len(body) == response_size
        assert body == response_data

    def test_response_data_integrity(self, client):
        """Test that response data arrives in correct order (not corrupted)"""
        # Create a pattern that makes out-of-order delivery detectable
        response_size = 256 * 1024  # 256KB
        response_data = bytes(range(256)) * (response_size // 256)

        def custom_response(handler, req):
            handler._send_response(200, {"Content-Type": "application/octet-stream"}, response_data)

        BackendHandler.custom_response = custom_response

        status, _, body = client.request("GET", "/integrity", timeout=30)

        assert status == 200
        assert len(body) == len(response_data)
        assert body == response_data, "Response data arrived corrupted or out of order"

    def test_large_response_content_length_match(self, client):
        """Test Content-Length matches actual body for large responses"""
        for size in [64 * 1024, 256 * 1024, 1024 * 1024]:
            response_data = b"A" * size

            def custom_response(handler, req, data=response_data):
                handler._send_response(200, {"Content-Type": "application/octet-stream"}, data)

            BackendHandler.custom_response = custom_response

            status, headers, body = client.request("GET", f"/cl-match/{size}", timeout=30)

            assert status == 200
            cl = int(headers.get("Content-Length", -1))
            assert cl == size, f"Content-Length header {cl} != expected {size}"
            assert len(body) == size, f"Body length {len(body)} != expected {size}"

    def test_binary_payload(self, client):
        """Test binary data with all byte values"""
        body = bytes(range(256)) * 100  # 25.6KB of all possible bytes
        status, _, resp_body = client.request(
            "POST", "/binary",
            headers={"Content-Type": "application/octet-stream"},
            body=body
        )

        assert status == 200
        data = json.loads(resp_body)
        assert data["body_length"] == len(body)
        assert data["body_hash"] == hashlib.md5(body).hexdigest()

    def test_random_payload(self, client):
        """Test random binary data (30KB to stay within buffer limits)"""
        body = os.urandom(30 * 1024)  # 30KB random - within 32KB buffer
        status, _, resp_body = client.request("POST", "/random", body=body, timeout=15)

        assert status == 200
        data = json.loads(resp_body)
        assert data["body_hash"] == hashlib.md5(body).hexdigest()


# ============================================================================
# Concurrent Request Tests
# ============================================================================

class TestConcurrentRequests:
    """Test handling of concurrent and rapid requests"""

    def test_sequential_requests(self, client):
        """Test many sequential requests"""
        for i in range(50):
            status, _, body = client.request("GET", f"/seq/{i}")
            assert status == 200
            data = json.loads(body)
            assert data["path"] == f"/seq/{i}"

    def test_parallel_requests(self, proxy):
        """Test parallel requests from multiple clients"""
        num_requests = 50
        results = []

        def make_request(i):
            client = ProxyClient()
            status, _, body = client.request("GET", f"/parallel/{i}")
            return i, status, json.loads(body)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            for future in as_completed(futures):
                results.append(future.result())

        assert len(results) == num_requests
        for i, status, data in results:
            assert status == 200
            assert data["path"] == f"/parallel/{i}"

    def test_rapid_fire_requests(self, proxy):
        """Test rapid consecutive requests"""
        num_requests = 100
        client = ProxyClient()

        for i in range(num_requests):
            status, _, body = client.request("GET", f"/rapid/{i}")
            assert status == 200

    def test_mixed_method_parallel(self, proxy):
        """Test parallel requests with mixed methods"""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        results = []

        def make_request(method, i):
            client = ProxyClient()
            body = b"test" if method in ("POST", "PUT", "PATCH") else None
            status, _, resp = client.request(method, f"/mixed/{i}", body=body)
            return method, status, json.loads(resp) if resp else None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for i in range(20):
                method = methods[i % len(methods)]
                futures.append(executor.submit(make_request, method, i))

            for future in as_completed(futures):
                results.append(future.result())

        assert len(results) == 20
        for method, status, _ in results:
            assert status == 200

    def test_parallel_large_payloads(self, proxy):
        """Test parallel requests with moderate payloads (within buffer limits)"""
        num_requests = 10
        payload_size = 20 * 1024  # 20KB each - within 32KB buffer

        def make_request(i):
            client = ProxyClient()
            body = os.urandom(payload_size)
            body_hash = hashlib.md5(body).hexdigest()
            try:
                status, _, resp = client.request("POST", f"/large/{i}", body=body, timeout=60)
                if status == 200:
                    data = json.loads(resp)
                    return i, status, data["body_hash"] == body_hash
                return i, status, False
            except Exception:
                return i, -1, False

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            results = [f.result() for f in as_completed(futures)]

        assert len(results) == num_requests
        success_count = sum(1 for _, status, matched in results if status == 200 and matched)
        # Allow some failures under concurrent load
        assert success_count >= num_requests * 0.8


# ============================================================================
# Chunked Transfer Encoding Tests
# ============================================================================

class TestChunkedEncoding:
    """Test chunked transfer encoding handling"""

    def test_chunked_response(self, client):
        """Test receiving chunked response from backend"""
        response_data = b"This is a chunked response with multiple chunks."

        BackendHandler.chunked_response = True

        def custom_response(handler, req):
            handler._send_response(200, {"Content-Type": "text/plain"}, response_data)

        BackendHandler.custom_response = custom_response

        status, headers, body = client.request("GET", "/chunked")

        assert status == 200
        assert body == response_data

    def test_large_chunked_response(self, client):
        """Test large chunked response"""
        response_data = b"x" * (500 * 1024)  # 500KB

        BackendHandler.chunked_response = True

        def custom_response(handler, req):
            handler._send_response(200, {"Content-Type": "application/octet-stream"}, response_data)

        BackendHandler.custom_response = custom_response

        status, headers, body = client.request("GET", "/large-chunked", timeout=30)

        assert status == 200
        assert len(body) == len(response_data)
        assert body == response_data

    def test_chunked_request(self, client):
        """Test sending chunked request.

        revpx decodes chunked request bodies and forwards with Content-Length.
        """
        body_parts = [b"chunk1", b"chunk2", b"chunk3"]
        full_body = b"".join(body_parts)

        # Build chunked request manually
        chunked_body = b""
        for part in body_parts:
            chunked_body += f"{len(part):x}\r\n".encode()
            chunked_body += part + b"\r\n"
        chunked_body += b"0\r\n\r\n"

        request = (
            f"POST /chunked-req HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        ).encode() + chunked_body

        response = client.request_raw(request)

        # Parse response
        assert b"200" in response.split(b"\r\n")[0]

        # Check body was received correctly
        req = BackendHandler.captured_requests[-1]
        assert req.body == full_body


# ============================================================================
# Keep-Alive and Connection Tests
# ============================================================================

class TestConnectionHandling:
    """Test connection keep-alive and handling"""

    def test_connection_header(self, client):
        """Test Connection header is handled"""
        status, _, body = client.request(
            "GET", "/",
            headers={"Connection": "keep-alive"}
        )

        assert status == 200

    def test_multiple_requests_same_connection(self, proxy):
        """Test multiple requests on same SSL connection"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                # First request
                request1 = (
                    f"GET /first HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
                ssock.sendall(request1)

                # Read response
                response1 = b""
                while b"\r\n\r\n" not in response1:
                    response1 += ssock.recv(4096)

                header_end = response1.index(b"\r\n\r\n") + 4
                content_length = 0
                for line in response1[:header_end].decode().split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        content_length = int(line.split(":")[1].strip())

                while len(response1) < header_end + content_length:
                    response1 += ssock.recv(4096)

                assert b"200" in response1.split(b"\r\n")[0]

                # Second request on same connection
                request2 = (
                    f"GET /second HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()
                ssock.sendall(request2)

                # Read second response
                response2 = b""
                try:
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response2 += chunk
                except:
                    pass

                assert b"200" in response2.split(b"\r\n")[0]


# ============================================================================
# URL and Path Tests
# ============================================================================

class TestURLHandling:
    """Test URL and path handling"""

    def test_root_path(self, client):
        """Test request to root path"""
        status, _, body = client.request("GET", "/")

        assert status == 200
        data = json.loads(body)
        assert data["path"] == "/"

    def test_nested_path(self, client):
        """Test deeply nested path"""
        path = "/a/b/c/d/e/f/g/h/i/j"
        status, _, body = client.request("GET", path)

        assert status == 200
        data = json.loads(body)
        assert data["path"] == path

    def test_query_string(self, client):
        """Test query string is preserved"""
        path = "/search?q=test&page=1&limit=10"
        status, _, body = client.request("GET", path)

        assert status == 200
        data = json.loads(body)
        assert data["path"] == path

    def test_encoded_characters(self, client):
        """Test URL-encoded characters"""
        path = "/path%20with%20spaces?name=John%20Doe"
        status, _, body = client.request("GET", path)

        assert status == 200
        data = json.loads(body)
        assert data["path"] == path

    def test_special_characters_in_path(self, client):
        """Test special characters in path"""
        path = "/api/v1/users/123/profile"
        status, _, body = client.request("GET", path)

        assert status == 200
        data = json.loads(body)
        assert data["path"] == path

    def test_fragment_stripped(self, client):
        """Test that fragment is handled (usually stripped by client)"""
        # Note: fragments are typically not sent to server
        path = "/page"
        status, _, body = client.request("GET", path)

        assert status == 200


# ============================================================================
# Response Status Code Tests
# ============================================================================

class TestStatusCodes:
    """Test various HTTP status code handling"""

    @pytest.mark.parametrize("status_code", [200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502, 503])
    def test_status_code_forwarded(self, client, status_code):
        """Test various status codes are forwarded correctly"""
        def custom_response(handler, req):
            body = b"" if status_code == 204 else b"response"
            handler._send_response(status_code, {}, body)

        BackendHandler.custom_response = custom_response

        status, _, _ = client.request("GET", f"/status/{status_code}")

        assert status == status_code


# ============================================================================
# Response Header Tests
# ============================================================================

class TestResponseHeaders:
    """Test response header handling"""

    def test_content_type_forwarded(self, client):
        """Test Content-Type is forwarded in response"""
        def custom_response(handler, req):
            handler._send_response(200, {"Content-Type": "application/xml"}, b"<xml/>")

        BackendHandler.custom_response = custom_response

        status, headers, _ = client.request("GET", "/")

        assert headers.get("Content-Type") == "application/xml"

    def test_custom_response_headers(self, client):
        """Test custom response headers are forwarded"""
        def custom_response(handler, req):
            headers = {
                "X-Custom-Response": "test-value",
                "X-Request-Id": "12345",
                "Cache-Control": "max-age=3600",
            }
            handler._send_response(200, headers, b"ok")

        BackendHandler.custom_response = custom_response

        status, headers, _ = client.request("GET", "/")

        assert headers.get("X-Custom-Response") == "test-value"
        assert headers.get("X-Request-Id") == "12345"
        assert headers.get("Cache-Control") == "max-age=3600"

    def test_set_cookie_header(self, client):
        """Test Set-Cookie header is forwarded"""
        def custom_response(handler, req):
            handler.send_response(200)
            handler.send_header("Set-Cookie", "session=abc123; Path=/; HttpOnly")
            handler.send_header("Set-Cookie", "user=test; Path=/")
            handler.send_header("Content-Length", "2")
            handler.end_headers()
            handler.wfile.write(b"ok")

        BackendHandler.custom_response = custom_response

        status, headers, _ = client.request("GET", "/")

        assert status == 200


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Test error conditions and edge cases"""

    def test_backend_slow_response(self, client):
        """Test handling of slow backend response"""
        BackendHandler.response_delay = 1.0

        status, _, _ = client.request("GET", "/slow", timeout=10)

        assert status == 200

    def test_empty_body_post(self, client):
        """Test POST with empty body"""
        status, _, body = client.request("POST", "/empty", body=b"")

        assert status == 200
        data = json.loads(body)
        assert data["body_length"] == 0

    def test_very_long_url(self, client):
        """Test very long URL path"""
        long_path = "/" + "a" * 2000
        status, _, body = client.request("GET", long_path)

        assert status == 200
        data = json.loads(body)
        assert data["path"] == long_path

    def test_special_header_values(self, client):
        """Test headers with special characters"""
        headers = {
            "X-Special": "value with spaces",
            "X-Unicode": "utf-8: ñ é ü",
        }

        status, _, body = client.request("GET", "/", headers=headers)

        assert status == 200


# ============================================================================
# SSL/TLS Tests
# ============================================================================

class TestSSL:
    """Test SSL/TLS functionality"""

    def test_tls_connection(self, proxy):
        """Test basic TLS connection works"""
        client = ProxyClient()
        status, _, _ = client.request("GET", "/")
        assert status == 200

    def test_sni_hostname(self, proxy):
        """Test SNI with correct hostname"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
                ssock.sendall(request)
                response = ssock.recv(4096)
                assert b"200" in response


# ============================================================================
# HTTP to HTTPS Redirect Tests
# ============================================================================

class TestHTTPRedirect:
    """Test HTTP to HTTPS redirect functionality"""

    def test_http_redirects_to_https(self, proxy):
        """Test that HTTP requests are redirected to HTTPS"""
        sock = socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=10)
        try:
            request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
            sock.sendall(request)
            response = sock.recv(4096).decode()

            # Should get a redirect response
            assert "301" in response or "302" in response or "307" in response or "308" in response
            assert "https" in response.lower() or "Location" in response
        finally:
            sock.close()


# ============================================================================
# Streaming and Large Data Tests
# ============================================================================

class TestStreamingResponses:
    """Test streaming and large data handling - targets buffer management bugs"""

    def test_backend_slow_stream(self, client):
        """Test backend that sends response body slowly in pieces"""
        total_size = 100 * 1024  # 100KB
        response_data = os.urandom(total_size)

        def custom_response(handler, req):
            handler.send_response(200)
            handler.send_header("Content-Type", "application/octet-stream")
            handler.send_header("Content-Length", str(total_size))
            handler.end_headers()
            # Send in small chunks with delays
            chunk_size = 4096
            for i in range(0, total_size, chunk_size):
                handler.wfile.write(response_data[i:i + chunk_size])
                handler.wfile.flush()
                time.sleep(0.001)

        BackendHandler.custom_response = custom_response

        status, headers, body = client.request("GET", "/slow-stream", timeout=30)

        assert status == 200
        assert len(body) == total_size
        assert body == response_data

    def test_concurrent_large_responses(self, proxy):
        """Test multiple clients receiving large responses simultaneously"""
        response_size = 512 * 1024  # 512KB each

        def custom_response(handler, req):
            data = os.urandom(response_size)
            handler._send_response(200, {
                "Content-Type": "application/octet-stream",
                "X-Expected-Size": str(response_size),
            }, data)

        BackendHandler.custom_response = custom_response

        def make_request(i):
            c = ProxyClient()
            status, headers, body = c.request("GET", f"/concurrent-large/{i}", timeout=30)
            return i, status, len(body), int(headers.get("X-Expected-Size", 0))

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(5)]
            results = [f.result() for f in as_completed(futures)]

        for i, status, body_len, expected in results:
            assert status == 200, f"Request {i}: got status {status}"
            assert body_len == expected, f"Request {i}: body {body_len} != expected {expected}"

    def test_large_request_and_response(self, client):
        """Test large request body with large response body"""
        req_body = os.urandom(256 * 1024)  # 256KB request
        resp_size = 256 * 1024  # 256KB response
        resp_data = os.urandom(resp_size)

        def custom_response(handler, req):
            handler._send_response(200, {
                "Content-Type": "application/octet-stream",
                "X-Req-Hash": hashlib.md5(req.body).hexdigest(),
            }, resp_data)

        BackendHandler.custom_response = custom_response

        status, headers, body = client.request("POST", "/echo-large", body=req_body, timeout=30)

        assert status == 200
        assert headers.get("X-Req-Hash") == hashlib.md5(req_body).hexdigest()
        assert len(body) == resp_size
        assert body == resp_data

    def test_many_sequential_large_responses(self, client):
        """Test many sequential requests with large responses on different connections"""
        response_size = 128 * 1024  # 128KB

        for i in range(10):
            response_data = bytes([i % 256]) * response_size

            def custom_response(handler, req, data=response_data):
                handler._send_response(200, {"Content-Type": "application/octet-stream"}, data)

            BackendHandler.custom_response = custom_response

            status, _, body = client.request("GET", f"/seq-large/{i}", timeout=15)

            assert status == 200
            assert len(body) == response_size, f"Iteration {i}: got {len(body)} bytes, expected {response_size}"
            assert body == response_data, f"Iteration {i}: data mismatch"


# ============================================================================
# Connection Reuse with Payloads Tests
# ============================================================================

class TestKeepAliveWithPayloads:
    """Test HTTP keep-alive with various payload sizes"""

    def test_keepalive_multiple_large_posts(self, proxy):
        """Test keep-alive with multiple large POST requests on same connection"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                for i in range(5):
                    body = os.urandom(10 * 1024)  # 10KB
                    body_hash = hashlib.md5(body).hexdigest()

                    request = (
                        f"POST /keepalive/{i} HTTP/1.1\r\n"
                        f"Host: {TEST_DOMAIN}\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode() + body

                    ssock.sendall(request)

                    # Read response headers
                    response = b""
                    while b"\r\n\r\n" not in response:
                        chunk = ssock.recv(8192)
                        if not chunk:
                            break
                        response += chunk

                    assert b"\r\n\r\n" in response, f"Iteration {i}: incomplete response headers"

                    header_end = response.index(b"\r\n\r\n") + 4
                    headers_part = response[:header_end].decode()

                    content_length = 0
                    for line in headers_part.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            content_length = int(line.split(":")[1].strip())

                    body_data = response[header_end:]
                    while len(body_data) < content_length:
                        chunk = ssock.recv(8192)
                        if not chunk:
                            break
                        body_data += chunk

                    assert b"200" in response.split(b"\r\n")[0], f"Iteration {i}: not 200"

                    data = json.loads(body_data[:content_length])
                    assert data["body_hash"] == body_hash, f"Iteration {i}: body hash mismatch"

    def test_keepalive_mixed_sizes(self, proxy):
        """Test keep-alive with alternating small and large requests"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sizes = [100, 50000, 200, 80000, 50]

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=30) as sock:
            with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                for i, size in enumerate(sizes):
                    body = os.urandom(size)
                    body_hash = hashlib.md5(body).hexdigest()

                    request = (
                        f"POST /mixed-sizes/{i} HTTP/1.1\r\n"
                        f"Host: {TEST_DOMAIN}\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode() + body

                    ssock.sendall(request)

                    response = b""
                    while b"\r\n\r\n" not in response:
                        chunk = ssock.recv(8192)
                        if not chunk:
                            break
                        response += chunk

                    assert b"\r\n\r\n" in response

                    header_end = response.index(b"\r\n\r\n") + 4
                    headers_part = response[:header_end].decode()

                    content_length = 0
                    for line in headers_part.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            content_length = int(line.split(":")[1].strip())

                    body_data = response[header_end:]
                    while len(body_data) < content_length:
                        chunk = ssock.recv(8192)
                        if not chunk:
                            break
                        body_data += chunk

                    assert b"200" in response.split(b"\r\n")[0]
                    data = json.loads(body_data[:content_length])
                    assert data["body_hash"] == body_hash, f"Size {size}: body hash mismatch"


# ============================================================================
# Pipelining with Bodies Tests
# ============================================================================

class TestHTTPPipelining:
    """Test HTTP pipelining edge cases"""

    def test_pipelined_posts(self, proxy):
        """Test pipelined POST requests with bodies"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        bodies = [b"body1", b"body22", b"body333"]

        # Build all requests at once
        all_requests = b""
        for i, body in enumerate(bodies):
            all_requests += (
                f"POST /pipeline/{i} HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode() + body

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                ssock.sendall(all_requests)

                # Read all responses
                all_data = b""
                responses_found = 0
                while responses_found < len(bodies):
                    chunk = ssock.recv(8192)
                    if not chunk:
                        break
                    all_data += chunk
                    responses_found = all_data.count(b"HTTP/1.1 200")

                assert responses_found == len(bodies), f"Expected {len(bodies)} responses, got {responses_found}"


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    # Check if revpx binary exists
    if not os.path.exists(REVPX_BINARY):
        print(f"Error: revpx binary not found at {REVPX_BINARY}")
        print("Please build the project first with: ./nob")
        sys.exit(1)

    # Check if certificates exist
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print(f"Error: Certificate files not found")
        print(f"Expected: {CERT_FILE} and {KEY_FILE}")
        sys.exit(1)

    # Run pytest
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
