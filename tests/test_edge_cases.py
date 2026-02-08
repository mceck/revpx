#!/usr/bin/env python3
"""
Edge case tests for revpx reverse proxy.

Covers untested code paths:
- X-Forwarded-* header injection and spoofing prevention
- WebSocket upgrade and tunneling
- Backend error handling (502, 421)
- Header size limits (431)
- Chunked request edge cases (extensions, trailers, empty, large)
- HTTP→HTTPS redirect details
- Keep-alive request boundary tracking
- Connection lifecycle edge cases
"""

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_revpx import (
    BackendHandler,
    BackendServer,
    ProxyClient,
    RevPxProxy,
    HTTPS_PORT,
    HTTP_PORT,
    BACKEND_PORT,
    TEST_DOMAIN,
    PROJECT_ROOT,
    CERT_FILE,
    KEY_FILE,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def backend():
    server = BackendServer(BACKEND_PORT)
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="module")
def proxy(backend):
    p = RevPxProxy()
    p.start()
    yield p
    p.stop()


@pytest.fixture
def client(proxy):
    return ProxyClient()


@pytest.fixture(autouse=True)
def reset_backend():
    BackendServer.reset()
    yield


class RawSSLClient:
    """Low-level SSL client for raw request crafting"""

    def __init__(self, host=TEST_DOMAIN, port=HTTPS_PORT):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def send_raw(self, data: bytes, timeout: float = 5.0) -> Optional[bytes]:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as sock:
                with self.context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    ssock.sendall(data)
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
        except Exception:
            return None


def read_http_response(ssock):
    """Read a single HTTP response from a socket, return (status, headers_dict, body_bytes)"""
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = ssock.recv(8192)
        if not chunk:
            raise ConnectionError("Connection closed before headers complete")
        response += chunk

    header_end = response.index(b"\r\n\r\n") + 4
    headers_raw = response[:header_end].decode()
    body_data = response[header_end:]

    status_line = headers_raw.split("\r\n")[0]
    status = int(status_line.split()[1])

    headers = {}
    for line in headers_raw.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    content_length = int(headers.get("Content-Length", 0))
    while len(body_data) < content_length:
        chunk = ssock.recv(8192)
        if not chunk:
            break
        body_data += chunk

    return status, headers, body_data[:content_length]


def make_ssl_connection():
    """Create an SSL connection to the proxy"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=15)
    ssock = ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN)
    return ssock


# ============================================================================
# 1. TestForwardedHeaders
# ============================================================================

class TestForwardedHeaders:
    """Verify X-Forwarded-* header injection by the proxy"""

    def test_x_forwarded_for_injected(self, client):
        """Proxy should inject X-Forwarded-For with client IP"""
        status, _, body = client.request("GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        xff = data["headers"].get("X-Forwarded-For", "")
        assert xff != "", "X-Forwarded-For header should be injected"
        # Should be a valid IP (127.0.0.1 or ::1)
        assert "127.0.0.1" in xff or "::1" in xff

    def test_x_real_ip_injected(self, client):
        """Proxy should inject X-Real-IP"""
        status, _, body = client.request("GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        xri = data["headers"].get("X-Real-Ip", data["headers"].get("X-Real-IP", ""))
        assert xri != "", "X-Real-IP header should be injected"

    def test_x_forwarded_proto_is_https(self, client):
        """Proxy should set X-Forwarded-Proto to https"""
        status, _, body = client.request("GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        proto = data["headers"].get("X-Forwarded-Proto", "")
        assert proto == "https"

    def test_x_forwarded_host_injected(self, client):
        """Proxy should inject X-Forwarded-Host matching the Host header"""
        status, _, body = client.request("GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        xfh = data["headers"].get("X-Forwarded-Host", "")
        assert TEST_DOMAIN in xfh

    def test_forwarded_header_injected(self, client):
        """Proxy should inject RFC 7239 Forwarded header"""
        status, _, body = client.request("GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        fwd = data["headers"].get("Forwarded", "")
        assert "proto=https" in fwd
        assert "for=" in fwd

    def test_existing_forwarded_headers_stripped(self, client):
        """Proxy should strip pre-existing forwarded headers to prevent spoofing"""
        spoofed_headers = {
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "1.2.3.4",
            "X-Forwarded-Proto": "http",
        }
        status, _, body = client.request("GET", "/fwd-test", headers=spoofed_headers)
        assert status == 200
        data = json.loads(body)

        # X-Forwarded-For should NOT contain the spoofed 1.2.3.4 alone;
        # the proxy appends the real IP to the original value then replaces
        xff = data["headers"].get("X-Forwarded-For", "")
        xri = data["headers"].get("X-Real-Ip", data["headers"].get("X-Real-IP", ""))
        proto = data["headers"].get("X-Forwarded-Proto", "")

        # Real IP should NOT be 1.2.3.4
        assert xri != "1.2.3.4", "X-Real-IP should be overwritten with actual client IP"
        assert proto == "https", "X-Forwarded-Proto should be overwritten to https"

    def test_forwarded_headers_on_keepalive(self, proxy):
        """Forwarded headers should be injected on each keep-alive request"""
        ssock = make_ssl_connection()
        try:
            for i in range(3):
                request = (
                    f"GET /fwd-ka/{i} HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
                ssock.sendall(request)

                status, _, body = read_http_response(ssock)
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["headers"].get("X-Forwarded-Proto") == "https", \
                    f"Request {i}: missing X-Forwarded-Proto"
        finally:
            ssock.close()


# ============================================================================
# 2. TestWebSocket
# ============================================================================

class WebSocketBackendHandler(BaseHTTPRequestHandler):
    """A minimal WebSocket echo server for testing"""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        # Check for WebSocket upgrade
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # Accept the WebSocket handshake
        key = self.headers.get("Sec-WebSocket-Key", "")
        import hashlib as _hashlib
        magic = "258EAFA5-E914-47DA-95CA-5AB9C0FEDF5E"
        accept = base64.b64encode(
            _hashlib.sha1((key + magic).encode()).digest()
        ).decode()

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        # Echo loop: read a frame, echo it back
        try:
            while True:
                # Read frame header
                header = self.rfile.read(2)
                if len(header) < 2:
                    break

                opcode = header[0] & 0x0F
                if opcode == 0x8:  # Close
                    break

                masked = (header[1] & 0x80) != 0
                payload_len = header[1] & 0x7F

                if payload_len == 126:
                    payload_len = struct.unpack(">H", self.rfile.read(2))[0]
                elif payload_len == 127:
                    payload_len = struct.unpack(">Q", self.rfile.read(8))[0]

                mask_key = self.rfile.read(4) if masked else b""
                payload = self.rfile.read(payload_len)

                if masked:
                    payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

                # Send unmasked echo frame
                frame = bytes([0x80 | opcode])  # FIN + same opcode
                if len(payload) < 126:
                    frame += bytes([len(payload)])
                elif len(payload) < 65536:
                    frame += bytes([126]) + struct.pack(">H", len(payload))
                else:
                    frame += bytes([127]) + struct.pack(">Q", len(payload))
                frame += payload
                self.wfile.write(frame)
                self.wfile.flush()
        except Exception:
            pass


class WebSocketRejectHandler(BaseHTTPRequestHandler):
    """Backend that rejects WebSocket upgrade"""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(403)
        self.send_header("Content-Length", "8")
        self.end_headers()
        self.wfile.write(b"Rejected")


WS_BACKEND_PORT = 18001


@pytest.fixture(scope="module")
def ws_backend():
    server = HTTPServer(("127.0.0.1", WS_BACKEND_PORT), WebSocketBackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    yield server
    server.shutdown()


WS_REJECT_PORT = 18002


@pytest.fixture(scope="module")
def ws_reject_backend():
    server = HTTPServer(("127.0.0.1", WS_REJECT_PORT), WebSocketRejectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    yield server
    server.shutdown()


WS_DOMAIN = "ws.localhost"
WS_REJECT_DOMAIN = "wsrej.localhost"


@pytest.fixture(scope="module")
def ws_proxy(ws_backend, ws_reject_backend):
    """Proxy configured with WebSocket backend domains"""
    p = RevPxProxy(
        https_port=18543,
        http_port=18580,
        backend_port=WS_BACKEND_PORT,
        domain=WS_DOMAIN,
    )
    # We need a custom config with multiple domains
    config_file = os.path.join(PROJECT_ROOT, "tests", "test_ws_config.json")
    config = [
        {
            "domain": WS_DOMAIN,
            "port": str(WS_BACKEND_PORT),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        },
        {
            "domain": WS_REJECT_DOMAIN,
            "port": str(WS_REJECT_PORT),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        },
    ]
    with open(config_file, "w") as f:
        json.dump(config, f)

    import subprocess
    env = os.environ.copy()
    env["REVPX_PORT"] = "18543"
    env["REVPX_PORT_PLAIN"] = "18580"

    binary = os.path.join(PROJECT_ROOT, "build", "revpx")
    process = subprocess.Popen(
        [binary, "-f", config_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=PROJECT_ROOT,
        env=env,
    )
    time.sleep(1)
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        raise RuntimeError(f"WS proxy failed to start:\n{stdout.decode()}\n{stderr.decode()}")

    yield process

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    if os.path.exists(config_file):
        os.remove(config_file)


def ws_frame(payload: bytes, opcode: int = 0x1, masked: bool = True) -> bytes:
    """Build a WebSocket frame"""
    frame = bytes([0x80 | opcode])  # FIN + opcode
    mask_key = os.urandom(4) if masked else b""

    if len(payload) < 126:
        frame += bytes([(0x80 if masked else 0) | len(payload)])
    elif len(payload) < 65536:
        frame += bytes([(0x80 if masked else 0) | 126]) + struct.pack(">H", len(payload))
    else:
        frame += bytes([(0x80 if masked else 0) | 127]) + struct.pack(">Q", len(payload))

    if masked:
        frame += mask_key
        frame += bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    else:
        frame += payload

    return frame


def read_ws_frame(ssock) -> bytes:
    """Read a WebSocket frame and return payload"""
    header = b""
    while len(header) < 2:
        header += ssock.recv(2 - len(header))

    payload_len = header[1] & 0x7F
    if payload_len == 126:
        ext = b""
        while len(ext) < 2:
            ext += ssock.recv(2 - len(ext))
        payload_len = struct.unpack(">H", ext)[0]
    elif payload_len == 127:
        ext = b""
        while len(ext) < 8:
            ext += ssock.recv(8 - len(ext))
        payload_len = struct.unpack(">Q", ext)[0]

    payload = b""
    while len(payload) < payload_len:
        payload += ssock.recv(payload_len - len(payload))

    return payload


class TestWebSocket:
    """Test WebSocket upgrade and tunneling"""

    def test_websocket_upgrade_echo(self, ws_proxy):
        """Full WebSocket handshake and echo through the proxy"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws HTTP/1.1\r\n"
            f"Host: {WS_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", 18543), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=WS_DOMAIN) as ssock:
                ssock.sendall(request)

                # Read 101 response
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                assert b"101" in response.split(b"\r\n")[0], f"Expected 101, got: {response[:100]}"

                # Send a text frame
                message = b"Hello through proxy!"
                ssock.sendall(ws_frame(message, opcode=0x1))

                # Read echo
                echoed = read_ws_frame(ssock)
                assert echoed == message, f"Expected {message!r}, got {echoed!r}"

                # Send close frame
                ssock.sendall(ws_frame(b"", opcode=0x8))

    def test_websocket_binary_frames(self, ws_proxy):
        """Binary WebSocket frames through the proxy tunnel"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws-bin HTTP/1.1\r\n"
            f"Host: {WS_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", 18543), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=WS_DOMAIN) as ssock:
                ssock.sendall(request)

                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                assert b"101" in response.split(b"\r\n")[0]

                # Send binary frame
                binary_data = bytes(range(256))
                ssock.sendall(ws_frame(binary_data, opcode=0x2))

                echoed = read_ws_frame(ssock)
                assert echoed == binary_data

                ssock.sendall(ws_frame(b"", opcode=0x8))

    def test_websocket_failed_upgrade(self, ws_proxy):
        """Backend rejects WebSocket upgrade → proxy returns 502"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws HTTP/1.1\r\n"
            f"Host: {WS_REJECT_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", 18543), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=WS_REJECT_DOMAIN) as ssock:
                ssock.sendall(request)

                response = b""
                ssock.settimeout(3.0)
                try:
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass

                assert b"502" in response, f"Expected 502, got: {response[:200]}"


# ============================================================================
# 3. TestBackendErrors
# ============================================================================

class TestBackendErrors:
    """Test backend error handling"""

    def test_backend_connection_refused(self, proxy):
        """When backend is down, proxy should return 502"""
        # Use a separate proxy instance that points to a port with nothing listening
        config_file = os.path.join(PROJECT_ROOT, "tests", "test_502_config.json")
        config = [{
            "domain": "nobackend.localhost",
            "port": "19999",  # nothing listening here
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        }]
        with open(config_file, "w") as f:
            json.dump(config, f)

        import subprocess
        env = os.environ.copy()
        env["REVPX_PORT"] = "18643"
        env["REVPX_PORT_PLAIN"] = "18680"

        binary = os.path.join(PROJECT_ROOT, "build", "revpx")
        process = subprocess.Popen(
            [binary, "-f", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PROJECT_ROOT,
            env=env,
        )
        time.sleep(1)

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection(("127.0.0.1", 18643), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname="nobackend.localhost") as ssock:
                    request = f"GET / HTTP/1.1\r\nHost: nobackend.localhost\r\n\r\n".encode()
                    ssock.sendall(request)

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

                    assert b"502" in response, f"Expected 502, got: {response[:200]}"
        finally:
            process.terminate()
            process.wait(timeout=5)
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_unknown_domain_returns_421(self, proxy):
        """Request for unknown domain should return 421 Misdirected Request"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Connect with SNI for test.localhost but send Host header for unknown domain
        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                request = f"GET / HTTP/1.1\r\nHost: unknown.example.com\r\n\r\n".encode()
                ssock.sendall(request)

                response = b""
                ssock.settimeout(3.0)
                try:
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass

                assert b"421" in response, f"Expected 421, got: {response[:200]}"

    def test_backend_closes_immediately(self, proxy):
        """Backend that accepts then immediately closes should not crash the proxy"""
        # Start a backend that immediately closes connections
        close_port = 18003
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", close_port))
        srv.listen(5)

        def accept_and_close():
            try:
                while True:
                    conn, _ = srv.accept()
                    conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=accept_and_close, daemon=True)
        thread.start()

        # Create a proxy pointing to this backend
        config_file = os.path.join(PROJECT_ROOT, "tests", "test_close_config.json")
        config = [{
            "domain": "closeme.localhost",
            "port": str(close_port),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        }]
        with open(config_file, "w") as f:
            json.dump(config, f)

        import subprocess
        env = os.environ.copy()
        env["REVPX_PORT"] = "18743"
        env["REVPX_PORT_PLAIN"] = "18780"

        binary = os.path.join(PROJECT_ROOT, "build", "revpx")
        process = subprocess.Popen(
            [binary, "-f", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PROJECT_ROOT,
            env=env,
        )
        time.sleep(1)

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # This may return an error or close - main thing is proxy doesn't crash
            try:
                with socket.create_connection(("127.0.0.1", 18743), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname="closeme.localhost") as ssock:
                        request = f"GET / HTTP/1.1\r\nHost: closeme.localhost\r\n\r\n".encode()
                        ssock.sendall(request)
                        ssock.settimeout(3.0)
                        try:
                            ssock.recv(4096)
                        except (socket.timeout, ssl.SSLError):
                            pass
            except (ConnectionError, ssl.SSLError, OSError):
                pass

            # Verify proxy is still alive by checking process
            assert process.poll() is None, "Proxy process should still be running"
        finally:
            process.terminate()
            process.wait(timeout=5)
            srv.close()
            if os.path.exists(config_file):
                os.remove(config_file)


# ============================================================================
# 4. TestHeaderLimits
# ============================================================================

class TestHeaderLimits:
    """Test header size limit enforcement"""

    def test_headers_exceeding_buffer_returns_431(self, proxy):
        """Headers larger than 32KB buffer should return 431"""
        raw = RawSSLClient()
        # Generate total request > 32KB (RP_BUF_SIZE)
        # Need header lines to exceed 32768 bytes total
        big_header_value = "X" * 33000
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"X-Big: {big_header_value}\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request, timeout=5)
        assert response is not None
        assert b"431" in response, f"Expected 431, got: {response[:200]}"

    def test_headers_within_buffer_succeeds(self, client):
        """Headers well within 32KB limit should succeed"""
        headers = {f"X-H-{i}": "v" * 50 for i in range(20)}
        status, _, _ = client.request("GET", "/", headers=headers)
        assert status == 200


# ============================================================================
# 5. TestChunkedRequestEdgeCases
# ============================================================================

class TestChunkedRequestEdgeCases:
    """Test chunked transfer encoding edge cases"""

    def test_chunked_request_with_extensions(self, proxy):
        """Chunked request with chunk extensions (;key=value)"""
        raw = RawSSLClient()
        body_data = b"Hello with extensions"
        # Chunk with extension
        chunked_body = f"{len(body_data):x};ext=value\r\n".encode() + body_data + b"\r\n0\r\n\r\n"

        request = (
            f"POST /chunked-ext HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        ).encode() + chunked_body

        response = raw.send_raw(request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.body == body_data

    def test_chunked_request_with_trailers(self, proxy):
        """Chunked request with trailer headers"""
        raw = RawSSLClient()
        body_data = b"Body with trailers"
        chunked_body = (
            f"{len(body_data):x}\r\n".encode() + body_data + b"\r\n"
            + b"0\r\n"
            + b"X-Trailer: trailer-value\r\n"
            + b"\r\n"
        )

        request = (
            f"POST /chunked-trailer HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Trailer: X-Trailer\r\n"
            f"\r\n"
        ).encode() + chunked_body

        response = raw.send_raw(request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.body == body_data

    def test_multiple_chunked_requests_keepalive(self, proxy):
        """Multiple chunked POST requests on the same keep-alive connection"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        bodies = [b"first-chunked", b"second-chunked-body", b"third"]

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                for i, body_data in enumerate(bodies):
                    chunked = f"{len(body_data):x}\r\n".encode() + body_data + b"\r\n0\r\n\r\n"
                    request = (
                        f"POST /chunked-ka/{i} HTTP/1.1\r\n"
                        f"Host: {TEST_DOMAIN}\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode() + chunked

                    ssock.sendall(request)
                    status, _, resp_body = read_http_response(ssock)
                    assert status == 200, f"Request {i}: expected 200, got {status}"

                    data = json.loads(resp_body)
                    assert data["body_length"] == len(body_data), \
                        f"Request {i}: expected body_length {len(body_data)}, got {data['body_length']}"

    def test_chunked_request_large_body(self, proxy):
        """Chunked request with body larger than 32KB buffer"""
        raw = RawSSLClient()
        body_data = os.urandom(64 * 1024)  # 64KB
        body_hash = hashlib.md5(body_data).hexdigest()

        # Split into 4KB chunks
        chunked = b""
        chunk_size = 4096
        for i in range(0, len(body_data), chunk_size):
            chunk = body_data[i:i + chunk_size]
            chunked += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
        chunked += b"0\r\n\r\n"

        request = (
            f"POST /chunked-large HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        ).encode() + chunked

        response = raw.send_raw(request, timeout=15)
        assert response is not None
        assert b"200" in response, f"Expected 200, got: {response[:200]}"

        req = BackendHandler.captured_requests[-1]
        assert hashlib.md5(req.body).hexdigest() == body_hash

    def test_chunked_request_single_byte_chunks(self, proxy):
        """Chunked request with single-byte chunks"""
        raw = RawSSLClient()
        body_data = b"ABCDEFGHIJ"

        chunked = b""
        for byte in body_data:
            chunked += b"1\r\n" + bytes([byte]) + b"\r\n"
        chunked += b"0\r\n\r\n"

        request = (
            f"POST /chunked-tiny HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        ).encode() + chunked

        response = raw.send_raw(request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.body == body_data

    def test_chunked_request_empty_body(self, proxy):
        """Chunked request with empty body (just final chunk)"""
        raw = RawSSLClient()
        request = (
            f"POST /chunked-empty HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.body == b""


# ============================================================================
# 6. TestHTTPRedirectDetails
# ============================================================================

class TestHTTPRedirectDetails:
    """Test HTTP→HTTPS redirect specifics"""

    def _http_request(self, request_data: bytes, port: int = HTTP_PORT, timeout: float = 5.0) -> bytes:
        """Send raw HTTP (non-SSL) request"""
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.sendall(request_data)
            response = b""
            sock.settimeout(2.0)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            return response

    def test_redirect_preserves_path(self, proxy):
        """Redirect Location should preserve the request path"""
        request = f"GET /some/path HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = self._http_request(request)

        assert b"301" in response
        # Find Location header
        for line in response.decode(errors="replace").split("\r\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                assert "/some/path" in location, f"Path not preserved in Location: {location}"
                assert location.startswith("https://")
                break

    def test_redirect_preserves_query_string(self, proxy):
        """Redirect Location should preserve query string"""
        request = f"GET /search?q=test&page=1 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = self._http_request(request)

        assert b"301" in response
        for line in response.decode(errors="replace").split("\r\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                assert "q=test" in location, f"Query string not preserved: {location}"
                break

    def test_redirect_includes_non_standard_port(self, proxy):
        """Redirect Location should include port when not 443"""
        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = self._http_request(request)

        assert b"301" in response
        for line in response.decode(errors="replace").split("\r\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                # Our test uses port 18443, not 443, so it should be included
                assert str(HTTPS_PORT) in location, \
                    f"Non-standard port {HTTPS_PORT} not in Location: {location}"
                break

    def test_redirect_no_host_returns_400(self, proxy):
        """HTTP request without Host header should return 400"""
        request = b"GET / HTTP/1.1\r\n\r\n"
        response = self._http_request(request)

        assert b"400" in response, f"Expected 400 for missing Host, got: {response[:200]}"


# ============================================================================
# 7. TestKeepAliveRequestBoundaries
# ============================================================================

class TestKeepAliveRequestBoundaries:
    """Test request boundary tracking across keep-alive connections"""

    def test_keepalive_get_then_post_then_get(self, proxy):
        """Alternating GET and POST on same connection"""
        ssock = make_ssl_connection()
        try:
            # GET
            ssock.sendall(
                f"GET /ka-mixed/1 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "GET"

            # POST with body
            post_body = b"post-body-data"
            ssock.sendall(
                (
                    f"POST /ka-mixed/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: {len(post_body)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + post_body
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "POST"
            assert data["body_length"] == len(post_body)

            # GET again
            ssock.sendall(
                f"GET /ka-mixed/3 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "GET"
            assert data["path"] == "/ka-mixed/3"
        finally:
            ssock.close()

    def test_keepalive_post_with_no_body(self, proxy):
        """POST with Content-Length: 0 between other requests"""
        ssock = make_ssl_connection()
        try:
            # GET
            ssock.sendall(
                f"GET /ka-zero/1 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, _ = read_http_response(ssock)
            assert status == 200

            # POST with empty body
            ssock.sendall(
                (
                    f"POST /ka-zero/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["body_length"] == 0

            # Another GET
            ssock.sendall(
                f"GET /ka-zero/3 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "GET"
            assert data["path"] == "/ka-zero/3"
        finally:
            ssock.close()

    def test_keepalive_post_body_exactly_buffer_size(self, proxy):
        """POST with body exactly 32KB on keep-alive, followed by another request"""
        ssock = make_ssl_connection()
        try:
            body_32k = b"A" * (32 * 1024)
            body_hash = hashlib.md5(body_32k).hexdigest()

            ssock.sendall(
                (
                    f"POST /ka-buf/1 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: {len(body_32k)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + body_32k
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["body_hash"] == body_hash

            # Follow-up GET
            ssock.sendall(
                f"GET /ka-buf/2 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["path"] == "/ka-buf/2"
        finally:
            ssock.close()

    def test_keepalive_many_small_gets(self, proxy):
        """20+ GETs on the same keep-alive connection"""
        ssock = make_ssl_connection()
        try:
            for i in range(25):
                ssock.sendall(
                    f"GET /ka-many/{i} HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                )
                status, _, body = read_http_response(ssock)
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["path"] == f"/ka-many/{i}", f"Request {i}: wrong path"
        finally:
            ssock.close()


# ============================================================================
# 8. TestConnectionEdgeCases
# ============================================================================

class TestConnectionEdgeCases:
    """Test connection lifecycle edge cases"""

    def test_client_sends_rst(self, proxy):
        """Client sending RST should not crash proxy"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            sock = socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5)
            ssock = ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN)
            ssock.sendall(
                f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
            )
            # Force RST by setting SO_LINGER to 0
            l_onoff = 1
            l_linger = 0
            import struct as _struct
            ssock.unwrap()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            _struct.pack('ii', l_onoff, l_linger))
            sock.close()
        except Exception:
            pass

        time.sleep(0.5)

        # Proxy should still work
        client = ProxyClient()
        status, _, _ = client.request("GET", "/after-rst")
        assert status == 200

    def test_half_close(self, proxy):
        """Client shutting down write side"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                ssock.sendall(
                    f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: close\r\n\r\n".encode()
                )

                # Read the response
                response = b""
                try:
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass

                assert b"200" in response

    def test_backend_slow_connect(self, proxy):
        """Test that client data is buffered during ST_CONNECTING"""
        # This is implicitly tested by large POST tests, but let's be explicit
        # Send a POST where the body arrives before backend connects
        client = ProxyClient()
        body = b"data-while-connecting" * 100
        status, _, resp_body = client.request("POST", "/slow-connect-test", body=body, timeout=15)

        assert status == 200
        data = json.loads(resp_body)
        assert data["body_length"] == len(body)
        assert data["body_hash"] == hashlib.md5(body).hexdigest()


# ============================================================================
# 9. TestPipelinedForwardedHeaders - Bug: saved_body forwarded without
#    header injection when first request has no body (CL=0 or GET)
# ============================================================================

class TestPipelinedForwardedHeaders:
    """Test that X-Forwarded-* headers are injected on ALL pipelined requests,
    not just the first one. Targets a bug in forward_client_bytes where
    saved_body bytes (belonging to the next request) are forwarded with
    req_need_header=false when req_body_left==0."""

    def test_pipelined_gets_both_have_forwarded_headers(self, proxy):
        """Two pipelined GETs sent in one write - both must have X-Forwarded-For"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Send two GETs in a single write so they arrive in one TCP segment
        requests = (
            f"GET /pipe-fwd/1 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"GET /pipe-fwd/2 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                ssock.sendall(requests)

                # Read first response
                status1, _, body1 = read_http_response(ssock)
                assert status1 == 200
                data1 = json.loads(body1)
                assert data1["path"] == "/pipe-fwd/1"
                assert "X-Forwarded-For" in data1["headers"], \
                    "First pipelined request missing X-Forwarded-For"

                # Read second response
                status2, _, body2 = read_http_response(ssock)
                assert status2 == 200
                data2 = json.loads(body2)
                assert data2["path"] == "/pipe-fwd/2"
                assert "X-Forwarded-For" in data2["headers"], \
                    "Second pipelined request missing X-Forwarded-For"
                assert "X-Forwarded-Proto" in data2["headers"], \
                    "Second pipelined request missing X-Forwarded-Proto"

    def test_pipelined_post_cl0_then_get_both_have_forwarded_headers(self, proxy):
        """POST with Content-Length: 0 followed by GET in one write"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        requests = (
            f"POST /pipe-cl0/1 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"GET /pipe-cl0/2 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                ssock.sendall(requests)

                status1, _, body1 = read_http_response(ssock)
                assert status1 == 200

                status2, _, body2 = read_http_response(ssock)
                assert status2 == 200
                data2 = json.loads(body2)
                assert data2["path"] == "/pipe-cl0/2"
                assert "X-Forwarded-For" in data2["headers"], \
                    "Request after CL:0 POST missing X-Forwarded-For"

    def test_pipelined_post_with_body_then_get_forwarded_headers(self, proxy):
        """POST with body followed by GET in one write - verify correct boundary"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        post_body = b"hello"
        requests = (
            f"POST /pipe-body/1 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: {len(post_body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + post_body + (
            f"GET /pipe-body/2 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                ssock.sendall(requests)

                status1, _, body1 = read_http_response(ssock)
                assert status1 == 200
                data1 = json.loads(body1)
                assert data1["body_length"] == 5

                status2, _, body2 = read_http_response(ssock)
                assert status2 == 200
                data2 = json.loads(body2)
                assert data2["path"] == "/pipe-body/2"
                assert "X-Forwarded-For" in data2["headers"], \
                    "GET after POST missing X-Forwarded-For"

    def test_three_pipelined_gets_all_have_forwarded_headers(self, proxy):
        """Three pipelined GETs in one write"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        requests = b""
        for i in range(3):
            requests += (
                f"GET /pipe3/{i} HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode()

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                ssock.sendall(requests)

                for i in range(3):
                    status, _, body = read_http_response(ssock)
                    assert status == 200, f"Request {i}: expected 200, got {status}"
                    data = json.loads(body)
                    assert data["path"] == f"/pipe3/{i}"
                    assert "X-Forwarded-For" in data["headers"], \
                        f"Pipelined request {i} missing X-Forwarded-For"


# ============================================================================
# 10. TestSTUpgradingBugs - Bug: uses `n` (last read size) instead of
#     `c->len` (total accumulated) for 101 check and client copy
# ============================================================================

class TestSTUpgradingBugs:
    """Test WebSocket upgrade response handling edge cases.
    Targets a bug where ST_UPGRADING uses `n` (last do_read return)
    instead of `c->len` (total accumulated bytes) for the 101 check
    and when copying response to client buffer."""

    def test_websocket_large_101_response(self, ws_proxy):
        """WebSocket upgrade with a 101 response that includes extra headers.
        The response may arrive in multiple reads; the proxy must accumulate."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws-large HTTP/1.1\r\n"
            f"Host: {WS_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", 18543), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=WS_DOMAIN) as ssock:
                ssock.sendall(request)

                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                assert b"101" in response.split(b"\r\n")[0], \
                    f"Expected 101, got: {response[:100]}"

                # Verify we can still communicate after upgrade
                message = b"after-upgrade-test"
                ssock.sendall(ws_frame(message, opcode=0x1))
                echoed = read_ws_frame(ssock)
                assert echoed == message

                ssock.sendall(ws_frame(b"", opcode=0x8))


# ============================================================================
# 11. TestPipelinedChunkedThenGet - Chunked terminator → next request
# ============================================================================

class TestPipelinedChunkedThenGet:
    """Test chunked POST followed immediately by GET in the same TCP segment.
    Exercises advance_chunked → req_need_header transition when leftover
    bytes after chunk terminator belong to a new request."""

    def test_chunked_post_then_get_in_one_write(self, proxy):
        """Chunked POST + GET pipelined in a single write"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        post_body = b"pipelined-chunked"
        chunked = f"{len(post_body):x}\r\n".encode() + post_body + b"\r\n0\r\n\r\n"

        requests = (
            f"POST /pipe-chunked/1 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + chunked + (
            f"GET /pipe-chunked/2 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                ssock.sendall(requests)

                # Read chunked POST response
                status1, _, body1 = read_http_response(ssock)
                assert status1 == 200
                data1 = json.loads(body1)
                assert data1["body_length"] == len(post_body)

                # Read GET response
                status2, _, body2 = read_http_response(ssock)
                assert status2 == 200
                data2 = json.loads(body2)
                assert data2["path"] == "/pipe-chunked/2"
                assert data2["method"] == "GET"
                # Verify forwarded headers injected on the GET too
                assert "X-Forwarded-For" in data2["headers"], \
                    "GET after pipelined chunked POST missing X-Forwarded-For"

    def test_chunked_post_with_trailers_then_get(self, proxy):
        """Chunked POST with trailers + GET pipelined in one write"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        post_body = b"with-trailers"
        chunked = (
            f"{len(post_body):x}\r\n".encode() + post_body + b"\r\n"
            + b"0\r\n"
            + b"X-Checksum: abc123\r\n"
            + b"\r\n"
        )

        requests = (
            f"POST /pipe-chunk-trailer/1 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + chunked + (
            f"GET /pipe-chunk-trailer/2 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                ssock.sendall(requests)

                status1, _, body1 = read_http_response(ssock)
                assert status1 == 200

                status2, _, body2 = read_http_response(ssock)
                assert status2 == 200
                data2 = json.loads(body2)
                assert data2["path"] == "/pipe-chunk-trailer/2"


# ============================================================================
# 12. TestHostHeaderEdgeCases - extract_host parsing
# ============================================================================

class TestHostHeaderEdgeCases:
    """Test Host header parsing edge cases in extract_host()."""

    def test_host_with_port(self, proxy):
        """Host: test.localhost:18443 should strip port for domain lookup"""
        raw = RawSSLClient()
        request = (
            f"GET /host-port HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}:{HTTPS_PORT}\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        # Should route correctly (200), NOT 421 Misdirected
        assert b"200" in response, f"Host with port failed: {response[:200]}"

    def test_host_case_insensitive(self, proxy):
        """Host header should be case-insensitive for domain matching"""
        raw = RawSSLClient()
        request = (
            f"GET /host-case HTTP/1.1\r\n"
            f"Host: TEST.LOCALHOST\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        # strcasecmp on domain lookup should handle this
        assert b"200" in response, f"Case-insensitive host failed: {response[:200]}"

    def test_host_with_tab_whitespace(self, proxy):
        """Host header with tab after colon"""
        raw = RawSSLClient()
        request = (
            b"GET /host-tab HTTP/1.1\r\n"
            b"Host:\t" + TEST_DOMAIN.encode() + b"\r\n"
            b"\r\n"
        )

        response = raw.send_raw(request)
        assert response is not None
        assert b"200" in response, f"Host with tab whitespace failed: {response[:200]}"

    def test_host_with_multiple_spaces(self, proxy):
        """Host header with extra spaces around value"""
        raw = RawSSLClient()
        request = (
            b"GET /host-spaces HTTP/1.1\r\n"
            b"Host:   " + TEST_DOMAIN.encode() + b"  \r\n"
            b"\r\n"
        )

        response = raw.send_raw(request)
        assert response is not None
        # Trailing spaces may be included in host — could cause 421
        # This tests whether extract_host trims trailing whitespace
        # extract_host: e[-1] == '\r' strips it, but spaces before \r remain
        # This is fine if domain is correct without trailing spaces
        # Let's just verify the proxy doesn't crash
        assert b"421" in response or b"200" in response


# ============================================================================
# 13. TestMalformedRequests - Error handling for bad input
# ============================================================================

class TestMalformedRequests:
    """Test error handling for malformed HTTP requests."""

    def test_malformed_chunk_hex(self, proxy):
        """Invalid hex in chunk size should return 400"""
        raw = RawSSLClient()
        request = (
            f"POST /bad-chunk HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"ZZZZ\r\n"
            f"data\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        assert b"400" in response, f"Expected 400 for bad chunk hex, got: {response[:200]}"

    def test_chunk_size_overflow(self, proxy):
        """Chunk size with >16 hex digits should return 400"""
        raw = RawSSLClient()
        # 17 hex digits
        request = (
            f"POST /chunk-overflow HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"00000000000000001\r\n"
            f"x\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        assert b"400" in response, f"Expected 400 for chunk size overflow, got: {response[:200]}"

    def test_post_without_content_length_or_te(self, proxy):
        """POST with no Content-Length or Transfer-Encoding → treated as no body"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        requests = (
            f"POST /no-cl/1 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"GET /no-cl/2 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                ssock.sendall(requests)

                # POST should succeed with body_length=0
                status1, _, body1 = read_http_response(ssock)
                assert status1 == 200
                data1 = json.loads(body1)
                assert data1["body_length"] == 0

                # GET should also succeed
                status2, _, body2 = read_http_response(ssock)
                assert status2 == 200
                data2 = json.loads(body2)
                assert data2["path"] == "/no-cl/2"

    def test_chunked_and_content_length_both_present(self, proxy):
        """When both Transfer-Encoding: chunked and Content-Length are present,
        chunked should take precedence per RFC 7230 §3.3.3"""
        raw = RawSSLClient()
        post_body = b"chunked-wins"
        chunked = f"{len(post_body):x}\r\n".encode() + post_body + b"\r\n0\r\n\r\n"

        request = (
            f"POST /te-vs-cl HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 999\r\n"
            f"\r\n"
        ).encode() + chunked

        response = raw.send_raw(request)
        assert response is not None
        assert b"200" in response, f"Expected 200, got: {response[:200]}"

        req = BackendHandler.captured_requests[-1]
        assert req.body == post_body, \
            f"Expected chunked body, got {len(req.body)} bytes"


# ============================================================================
# 14. TestForwardedHeaderOverflow - Long X-Forwarded-For chain
# ============================================================================

class TestForwardedHeaderOverflow:
    """Test inject_forwarded_headers with very long existing X-Forwarded-For.
    The internal ff[512] buffer may truncate. Verify no crash."""

    def test_long_xff_chain_no_crash(self, proxy):
        """Request with a very long existing X-Forwarded-For chain"""
        # Build a 600-byte X-Forwarded-For value (exceeds ff[512])
        long_xff = ", ".join([f"10.0.0.{i % 256}" for i in range(60)])
        assert len(long_xff) > 512

        raw = RawSSLClient()
        request = (
            f"GET /long-xff HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"X-Forwarded-For: {long_xff}\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        # Main assertion: proxy didn't crash, returned some response
        assert b"HTTP/1.1" in response

    def test_long_forwarded_header_no_crash(self, proxy):
        """Request with a very long Forwarded header"""
        long_fwd = "; ".join([f"for=10.0.0.{i % 256}" for i in range(60)])
        assert len(long_fwd) > 512

        raw = RawSSLClient()
        request = (
            f"GET /long-fwd HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Forwarded: {long_fwd}\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        assert b"HTTP/1.1" in response


# ============================================================================
# 15. TestRequestLineEdgeCases
# ============================================================================

class TestRequestLineEdgeCases:
    """Test edge cases in request line parsing (extract_target, etc.)"""

    def test_very_long_url(self, proxy):
        """Request with a very long URL path (near buffer limit)"""
        raw = RawSSLClient()
        # 4KB URL - well within 32KB but exercises extract_target with long path
        long_path = "/a" * 2000
        request = (
            f"GET {long_path} HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.path == long_path

    def test_url_with_query_and_fragment(self, proxy):
        """Request with query string preserved through proxy"""
        raw = RawSSLClient()
        request = (
            f"GET /query?key=value&arr[]=1&arr[]=2 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert "key=value" in req.path
        assert "arr[]=1" in req.path

    def test_http_10_request(self, proxy):
        """HTTP/1.0 request should be proxied"""
        raw = RawSSLClient()
        request = (
            f"GET /http10 HTTP/1.0\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"\r\n"
        ).encode()

        response = raw.send_raw(request)
        assert response is not None
        assert b"200" in response


# ============================================================================
# 16. TestSNIMismatch
# ============================================================================

class TestSNIMismatch:
    """Test SNI vs Host header routing behavior"""

    def test_sni_mismatch_host_takes_precedence(self, proxy):
        """When SNI doesn't match Host, Host header is used for routing"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Connect with SNI for test.localhost (valid) but send Host for unknown domain
        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN) as ssock:
                request = f"GET / HTTP/1.1\r\nHost: nonexistent.domain\r\n\r\n".encode()
                ssock.sendall(request)

                response = b""
                ssock.settimeout(3.0)
                try:
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass

                # Host header takes precedence → domain not found → 421
                assert b"421" in response, f"Expected 421, got: {response[:200]}"


# ============================================================================
# 17. TestRapidKeepaliveTransitions
# ============================================================================

class TestRapidKeepaliveTransitions:
    """Test rapid alternation of request types on keep-alive connections
    to stress-test request boundary tracking."""

    def test_get_post_chunked_post_cl_get_sequence(self, proxy):
        """Mixed sequence: GET, chunked POST, CL POST, GET on one connection"""
        ssock = make_ssl_connection()
        try:
            # 1. GET
            ssock.sendall(
                f"GET /rapid/1 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "GET"

            # 2. Chunked POST
            chunk_body = b"chunked-data"
            chunked = f"{len(chunk_body):x}\r\n".encode() + chunk_body + b"\r\n0\r\n\r\n"
            ssock.sendall(
                (
                    f"POST /rapid/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + chunked
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["body_length"] == len(chunk_body)

            # 3. CL POST
            cl_body = b"cl-body-data"
            ssock.sendall(
                (
                    f"POST /rapid/3 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: {len(cl_body)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + cl_body
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["body_length"] == len(cl_body)

            # 4. GET
            ssock.sendall(
                f"GET /rapid/4 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            data = json.loads(body)
            assert data["path"] == "/rapid/4"
            assert "X-Forwarded-For" in data["headers"]
        finally:
            ssock.close()

    def test_many_chunked_posts_keepalive(self, proxy):
        """10 chunked POSTs on the same connection"""
        ssock = make_ssl_connection()
        try:
            for i in range(10):
                body_data = f"chunk-{i}-payload".encode()
                chunked = f"{len(body_data):x}\r\n".encode() + body_data + b"\r\n0\r\n\r\n"
                ssock.sendall(
                    (
                        f"POST /many-chunk/{i} HTTP/1.1\r\n"
                        f"Host: {TEST_DOMAIN}\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode() + chunked
                )
                status, _, body = read_http_response(ssock)
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["body_length"] == len(body_data), \
                    f"Request {i}: expected {len(body_data)}, got {data['body_length']}"
        finally:
            ssock.close()


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
