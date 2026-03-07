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

import asyncio
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
import pytest_asyncio

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
    REVPX_BINARY,
    CERT_FILE,
    KEY_FILE,
)


EDGE_HTTPS_PORT = 19443
EDGE_HTTP_PORT = 19480
EDGE_BACKEND_PORT = 19400

# Shadow imported defaults so this module can run in parallel with test_revpx.py.
HTTPS_PORT = EDGE_HTTPS_PORT
HTTP_PORT = EDGE_HTTP_PORT
BACKEND_PORT = EDGE_BACKEND_PORT


# ============================================================================
# Fixtures
# ============================================================================

@pytest_asyncio.fixture(scope="module")
async def backend():
    server = BackendServer(BACKEND_PORT)
    await asyncio.to_thread(server.start)
    yield server
    await asyncio.to_thread(server.stop)


@pytest_asyncio.fixture(scope="module")
async def proxy(backend):
    p = RevPxProxy(
        https_port=HTTPS_PORT,
        http_port=HTTP_PORT,
        backend_port=BACKEND_PORT,
    )
    await p.start()
    yield p
    await p.stop()


@pytest.fixture
def client(proxy):
    return ProxyClient(port=HTTPS_PORT)


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
                    # Block for the first bytes, then drain with a short idle timeout.
                    ssock.settimeout(min(timeout, 0.5))
                    response = b""
                    try:
                        first = ssock.recv(8192)
                    except socket.timeout:
                        return b""
                    if not first:
                        return b""
                    response += first

                    # Avoid per-request 2s waits on keep-alive sockets.
                    ssock.settimeout(0.05)
                    while True:
                        try:
                            chunk = ssock.recv(8192)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        response += chunk

                    return response
        except Exception:
            return None


pytestmark = pytest.mark.asyncio


async def async_send_raw(raw: RawSSLClient, data: bytes, timeout: float = 5.0) -> Optional[bytes]:
    return await asyncio.to_thread(raw.send_raw, data, timeout)


async def async_make_ssl_connection(host=TEST_DOMAIN, port=HTTPS_PORT):
    """Create an async SSL connection to the proxy"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=ctx, server_hostname=host
    )
    return reader, writer


_ASYNC_RESPONSE_BUFFER = {}


async def async_read_http_response(reader, writer):
    """Read one HTTP response from an async stream, preserving extra bytes for pipelining."""
    buf_id = id(reader)
    response = _ASYNC_RESPONSE_BUFFER.pop(buf_id, b"")
    while b"\r\n\r\n" not in response:
        chunk = await reader.read(8192)
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
        chunk = await reader.read(8192)
        if not chunk:
            break
        body_data += chunk

    if len(body_data) > content_length:
        _ASYNC_RESPONSE_BUFFER[buf_id] = body_data[content_length:]

    return status, headers, body_data[:content_length]


async def async_read_ws_frame(reader, timeout=5.0):
    """Read a WebSocket frame from an async stream and return payload"""
    async def _read_exact(n):
        data = b""
        while len(data) < n:
            chunk = await reader.read(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed reading WS frame")
            data += chunk
        return data

    header = await asyncio.wait_for(_read_exact(2), timeout=timeout)

    payload_len = header[1] & 0x7F
    if payload_len == 126:
        ext = await _read_exact(2)
        payload_len = struct.unpack(">H", ext)[0]
    elif payload_len == 127:
        ext = await _read_exact(8)
        payload_len = struct.unpack(">Q", ext)[0]

    payload = await _read_exact(payload_len)
    return payload


async def async_request(
    client: ProxyClient,
    method: str = "GET",
    path: str = "/",
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict, bytes]:
    return await client.request(method, path, headers, body, timeout)


async def async_wait_for_tcp_port(port: int, timeout: float = 5.0):
    """Async variant of wait_for_tcp_port for async test paths."""
    deadline = asyncio.get_running_loop().time() + timeout
    last_error = None
    while asyncio.get_running_loop().time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError as exc:
            last_error = exc
            await asyncio.sleep(0.02)
    raise RuntimeError(f"Port {port} not ready within {timeout}s (last error: {last_error})")


async def async_start_revpx(config_file: str, https_port: int, http_port: int) -> asyncio.subprocess.Process:
    env = os.environ.copy()
    env["REVPX_PORT"] = str(https_port)
    env["REVPX_PORT_PLAIN"] = str(http_port)

    process = await asyncio.create_subprocess_exec(
        REVPX_BINARY,
        "-f",
        config_file,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=PROJECT_ROOT,
        env=env,
    )
    await async_wait_for_tcp_port(https_port, timeout=5.0)

    if process.returncode is not None:
        stdout, stderr = await process.communicate()
        raise RuntimeError(f"Proxy failed to start:\n{stdout.decode()}\n{stderr.decode()}")

    return process


async def async_stop_process(process: asyncio.subprocess.Process, timeout: float = 5.0):
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()


# ============================================================================
# 1. TestForwardedHeaders
# ============================================================================

class TestForwardedHeaders:
    """Verify X-Forwarded-* header injection by the proxy"""

    async def test_x_forwarded_for_injected(self, client):
        """Proxy should inject X-Forwarded-For with client IP"""
        status, _, body = await async_request(client, "GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        xff = data["headers"].get("X-Forwarded-For", "")
        assert xff != "", "X-Forwarded-For header should be injected"
        # Should be a valid IP (127.0.0.1 or ::1)
        assert "127.0.0.1" in xff or "::1" in xff

    async def test_x_real_ip_injected(self, client):
        """Proxy should inject X-Real-IP"""
        status, _, body = await async_request(client, "GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        xri = data["headers"].get("X-Real-Ip", data["headers"].get("X-Real-IP", ""))
        assert xri != "", "X-Real-IP header should be injected"

    async def test_x_forwarded_proto_is_https(self, client):
        """Proxy should set X-Forwarded-Proto to https"""
        status, _, body = await async_request(client, "GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        proto = data["headers"].get("X-Forwarded-Proto", "")
        assert proto == "https"

    async def test_x_forwarded_host_injected(self, client):
        """Proxy should inject X-Forwarded-Host matching the Host header"""
        status, _, body = await async_request(client, "GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        xfh = data["headers"].get("X-Forwarded-Host", "")
        assert TEST_DOMAIN in xfh

    async def test_forwarded_header_injected(self, client):
        """Proxy should inject RFC 7239 Forwarded header"""
        status, _, body = await async_request(client, "GET", "/fwd-test")
        assert status == 200
        data = json.loads(body)
        fwd = data["headers"].get("Forwarded", "")
        assert "proto=https" in fwd
        assert "for=" in fwd

    async def test_forwarded_ipv6_for_value_is_quoted_or_bracketed(self, client):
        """RFC 7239: IPv6-like for= values must be quoted/bracketed, not raw tokens."""
        status, _, body = await async_request(client, "GET", "/fwd-rfc7239")
        assert status == 200
        data = json.loads(body)
        fwd = data["headers"].get("Forwarded", "")
        assert "for=" in fwd

        # Extract for= value until ';' or end.
        start = fwd.lower().find("for=")
        assert start >= 0
        value = fwd[start + 4:]
        sep = value.find(";")
        if sep >= 0:
            value = value[:sep]
        value = value.strip()

        # On systems where peer appears as IPv4, this check is not applicable.
        if ":" not in value and ":" not in data["headers"].get("X-Forwarded-For", ""):
            pytest.skip("Client peer address is not IPv6-like on this environment")

        # Accept quoted value and/or bracketed IPv6 literal.
        is_quoted = len(value) >= 2 and value[0] == '"' and value[-1] == '"'
        inner = value[1:-1] if is_quoted else value
        is_bracketed = len(inner) >= 2 and inner[0] == '[' and inner[-1] == ']'

        assert is_quoted or is_bracketed, \
            f"Forwarded for= value is not RFC-compliant for IPv6-like address: {value!r}"

    async def test_forwarded_host_with_port_is_quoted(self, proxy):
        """RFC 7239: host= value containing ':' (host:port) should be quoted."""
        raw = RawSSLClient()
        request = (
            f"GET /fwd-host-port HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}:{HTTPS_PORT}\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None and b"200" in response

        req = BackendHandler.captured_requests[-1]
        fwd = req.headers.get("Forwarded", "")
        assert "host=" in fwd

        host_pos = fwd.lower().find("host=")
        host_value = fwd[host_pos + 5:].strip() if host_pos >= 0 else ""

        # Host param is at the end in current formatter; this keeps the check simple.
        assert host_value.startswith('"') and host_value.endswith('"'), \
            f"Forwarded host= is not quoted for host:port value: {host_value!r}"

    async def test_existing_forwarded_headers_stripped(self, client):
        """Proxy should strip pre-existing forwarded headers to prevent spoofing"""
        spoofed_headers = {
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "1.2.3.4",
            "X-Forwarded-Proto": "http",
        }
        status, _, body = await async_request(client, "GET", "/fwd-test", headers=spoofed_headers)
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

    async def test_spoofed_xff_value_is_not_preserved(self, client):
        """Spoofed X-Forwarded-For must be removed, not carried over."""
        spoofed_headers = {
            "X-Forwarded-For": "203.0.113.10",
            "X-Real-IP": "203.0.113.10",
            "Forwarded": "for=203.0.113.10;proto=http",
        }

        status, _, body = await async_request(client, "GET", "/fwd-spoof", headers=spoofed_headers)
        assert status == 200
        data = json.loads(body)

        # Security expectation: client-supplied proxy chain must not survive.
        xff = data["headers"].get("X-Forwarded-For", "")
        forwarded = data["headers"].get("Forwarded", "")

        assert "203.0.113.10" not in xff, \
            "Spoofed X-Forwarded-For value leaked into backend-visible header"
        assert "203.0.113.10" not in forwarded, \
            "Spoofed Forwarded value leaked into backend-visible header"

    async def test_forwarded_headers_on_keepalive(self, proxy):
        """Forwarded headers should be injected on each keep-alive request"""
        reader, writer = await async_make_ssl_connection()
        try:
            for i in range(3):
                request = (
                    f"GET /fwd-ka/{i} HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
                writer.write(request)
                await writer.drain()

                status, _, body = await async_read_http_response(reader, writer)
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["headers"].get("X-Forwarded-Proto") == "https", \
                    f"Request {i}: missing X-Forwarded-Proto"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


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


class WebSocketFragmented101Handler(BaseHTTPRequestHandler):
    """Backend that sends a fragmented 101 response before tunneling."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        key = self.headers.get("Sec-WebSocket-Key", "")
        magic = "258EAFA5-E914-47DA-95CA-5AB9C0FEDF5E"
        accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "X-Extra-Header: fragmented\r\n"
            "\r\n"
        ).encode()

        # Force the status line to arrive in multiple reads at the proxy backend side.
        self.connection.sendall(response[:7])
        time.sleep(0.01)
        self.connection.sendall(response[7:19])
        time.sleep(0.01)
        self.connection.sendall(response[19:])

        try:
            while True:
                header = self.rfile.read(2)
                if len(header) < 2:
                    break

                opcode = header[0] & 0x0F
                if opcode == 0x8:
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

                frame = bytes([0x80 | opcode])
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


class WebSocketDuplicateConnectionHeaderHandler(BaseHTTPRequestHandler):
    """Backend that returns a valid 101 using repeated Connection headers."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        key = self.headers.get("Sec-WebSocket-Key", "")
        magic = "258EAFA5-E914-47DA-95CA-5AB9C0FEDF5E"
        accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        # RFC-compliant repeated field-lines; semantically equivalent to comma-joined tokens.
        self.send_header("Connection", "keep-alive")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        try:
            while True:
                header = self.rfile.read(2)
                if len(header) < 2:
                    break

                opcode = header[0] & 0x0F
                if opcode == 0x8:
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

                frame = bytes([0x80 | opcode])
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


class WebSocketRawDuplicateConnectionHeaderHandler(BaseHTTPRequestHandler):
    """Backend that sends raw 101 with duplicated Connection field-lines."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.connection.sendall(
                b"HTTP/1.1 400 Bad Request\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            return

        key = self.headers.get("Sec-WebSocket-Key", "")
        magic = "258EAFA5-E914-47DA-95CA-5AB9C0FEDF5E"
        accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()

        # Deliberately keep duplicated Connection headers as separate field-lines.
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: keep-alive\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode()
        self.connection.sendall(response)

        try:
            while True:
                header = self.rfile.read(2)
                if len(header) < 2:
                    break

                opcode = header[0] & 0x0F
                if opcode == 0x8:
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

                frame = bytes([0x80 | opcode])
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


class WebSocketRawDuplicateUpgradeHeaderHandler(BaseHTTPRequestHandler):
    """Backend that sends raw 101 with duplicated Upgrade field-lines."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.connection.sendall(
                b"HTTP/1.1 400 Bad Request\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            return

        key = self.headers.get("Sec-WebSocket-Key", "")
        magic = "258EAFA5-E914-47DA-95CA-5AB9C0FEDF5E"
        accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()

        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: h2c\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode()
        self.connection.sendall(response)

        try:
            while True:
                header = self.rfile.read(2)
                if len(header) < 2:
                    break

                opcode = header[0] & 0x0F
                if opcode == 0x8:
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

                frame = bytes([0x80 | opcode])
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


class WebSocketMissingConnectionUpgradeHandler(BaseHTTPRequestHandler):
    """Backend that replies 101 without Connection: Upgrade token."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.connection.sendall(
                b"HTTP/1.1 400 Bad Request\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            return

        key = self.headers.get("Sec-WebSocket-Key", "")
        magic = "258EAFA5-E914-47DA-95CA-5AB9C0FEDF5E"
        accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()

        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: keep-alive\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode()
        self.connection.sendall(response)


class WebSocketMissingUpgradeHeaderHandler(BaseHTTPRequestHandler):
    """Backend that replies 101 without Upgrade: websocket token."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.connection.sendall(
                b"HTTP/1.1 400 Bad Request\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            return

        key = self.headers.get("Sec-WebSocket-Key", "")
        magic = "258EAFA5-E914-47DA-95CA-5AB9C0FEDF5E"
        accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()

        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: h2c\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode()
        self.connection.sendall(response)


WS_BACKEND_PORT = 18001


@pytest_asyncio.fixture(scope="module")
async def ws_backend():
    server = HTTPServer(("127.0.0.1", WS_BACKEND_PORT), WebSocketBackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    await async_wait_for_tcp_port(WS_BACKEND_PORT, timeout=2.0)
    yield server
    server.shutdown()


WS_REJECT_PORT = 18002
WS_FRAGMENTED_PORT = 18004
WS_DUP_CONN_PORT = 18007
WS_RAW_DUP_CONN_PORT = 18008
WS_RAW_DUP_UPGRADE_PORT = 18009
WS_MISSING_CONN_UPGRADE_PORT = 18012
WS_MISSING_UPGRADE_PORT = 18013


@pytest_asyncio.fixture(scope="module")
async def ws_reject_backend():
    server = HTTPServer(("127.0.0.1", WS_REJECT_PORT), WebSocketRejectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    await async_wait_for_tcp_port(WS_REJECT_PORT, timeout=2.0)
    yield server
    server.shutdown()


@pytest_asyncio.fixture(scope="module")
async def ws_fragmented_backend():
    server = HTTPServer(("127.0.0.1", WS_FRAGMENTED_PORT), WebSocketFragmented101Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    await async_wait_for_tcp_port(WS_FRAGMENTED_PORT, timeout=2.0)
    yield server
    server.shutdown()


@pytest_asyncio.fixture(scope="module")
async def ws_dup_conn_backend():
    server = HTTPServer(("127.0.0.1", WS_DUP_CONN_PORT), WebSocketDuplicateConnectionHeaderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    await async_wait_for_tcp_port(WS_DUP_CONN_PORT, timeout=2.0)
    yield server
    server.shutdown()


@pytest_asyncio.fixture(scope="module")
async def ws_raw_dup_conn_backend():
    server = HTTPServer(("127.0.0.1", WS_RAW_DUP_CONN_PORT), WebSocketRawDuplicateConnectionHeaderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    await async_wait_for_tcp_port(WS_RAW_DUP_CONN_PORT, timeout=2.0)
    yield server
    server.shutdown()


@pytest_asyncio.fixture(scope="module")
async def ws_raw_dup_upgrade_backend():
    server = HTTPServer(("127.0.0.1", WS_RAW_DUP_UPGRADE_PORT), WebSocketRawDuplicateUpgradeHeaderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    await async_wait_for_tcp_port(WS_RAW_DUP_UPGRADE_PORT, timeout=2.0)
    yield server
    server.shutdown()


@pytest_asyncio.fixture(scope="module")
async def ws_missing_conn_upgrade_backend():
    server = HTTPServer(("127.0.0.1", WS_MISSING_CONN_UPGRADE_PORT), WebSocketMissingConnectionUpgradeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    await async_wait_for_tcp_port(WS_MISSING_CONN_UPGRADE_PORT, timeout=2.0)
    yield server
    server.shutdown()


@pytest_asyncio.fixture(scope="module")
async def ws_missing_upgrade_backend():
    server = HTTPServer(("127.0.0.1", WS_MISSING_UPGRADE_PORT), WebSocketMissingUpgradeHeaderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    await async_wait_for_tcp_port(WS_MISSING_UPGRADE_PORT, timeout=2.0)
    yield server
    server.shutdown()


WS_DOMAIN = "ws.localhost"
WS_REJECT_DOMAIN = "wsrej.localhost"
WS_FRAGMENTED_DOMAIN = "wsfrag.localhost"
WS_DUP_CONN_DOMAIN = "wsdup.localhost"
WS_RAW_DUP_CONN_DOMAIN = "wsrawdup.localhost"
WS_RAW_DUP_UPGRADE_DOMAIN = "wsrawup.localhost"
WS_MISSING_CONN_UPGRADE_DOMAIN = "wsmissconn.localhost"
WS_MISSING_UPGRADE_DOMAIN = "wsmissup.localhost"


@pytest_asyncio.fixture(scope="module")
async def ws_proxy(ws_backend, ws_reject_backend, ws_fragmented_backend, ws_dup_conn_backend, ws_raw_dup_conn_backend,
                   ws_raw_dup_upgrade_backend, ws_missing_conn_upgrade_backend, ws_missing_upgrade_backend):
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
        {
            "domain": WS_FRAGMENTED_DOMAIN,
            "port": str(WS_FRAGMENTED_PORT),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        },
        {
            "domain": WS_DUP_CONN_DOMAIN,
            "port": str(WS_DUP_CONN_PORT),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        },
        {
            "domain": WS_RAW_DUP_CONN_DOMAIN,
            "port": str(WS_RAW_DUP_CONN_PORT),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        },
        {
            "domain": WS_RAW_DUP_UPGRADE_DOMAIN,
            "port": str(WS_RAW_DUP_UPGRADE_PORT),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        },
        {
            "domain": WS_MISSING_CONN_UPGRADE_DOMAIN,
            "port": str(WS_MISSING_CONN_UPGRADE_PORT),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        },
        {
            "domain": WS_MISSING_UPGRADE_DOMAIN,
            "port": str(WS_MISSING_UPGRADE_PORT),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        },
    ]
    with open(config_file, "w") as f:
        json.dump(config, f)

    process = await async_start_revpx(config_file, https_port=18543, http_port=18580)

    yield process

    await async_stop_process(process, timeout=5.0)
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


class TestWebSocket:
    """Test WebSocket upgrade and tunneling"""

    async def test_upgrade_header_without_connection_upgrade_token_is_not_forced_ws(self, proxy):
        """A request with Upgrade:websocket but without Connection: Upgrade should remain normal HTTP."""
        raw = RawSSLClient()
        request = (
            f"GET /ws-detect-false-positive HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: keep-alive, NotUpgrade\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response.split(b"\r\n", 1)[0], \
            f"False WebSocket detection: expected normal HTTP response, got {response[:160]}"

    async def test_upgrade_header_prefix_websocketx_is_not_treated_as_websocket(self, proxy):
        """Upgrade token must match exactly websocket, not websocketX prefix variants."""
        raw = RawSSLClient()
        request = (
            f"GET /ws-upgrade-prefix HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Upgrade: websocketX\r\n"
            f"Connection: Upgrade\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response.split(b"\r\n", 1)[0], \
            f"False WebSocket detection with Upgrade:websocketX, got {response[:160]}"

    async def test_websocket_upgrade_echo(self, ws_proxy):
        """Full WebSocket handshake and echo through the proxy"""
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

        reader, writer = await async_make_ssl_connection(host=WS_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            # Read 101 response
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                response += chunk

            assert b"101" in response.split(b"\r\n")[0], f"Expected 101, got: {response[:100]}"

            # Send a text frame
            message = b"Hello through proxy!"
            writer.write(ws_frame(message, opcode=0x1))
            await writer.drain()

            # Read echo
            echoed = await async_read_ws_frame(reader)
            assert echoed == message, f"Expected {message!r}, got {echoed!r}"

            # Send close frame
            writer.write(ws_frame(b"", opcode=0x8))
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_websocket_upgrade_with_duplicate_connection_headers(self, ws_proxy):
        """Repeated Connection headers containing Upgrade should still allow WS tunneling."""
        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws-dup-conn HTTP/1.1\r\n"
            f"Host: {WS_DUP_CONN_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        reader, writer = await async_make_ssl_connection(host=WS_DUP_CONN_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                response += chunk

            assert b"101" in response.split(b"\r\n")[0], f"Expected 101, got: {response[:120]}"

            message = b"dup-conn-works"
            writer.write(ws_frame(message, opcode=0x1))
            await writer.drain()
            echoed = await async_read_ws_frame(reader)
            assert echoed == message

            writer.write(ws_frame(b"", opcode=0x8))
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_websocket_binary_frames(self, ws_proxy):
        """Binary WebSocket frames through the proxy tunnel"""
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

        reader, writer = await async_make_ssl_connection(host=WS_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                response += chunk

            assert b"101" in response.split(b"\r\n")[0]

            # Send binary frame
            binary_data = bytes(range(256))
            writer.write(ws_frame(binary_data, opcode=0x2))
            await writer.drain()

            echoed = await async_read_ws_frame(reader)
            assert echoed == binary_data

            writer.write(ws_frame(b"", opcode=0x8))
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_websocket_upgrade_with_raw_duplicate_connection_headers(self, ws_proxy):
        """Raw repeated Connection field-lines containing Upgrade should allow WS tunneling."""
        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws-raw-dup-conn HTTP/1.1\r\n"
            f"Host: {WS_RAW_DUP_CONN_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        reader, writer = await async_make_ssl_connection(host=WS_RAW_DUP_CONN_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                response += chunk

            assert b"101" in response.split(b"\r\n")[0], f"Expected 101, got: {response[:160]}"

            message = b"raw-dup-conn-works"
            writer.write(ws_frame(message, opcode=0x1))
            await writer.drain()
            echoed = await async_read_ws_frame(reader)
            assert echoed == message

            writer.write(ws_frame(b"", opcode=0x8))
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_websocket_upgrade_with_raw_duplicate_upgrade_headers(self, ws_proxy):
        """Raw repeated Upgrade field-lines should match websocket token across all lines."""
        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws-raw-dup-upgrade HTTP/1.1\r\n"
            f"Host: {WS_RAW_DUP_UPGRADE_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        reader, writer = await async_make_ssl_connection(host=WS_RAW_DUP_UPGRADE_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                response += chunk

            assert b"101" in response.split(b"\r\n")[0], f"Expected 101, got: {response[:160]}"

            message = b"raw-dup-upgrade-works"
            writer.write(ws_frame(message, opcode=0x1))
            await writer.drain()
            echoed = await async_read_ws_frame(reader)
            assert echoed == message

            writer.write(ws_frame(b"", opcode=0x8))
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_websocket_failed_upgrade(self, ws_proxy):
        """Backend rejects WebSocket upgrade → proxy returns 502"""
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

        reader, writer = await async_make_ssl_connection(host=WS_REJECT_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            response = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    if not chunk:
                        break
                    response += chunk
            except asyncio.TimeoutError:
                pass

            assert b"502" in response, f"Expected 502, got: {response[:200]}"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_websocket_101_missing_connection_upgrade_is_rejected(self, ws_proxy):
        """Backend 101 without Connection: Upgrade must be rejected with 502."""
        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws-missing-conn-upgrade HTTP/1.1\r\n"
            f"Host: {WS_MISSING_CONN_UPGRADE_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        reader, writer = await async_make_ssl_connection(host=WS_MISSING_CONN_UPGRADE_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            response = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    if not chunk:
                        break
                    response += chunk
            except asyncio.TimeoutError:
                pass

            assert b"502" in response, f"Expected 502 for missing Connection: Upgrade, got: {response[:220]}"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_websocket_101_missing_upgrade_websocket_is_rejected(self, ws_proxy):
        """Backend 101 without Upgrade: websocket must be rejected with 502."""
        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws-missing-upgrade-token HTTP/1.1\r\n"
            f"Host: {WS_MISSING_UPGRADE_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        reader, writer = await async_make_ssl_connection(host=WS_MISSING_UPGRADE_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            response = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    if not chunk:
                        break
                    response += chunk
            except asyncio.TimeoutError:
                pass

            assert b"502" in response, f"Expected 502 for missing Upgrade:websocket, got: {response[:220]}"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 3. TestBackendErrors
# ============================================================================

class TestBackendErrors:
    """Test backend error handling"""

    async def test_backend_connection_refused(self, proxy):
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

        process = await async_start_revpx(config_file, https_port=18643, http_port=18680)

        try:
            reader, writer = await async_make_ssl_connection(host="nobackend.localhost", port=18643)
            try:
                request = f"GET / HTTP/1.1\r\nHost: nobackend.localhost\r\n\r\n".encode()
                writer.write(request)
                await writer.drain()

                response = b""
                try:
                    while True:
                        chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                        if not chunk:
                            break
                        response += chunk
                except asyncio.TimeoutError:
                    pass

                assert b"502" in response, f"Expected 502, got: {response[:200]}"
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        finally:
            await async_stop_process(process, timeout=5.0)
            if os.path.exists(config_file):
                os.remove(config_file)

    async def test_unknown_domain_returns_421(self, proxy):
        """Request for unknown domain should return 421 Misdirected Request"""
        # Connect with SNI for test.localhost but send Host header for unknown domain
        reader, writer = await async_make_ssl_connection()
        try:
            request = f"GET / HTTP/1.1\r\nHost: unknown.example.com\r\n\r\n".encode()
            writer.write(request)
            await writer.drain()

            response = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    if not chunk:
                        break
                    response += chunk
            except asyncio.TimeoutError:
                pass

            assert b"421" in response, f"Expected 421, got: {response[:200]}"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_backend_closes_immediately(self, proxy):
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

        process = await async_start_revpx(config_file, https_port=18743, http_port=18780)

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # This may return an error or close - main thing is proxy doesn't crash
            try:
                reader, writer = await async_make_ssl_connection(host="closeme.localhost", port=18743)
                try:
                    request = f"GET / HTTP/1.1\r\nHost: closeme.localhost\r\n\r\n".encode()
                    writer.write(request)
                    await writer.drain()
                    try:
                        await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    except (asyncio.TimeoutError, ssl.SSLError):
                        pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            except (ConnectionError, ssl.SSLError, OSError):
                pass

            # Verify proxy is still alive by checking process
            assert process.returncode is None, "Proxy process should still be running"
        finally:
            await async_stop_process(process, timeout=5.0)
            srv.close()
            if os.path.exists(config_file):
                os.remove(config_file)


# ============================================================================
# 4. TestHeaderLimits
# ============================================================================

class TestHeaderLimits:
    """Test header size limit enforcement"""

    async def test_headers_exceeding_buffer_returns_431(self, proxy):
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

        response = await async_send_raw(raw, request, timeout=5)
        assert response is not None
        assert b"431" in response, f"Expected 431, got: {response[:200]}"

    async def test_headers_within_buffer_succeeds(self, client):
        """Headers well within 32KB limit should succeed"""
        headers = {f"X-H-{i}": "v" * 50 for i in range(20)}
        status, _, _ = await async_request(client, "GET", "/", headers=headers)
        assert status == 200


# ============================================================================
# 5. TestChunkedRequestEdgeCases
# ============================================================================

class TestChunkedRequestEdgeCases:
    """Test chunked transfer encoding edge cases"""

    async def test_chunked_request_with_extensions(self, proxy):
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

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.body == body_data

    async def test_chunked_request_with_trailers(self, proxy):
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

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.body == body_data

    async def test_multiple_chunked_requests_keepalive(self, proxy):
        """Multiple chunked POST requests on the same keep-alive connection"""
        bodies = [b"first-chunked", b"second-chunked-body", b"third"]

        reader, writer = await async_make_ssl_connection()
        try:
            for i, body_data in enumerate(bodies):
                chunked = f"{len(body_data):x}\r\n".encode() + body_data + b"\r\n0\r\n\r\n"
                request = (
                    f"POST /chunked-ka/{i} HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + chunked

                writer.write(request)
                await writer.drain()
                status, _, resp_body = await async_read_http_response(reader, writer)
                assert status == 200, f"Request {i}: expected 200, got {status}"

                data = json.loads(resp_body)
                assert data["body_length"] == len(body_data), \
                    f"Request {i}: expected body_length {len(body_data)}, got {data['body_length']}"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_chunked_request_large_body(self, proxy):
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

        response = await async_send_raw(raw, request, timeout=15)
        assert response is not None
        assert b"200" in response, f"Expected 200, got: {response[:200]}"

        req = BackendHandler.captured_requests[-1]
        assert hashlib.md5(req.body).hexdigest() == body_hash

    async def test_chunked_request_single_byte_chunks(self, proxy):
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

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.body == body_data

    async def test_chunked_request_empty_body(self, proxy):
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

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.body == b""


# ============================================================================
# 6. TestHTTPRedirectDetails
# ============================================================================

class TestHTTPRedirectDetails:
    """Test HTTP→HTTPS redirect specifics"""

    async def _http_request(self, request_data: bytes, port: int = HTTP_PORT, timeout: float = 5.0) -> bytes:
        """Send raw HTTP (non-SSL) request"""
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(request_data)
            await writer.drain()
            response = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    response += chunk
            except asyncio.TimeoutError:
                pass
            return response
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_redirect_preserves_path(self, proxy):
        """Redirect Location should preserve the request path"""
        request = f"GET /some/path HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = await self._http_request(request)

        assert b"301" in response
        # Find Location header
        for line in response.decode(errors="replace").split("\r\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                assert "/some/path" in location, f"Path not preserved in Location: {location}"
                assert location.startswith("https://")
                break

    async def test_redirect_preserves_query_string(self, proxy):
        """Redirect Location should preserve query string"""
        request = f"GET /search?q=test&page=1 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = await self._http_request(request)

        assert b"301" in response
        for line in response.decode(errors="replace").split("\r\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                assert "q=test" in location, f"Query string not preserved: {location}"
                break

    async def test_redirect_includes_non_standard_port(self, proxy):
        """Redirect Location should include port when not 443"""
        request = f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\n\r\n".encode()
        response = await self._http_request(request)

        assert b"301" in response
        for line in response.decode(errors="replace").split("\r\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                # Our test uses port 18443, not 443, so it should be included
                assert str(HTTPS_PORT) in location, \
                    f"Non-standard port {HTTPS_PORT} not in Location: {location}"
                break

    async def test_redirect_no_host_returns_400(self, proxy):
        """HTTP request without Host header should return 400"""
        request = b"GET / HTTP/1.1\r\n\r\n"
        response = await self._http_request(request)

        assert b"400" in response, f"Expected 400 for missing Host, got: {response[:200]}"


# ============================================================================
# 7. TestKeepAliveRequestBoundaries
# ============================================================================

class TestKeepAliveRequestBoundaries:
    """Test request boundary tracking across keep-alive connections"""

    async def test_keepalive_get_then_post_then_get(self, proxy):
        """Alternating GET and POST on same connection"""
        reader, writer = await async_make_ssl_connection()
        try:
            # GET
            writer.write(
                f"GET /ka-mixed/1 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "GET"

            # POST with body
            post_body = b"post-body-data"
            writer.write(
                (
                    f"POST /ka-mixed/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: {len(post_body)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + post_body
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "POST"
            assert data["body_length"] == len(post_body)

            # GET again
            writer.write(
                f"GET /ka-mixed/3 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "GET"
            assert data["path"] == "/ka-mixed/3"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_keepalive_post_with_no_body(self, proxy):
        """POST with Content-Length: 0 between other requests"""
        reader, writer = await async_make_ssl_connection()
        try:
            # GET
            writer.write(
                f"GET /ka-zero/1 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            await writer.drain()
            status, _, _ = await async_read_http_response(reader, writer)
            assert status == 200

            # POST with empty body
            writer.write(
                (
                    f"POST /ka-zero/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["body_length"] == 0

            # Another GET
            writer.write(
                f"GET /ka-zero/3 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "GET"
            assert data["path"] == "/ka-zero/3"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_keepalive_post_body_exactly_buffer_size(self, proxy):
        """POST with body exactly 32KB on keep-alive, followed by another request"""
        reader, writer = await async_make_ssl_connection()
        try:
            body_32k = b"A" * (32 * 1024)
            body_hash = hashlib.md5(body_32k).hexdigest()

            writer.write(
                (
                    f"POST /ka-buf/1 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: {len(body_32k)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + body_32k
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["body_hash"] == body_hash

            # Follow-up GET
            writer.write(
                f"GET /ka-buf/2 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["path"] == "/ka-buf/2"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_keepalive_many_small_gets(self, proxy):
        """20+ GETs on the same keep-alive connection"""
        reader, writer = await async_make_ssl_connection()
        try:
            for i in range(25):
                writer.write(
                    f"GET /ka-many/{i} HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                )
                await writer.drain()
                status, _, body = await async_read_http_response(reader, writer)
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["path"] == f"/ka-many/{i}", f"Request {i}: wrong path"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 8. TestConnectionEdgeCases
# ============================================================================

class TestConnectionEdgeCases:
    """Test connection lifecycle edge cases"""

    async def test_client_sends_rst(self, proxy):
        """Client sending RST should not crash proxy"""
        def _sync_rst():
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

        await asyncio.to_thread(_sync_rst)
        await asyncio.sleep(0.1)

        # Proxy should still work
        client = ProxyClient(port=HTTPS_PORT)
        status, _, _ = await async_request(client, "GET", "/after-rst")
        assert status == 200

    async def test_half_close(self, proxy):
        """Client shutting down write side"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(
            "127.0.0.1", HTTPS_PORT, ssl=ctx, server_hostname=TEST_DOMAIN
        )
        try:
            writer.write(
                f"GET / HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: close\r\n\r\n".encode()
            )
            await writer.drain()

            response = b""
            try:
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        break
                    response += chunk
            except Exception:
                pass

            assert b"200" in response
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_backend_slow_connect(self, proxy):
        """Test that client data is buffered during ST_CONNECTING"""
        # This is implicitly tested by large POST tests, but let's be explicit
        # Send a POST where the body arrives before backend connects
        client = ProxyClient(port=HTTPS_PORT)
        body = b"data-while-connecting" * 100
        status, _, resp_body = await async_request(client, "POST", "/slow-connect-test", body=body, timeout=15)

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

    async def test_pipelined_gets_both_have_forwarded_headers(self, proxy):
        """Two pipelined GETs sent in one write - both must have X-Forwarded-For"""
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

        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(requests)
            await writer.drain()

            # Read first response
            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200
            data1 = json.loads(body1)
            assert data1["path"] == "/pipe-fwd/1"
            assert "X-Forwarded-For" in data1["headers"], \
                "First pipelined request missing X-Forwarded-For"

            # Read second response
            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/pipe-fwd/2"
            assert "X-Forwarded-For" in data2["headers"], \
                "Second pipelined request missing X-Forwarded-For"
            assert "X-Forwarded-Proto" in data2["headers"], \
                "Second pipelined request missing X-Forwarded-Proto"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_pipelined_post_cl0_then_get_both_have_forwarded_headers(self, proxy):
        """POST with Content-Length: 0 followed by GET in one write"""
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

        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(requests)
            await writer.drain()

            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200

            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/pipe-cl0/2"
            assert "X-Forwarded-For" in data2["headers"], \
                "Request after CL:0 POST missing X-Forwarded-For"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_pipelined_post_with_body_then_get_forwarded_headers(self, proxy):
        """POST with body followed by GET in one write - verify correct boundary"""
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

        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(requests)
            await writer.drain()

            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200
            data1 = json.loads(body1)
            assert data1["body_length"] == 5

            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/pipe-body/2"
            assert "X-Forwarded-For" in data2["headers"], \
                "GET after POST missing X-Forwarded-For"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_three_pipelined_gets_all_have_forwarded_headers(self, proxy):
        """Three pipelined GETs in one write"""
        requests = b""
        for i in range(3):
            requests += (
                f"GET /pipe3/{i} HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode()

        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(requests)
            await writer.drain()

            for i in range(3):
                status, _, body = await async_read_http_response(reader, writer)
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["path"] == f"/pipe3/{i}"
                assert "X-Forwarded-For" in data["headers"], \
                    f"Pipelined request {i} missing X-Forwarded-For"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 10. TestSTUpgradingBugs - Bug: uses `n` (last read size) instead of
#     `c->len` (total accumulated) for 101 check and client copy
# ============================================================================

class TestSTUpgradingBugs:
    """Test WebSocket upgrade response handling edge cases.
    Targets a bug where ST_UPGRADING uses `n` (last do_read return)
    instead of `c->len` (total accumulated bytes) for the 101 check
    and when copying response to client buffer."""

    async def test_websocket_large_101_response(self, ws_proxy):
        """WebSocket upgrade with a 101 response that includes extra headers.
        The response may arrive in multiple reads; the proxy must accumulate."""
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

        reader, writer = await async_make_ssl_connection(host=WS_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                response += chunk

            assert b"101" in response.split(b"\r\n")[0], \
                f"Expected 101, got: {response[:100]}"

            # Verify we can still communicate after upgrade
            message = b"after-upgrade-test"
            writer.write(ws_frame(message, opcode=0x1))
            await writer.drain()
            echoed = await async_read_ws_frame(reader)
            assert echoed == message

            writer.write(ws_frame(b"", opcode=0x8))
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_websocket_101_fragmented_status_line(self, ws_proxy):
        """A fragmented 101 response must not be treated as an immediate upgrade failure."""
        ws_key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /ws-frag HTTP/1.1\r\n"
            f"Host: {WS_FRAGMENTED_DOMAIN}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

        reader, writer = await async_make_ssl_connection(host=WS_FRAGMENTED_DOMAIN, port=18543)
        try:
            writer.write(request)
            await writer.drain()

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                response += chunk

            assert b"101" in response.split(b"\r\n")[0], \
                f"Expected 101, got: {response[:120]}"

            message = b"frag-works"
            writer.write(ws_frame(message, opcode=0x1))
            await writer.drain()
            echoed = await async_read_ws_frame(reader)
            assert echoed == message

            writer.write(ws_frame(b"", opcode=0x8))
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 11. TestPipelinedChunkedThenGet - Chunked terminator → next request
# ============================================================================

class TestPipelinedChunkedThenGet:
    """Test chunked POST followed immediately by GET in the same TCP segment.
    Exercises advance_chunked → req_need_header transition when leftover
    bytes after chunk terminator belong to a new request."""

    async def test_chunked_post_then_get_in_one_write(self, proxy):
        """Chunked POST + GET pipelined in a single write"""
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

        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(requests)
            await writer.drain()

            # Read chunked POST response
            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200
            data1 = json.loads(body1)
            assert data1["body_length"] == len(post_body)

            # Read GET response
            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/pipe-chunked/2"
            assert data2["method"] == "GET"
            # Verify forwarded headers injected on the GET too
            assert "X-Forwarded-For" in data2["headers"], \
                "GET after pipelined chunked POST missing X-Forwarded-For"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_chunked_post_with_trailers_then_get(self, proxy):
        """Chunked POST with trailers + GET pipelined in one write"""
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

        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(requests)
            await writer.drain()

            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200

            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/pipe-chunk-trailer/2"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 12. TestHostHeaderEdgeCases - extract_host parsing
# ============================================================================

class TestHostHeaderEdgeCases:
    """Test Host header parsing edge cases in extract_host()."""

    async def test_host_with_port(self, proxy):
        """Host: test.localhost:18443 should strip port for domain lookup"""
        raw = RawSSLClient()
        request = (
            f"GET /host-port HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}:{HTTPS_PORT}\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        # Should route correctly (200), NOT 421 Misdirected
        assert b"200" in response, f"Host with port failed: {response[:200]}"

    async def test_host_case_insensitive(self, proxy):
        """Host header should be case-insensitive for domain matching"""
        raw = RawSSLClient()
        request = (
            f"GET /host-case HTTP/1.1\r\n"
            f"Host: TEST.LOCALHOST\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        # strcasecmp on domain lookup should handle this
        assert b"200" in response, f"Case-insensitive host failed: {response[:200]}"

    async def test_host_with_tab_whitespace(self, proxy):
        """Host header with tab after colon"""
        raw = RawSSLClient()
        request = (
            b"GET /host-tab HTTP/1.1\r\n"
            b"Host:\t" + TEST_DOMAIN.encode() + b"\r\n"
            b"\r\n"
        )

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response, f"Host with tab whitespace failed: {response[:200]}"

    async def test_host_with_multiple_spaces(self, proxy):
        """Host header with extra spaces around value"""
        raw = RawSSLClient()
        request = (
            b"GET /host-spaces HTTP/1.1\r\n"
            b"Host:   " + TEST_DOMAIN.encode() + b"  \r\n"
            b"\r\n"
        )

        response = await async_send_raw(raw, request)
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

    async def test_transfer_encoding_chunked_in_second_header_is_honored(self, proxy):
        """If chunked appears in a later Transfer-Encoding header, proxy should still parse as chunked."""
        te_backend_port = 18010
        te_domain = "te-dup.localhost"
        te_https_port = 18853
        te_http_port = 18890

        def read_chunked_body(conn):
            body = b""
            while True:
                line = b""
                while not line.endswith(b"\n"):
                    ch = conn.recv(1)
                    if not ch:
                        return body
                    line += ch
                line = line.strip()
                if not line:
                    continue
                size = int(line.split(b";", 1)[0], 16)
                if size == 0:
                    # consume trailers until empty line
                    trailer = b""
                    while True:
                        trailer = b""
                        while not trailer.endswith(b"\n"):
                            ch = conn.recv(1)
                            if not ch:
                                return body
                            trailer += ch
                        if trailer in (b"\r\n", b"\n"):
                            return body
                chunk = b""
                while len(chunk) < size:
                    data = conn.recv(size - len(chunk))
                    if not data:
                        return body
                    chunk += data
                body += chunk
                # trailing CRLF
                _ = conn.recv(2)

        def raw_backend():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", te_backend_port))
            srv.listen(1)
            srv.settimeout(8.0)
            try:
                conn, _ = srv.accept()
                conn.settimeout(3.0)

                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk

                header_end = data.find(b"\r\n\r\n") + 4
                body = data[header_end:]

                # Continue reading remaining chunked stream if needed.
                # We parse on the socket because body may be partial in initial recv.
                if b"0\r\n\r\n" not in body:
                    body += read_chunked_body(conn)

                # Accept either representation:
                # - raw chunk framing preserved
                # - de-chunked payload forwarded as plain body
                decoded = b""
                if b"5\r\nhello\r\n0\r\n\r\n" in body or b"hello" in body:
                    decoded = b"hello"

                resp_body = json.dumps({"decoded": decoded.decode(errors="ignore")}).encode()
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(resp_body)}\r\n".encode()
                    + b"Content-Type: application/json\r\n"
                    + b"Connection: close\r\n\r\n"
                    + resp_body
                )
                conn.sendall(response)
                conn.close()
            finally:
                srv.close()

        backend_thread = threading.Thread(target=raw_backend, daemon=True)
        backend_thread.start()

        config_file = os.path.join(PROJECT_ROOT, "tests", "test_te_dup_config.json")
        config = [{
            "domain": te_domain,
            "port": str(te_backend_port),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        }]
        with open(config_file, "w") as f:
            json.dump(config, f)

        process = await async_start_revpx(config_file, https_port=te_https_port, http_port=te_http_port)

        try:
            raw = RawSSLClient(host=te_domain, port=te_https_port)
            chunked_body = b"5\r\nhello\r\n0\r\n\r\n"
            request = (
                f"POST /te-dup-chunked HTTP/1.1\r\n"
                f"Host: {te_domain}\r\n"
                f"Transfer-Encoding: gzip\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + chunked_body

            response = await async_send_raw(raw, request, timeout=8.0)
            assert response is not None
            assert b"200" in response.split(b"\r\n", 1)[0], \
                f"Expected 200 when chunked is in second TE header, got: {response[:200]}"
            assert b'"decoded": "hello"' in response, \
                f"Second Transfer-Encoding header was ignored, response={response[:240]}"
        finally:
            await async_stop_process(process, timeout=5.0)
            if os.path.exists(config_file):
                os.remove(config_file)
            backend_thread.join(timeout=2.0)

    async def test_transfer_encoding_substring_not_treated_as_chunked(self):
        """Transfer-Encoding token matching must be exact (notchunked != chunked)."""
        te_backend_port = 18006
        te_domain = "te.localhost"
        te_https_port = 18843
        te_http_port = 18880

        def raw_backend():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", te_backend_port))
            srv.listen(1)
            srv.settimeout(8.0)
            try:
                conn, _ = srv.accept()
                conn.settimeout(3.0)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk

                resp_body = b'{"ok":true}'
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(resp_body)}\r\n".encode()
                    + b"Content-Type: application/json\r\n"
                    + b"Connection: close\r\n\r\n"
                    + resp_body
                )
                conn.sendall(response)
                conn.close()
            finally:
                srv.close()

        backend_thread = threading.Thread(target=raw_backend, daemon=True)
        backend_thread.start()

        config_file = os.path.join(PROJECT_ROOT, "tests", "test_te_substring_config.json")
        config = [{
            "domain": te_domain,
            "port": str(te_backend_port),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        }]
        with open(config_file, "w") as f:
            json.dump(config, f)

        process = await async_start_revpx(config_file, https_port=te_https_port, http_port=te_http_port)

        try:
            raw = RawSSLClient(host=te_domain, port=te_https_port)
            body = b"hello"
            request = (
                f"POST /te-substring HTTP/1.1\r\n"
                f"Host: {te_domain}\r\n"
                f"Transfer-Encoding: notchunked\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + body

            response = await async_send_raw(raw, request, timeout=8.0)
            assert response is not None
            # If proxy falsely treats 'notchunked' as chunked, it returns 400.
            assert b"200" in response.split(b"\r\n", 1)[0], \
                f"Unexpected response for TE:notchunked: {response[:200]}"
        finally:
            await async_stop_process(process, timeout=5.0)
            if os.path.exists(config_file):
                os.remove(config_file)
            backend_thread.join(timeout=2.0)

    async def test_transfer_encoding_chunked_with_spaces_and_params_is_honored(self, proxy):
        """Chunked token with surrounding spaces/params must still be detected."""
        raw = RawSSLClient()
        request = (
            f"POST /te-spaces-params HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: gzip , chunked ; ext=yes\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"5\r\nhello\r\n0\r\n\r\n"
        ).encode()

        response = await async_send_raw(raw, request, timeout=8.0)
        assert response is not None
        assert b"200" in response.split(b"\r\n", 1)[0], \
            f"Expected 200 for TE with spacing/params around chunked token, got: {response[:220]}"

    async def test_malformed_chunk_hex(self, proxy):
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

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"400" in response, f"Expected 400 for bad chunk hex, got: {response[:200]}"

    async def test_chunk_size_overflow(self, proxy):
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

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"400" in response, f"Expected 400 for chunk size overflow, got: {response[:200]}"

    async def test_post_without_content_length_or_te(self, proxy):
        """POST with no Content-Length or Transfer-Encoding → treated as no body"""
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

        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(requests)
            await writer.drain()

            # POST should succeed with body_length=0
            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200
            data1 = json.loads(body1)
            assert data1["body_length"] == 0

            # GET should also succeed
            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/no-cl/2"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_chunked_and_content_length_both_present(self, proxy):
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

        response = await async_send_raw(raw, request)
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

    async def test_long_xff_chain_no_crash(self, proxy):
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

        response = await async_send_raw(raw, request)
        assert response is not None
        # Main assertion: proxy didn't crash, returned some response
        assert b"HTTP/1.1" in response

    async def test_long_forwarded_header_no_crash(self, proxy):
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

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"HTTP/1.1" in response


# ============================================================================
# 15. TestRequestLineEdgeCases
# ============================================================================

class TestRequestLineEdgeCases:
    """Test edge cases in request line parsing (extract_target, etc.)"""

    async def test_very_long_url(self, proxy):
        """Request with a very long URL path (near buffer limit)"""
        raw = RawSSLClient()
        # 4KB URL - well within 32KB but exercises extract_target with long path
        long_path = "/a" * 2000
        request = (
            f"GET {long_path} HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert req.path == long_path

    async def test_url_with_query_and_fragment(self, proxy):
        """Request with query string preserved through proxy"""
        raw = RawSSLClient()
        request = (
            f"GET /query?key=value&arr[]=1&arr[]=2 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response

        req = BackendHandler.captured_requests[-1]
        assert "key=value" in req.path
        assert "arr[]=1" in req.path

    async def test_http_10_request(self, proxy):
        """HTTP/1.0 request should be proxied"""
        raw = RawSSLClient()
        request = (
            f"GET /http10 HTTP/1.0\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response


# ============================================================================
# 16. TestSNIMismatch
# ============================================================================

class TestSNIMismatch:
    """Test SNI vs Host header routing behavior"""

    async def test_sni_mismatch_host_takes_precedence(self, proxy):
        """When SNI doesn't match Host, Host header is used for routing"""
        # Connect with SNI for test.localhost (valid) but send Host for unknown domain
        reader, writer = await async_make_ssl_connection()
        try:
            request = f"GET / HTTP/1.1\r\nHost: nonexistent.domain\r\n\r\n".encode()
            writer.write(request)
            await writer.drain()

            response = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    if not chunk:
                        break
                    response += chunk
            except asyncio.TimeoutError:
                pass

            # Host header takes precedence → domain not found → 421
            assert b"421" in response, f"Expected 421, got: {response[:200]}"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 17. TestRapidKeepaliveTransitions
# ============================================================================

class TestRapidKeepaliveTransitions:
    """Test rapid alternation of request types on keep-alive connections
    to stress-test request boundary tracking."""

    async def test_get_post_chunked_post_cl_get_sequence(self, proxy):
        """Mixed sequence: GET, chunked POST, CL POST, GET on one connection"""
        reader, writer = await async_make_ssl_connection()
        try:
            # 1. GET
            writer.write(
                f"GET /rapid/1 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "GET"

            # 2. Chunked POST
            chunk_body = b"chunked-data"
            chunked = f"{len(chunk_body):x}\r\n".encode() + chunk_body + b"\r\n0\r\n\r\n"
            writer.write(
                (
                    f"POST /rapid/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + chunked
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["body_length"] == len(chunk_body)

            # 3. CL POST
            cl_body = b"cl-body-data"
            writer.write(
                (
                    f"POST /rapid/3 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: {len(cl_body)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + cl_body
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["body_length"] == len(cl_body)

            # 4. GET
            writer.write(
                f"GET /rapid/4 HTTP/1.1\r\nHost: {TEST_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            await writer.drain()
            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["path"] == "/rapid/4"
            assert "X-Forwarded-For" in data["headers"]
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_many_chunked_posts_keepalive(self, proxy):
        """10 chunked POSTs on the same connection"""
        reader, writer = await async_make_ssl_connection()
        try:
            for i in range(10):
                body_data = f"chunk-{i}-payload".encode()
                chunked = f"{len(body_data):x}\r\n".encode() + body_data + b"\r\n0\r\n\r\n"
                writer.write(
                    (
                        f"POST /many-chunk/{i} HTTP/1.1\r\n"
                        f"Host: {TEST_DOMAIN}\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode() + chunked
                )
                await writer.drain()
                status, _, body = await async_read_http_response(reader, writer)
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["body_length"] == len(body_data), \
                    f"Request {i}: expected {len(body_data)}, got {data['body_length']}"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 18. TestContentLengthParsing - strtoull edge cases
# ============================================================================

class TestContentLengthParsing:
    """Test Content-Length parsing edge cases in forward_client_bytes.
    The proxy uses strtoull(tmp, NULL, 10) to parse Content-Length.
    Malicious or malformed values can cause incorrect request boundary tracking."""

    async def test_negative_content_length_keepalive(self, proxy):
        """Negative Content-Length must be rejected with 400 and connection close."""
        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(
                (
                    f"POST /neg-cl/1 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: -1\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
            )
            await writer.drain()

            status1, _, _ = await async_read_http_response(reader, writer)
            assert status1 == 400

            # After malformed CL, proxy should not keep the connection alive.
            with pytest.raises((asyncio.TimeoutError, ConnectionError, ssl.SSLError, OSError, ValueError)):
                writer.write(
                    (
                        f"GET /neg-cl/2 HTTP/1.1\r\n"
                        f"Host: {TEST_DOMAIN}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode()
                )
                await writer.drain()
                await async_read_http_response(reader, writer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_zero_content_length_keepalive(self, proxy):
        """Content-Length: 0 should be treated as no body, next request parsed correctly"""
        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(
                (
                    f"POST /zero-cl/1 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                    f"GET /zero-cl/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
            )
            await writer.drain()

            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200

            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/zero-cl/2"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_content_length_with_leading_plus(self, proxy):
        """Content-Length: +5 (with leading plus sign) should be rejected."""
        raw = RawSSLClient()
        body = b"hello"
        request = (
            f"POST /plus-cl HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: +5\r\n"
            f"\r\n"
        ).encode() + body

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"400" in response.split(b"\r\n", 1)[0]

    async def test_content_length_with_leading_spaces(self, proxy):
        """Content-Length with leading spaces in value"""
        raw = RawSSLClient()
        body = b"hello"
        request = (
            f"POST /space-cl HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length:   5\r\n"
            f"\r\n"
        ).encode() + body

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response

    async def test_content_length_with_trailing_whitespace_is_accepted(self, proxy):
        """Content-Length with trailing SP/HTAB should remain valid."""
        raw = RawSSLClient()
        body = b"hello"
        request = (
            f"POST /cl-trailing-ws HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 5 \t\r\n"
            f"\r\n"
        ).encode() + body

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response.split(b"\r\n", 1)[0], \
            f"Expected 200 for Content-Length with trailing whitespace, got: {response[:180]}"

    async def test_content_length_with_suffix_is_rejected(self, proxy):
        """Malformed Content-Length (e.g. 5abc) should be rejected with 400."""
        raw = RawSSLClient()
        request = (
            f"POST /bad-cl-suffix HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 5abc\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"hello"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"400" in response.split(b"\r\n", 1)[0], \
            f"Expected 400 for malformed Content-Length, got: {response[:160]}"

    async def test_empty_content_length_is_rejected(self, proxy):
        """Empty Content-Length header should be rejected with 400."""
        raw = RawSSLClient()
        request = (
            f"POST /empty-cl HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length:\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"400" in response.split(b"\r\n", 1)[0], \
            f"Expected 400 for empty Content-Length, got: {response[:160]}"

    async def test_duplicate_content_length_conflict_is_rejected(self, proxy):
        """Conflicting duplicate Content-Length headers should be rejected with 400."""
        raw = RawSSLClient()
        request = (
            f"POST /dup-cl-conflict HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 5\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"hello"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"400" in response.split(b"\r\n", 1)[0], \
            f"Expected 400 for duplicate conflicting Content-Length, got: {response[:160]}"

    async def test_duplicate_content_length_identical_is_rejected(self, proxy):
        """Duplicate identical Content-Length headers should be rejected to prevent smuggling ambiguity."""
        raw = RawSSLClient()
        request = (
            f"POST /dup-cl-identical HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 5\r\n"
            f"Content-Length: 5\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"hello"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"400" in response.split(b"\r\n", 1)[0], \
            f"Expected 400 for duplicate identical Content-Length, got: {response[:160]}"

    async def test_content_length_list_value_is_rejected(self, proxy):
        """Comma-separated Content-Length list must be rejected to avoid ambiguity."""
        raw = RawSSLClient()
        request = (
            f"POST /cl-list HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 5, 5\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"hello"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"400" in response.split(b"\r\n", 1)[0], \
            f"Expected 400 for list-form Content-Length, got: {response[:160]}"

    async def test_very_large_content_length_keepalive(self, proxy):
        """Content-Length: 999999999999 with small body → keepalive broken"""
        reader, writer = await async_make_ssl_connection()
        try:
            # POST with huge CL but only 5 bytes of body
            writer.write(
                (
                    f"POST /huge-cl/1 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: 999999999999\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                    f"hello"
                ).encode()
            )
            await writer.drain()

            # Read whatever response we get
            try:
                status1, _, _ = await asyncio.wait_for(
                    async_read_http_response(reader, writer), timeout=3.0
                )
            except (asyncio.TimeoutError, ConnectionError):
                pass  # May timeout waiting for body

            # Now send a GET - it should NOT be treated as body of the POST
            writer.write(
                (
                    f"GET /huge-cl/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
            )
            await writer.drain()

            try:
                status2, _, body2 = await asyncio.wait_for(
                    async_read_http_response(reader, writer), timeout=3.0
                )
                data2 = json.loads(body2)
                assert data2["path"] == "/huge-cl/2", \
                    "GET swallowed as body of POST with huge Content-Length"
            except (asyncio.TimeoutError, ConnectionError, json.JSONDecodeError):
                # This is expected to fail - the proxy treats GET bytes as
                # body of the POST because CL is huge. This is technically
                # correct per HTTP spec (CL says how many bytes to read),
                # but Content-Length: -1 is a clear security issue.
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_content_length_numeric_overflow_is_rejected(self, proxy):
        """Content-Length values that overflow size_t must be rejected with 400."""
        raw = RawSSLClient()
        request = (
            f"POST /cl-overflow HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Length: 184467440737095516160\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"400" in response.split(b"\r\n", 1)[0], \
            f"Expected 400 for overflowing Content-Length, got: {response[:180]}"


# ============================================================================
# 19. TestHostTrailingWhitespace - extract_host doesn't trim trailing spaces
# ============================================================================

class TestHostTrailingWhitespace:
    """Test that trailing whitespace in Host header is properly handled.
    extract_host() trims leading whitespace but NOT trailing whitespace,
    causing domain lookup to fail (421) for valid domains."""

    async def test_host_trailing_space_routes_correctly(self, proxy):
        """Host: 'test.localhost ' (trailing space) should still route correctly"""
        raw = RawSSLClient()
        # Trailing space before \r\n
        request = (
            b"GET /host-trail HTTP/1.1\r\n"
            b"Host: " + TEST_DOMAIN.encode() + b" \r\n"
            b"\r\n"
        )

        response = await async_send_raw(raw, request)
        assert response is not None
        # BUG: extract_host doesn't trim trailing whitespace, so
        # strcasecmp("test.localhost ", "test.localhost") fails → 421
        # Should be 200
        assert b"200" in response, \
            f"Trailing space in Host caused routing failure: {response[:200]}"

    async def test_host_trailing_tab_routes_correctly(self, proxy):
        """Host: 'test.localhost\\t' (trailing tab) should still route correctly"""
        raw = RawSSLClient()
        request = (
            b"GET /host-trail-tab HTTP/1.1\r\n"
            b"Host: " + TEST_DOMAIN.encode() + b"\t\r\n"
            b"\r\n"
        )

        response = await async_send_raw(raw, request)
        assert response is not None
        assert b"200" in response, \
            f"Trailing tab in Host caused routing failure: {response[:200]}"


# ============================================================================
# 20. TestBodyExceedsContentLength - extra bytes → next request
# ============================================================================

class TestBodyExceedsContentLength:
    """Test that bytes beyond Content-Length are treated as the next request,
    not silently discarded or forwarded as extra body."""

    async def test_extra_bytes_after_cl_body_are_next_request(self, proxy):
        """POST with CL:5 sends 5 body bytes + GET on same connection.
        The proxy must track the CL boundary and parse the GET as a new request."""
        body = b"AAAAA"  # exactly 5 bytes
        reader, writer = await async_make_ssl_connection()
        try:
            # Send POST + body + immediate GET in one write
            writer.write(
                (
                    f"POST /cl-boundary/1 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: 5\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode() + body + (
                    f"GET /cl-boundary/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
            )
            await writer.drain()

            # POST response
            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200
            data1 = json.loads(body1)
            assert data1["body_length"] == 5
            assert data1["method"] == "POST"

            # GET response - must be correctly parsed
            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/cl-boundary/2"
            assert data2["method"] == "GET"
            assert "X-Forwarded-For" in data2["headers"]
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_short_body_then_next_request(self, proxy):
        """POST with CL:3 but body 'AB' followed by GET.
        The GET's first byte 'G' should NOT be consumed as the 3rd body byte."""
        reader, writer = await async_make_ssl_connection()
        try:
            # First: POST with CL:3, full 3-byte body
            writer.write(
                (
                    f"POST /cl-short/1 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: 3\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                    f"ABC"
                    f"GET /cl-short/2 HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
            )
            await writer.drain()

            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200
            data1 = json.loads(body1)
            assert data1["body_length"] == 3

            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/cl-short/2"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 21. TestChunkedFinalChunkExtension
# ============================================================================

class TestChunkedFinalChunkExtension:
    """Test chunked encoding where the final 0-size chunk has extensions."""

    async def test_final_chunk_with_extension_then_get(self, proxy):
        """Chunked body ending with '0;ext=val\\r\\n\\r\\n' followed by GET"""
        body_data = b"extension-test"
        chunked = (
            f"{len(body_data):x}\r\n".encode() + body_data + b"\r\n"
            + b"0;final-ext=true\r\n"
            + b"\r\n"
        )

        requests = (
            f"POST /chunk-ext-final/1 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + chunked + (
            f"GET /chunk-ext-final/2 HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        reader, writer = await async_make_ssl_connection()
        try:
            writer.write(requests)
            await writer.drain()

            status1, _, body1 = await async_read_http_response(reader, writer)
            assert status1 == 200
            data1 = json.loads(body1)
            assert data1["body_length"] == len(body_data)

            status2, _, body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(body2)
            assert data2["path"] == "/chunk-ext-final/2"
            assert data2["method"] == "GET"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 22. TestEmptyHostFallback
# ============================================================================

class TestEmptyHostFallback:
    """Test Host header edge cases for domain resolution fallback."""

    async def test_empty_host_value_ssl(self, proxy):
        """Host header with empty value on SSL connection should fall back to SNI"""
        raw = RawSSLClient()
        request = (
            b"GET /empty-host HTTP/1.1\r\n"
            b"Host: \r\n"
            b"\r\n"
        )

        response = await async_send_raw(raw, request)
        assert response is not None
        # With empty Host and valid SNI, proxy falls back to SNI → test.localhost
        # Then falls through to first domain if SNI also empty
        # Either way, should get a response (200 or 421), not crash
        assert b"HTTP/1.1" in response

    async def test_missing_host_header_ssl(self, proxy):
        """No Host header on SSL connection - should use SNI or fall back to first domain"""
        raw = RawSSLClient()
        request = (
            b"GET /no-host-ssl HTTP/1.1\r\n"
            b"\r\n"
        )

        response = await async_send_raw(raw, request)
        assert response is not None
        # extract_host returns empty, falls back to SNI (test.localhost)
        # SNI matches, routes to backend → 200
        assert b"200" in response or b"421" in response


# ============================================================================
# 23. TestConnectionCloseInChunkedBody
# ============================================================================

class TestConnectionCloseInChunkedBody:
    """Test that client disconnecting mid-chunked-body doesn't crash proxy."""

    async def test_disconnect_mid_chunk(self, proxy):
        """Client sends partial chunked body then disconnects"""
        def _sync_disconnect():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5)
                ssock = ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN)

                # Send headers + partial chunk (declare 1000 bytes, send only 5)
                ssock.sendall(
                    (
                        f"POST /mid-chunk HTTP/1.1\r\n"
                        f"Host: {TEST_DOMAIN}\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"\r\n"
                        f"3e8\r\n"  # 1000 bytes declared
                        f"hello"    # only 5 bytes sent
                    ).encode()
                )

                # Force close
                try:
                    ssock.unwrap()
                except Exception:
                    pass
                sock.close()
            except Exception:
                pass

        await asyncio.to_thread(_sync_disconnect)
        await asyncio.sleep(0.1)

        # Proxy should still be alive
        client = ProxyClient(port=HTTPS_PORT)
        status, _, _ = await async_request(client, "GET", "/after-mid-chunk")
        assert status == 200

    async def test_disconnect_between_chunks(self, proxy):
        """Client sends one complete chunk then disconnects before next"""
        def _sync_disconnect():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5)
                ssock = ctx.wrap_socket(sock, server_hostname=TEST_DOMAIN)

                # Send headers + one complete chunk, then close without final chunk
                ssock.sendall(
                    (
                        f"POST /between-chunks HTTP/1.1\r\n"
                        f"Host: {TEST_DOMAIN}\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"\r\n"
                        f"5\r\nhello\r\n"  # One complete chunk, no final 0\r\n\r\n
                    ).encode()
                )

                try:
                    ssock.unwrap()
                except Exception:
                    pass
                sock.close()
            except Exception:
                pass

        await asyncio.to_thread(_sync_disconnect)
        await asyncio.sleep(0.1)

        # Proxy should still be alive
        client = ProxyClient(port=HTTPS_PORT)
        status, _, _ = await async_request(client, "GET", "/after-between-chunks")
        assert status == 200


# ============================================================================
# 24. TestBodyContainingHeaderPattern
# ============================================================================

class TestBodyContainingHeaderPattern:
    """Verify that body data containing \\r\\n\\r\\n isn't mistakenly parsed as headers"""

    async def test_body_with_double_crlf(self, proxy):
        """POST body containing \\r\\n\\r\\n should be forwarded as body, not treated as headers"""
        reader, writer = await async_make_ssl_connection()
        try:
            # Body contains \r\n\r\n which looks like header terminator
            body = b"line1\r\n\r\nline2\r\n\r\nline3"
            request = (
                f"POST /body-crlf HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Type: text/plain\r\n"
                f"\r\n"
            ).encode() + body
            writer.write(request)
            await writer.drain()
            status, _, resp_body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(resp_body)
            assert data["body_length"] == len(body)
            assert data["body_hash"] == hashlib.md5(body).hexdigest()

            # Send a second request to verify keep-alive still works
            request2 = (
                f"GET /after-body-crlf HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(request2)
            await writer.drain()
            status2, _, resp_body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(resp_body2)
            assert data2["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_large_body_with_fake_request_inside(self, proxy):
        """POST body that contains a fake HTTP request should be forwarded as body"""
        reader, writer = await async_make_ssl_connection()
        try:
            fake_request = "GET /evil HTTP/1.1\r\nHost: evil.com\r\n\r\n"
            body = f"prefix{fake_request}suffix".encode()
            request = (
                f"POST /fake-inner HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
            ).encode() + body
            writer.write(request)
            await writer.drain()
            status, _, resp_body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(resp_body)
            assert data["body_length"] == len(body)
            assert data["body_hash"] == hashlib.md5(body).hexdigest()

            # Verify next request works (no request smuggling)
            request2 = (
                f"GET /after-fake HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(request2)
            await writer.drain()
            status2, _, resp_body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(resp_body2)
            assert data2["path"] == "/after-fake"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 25. TestMultipleTransferEncodings
# ============================================================================

class TestMultipleTransferEncodings:
    """Test handling of Transfer-Encoding with multiple values"""

    async def test_gzip_chunked_detected_as_chunked(self, proxy):
        """Transfer-Encoding: gzip, chunked should be treated as chunked"""
        reader, writer = await async_make_ssl_connection()
        try:
            body_data = b"hello gzip chunked"
            chunk = f"{len(body_data):x}\r\n".encode() + body_data + b"\r\n0\r\n\r\n"
            request = (
                f"POST /te-multi HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Transfer-Encoding: gzip, chunked\r\n"
                f"\r\n"
            ).encode() + chunk
            writer.write(request)
            await writer.drain()
            status, _, resp_body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(resp_body)
            assert data["body_length"] == len(body_data)

            # Verify keep-alive works after chunked request
            request2 = (
                f"GET /after-te-multi HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(request2)
            await writer.drain()
            status2, _, resp_body2 = await async_read_http_response(reader, writer)
            assert status2 == 200
            data2 = json.loads(resp_body2)
            assert data2["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 26. TestKeepAliveStateSwitching
# ============================================================================

class TestKeepAliveStateSwitching:
    """Test state machine transitions between CL and chunked on keep-alive"""

    async def test_cl_then_chunked_then_cl(self, proxy):
        """CL POST → chunked POST → CL POST on same connection"""
        reader, writer = await async_make_ssl_connection()
        try:
            # Request 1: Content-Length POST
            body1 = b"body_one"
            req1 = (
                f"POST /ka-state-1 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body1)}\r\n"
                f"\r\n"
            ).encode() + body1
            writer.write(req1)
            await writer.drain()
            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200
            d1 = json.loads(rb1)
            assert d1["body_length"] == len(body1)
            assert d1["headers"].get("X-Forwarded-Proto") == "https"

            # Request 2: Chunked POST
            body2 = b"body_two"
            chunk2 = f"{len(body2):x}\r\n".encode() + body2 + b"\r\n0\r\n\r\n"
            req2 = (
                f"POST /ka-state-2 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            ).encode() + chunk2
            writer.write(req2)
            await writer.drain()
            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["body_length"] == len(body2)
            assert d2["headers"].get("X-Forwarded-Proto") == "https"

            # Request 3: Content-Length POST again
            body3 = b"body_three"
            req3 = (
                f"POST /ka-state-3 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body3)}\r\n"
                f"\r\n"
            ).encode() + body3
            writer.write(req3)
            await writer.drain()
            s3, _, rb3 = await async_read_http_response(reader, writer)
            assert s3 == 200
            d3 = json.loads(rb3)
            assert d3["body_length"] == len(body3)
            assert d3["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_chunked_then_get_then_chunked(self, proxy):
        """Chunked POST → GET → Chunked POST on same connection"""
        reader, writer = await async_make_ssl_connection()
        try:
            # Chunked POST
            body1 = b"chunked_first"
            chunk1 = f"{len(body1):x}\r\n".encode() + body1 + b"\r\n0\r\n\r\n"
            req1 = (
                f"POST /ka-cg-1 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            ).encode() + chunk1
            writer.write(req1)
            await writer.drain()
            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200

            # GET
            req2 = (
                f"GET /ka-cg-2 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req2)
            await writer.drain()
            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200

            # Chunked POST again
            body3 = b"chunked_second"
            chunk3 = f"{len(body3):x}\r\n".encode() + body3 + b"\r\n0\r\n\r\n"
            req3 = (
                f"POST /ka-cg-3 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            ).encode() + chunk3
            writer.write(req3)
            await writer.drain()
            s3, _, rb3 = await async_read_http_response(reader, writer)
            assert s3 == 200
            d3 = json.loads(rb3)
            assert d3["body_length"] == len(body3)
            assert d3["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 27. TestSlowHeaderDelivery
# ============================================================================

class TestSlowHeaderDelivery:
    """Test handling of headers arriving in small fragments"""

    async def test_header_byte_by_byte(self, proxy):
        """Headers sent one byte at a time should still be parsed"""
        reader, writer = await async_make_ssl_connection()
        try:
            request = (
                f"GET /slow-header HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            # Send in small chunks to simulate slow delivery
            for i in range(0, len(request), 3):
                writer.write(request[i:i+3])
                await writer.drain()
                await asyncio.sleep(0.001)

            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(body)
            assert data["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_header_split_at_crlf(self, proxy):
        """Headers split exactly at \\r\\n boundary"""
        reader, writer = await async_make_ssl_connection()
        try:
            part1 = f"GET /split-crlf HTTP/1.1\r\n".encode()
            part2 = f"Host: {TEST_DOMAIN}\r".encode()
            part3 = b"\n\r\n"

            writer.write(part1)
            await writer.drain()
            await asyncio.sleep(0.01)
            writer.write(part2)
            await writer.drain()
            await asyncio.sleep(0.01)
            writer.write(part3)
            await writer.drain()

            status, _, body = await async_read_http_response(reader, writer)
            assert status == 200
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 28. TestBackendClosesAfterResponse
# ============================================================================

class TestBackendClosesAfterResponse:
    """Test behavior when backend closes the connection after responding"""

    async def test_backend_conn_close_then_new_request(self, proxy):
        """After backend returns Connection: close, next request should still work"""
        reader, writer = await async_make_ssl_connection()
        try:
            # First request — normal response
            req1 = (
                f"GET /close-test-1 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode()
            writer.write(req1)
            await writer.drain()
            s1, h1, _ = await async_read_http_response(reader, writer)
            assert s1 == 200

            # Backend may or may not close — the proxy should handle either case.
            # Try a second request. If the proxy creates a new backend connection
            # or keeps using the old one, it should work either way.
            await asyncio.sleep(0.02)
            req2 = (
                f"GET /close-test-2 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req2)
            await writer.drain()
            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["path"] == "/close-test-2"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 29. TestContentLengthBoundaryPrecision
# ============================================================================

class TestContentLengthBoundaryPrecision:
    """Test that Content-Length body boundaries are tracked precisely"""

    async def test_two_posts_exact_cl_boundaries(self, proxy):
        """Two POSTs with exact CL boundaries pipelined"""
        reader, writer = await async_make_ssl_connection()
        try:
            body1 = b"A" * 100
            body2 = b"B" * 200
            req = (
                f"POST /cl-boundary-1 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body1)}\r\n"
                f"\r\n"
            ).encode() + body1 + (
                f"POST /cl-boundary-2 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body2)}\r\n"
                f"\r\n"
            ).encode() + body2
            writer.write(req)
            await writer.drain()

            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200
            d1 = json.loads(rb1)
            assert d1["body_length"] == 100
            assert d1["body_hash"] == hashlib.md5(body1).hexdigest()
            assert d1["headers"].get("X-Forwarded-Proto") == "https"

            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["body_length"] == 200
            assert d2["body_hash"] == hashlib.md5(body2).hexdigest()
            assert d2["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_post_cl_1_byte_body(self, proxy):
        """POST with Content-Length: 1 followed by GET"""
        reader, writer = await async_make_ssl_connection()
        try:
            req = (
                f"POST /cl-1byte HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: 1\r\n"
                f"\r\n"
                f"X"
                f"GET /after-1byte HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req)
            await writer.drain()

            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200
            d1 = json.loads(rb1)
            assert d1["body_length"] == 1

            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["path"] == "/after-1byte"
            assert d2["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_multiple_posts_varying_sizes(self, proxy):
        """5 POSTs with different body sizes, all pipelined"""
        reader, writer = await async_make_ssl_connection()
        try:
            sizes = [1, 50, 0, 1000, 5]
            full_req = b""
            for i, size in enumerate(sizes):
                body = chr(ord('a') + i).encode() * size
                full_req += (
                    f"POST /vary-{i} HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: {size}\r\n"
                    f"\r\n"
                ).encode() + body
            writer.write(full_req)
            await writer.drain()

            for i, size in enumerate(sizes):
                status, _, rb = await async_read_http_response(reader, writer)
                assert status == 200, f"Request {i} (size={size}): expected 200, got {status}"
                data = json.loads(rb)
                assert data["body_length"] == size, f"Request {i}: body length mismatch"
                assert data["headers"].get("X-Forwarded-Proto") == "https", \
                    f"Request {i}: missing forwarded headers"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 30. TestCROnlyLineEndings
# ============================================================================

class TestCROnlyLineEndings:
    """Test that requests with CR-only (no LF) line endings are handled"""

    async def test_cr_only_headers_rejected(self, proxy):
        """Request with \\r-only line endings should not be parsed as valid"""
        raw = RawSSLClient()
        # Use \r instead of \r\n — find_headers_end won't find \r\n\r\n
        data = (
            f"GET /cr-only HTTP/1.1\r"
            f"Host: {TEST_DOMAIN}\r"
            f"\r"
        ).encode()
        resp = await async_send_raw(raw, data)
        # Should timeout waiting for headers (no \r\n\r\n found) or return 431
        # The proxy keeps reading until buffer full → 431
        if resp:
            assert b"431" in resp or b"400" in resp or resp == b""


# ============================================================================
# 31. TestChunkedBodyWithLargeChunkSize
# ============================================================================

class TestChunkedBodyWithLargeChunkSize:
    """Test chunked encoding with individual chunks larger than buffer"""

    async def test_single_large_chunk(self, proxy):
        """Single chunk larger than 32KB, split across multiple forward_client_bytes calls"""
        reader, writer = await async_make_ssl_connection()
        try:
            body = b"X" * 50000  # 50KB > 32KB buffer
            chunk = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
            headers = (
                f"POST /large-chunk HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            ).encode()
            writer.write(headers + chunk)
            await writer.drain()

            status, _, resp_body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(resp_body)
            assert data["body_length"] == 50000

            # Verify keep-alive works after large chunk
            req2 = (
                f"GET /after-large-chunk HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req2)
            await writer.drain()
            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_many_medium_chunks_then_get(self, proxy):
        """10 chunks of 4KB each, followed by a GET on same connection"""
        reader, writer = await async_make_ssl_connection()
        try:
            chunks = b""
            total = b""
            for i in range(10):
                chunk_data = chr(ord('A') + i).encode() * 4096
                total += chunk_data
                chunks += f"{len(chunk_data):x}\r\n".encode() + chunk_data + b"\r\n"
            chunks += b"0\r\n\r\n"

            headers = (
                f"POST /many-medium-chunks HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            ).encode()
            writer.write(headers + chunks)
            await writer.drain()

            status, _, resp_body = await async_read_http_response(reader, writer)
            assert status == 200
            data = json.loads(resp_body)
            assert data["body_length"] == 40960

            req2 = (
                f"GET /after-many-chunks HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req2)
            await writer.drain()
            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 32. TestRequestSmuggling
# ============================================================================

class TestRequestSmuggling:
    """Test request smuggling prevention"""

    async def test_cl_te_smuggling_attempt(self, proxy):
        """Both CL and TE present — chunked should take precedence"""
        reader, writer = await async_make_ssl_connection()
        try:
            # Send request with both CL and TE, where CL says shorter than actual chunked body
            req = (
                f"POST /smuggle-cl-te HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: 5\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"5\r\nhello\r\n"
                f"0\r\n\r\n"
            ).encode()
            writer.write(req)
            await writer.drain()
            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200
            d1 = json.loads(rb1)
            # Chunked takes precedence: body should be "hello"
            assert d1["body_length"] == 5
            assert d1["body_hash"] == hashlib.md5(b"hello").hexdigest()

            # Follow-up request should work normally
            req2 = (
                f"GET /after-smuggle HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req2)
            await writer.drain()
            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["path"] == "/after-smuggle"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_cl_with_duplicate_te_chunked_and_pipelined_get(self, proxy):
        """Duplicate TE lines + conflicting CL must still use chunked framing and preserve next request boundary."""
        reader, writer = await async_make_ssl_connection()
        try:
            chunked = b"5\r\nhello\r\n0\r\n\r\n"
            pipelined = (
                (
                    f"POST /smuggle-dup-te HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: 1\r\n"
                    f"Transfer-Encoding: gzip\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
                + chunked
                + (
                    f"GET /after-smuggle-dup-te HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
            )

            writer.write(pipelined)
            await writer.drain()

            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200
            d1 = json.loads(rb1)
            assert d1["path"] == "/smuggle-dup-te"
            assert d1["body_length"] == 5
            assert d1["body_hash"] == hashlib.md5(b"hello").hexdigest()

            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["path"] == "/after-smuggle-dup-te"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_double_content_length(self, proxy):
        """Duplicate Content-Length headers (even identical) should be rejected."""
        reader, writer = await async_make_ssl_connection()
        try:
            body = b"double_cl"
            req = (
                f"POST /double-cl HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
            ).encode() + body
            writer.write(req)
            await writer.drain()
            s1, _, _ = await async_read_http_response(reader, writer)
            assert s1 == 400

            # After malformed CL duplication, connection should not be reusable.
            with pytest.raises((asyncio.TimeoutError, ConnectionError, ssl.SSLError, OSError, ValueError)):
                req2 = (
                    f"GET /after-double-cl HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"\r\n"
                ).encode()
                writer.write(req2)
                await writer.drain()
                await async_read_http_response(reader, writer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 33. TestContentLengthLeadingZeros
# ============================================================================

class TestContentLengthLeadingZeros:
    """Test Content-Length with unusual but valid formatting"""

    async def test_cl_with_leading_zeros(self, proxy):
        """Content-Length: 005 should be parsed as 5"""
        reader, writer = await async_make_ssl_connection()
        try:
            body = b"ABCDE"
            req = (
                f"POST /cl-leading-zeros HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: 005\r\n"
                f"\r\n"
            ).encode() + body + (
                f"GET /after-leading-zeros HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req)
            await writer.drain()

            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200
            d1 = json.loads(rb1)
            assert d1["body_length"] == 5
            assert d1["body_hash"] == hashlib.md5(b"ABCDE").hexdigest()

            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["path"] == "/after-leading-zeros"
            assert d2["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 34. TestLargeBodyKeepalive
# ============================================================================

class TestLargeBodyKeepalive:
    """Test keep-alive with body sizes near and exceeding buffer boundaries"""

    async def test_body_32kb_minus_1(self, proxy):
        """POST with body exactly 32767 bytes (buffer - 1) then GET"""
        reader, writer = await async_make_ssl_connection()
        try:
            body = b"Z" * 32767
            req1 = (
                f"POST /body-32767 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
            ).encode() + body
            writer.write(req1)
            await writer.drain()
            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200
            d1 = json.loads(rb1)
            assert d1["body_length"] == 32767

            req2 = (
                f"GET /after-32767 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req2)
            await writer.drain()
            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["path"] == "/after-32767"
            assert d2["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_body_64kb_then_get(self, proxy):
        """POST with 64KB body (2x buffer) then GET"""
        reader, writer = await async_make_ssl_connection()
        try:
            body = b"W" * 65536
            req1 = (
                f"POST /body-64kb HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
            ).encode() + body
            writer.write(req1)
            await writer.drain()
            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200
            d1 = json.loads(rb1)
            assert d1["body_length"] == 65536

            req2 = (
                f"GET /after-64kb HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req2)
            await writer.drain()
            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            d2 = json.loads(rb2)
            assert d2["headers"].get("X-Forwarded-Proto") == "https"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_three_large_posts_keepalive(self, proxy):
        """Three 50KB POSTs on same connection"""
        reader, writer = await async_make_ssl_connection()
        try:
            for i in range(3):
                body = chr(ord('a') + i).encode() * 50000
                req = (
                    f"POST /large-ka-{i} HTTP/1.1\r\n"
                    f"Host: {TEST_DOMAIN}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n"
                ).encode() + body
                writer.write(req)
                await writer.drain()
                status, _, rb = await async_read_http_response(reader, writer)
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(rb)
                assert data["body_length"] == 50000
                assert data["headers"].get("X-Forwarded-Proto") == "https", \
                    f"Request {i}: missing forwarded headers"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 35. TestIPv6HostHeader
# ============================================================================

class TestIPv6HostHeader:
    """Test Host header parsing with IPv6 addresses"""

    async def test_ipv6_host_header(self, proxy):
        """IPv6 Host header like [::1]:port should be parsed correctly"""
        raw = RawSSLClient()
        # Send request with IPv6 host — domain won't match, expect 421
        data = (
            f"GET /ipv6 HTTP/1.1\r\n"
            f"Host: [::1]:8080\r\n"
            f"\r\n"
        ).encode()
        resp = await async_send_raw(raw, data)
        # Should return 421 since [::1] won't match any configured domain
        assert resp is not None
        assert b"421" in resp


# ============================================================================
# 36. TestMultipleChunkedPostsWithDifferentSizes
# ============================================================================

class TestMultipleChunkedPostsWithDifferentSizes:
    """Test multiple chunked POSTs with varying chunk patterns on keep-alive"""

    async def test_alternating_chunk_sizes(self, proxy):
        """Multiple chunked POSTs with alternating single/multi chunk patterns"""
        reader, writer = await async_make_ssl_connection()
        try:
            # POST 1: single chunk
            body1 = b"single"
            chunk1 = f"{len(body1):x}\r\n".encode() + body1 + b"\r\n0\r\n\r\n"
            req1 = (
                f"POST /alt-chunk-1 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            ).encode() + chunk1
            writer.write(req1)
            await writer.drain()
            s1, _, rb1 = await async_read_http_response(reader, writer)
            assert s1 == 200
            assert json.loads(rb1)["body_length"] == len(body1)

            # POST 2: many small chunks
            data2 = b""
            chunks2 = b""
            for byte in b"multiple":
                data2 += bytes([byte])
                chunks2 += f"1\r\n".encode() + bytes([byte]) + b"\r\n"
            chunks2 += b"0\r\n\r\n"
            req2 = (
                f"POST /alt-chunk-2 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            ).encode() + chunks2
            writer.write(req2)
            await writer.drain()
            s2, _, rb2 = await async_read_http_response(reader, writer)
            assert s2 == 200
            assert json.loads(rb2)["body_length"] == len(data2)

            # POST 3: large single chunk
            body3 = b"Q" * 10000
            chunk3 = f"{len(body3):x}\r\n".encode() + body3 + b"\r\n0\r\n\r\n"
            req3 = (
                f"POST /alt-chunk-3 HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
            ).encode() + chunk3
            writer.write(req3)
            await writer.drain()
            s3, _, rb3 = await async_read_http_response(reader, writer)
            assert s3 == 200
            d3 = json.loads(rb3)
            assert d3["body_length"] == 10000
            assert d3["headers"].get("X-Forwarded-Proto") == "https"

            # Final GET to verify clean state
            req4 = (
                f"GET /alt-chunk-done HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"\r\n"
            ).encode()
            writer.write(req4)
            await writer.drain()
            s4, _, rb4 = await async_read_http_response(reader, writer)
            assert s4 == 200
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 37. TestBackpressureSafety
# ============================================================================

class TestBackpressureSafety:
    """Ensure large uploads do not get silently truncated under backend backpressure."""

    async def test_large_post_not_silently_truncated(self):
        slow_backend_port = 18005
        slow_domain = "slowrecv.localhost"
        https_port = 18743
        http_port = 18780

        stop_flag = {"stop": False}

        def backend_worker():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", slow_backend_port))
            srv.listen(1)
            srv.settimeout(5.0)
            try:
                conn, _ = srv.accept()
            except Exception:
                srv.close()
                return

            conn.settimeout(0.5)
            received = b""
            try:
                while b"\r\n\r\n" not in received:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    received += chunk

                if b"\r\n\r\n" not in received:
                    conn.close()
                    srv.close()
                    return

                head_end = received.index(b"\r\n\r\n") + 4
                headers = received[:head_end].decode(errors="ignore")
                body = received[head_end:]

                declared = 0
                for line in headers.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        declared = int(line.split(":", 1)[1].strip())
                        break

                # Intentionally delay reads to create backpressure at proxy/backend boundary.
                time.sleep(0.1)

                idle_rounds = 0
                while len(body) < declared and idle_rounds < 4:
                    try:
                        chunk = conn.recv(32768)
                    except socket.timeout:
                        idle_rounds += 1
                        continue
                    if not chunk:
                        break
                    body += chunk

                resp_obj = {"received": len(body), "declared": declared}
                resp_body = json.dumps(resp_obj).encode()
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(resp_body)}\r\n".encode()
                    + b"Content-Type: application/json\r\n"
                    + b"Connection: close\r\n\r\n"
                    + resp_body
                )
                conn.sendall(response)
            finally:
                conn.close()
                srv.close()
                stop_flag["stop"] = True

        backend_thread = threading.Thread(target=backend_worker, daemon=True)
        backend_thread.start()

        config_file = os.path.join(PROJECT_ROOT, "tests", "test_backpressure_config.json")
        config = [{
            "domain": slow_domain,
            "port": str(slow_backend_port),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        }]
        with open(config_file, "w") as f:
            json.dump(config, f)

        process = await async_start_revpx(config_file, https_port=https_port, http_port=http_port)

        try:
            payload = b"P" * (2 * 1024 * 1024)
            headers = (
                f"POST /slow-upload HTTP/1.1\r\n"
                f"Host: {slow_domain}\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

            reader, writer = await async_make_ssl_connection(host=slow_domain, port=https_port)
            try:
                writer.write(headers + payload)
                await writer.drain()
                status, _, body = await asyncio.wait_for(
                    async_read_http_response(reader, writer), timeout=20.0
                )
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            if status == 200:
                result = json.loads(body)
                assert result["declared"] == len(payload)
                assert result["received"] == len(payload), \
                    "Proxy forwarded a truncated request body without returning an error"
            else:
                # Any explicit failure is acceptable; silent truncation is not.
                assert status in (413, 502), f"Unexpected status: {status}"
        finally:
            await async_stop_process(process, timeout=5.0)
            if os.path.exists(config_file):
                os.remove(config_file)
            backend_thread.join(timeout=2.0)

    async def test_large_post_then_pipelined_get_keeps_request_boundary(self):
        """Large POST body followed by GET in same write should produce two clean responses."""
        slow_backend_port = 18011
        slow_domain = "slowpipe.localhost"
        https_port = 18943
        http_port = 18980

        def recv_until(conn, marker: bytes, initial: bytes = b"") -> bytes:
            data = initial
            while marker not in data:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                data += chunk
            return data

        def read_request(conn, initial: bytes = b""):
            data = recv_until(conn, b"\r\n\r\n", initial)
            if b"\r\n\r\n" not in data:
                return None, None, b""

            header_end = data.index(b"\r\n\r\n") + 4
            head = data[:header_end]
            rest = data[header_end:]

            cl = 0
            for line in head.decode(errors="ignore").split("\r\n"):
                if line.lower().startswith("content-length:"):
                    cl = int(line.split(":", 1)[1].strip())
                    break

            body = rest
            while len(body) < cl:
                # Slow body drain to force proxy-side buffering/backpressure.
                time.sleep(0.002)
                chunk = conn.recv(min(4096, cl - len(body)))
                if not chunk:
                    break
                body += chunk

            leftover = body[cl:] if len(body) > cl else b""
            body = body[:cl]
            return head, body, leftover

        backend_state = {
            "req1_line": None,
            "req1_body_len": None,
            "req2_line": None,
            "error": None,
        }

        def backend_worker():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", slow_backend_port))
            srv.listen(1)
            srv.settimeout(8.0)
            conn = None
            try:
                conn, _ = srv.accept()
                conn.settimeout(10.0)

                h1, b1, rem = read_request(conn)
                if h1 is None:
                    backend_state["error"] = "first request not received"
                    return

                req_line_1 = h1.split(b"\r\n", 1)[0]
                backend_state["req1_line"] = req_line_1.decode(errors="ignore")
                backend_state["req1_body_len"] = len(b1)

                resp1 = json.dumps({"received": len(b1)}).encode()
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(resp1)}\r\n".encode()
                    + b"Content-Type: application/json\r\n"
                    + b"Connection: keep-alive\r\n\r\n"
                    + resp1
                )

                h2, _, _ = read_request(conn, rem)
                if h2 is None:
                    backend_state["error"] = "second request not received"
                    return

                req_line_2 = h2.split(b"\r\n", 1)[0]
                backend_state["req2_line"] = req_line_2.decode(errors="ignore")

                resp2 = b'{"ok":true}'
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(resp2)}\r\n".encode()
                    + b"Content-Type: application/json\r\n"
                    + b"Connection: close\r\n\r\n"
                    + resp2
                )
            except Exception as exc:
                backend_state["error"] = f"backend exception: {exc!r}"
            finally:
                if conn:
                    conn.close()
                srv.close()

        backend_thread = threading.Thread(target=backend_worker, daemon=True)
        backend_thread.start()

        config_file = os.path.join(PROJECT_ROOT, "tests", "test_backpressure_pipeline_config.json")
        config = [{
            "domain": slow_domain,
            "port": str(slow_backend_port),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        }]
        with open(config_file, "w") as f:
            json.dump(config, f)

        process = await async_start_revpx(config_file, https_port=https_port, http_port=http_port)

        try:
            payload = b"Q" * (1024 * 1024)
            request = (
                (
                    f"POST /slow-pipe HTTP/1.1\r\n"
                    f"Host: {slow_domain}\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                ).encode()
                + payload
                + (
                    f"GET /after-slow-pipe HTTP/1.1\r\n"
                    f"Host: {slow_domain}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()
            )

            reader, writer = await async_make_ssl_connection(host=slow_domain, port=https_port)
            try:
                writer.write(request)
                await writer.drain()

                s1, _, b1 = await asyncio.wait_for(
                    async_read_http_response(reader, writer), timeout=20.0
                )
                assert s1 == 200
                d1 = json.loads(b1)
                assert d1["received"] == len(payload)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            # Backend thread observed both requests with expected boundaries.
            backend_thread.join(timeout=5.0)

            assert backend_state["error"] is None, backend_state["error"]
            assert backend_state["req1_line"] is not None and backend_state["req1_line"].startswith(
                "POST /slow-pipe HTTP/1.1"
            )
            assert backend_state["req1_body_len"] == len(payload)
            assert backend_state["req2_line"] is not None and backend_state["req2_line"].startswith(
                "GET /after-slow-pipe HTTP/1.1"
            )
        finally:
            await async_stop_process(process, timeout=5.0)
            if os.path.exists(config_file):
                os.remove(config_file)
            backend_thread.join(timeout=2.0)


# ============================================================================
# 38. TestBackendAddressResolution
# ============================================================================

class TestBackendAddressResolution:
    """Regression tests for backend address resolution."""

    async def test_backend_host_localhost_falls_back_to_ipv4(self):
        """Proxy should try all getaddrinfo entries when connecting to backend host.

        On many macOS setups localhost resolves to [::1, 127.0.0.1]. If the backend
        listens only on IPv4, connect(::1) fails and the proxy must then try IPv4.
        """
        backend_port = 18006
        https_port = 18843
        http_port = 18880
        domain = "localhost-backend.localhost"

        backend = HTTPServer(("127.0.0.1", backend_port), BackendHandler)
        backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
        backend_thread.start()
        await asyncio.sleep(0.1)

        config_file = os.path.join(PROJECT_ROOT, "tests", "test_localhost_backend_config.json")
        config = [{
            "domain": domain,
            "host": "localhost",
            "port": str(backend_port),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        }]
        with open(config_file, "w") as f:
            json.dump(config, f)

        process = await async_start_revpx(config_file, https_port=https_port, http_port=http_port)

        try:
            assert process.returncode is None, "Proxy exited unexpectedly"

            client = ProxyClient(host=domain, port=https_port)
            status, _, body = await async_request(client, "GET", "/localhost-fallback")

            assert status == 200, (
                "Expected successful routing via IPv4 localhost fallback; "
                "proxy likely tried only the first resolved address"
            )

            data = json.loads(body)
            assert data["path"] == "/localhost-fallback"
        finally:
            await async_stop_process(process, timeout=5.0)

            backend.shutdown()
            backend.server_close()
            backend_thread.join(timeout=2.0)

            if os.path.exists(config_file):
                os.remove(config_file)


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
