#!/usr/bin/env python3
"""
Tests for mixed WebSocket + HTTP API traffic through a single revpx proxy instance.

The existing tests test WebSocket and HTTP separately (on different proxy instances
with different backends). This file tests the scenario where both WebSocket and
regular HTTP API calls flow through the SAME proxy to the SAME backend, which is
the typical real-world usage pattern (e.g., a web app making API calls + opening
a WebSocket connection simultaneously).
"""

import base64
import hashlib
import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_revpx import (
    PROJECT_ROOT,
    CERT_FILE,
    KEY_FILE,
    ProxyClient,
)


# ============================================================================
# Configuration - use unique ports to avoid conflicts with other test files
# ============================================================================

MIXED_BACKEND_PORT = 18100
MIXED_HTTPS_PORT = 18943
MIXED_HTTP_PORT = 18980
MIXED_DOMAIN = "test.localhost"


# ============================================================================
# Combined WebSocket + HTTP Backend
# ============================================================================

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """HTTPServer that handles each request in a new thread"""
    daemon_threads = True


class MixedBackendHandler(BaseHTTPRequestHandler):
    """
    Backend that handles BOTH regular HTTP requests AND WebSocket upgrades.
    This simulates a real application backend (e.g., a Node.js/Python app
    that serves API endpoints and WebSocket connections on the same port).
    """

    protocol_version = "HTTP/1.1"
    captured_requests = []
    lock = threading.Lock()

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        # Check for WebSocket upgrade
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self._handle_websocket()
            return
        self._handle_http()

    def do_POST(self):
        self._handle_http()

    def do_PUT(self):
        self._handle_http()

    def do_DELETE(self):
        self._handle_http()

    def _handle_http(self):
        """Handle regular HTTP request - echo back request details as JSON"""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        with self.lock:
            MixedBackendHandler.captured_requests.append({
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body_length": len(body),
                "body_hash": hashlib.md5(body).hexdigest() if body else None,
            })

        response_data = {
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body_length": len(body),
            "body_hash": hashlib.md5(body).hexdigest() if body else None,
        }

        response_body = json.dumps(response_data, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def _handle_websocket(self):
        """Handle WebSocket upgrade and echo messages"""
        key = self.headers.get("Sec-WebSocket-Key", "")
        magic = "258EAFA5-E914-47DA-95CA-5AB9C0FEDF5E"
        accept = base64.b64encode(
            hashlib.sha1((key + magic).encode()).digest()
        ).decode()

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        # Echo loop
        try:
            while True:
                header = self.rfile.read(2)
                if len(header) < 2:
                    break

                opcode = header[0] & 0x0F
                if opcode == 0x8:  # Close frame
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

                # Echo back unmasked
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


# ============================================================================
# WebSocket helpers
# ============================================================================

def ws_frame(payload: bytes, opcode: int = 0x1, masked: bool = True) -> bytes:
    """Build a WebSocket frame"""
    frame = bytes([0x80 | opcode])
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


def read_ws_frame(ssock, timeout=5.0) -> bytes:
    """Read a WebSocket frame and return payload"""
    ssock.settimeout(timeout)
    header = b""
    while len(header) < 2:
        chunk = ssock.recv(2 - len(header))
        if not chunk:
            raise ConnectionError("Connection closed reading WS frame header")
        header += chunk

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
        chunk = ssock.recv(payload_len - len(payload))
        if not chunk:
            raise ConnectionError("Connection closed reading WS frame payload")
        payload += chunk

    return payload


def make_ws_connection(port=MIXED_HTTPS_PORT, domain=MIXED_DOMAIN):
    """Create an SSL connection and perform WebSocket handshake, return ssock"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    ws_key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET /ws HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    ).encode()

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    ssock = ctx.wrap_socket(sock, server_hostname=domain)
    ssock.sendall(request)

    # Read 101 response
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = ssock.recv(4096)
        if not chunk:
            ssock.close()
            raise ConnectionError("Connection closed before WS handshake complete")
        response += chunk

    status_line = response.split(b"\r\n")[0]
    if b"101" not in status_line:
        ssock.close()
        raise ConnectionError(f"WebSocket handshake failed: {status_line.decode()}")

    return ssock


def make_http_request(path="/api/test", method="GET", body=None, port=MIXED_HTTPS_PORT, domain=MIXED_DOMAIN, timeout=10.0):
    """Make an HTTP request through the proxy and return (status, headers, body)"""
    client = ProxyClient(host=domain, port=port)
    return client.request(method=method, path=path, body=body, timeout=timeout)


def read_http_response(ssock):
    """Read a single HTTP response from an SSL socket"""
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


def make_ssl_connection(port=MIXED_HTTPS_PORT, domain=MIXED_DOMAIN):
    """Create a raw SSL connection to the proxy"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection(("127.0.0.1", port), timeout=15)
    ssock = ctx.wrap_socket(sock, server_hostname=domain)
    return ssock


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def mixed_backend():
    """Start a combined WS+HTTP backend"""
    server = ThreadedHTTPServer(("127.0.0.1", MIXED_BACKEND_PORT), MixedBackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    yield server
    server.shutdown()


@pytest.fixture(scope="module")
def mixed_proxy(mixed_backend):
    """Start a single revpx proxy that forwards to the combined backend"""
    config_file = os.path.join(PROJECT_ROOT, "tests", "test_mixed_config.json")
    config = [{
        "domain": MIXED_DOMAIN,
        "port": str(MIXED_BACKEND_PORT),
        "cert_file": CERT_FILE,
        "key_file": KEY_FILE,
    }]
    with open(config_file, "w") as f:
        json.dump(config, f)

    env = os.environ.copy()
    env["REVPX_PORT"] = str(MIXED_HTTPS_PORT)
    env["REVPX_PORT_PLAIN"] = str(MIXED_HTTP_PORT)

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
        raise RuntimeError(f"Mixed proxy failed to start:\n{stdout.decode()}\n{stderr.decode()}")

    yield process

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    if os.path.exists(config_file):
        os.remove(config_file)


@pytest.fixture(autouse=True)
def reset_captured():
    MixedBackendHandler.captured_requests.clear()
    yield


# ============================================================================
# Test: HTTP requests while a WebSocket connection is open
# ============================================================================

class TestHTTPWhileWSOpen:
    """
    Simulates a browser that has an open WebSocket connection and also
    makes HTTP API calls (e.g., fetching data, posting forms).
    """

    def test_single_get_while_ws_idle(self, mixed_proxy):
        """Open WS, leave it idle, make a single HTTP GET"""
        ws = make_ws_connection()
        try:
            status, _, body = make_http_request("/api/data")
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "GET"
            assert data["path"] == "/api/data"
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_multiple_gets_while_ws_idle(self, mixed_proxy):
        """Open WS, make several sequential HTTP GETs"""
        ws = make_ws_connection()
        try:
            for i in range(5):
                status, _, body = make_http_request(f"/api/items/{i}")
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["path"] == f"/api/items/{i}", f"Request {i}: wrong path"
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_post_while_ws_idle(self, mixed_proxy):
        """Open WS, make HTTP POST with body"""
        ws = make_ws_connection()
        try:
            post_body = b'{"key": "value", "number": 42}'
            status, _, body = make_http_request("/api/create", method="POST", body=post_body)
            assert status == 200
            data = json.loads(body)
            assert data["method"] == "POST"
            assert data["body_length"] == len(post_body)
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_mixed_methods_while_ws_idle(self, mixed_proxy):
        """Open WS, make GET/POST/PUT/DELETE requests"""
        ws = make_ws_connection()
        try:
            # GET
            status, _, body = make_http_request("/api/resource")
            assert status == 200
            assert json.loads(body)["method"] == "GET"

            # POST
            status, _, body = make_http_request("/api/resource", method="POST", body=b"post-data")
            assert status == 200
            assert json.loads(body)["method"] == "POST"

            # PUT
            status, _, body = make_http_request("/api/resource/1", method="PUT", body=b"put-data")
            assert status == 200
            assert json.loads(body)["method"] == "PUT"

            # DELETE
            status, _, body = make_http_request("/api/resource/1", method="DELETE")
            assert status == 200
            assert json.loads(body)["method"] == "DELETE"
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_parallel_gets_while_ws_idle(self, mixed_proxy):
        """Open WS, make parallel HTTP GETs"""
        ws = make_ws_connection()
        try:
            def do_request(i):
                return i, make_http_request(f"/api/parallel/{i}")

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(do_request, i) for i in range(10)]
                results = [f.result() for f in as_completed(futures)]

            for i, (status, _, body) in results:
                assert status == 200, f"Request {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["path"] == f"/api/parallel/{i}"
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()


# ============================================================================
# Test: WS messages interleaved with HTTP requests
# ============================================================================

class TestInterleavedWSAndHTTP:
    """
    Simulates a real app where WebSocket messages and HTTP API calls
    happen interleaved - e.g., receiving a WS notification triggers
    an HTTP fetch.
    """

    def test_ws_echo_then_http_get(self, mixed_proxy):
        """Send WS message, get echo, then make HTTP request"""
        ws = make_ws_connection()
        try:
            # WS echo
            msg = b"hello websocket"
            ws.sendall(ws_frame(msg))
            echoed = read_ws_frame(ws)
            assert echoed == msg

            # HTTP request
            status, _, body = make_http_request("/api/after-ws")
            assert status == 200
            data = json.loads(body)
            assert data["path"] == "/api/after-ws"
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_http_get_then_ws_echo(self, mixed_proxy):
        """Make HTTP request, then send/receive WS message"""
        ws = make_ws_connection()
        try:
            # HTTP request first
            status, _, body = make_http_request("/api/before-ws")
            assert status == 200

            # Then WS echo
            msg = b"hello after http"
            ws.sendall(ws_frame(msg))
            echoed = read_ws_frame(ws)
            assert echoed == msg
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_alternating_ws_and_http(self, mixed_proxy):
        """Alternate between WS messages and HTTP requests"""
        ws = make_ws_connection()
        try:
            for i in range(5):
                # WS message
                msg = f"ws-msg-{i}".encode()
                ws.sendall(ws_frame(msg))
                echoed = read_ws_frame(ws)
                assert echoed == msg, f"WS round {i}: expected {msg!r}, got {echoed!r}"

                # HTTP request
                status, _, body = make_http_request(f"/api/interleaved/{i}")
                assert status == 200, f"HTTP round {i}: expected 200, got {status}"
                data = json.loads(body)
                assert data["path"] == f"/api/interleaved/{i}"
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_ws_echo_during_http_request(self, mixed_proxy):
        """
        Send a WS message and make an HTTP request concurrently.
        This simulates a real app where the server pushes a WS notification
        while the client is also making an API call.
        """
        ws = make_ws_connection()
        errors = []
        try:
            def ws_exchange():
                try:
                    for i in range(3):
                        msg = f"concurrent-ws-{i}".encode()
                        ws.sendall(ws_frame(msg))
                        echoed = read_ws_frame(ws)
                        if echoed != msg:
                            errors.append(f"WS {i}: expected {msg!r}, got {echoed!r}")
                except Exception as e:
                    errors.append(f"WS error: {e}")

            def http_requests():
                try:
                    for i in range(3):
                        status, _, body = make_http_request(f"/api/concurrent/{i}")
                        if status != 200:
                            errors.append(f"HTTP {i}: expected 200, got {status}")
                        else:
                            data = json.loads(body)
                            if data["path"] != f"/api/concurrent/{i}":
                                errors.append(f"HTTP {i}: wrong path {data['path']}")
                except Exception as e:
                    errors.append(f"HTTP error: {e}")

            t1 = threading.Thread(target=ws_exchange)
            t2 = threading.Thread(target=http_requests)
            t1.start()
            t2.start()
            t1.join(timeout=15)
            t2.join(timeout=15)

            assert not errors, f"Errors during concurrent WS+HTTP: {errors}"
        finally:
            try:
                ws.sendall(ws_frame(b"", opcode=0x8))
            except Exception:
                pass
            ws.close()


# ============================================================================
# Test: Multiple WebSocket connections + HTTP connections simultaneously
# ============================================================================

class TestMultipleWSAndHTTP:
    """
    Simulates multiple browser tabs or multiple components each with
    their own WebSocket connection, plus HTTP API traffic.
    """

    def test_two_ws_connections_plus_http(self, mixed_proxy):
        """Two concurrent WS connections + HTTP requests"""
        ws1 = make_ws_connection()
        ws2 = make_ws_connection()
        try:
            # Echo on WS1
            ws1.sendall(ws_frame(b"ws1-hello"))
            assert read_ws_frame(ws1) == b"ws1-hello"

            # HTTP request
            status, _, body = make_http_request("/api/with-two-ws")
            assert status == 200

            # Echo on WS2
            ws2.sendall(ws_frame(b"ws2-hello"))
            assert read_ws_frame(ws2) == b"ws2-hello"

            # Another HTTP request
            status, _, body = make_http_request("/api/with-two-ws-2")
            assert status == 200
        finally:
            for ws in (ws1, ws2):
                try:
                    ws.sendall(ws_frame(b"", opcode=0x8))
                except Exception:
                    pass
                ws.close()

    def test_many_ws_connections_with_http_traffic(self, mixed_proxy):
        """Open several WS connections and make HTTP requests in between"""
        ws_connections = []
        try:
            for i in range(3):
                ws = make_ws_connection()
                ws_connections.append(ws)

                # HTTP request after each WS connection
                status, _, body = make_http_request(f"/api/multi-ws/{i}")
                assert status == 200, f"HTTP after WS {i}: expected 200, got {status}"

            # Verify all WS connections still work
            for i, ws in enumerate(ws_connections):
                msg = f"multi-ws-{i}".encode()
                ws.sendall(ws_frame(msg))
                echoed = read_ws_frame(ws)
                assert echoed == msg, f"WS {i}: expected {msg!r}, got {echoed!r}"

            # More HTTP requests with all WS open
            for i in range(5):
                status, _, body = make_http_request(f"/api/all-ws-open/{i}")
                assert status == 200, f"HTTP {i} with all WS open: expected 200, got {status}"
        finally:
            for ws in ws_connections:
                try:
                    ws.sendall(ws_frame(b"", opcode=0x8))
                except Exception:
                    pass
                ws.close()

    def test_parallel_ws_and_http_connections(self, mixed_proxy):
        """Open WS and HTTP connections in parallel threads"""
        errors = []
        ws_connections = []
        ws_lock = threading.Lock()

        def open_ws_and_echo(i):
            try:
                ws = make_ws_connection()
                with ws_lock:
                    ws_connections.append(ws)
                msg = f"parallel-ws-{i}".encode()
                ws.sendall(ws_frame(msg))
                echoed = read_ws_frame(ws)
                if echoed != msg:
                    errors.append(f"WS {i}: echo mismatch")
            except Exception as e:
                errors.append(f"WS {i}: {e}")

        def make_http(i):
            try:
                status, _, body = make_http_request(f"/api/parallel-mix/{i}")
                if status != 200:
                    errors.append(f"HTTP {i}: status {status}")
            except Exception as e:
                errors.append(f"HTTP {i}: {e}")

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for i in range(4):
                futures.append(executor.submit(open_ws_and_echo, i))
                futures.append(executor.submit(make_http, i))
            for f in as_completed(futures):
                f.result()  # Re-raise exceptions

        assert not errors, f"Errors: {errors}"

        # Cleanup WS
        for ws in ws_connections:
            try:
                ws.sendall(ws_frame(b"", opcode=0x8))
            except Exception:
                pass
            ws.close()


# ============================================================================
# Test: HTTP keep-alive connection while WS is active
# ============================================================================

class TestHTTPKeepAliveWithWS:
    """
    Tests HTTP keep-alive (persistent connection) behavior while a WebSocket
    connection is active on the same proxy. This is especially important
    because browsers reuse HTTP connections for multiple API calls.
    """

    def test_keepalive_gets_while_ws_open(self, mixed_proxy):
        """Multiple GETs on a keep-alive connection while WS is open"""
        ws = make_ws_connection()
        try:
            ssock = make_ssl_connection()
            try:
                for i in range(5):
                    request = (
                        f"GET /api/ka-ws/{i} HTTP/1.1\r\n"
                        f"Host: {MIXED_DOMAIN}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode()
                    ssock.sendall(request)
                    status, headers, body = read_http_response(ssock)
                    assert status == 200, f"Request {i}: expected 200, got {status}"
                    data = json.loads(body)
                    assert data["path"] == f"/api/ka-ws/{i}"
            finally:
                ssock.close()
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_keepalive_mixed_methods_with_ws(self, mixed_proxy):
        """GET and POST on keep-alive while WS is open"""
        ws = make_ws_connection()
        try:
            ssock = make_ssl_connection()
            try:
                # GET
                ssock.sendall(
                    f"GET /api/ka-mix/1 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                )
                status, _, body = read_http_response(ssock)
                assert status == 200
                assert json.loads(body)["method"] == "GET"

                # POST with body
                post_body = b"keepalive-post-body"
                ssock.sendall(
                    (
                        f"POST /api/ka-mix/2 HTTP/1.1\r\n"
                        f"Host: {MIXED_DOMAIN}\r\n"
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
                    f"GET /api/ka-mix/3 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                )
                status, _, body = read_http_response(ssock)
                assert status == 200
                assert json.loads(body)["path"] == "/api/ka-mix/3"
            finally:
                ssock.close()
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_keepalive_with_ws_messages_between(self, mixed_proxy):
        """HTTP keep-alive requests interleaved with WS messages"""
        ws = make_ws_connection()
        try:
            ssock = make_ssl_connection()
            try:
                for i in range(3):
                    # Send WS message and get echo
                    msg = f"ka-ws-interleave-{i}".encode()
                    ws.sendall(ws_frame(msg))
                    echoed = read_ws_frame(ws)
                    assert echoed == msg, f"WS {i}: expected {msg!r}, got {echoed!r}"

                    # HTTP keep-alive request
                    ssock.sendall(
                        f"GET /api/ka-interleave/{i} HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                    )
                    status, _, body = read_http_response(ssock)
                    assert status == 200, f"HTTP {i}: expected 200, got {status}"
                    data = json.loads(body)
                    assert data["path"] == f"/api/ka-interleave/{i}"
            finally:
                ssock.close()
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_two_keepalive_connections_with_ws(self, mixed_proxy):
        """Two HTTP keep-alive connections + WS connection"""
        ws = make_ws_connection()
        try:
            ssock1 = make_ssl_connection()
            ssock2 = make_ssl_connection()
            try:
                for i in range(3):
                    # Request on connection 1
                    ssock1.sendall(
                        f"GET /api/ka1/{i} HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                    )
                    status, _, body = read_http_response(ssock1)
                    assert status == 200, f"Conn1 req {i}: status {status}"

                    # Request on connection 2
                    ssock2.sendall(
                        f"GET /api/ka2/{i} HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                    )
                    status, _, body = read_http_response(ssock2)
                    assert status == 200, f"Conn2 req {i}: status {status}"
            finally:
                ssock1.close()
                ssock2.close()
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()


# ============================================================================
# Test: Rapid WS open/close with HTTP
# ============================================================================

class TestRapidWSCyclingWithHTTP:
    """
    Tests rapidly opening and closing WebSocket connections while
    also making HTTP requests. This simulates page navigation in a SPA
    where each page opens a new WS connection and closes the old one.
    """

    def test_ws_open_close_then_http(self, mixed_proxy):
        """Open WS, close it, then make HTTP request"""
        ws = make_ws_connection()
        ws.sendall(ws_frame(b"quick-msg"))
        echoed = read_ws_frame(ws)
        assert echoed == b"quick-msg"
        ws.sendall(ws_frame(b"", opcode=0x8))
        ws.close()

        # HTTP after WS close
        status, _, body = make_http_request("/api/after-ws-close")
        assert status == 200
        assert json.loads(body)["path"] == "/api/after-ws-close"

    def test_http_then_ws_open_close(self, mixed_proxy):
        """Make HTTP request, then open and close WS"""
        status, _, body = make_http_request("/api/before-ws-open")
        assert status == 200

        ws = make_ws_connection()
        ws.sendall(ws_frame(b"after-http"))
        echoed = read_ws_frame(ws)
        assert echoed == b"after-http"
        ws.sendall(ws_frame(b"", opcode=0x8))
        ws.close()

    def test_repeated_ws_cycle_with_http(self, mixed_proxy):
        """Repeatedly open WS, use it, close it, make HTTP request"""
        for i in range(5):
            # Open WS
            ws = make_ws_connection()
            msg = f"cycle-{i}".encode()
            ws.sendall(ws_frame(msg))
            echoed = read_ws_frame(ws)
            assert echoed == msg, f"Cycle {i} WS: expected {msg!r}, got {echoed!r}"
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

            # HTTP request
            status, _, body = make_http_request(f"/api/cycle/{i}")
            assert status == 200, f"Cycle {i} HTTP: expected 200, got {status}"

    def test_ws_replace_with_http_between(self, mixed_proxy):
        """Close old WS, make HTTP request, open new WS - simulates page nav"""
        ws = make_ws_connection()
        try:
            ws.sendall(ws_frame(b"page1-msg"))
            assert read_ws_frame(ws) == b"page1-msg"
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

        # Page navigation: fetch page data
        status, _, body = make_http_request("/api/page2/data")
        assert status == 200

        # Open new WS for page 2
        ws = make_ws_connection()
        try:
            ws.sendall(ws_frame(b"page2-msg"))
            assert read_ws_frame(ws) == b"page2-msg"

            # Make API call while new WS is open
            status, _, body = make_http_request("/api/page2/extra")
            assert status == 200
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()


# ============================================================================
# Test: Large payloads mixed with WS
# ============================================================================

class TestLargePayloadsWithWS:
    """
    Tests that large HTTP request/response bodies work correctly
    while WebSocket connections are active.
    """

    def test_large_post_while_ws_open(self, mixed_proxy):
        """POST with large body while WS connection is active"""
        ws = make_ws_connection()
        try:
            large_body = os.urandom(50 * 1024)  # 50KB
            body_hash = hashlib.md5(large_body).hexdigest()

            status, _, resp_body = make_http_request("/api/large-post", method="POST", body=large_body)
            assert status == 200
            data = json.loads(resp_body)
            assert data["body_length"] == len(large_body)
            assert data["body_hash"] == body_hash
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_large_ws_frame_then_http(self, mixed_proxy):
        """Send large WS frame, then make HTTP request"""
        ws = make_ws_connection()
        try:
            # Large WS binary frame
            large_msg = os.urandom(16 * 1024)  # 16KB
            ws.sendall(ws_frame(large_msg, opcode=0x2))
            echoed = read_ws_frame(ws)
            assert echoed == large_msg

            # HTTP request should still work
            status, _, body = make_http_request("/api/after-large-ws")
            assert status == 200
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_concurrent_large_http_and_ws_traffic(self, mixed_proxy):
        """Large WS messages and large HTTP bodies concurrently"""
        ws = make_ws_connection()
        errors = []
        try:
            def ws_large_exchange():
                try:
                    for i in range(3):
                        msg = os.urandom(8 * 1024)
                        ws.sendall(ws_frame(msg, opcode=0x2))
                        echoed = read_ws_frame(ws)
                        if echoed != msg:
                            errors.append(f"WS large {i}: data mismatch")
                except Exception as e:
                    errors.append(f"WS large error: {e}")

            def http_large_requests():
                try:
                    for i in range(3):
                        body = os.urandom(20 * 1024)
                        body_hash = hashlib.md5(body).hexdigest()
                        status, _, resp = make_http_request(f"/api/large-concurrent/{i}", method="POST", body=body)
                        if status != 200:
                            errors.append(f"HTTP large {i}: status {status}")
                        else:
                            data = json.loads(resp)
                            if data["body_hash"] != body_hash:
                                errors.append(f"HTTP large {i}: body hash mismatch")
                except Exception as e:
                    errors.append(f"HTTP large error: {e}")

            t1 = threading.Thread(target=ws_large_exchange)
            t2 = threading.Thread(target=http_large_requests)
            t1.start()
            t2.start()
            t1.join(timeout=30)
            t2.join(timeout=30)

            assert not errors, f"Errors: {errors}"
        finally:
            try:
                ws.sendall(ws_frame(b"", opcode=0x8))
            except Exception:
                pass
            ws.close()


# ============================================================================
# Test: HTTP request immediately after WS on same connection
# ============================================================================

class TestWSFollowedByHTTPSameConnection:
    """
    Edge case: can we use the same TCP connection for WS upgrade
    and then HTTP? (The answer should be no - WS upgrade is permanent.
    But the proxy should handle this gracefully.)
    """

    def test_ws_and_http_on_separate_connections(self, mixed_proxy):
        """Verify WS and HTTP work fine on separate connections to same proxy"""
        # This is the basic sanity check for the whole test suite
        ws = make_ws_connection()
        try:
            ws.sendall(ws_frame(b"sanity-check"))
            echoed = read_ws_frame(ws)
            assert echoed == b"sanity-check"
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

        status, _, body = make_http_request("/api/sanity-check")
        assert status == 200
        data = json.loads(body)
        assert data["path"] == "/api/sanity-check"


# ============================================================================
# Test: Stress test with mixed traffic
# ============================================================================

class TestMixedTrafficStress:
    """
    Stress tests that mix WebSocket and HTTP traffic with more
    connections and requests to try to trigger issues.
    """

    def test_many_parallel_http_with_active_ws(self, mixed_proxy):
        """20 parallel HTTP requests while WS connection has active traffic"""
        ws = make_ws_connection()
        errors = []
        stop_ws = threading.Event()

        def ws_traffic():
            try:
                i = 0
                while not stop_ws.is_set():
                    msg = f"stress-ws-{i}".encode()
                    ws.sendall(ws_frame(msg))
                    echoed = read_ws_frame(ws)
                    if echoed != msg:
                        errors.append(f"WS stress {i}: mismatch")
                    i += 1
                    time.sleep(0.01)
            except Exception as e:
                if not stop_ws.is_set():
                    errors.append(f"WS stress error: {e}")

        ws_thread = threading.Thread(target=ws_traffic)
        ws_thread.start()

        try:
            # Give WS thread a moment to start
            time.sleep(0.1)

            def do_http(i):
                try:
                    status, _, body = make_http_request(f"/api/stress/{i}")
                    return i, status, json.loads(body)["path"]
                except Exception as e:
                    return i, -1, str(e)

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(do_http, i) for i in range(20)]
                results = [f.result() for f in as_completed(futures)]

            for i, status, path in results:
                assert status == 200, f"Stress HTTP {i}: status {status}, path/err: {path}"
                assert path == f"/api/stress/{i}", f"Stress HTTP {i}: wrong path {path}"

        finally:
            stop_ws.set()
            ws_thread.join(timeout=5)
            try:
                ws.sendall(ws_frame(b"", opcode=0x8))
            except Exception:
                pass
            ws.close()

        assert not errors, f"WS errors during stress: {errors}"

    def test_sequential_ws_http_many_rounds(self, mixed_proxy):
        """Many rounds of: open WS, exchange message, close WS, make HTTP request"""
        for i in range(10):
            ws = make_ws_connection()
            try:
                msg = f"round-{i}".encode()
                ws.sendall(ws_frame(msg))
                echoed = read_ws_frame(ws)
                assert echoed == msg, f"Round {i} WS: mismatch"
            finally:
                ws.sendall(ws_frame(b"", opcode=0x8))
                ws.close()

            status, _, body = make_http_request(f"/api/round/{i}")
            assert status == 200, f"Round {i} HTTP: status {status}"

    def test_burst_mixed_connections(self, mixed_proxy):
        """Burst of mixed WS and HTTP connections"""
        errors = []
        ws_connections = []
        ws_lock = threading.Lock()

        def burst_ws(i):
            try:
                ws = make_ws_connection()
                with ws_lock:
                    ws_connections.append(ws)
                msg = f"burst-{i}".encode()
                ws.sendall(ws_frame(msg))
                echoed = read_ws_frame(ws)
                if echoed != msg:
                    errors.append(f"Burst WS {i}: mismatch")
                return True
            except Exception as e:
                errors.append(f"Burst WS {i}: {e}")
                return False

        def burst_http(i):
            try:
                status, _, body = make_http_request(f"/api/burst/{i}")
                if status != 200:
                    errors.append(f"Burst HTTP {i}: status {status}")
                return True
            except Exception as e:
                errors.append(f"Burst HTTP {i}: {e}")
                return False

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for i in range(5):
                futures.append(executor.submit(burst_ws, i))
                futures.append(executor.submit(burst_http, i))
            for f in as_completed(futures):
                f.result()

        # Cleanup WS
        for ws in ws_connections:
            try:
                ws.sendall(ws_frame(b"", opcode=0x8))
            except Exception:
                pass
            ws.close()

        assert not errors, f"Burst errors: {errors}"


# ============================================================================
# Test: Edge cases - abrupt disconnects, pipelining, slow responses
# ============================================================================

class TestMixedEdgeCases:
    """
    More aggressive edge cases that simulate real browser behavior:
    - Abrupt WS disconnects (no close frame)
    - HTTP pipelining while WS is active
    - Slow backend responses
    - Connection abandonment during page navigation
    """

    def test_abrupt_ws_close_then_http(self, mixed_proxy):
        """Close WS connection without close frame, then make HTTP request"""
        ws = make_ws_connection()
        ws.sendall(ws_frame(b"before-abrupt-close"))
        read_ws_frame(ws)
        # Abrupt close - no close frame
        ws.close()
        time.sleep(0.2)

        # HTTP should still work
        status, _, body = make_http_request("/api/after-abrupt-ws")
        assert status == 200
        assert json.loads(body)["path"] == "/api/after-abrupt-ws"

    def test_abrupt_ws_close_with_rst_then_http(self, mixed_proxy):
        """Force RST on WS connection, then make HTTP request"""
        ws = make_ws_connection()
        ws.sendall(ws_frame(b"before-rst"))
        read_ws_frame(ws)
        # Force RST by setting SO_LINGER to 0
        try:
            underlying = ws.unwrap()
            underlying.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                  struct.pack('ii', 1, 0))
            underlying.close()
        except Exception:
            ws.close()
        time.sleep(0.3)

        # HTTP should still work
        status, _, body = make_http_request("/api/after-rst-ws")
        assert status == 200
        assert json.loads(body)["path"] == "/api/after-rst-ws"

    def test_http_pipelining_while_ws_active(self, mixed_proxy):
        """Send multiple HTTP requests pipelined (without waiting for responses)
        while a WS connection is active"""
        ws = make_ws_connection()
        try:
            ssock = make_ssl_connection()
            try:
                # Pipeline 3 GET requests
                for i in range(3):
                    request = (
                        f"GET /api/pipeline/{i} HTTP/1.1\r\n"
                        f"Host: {MIXED_DOMAIN}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode()
                    ssock.sendall(request)

                # Read all 3 responses
                for i in range(3):
                    status, _, body = read_http_response(ssock)
                    assert status == 200, f"Pipeline {i}: expected 200, got {status}"
                    data = json.loads(body)
                    assert data["path"] == f"/api/pipeline/{i}", \
                        f"Pipeline {i}: expected /api/pipeline/{i}, got {data['path']}"
            finally:
                ssock.close()
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_http_pipelining_post_while_ws_active(self, mixed_proxy):
        """Pipeline POST requests with bodies while WS active"""
        ws = make_ws_connection()
        try:
            ssock = make_ssl_connection()
            try:
                # Pipeline POST requests with different body sizes
                bodies = [b"small", b"medium body content here", os.urandom(1024)]
                for i, body in enumerate(bodies):
                    request = (
                        f"POST /api/pipe-post/{i} HTTP/1.1\r\n"
                        f"Host: {MIXED_DOMAIN}\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode() + body
                    ssock.sendall(request)

                for i, body in enumerate(bodies):
                    status, _, resp_body = read_http_response(ssock)
                    assert status == 200, f"Pipe POST {i}: expected 200, got {status}"
                    data = json.loads(resp_body)
                    assert data["body_length"] == len(body), \
                        f"Pipe POST {i}: expected body_length {len(body)}, got {data['body_length']}"
            finally:
                ssock.close()
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_ws_active_during_http_pipelining_mixed(self, mixed_proxy):
        """Pipeline GET+POST+GET while WS is exchanging messages"""
        ws = make_ws_connection()
        errors = []
        try:
            def ws_continuous():
                try:
                    for i in range(5):
                        msg = f"pipeline-ws-{i}".encode()
                        ws.sendall(ws_frame(msg))
                        echoed = read_ws_frame(ws)
                        if echoed != msg:
                            errors.append(f"WS pipeline {i}: mismatch")
                        time.sleep(0.05)
                except Exception as e:
                    errors.append(f"WS pipeline error: {e}")

            def http_pipeline():
                try:
                    ssock = make_ssl_connection()
                    try:
                        # Send all requests without waiting
                        body1 = b"post-in-pipeline"
                        requests = [
                            f"GET /api/mix-pipe/1 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode(),
                            (f"POST /api/mix-pipe/2 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\n"
                             f"Content-Length: {len(body1)}\r\nConnection: keep-alive\r\n\r\n").encode() + body1,
                            f"GET /api/mix-pipe/3 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode(),
                        ]
                        for req in requests:
                            ssock.sendall(req)

                        # Read all responses
                        expected_paths = ["/api/mix-pipe/1", "/api/mix-pipe/2", "/api/mix-pipe/3"]
                        for i, expected_path in enumerate(expected_paths):
                            status, _, body = read_http_response(ssock)
                            if status != 200:
                                errors.append(f"HTTP pipeline {i}: status {status}")
                            else:
                                data = json.loads(body)
                                if data["path"] != expected_path:
                                    errors.append(f"HTTP pipeline {i}: expected {expected_path}, got {data['path']}")
                    finally:
                        ssock.close()
                except Exception as e:
                    errors.append(f"HTTP pipeline error: {e}")

            t1 = threading.Thread(target=ws_continuous)
            t2 = threading.Thread(target=http_pipeline)
            t1.start()
            t2.start()
            t1.join(timeout=15)
            t2.join(timeout=15)

            assert not errors, f"Errors: {errors}"
        finally:
            try:
                ws.sendall(ws_frame(b"", opcode=0x8))
            except Exception:
                pass
            ws.close()

    def test_page_navigation_simulation(self, mixed_proxy):
        """
        Simulate realistic SPA page navigation:
        1. Load page 1: HTTP GET + open WS
        2. Navigate to page 2: abruptly close WS + HTTP GET + open new WS
        3. Navigate to page 3: close WS + HTTP GET + open new WS
        Each page also makes a few API calls after WS is open.
        """
        for page in range(1, 4):
            # "Load" the page
            status, _, body = make_http_request(f"/page/{page}")
            assert status == 200, f"Page {page} load: status {status}"

            # Open WS for this page
            ws = make_ws_connection()
            try:
                # Make some API calls while WS is open
                for i in range(3):
                    status, _, body = make_http_request(f"/api/page{page}/data/{i}")
                    assert status == 200, f"Page {page} API {i}: status {status}"

                # WS activity
                msg = f"page{page}-ws".encode()
                ws.sendall(ws_frame(msg))
                echoed = read_ws_frame(ws)
                assert echoed == msg

            finally:
                if page < 3:
                    # Abrupt close (simulating navigation)
                    ws.close()
                    time.sleep(0.1)
                else:
                    # Clean close on last page
                    ws.sendall(ws_frame(b"", opcode=0x8))
                    ws.close()

    def test_ws_established_after_keepalive_requests(self, mixed_proxy):
        """
        Make several keep-alive HTTP requests, then open WS, then more HTTP.
        This simulates an app that loads data first, then establishes WS.
        """
        # Initial HTTP keep-alive requests
        ssock = make_ssl_connection()
        try:
            for i in range(3):
                ssock.sendall(
                    f"GET /api/pre-ws/{i} HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                )
                status, _, body = read_http_response(ssock)
                assert status == 200, f"Pre-WS {i}: status {status}"
        finally:
            ssock.close()

        # Now open WS
        ws = make_ws_connection()
        try:
            ws.sendall(ws_frame(b"after-keepalive"))
            assert read_ws_frame(ws) == b"after-keepalive"

            # More HTTP requests while WS open
            for i in range(3):
                status, _, body = make_http_request(f"/api/post-ws/{i}")
                assert status == 200, f"Post-WS {i}: status {status}"
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_ws_and_http_keepalive_concurrent(self, mixed_proxy):
        """
        HTTP keep-alive connection and WS connection used concurrently.
        Both threads actively send/receive at the same time.
        """
        ws = make_ws_connection()
        errors = []
        stop = threading.Event()

        def ws_loop():
            try:
                i = 0
                while not stop.is_set() and i < 10:
                    msg = f"concurrent-ka-ws-{i}".encode()
                    ws.sendall(ws_frame(msg))
                    echoed = read_ws_frame(ws)
                    if echoed != msg:
                        errors.append(f"WS concurrent {i}: mismatch")
                        break
                    i += 1
                    time.sleep(0.02)
            except Exception as e:
                if not stop.is_set():
                    errors.append(f"WS concurrent error: {e}")

        def http_ka_loop():
            try:
                ssock = make_ssl_connection()
                try:
                    for i in range(10):
                        if stop.is_set():
                            break
                        ssock.sendall(
                            f"GET /api/concurrent-ka/{i} HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
                        )
                        status, _, body = read_http_response(ssock)
                        if status != 200:
                            errors.append(f"HTTP ka {i}: status {status}")
                            break
                        data = json.loads(body)
                        if data["path"] != f"/api/concurrent-ka/{i}":
                            errors.append(f"HTTP ka {i}: wrong path")
                            break
                finally:
                    ssock.close()
            except Exception as e:
                errors.append(f"HTTP ka error: {e}")

        t1 = threading.Thread(target=ws_loop)
        t2 = threading.Thread(target=http_ka_loop)
        t1.start()
        t2.start()
        t1.join(timeout=20)
        t2.join(timeout=20)
        stop.set()

        try:
            ws.sendall(ws_frame(b"", opcode=0x8))
        except Exception:
            pass
        ws.close()

        assert not errors, f"Concurrent ka errors: {errors}"

    def test_ws_high_frequency_with_http(self, mixed_proxy):
        """
        High frequency WS messages (no delay) while HTTP requests also happen.
        Tests that rapid WS traffic doesn't starve HTTP connections.
        """
        ws = make_ws_connection()
        errors = []
        stop = threading.Event()

        def rapid_ws():
            try:
                for i in range(50):
                    if stop.is_set():
                        break
                    msg = f"rapid-{i}".encode()
                    ws.sendall(ws_frame(msg))
                    echoed = read_ws_frame(ws)
                    if echoed != msg:
                        errors.append(f"Rapid WS {i}: mismatch")
                        break
            except Exception as e:
                if not stop.is_set():
                    errors.append(f"Rapid WS error: {e}")

        def slow_http():
            try:
                for i in range(5):
                    if stop.is_set():
                        break
                    status, _, body = make_http_request(f"/api/during-rapid-ws/{i}")
                    if status != 200:
                        errors.append(f"HTTP during rapid WS {i}: status {status}")
                    time.sleep(0.05)
            except Exception as e:
                errors.append(f"HTTP during rapid WS error: {e}")

        t1 = threading.Thread(target=rapid_ws)
        t2 = threading.Thread(target=slow_http)
        t1.start()
        t2.start()
        t1.join(timeout=20)
        t2.join(timeout=20)
        stop.set()

        try:
            ws.sendall(ws_frame(b"", opcode=0x8))
        except Exception:
            pass
        ws.close()

        assert not errors, f"Rapid WS + HTTP errors: {errors}"

    def test_multiple_keepalive_connections_with_ws_lifecycle(self, mixed_proxy):
        """
        Multiple HTTP keep-alive connections + WS lifecycle (open/close/reopen).
        Simulates a real browser session with connection pooling.
        """
        # Open 2 HTTP keep-alive connections
        ka1 = make_ssl_connection()
        ka2 = make_ssl_connection()
        try:
            # Initial HTTP requests
            ka1.sendall(f"GET /api/pool/1 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode())
            status, _, _ = read_http_response(ka1)
            assert status == 200

            ka2.sendall(f"GET /api/pool/2 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode())
            status, _, _ = read_http_response(ka2)
            assert status == 200

            # Open WS
            ws = make_ws_connection()
            try:
                ws.sendall(ws_frame(b"pool-test"))
                assert read_ws_frame(ws) == b"pool-test"

                # Use HTTP connections while WS open
                ka1.sendall(f"GET /api/pool/3 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode())
                status, _, body = read_http_response(ka1)
                assert status == 200
                assert json.loads(body)["path"] == "/api/pool/3"

                ka2.sendall(f"GET /api/pool/4 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode())
                status, _, body = read_http_response(ka2)
                assert status == 200
                assert json.loads(body)["path"] == "/api/pool/4"

                # WS activity between HTTP requests
                ws.sendall(ws_frame(b"between-http"))
                assert read_ws_frame(ws) == b"between-http"

                # More HTTP
                ka1.sendall(f"GET /api/pool/5 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode())
                status, _, _ = read_http_response(ka1)
                assert status == 200

            finally:
                ws.sendall(ws_frame(b"", opcode=0x8))
                ws.close()

            # HTTP still works after WS close
            ka2.sendall(f"GET /api/pool/6 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode())
            status, _, _ = read_http_response(ka2)
            assert status == 200

            # Reopen WS
            ws2 = make_ws_connection()
            try:
                ws2.sendall(ws_frame(b"pool-test-2"))
                assert read_ws_frame(ws2) == b"pool-test-2"

                ka1.sendall(f"GET /api/pool/7 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode())
                status, _, _ = read_http_response(ka1)
                assert status == 200
            finally:
                ws2.sendall(ws_frame(b"", opcode=0x8))
                ws2.close()

        finally:
            ka1.close()
            ka2.close()

    def test_http_post_with_body_close_to_buffer_boundary_with_ws(self, mixed_proxy):
        """POST with body sizes near 32KB buffer boundary while WS active"""
        ws = make_ws_connection()
        try:
            # Test various sizes around buffer boundaries
            for size in [32 * 1024 - 512, 32 * 1024, 32 * 1024 + 512, 64 * 1024]:
                body = os.urandom(size)
                body_hash = hashlib.md5(body).hexdigest()

                status, _, resp = make_http_request(
                    f"/api/boundary/{size}", method="POST", body=body, timeout=15
                )
                assert status == 200, f"Size {size}: expected 200, got {status}"
                data = json.loads(resp)
                assert data["body_length"] == size, f"Size {size}: wrong body_length"
                assert data["body_hash"] == body_hash, f"Size {size}: body hash mismatch"

                # WS still works
                msg = f"after-{size}".encode()
                ws.sendall(ws_frame(msg))
                echoed = read_ws_frame(ws)
                assert echoed == msg
        finally:
            ws.sendall(ws_frame(b"", opcode=0x8))
            ws.close()

    def test_ws_abrupt_close_during_active_http_keepalive(self, mixed_proxy):
        """WS connection is abruptly closed while HTTP keep-alive requests are in flight"""
        ws = make_ws_connection()
        ws.sendall(ws_frame(b"setup"))
        read_ws_frame(ws)

        ssock = make_ssl_connection()
        try:
            # Start a keep-alive session
            ssock.sendall(
                f"GET /api/active-ka/1 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, _ = read_http_response(ssock)
            assert status == 200

            # Abruptly close WS mid-session
            ws.close()
            time.sleep(0.1)

            # HTTP keep-alive should still work
            ssock.sendall(
                f"GET /api/active-ka/2 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            assert json.loads(body)["path"] == "/api/active-ka/2"

            # Make more requests to be sure
            ssock.sendall(
                f"GET /api/active-ka/3 HTTP/1.1\r\nHost: {MIXED_DOMAIN}\r\nConnection: keep-alive\r\n\r\n".encode()
            )
            status, _, body = read_http_response(ssock)
            assert status == 200
            assert json.loads(body)["path"] == "/api/active-ka/3"
        finally:
            ssock.close()

    def test_many_ws_open_close_cycles_with_continuous_http(self, mixed_proxy):
        """
        Rapidly cycle WS connections while HTTP traffic is continuous.
        This is the most realistic simulation of SPA navigation.
        """
        errors = []
        stop = threading.Event()

        def continuous_http():
            """Continuously make HTTP requests"""
            try:
                for i in range(20):
                    if stop.is_set():
                        break
                    status, _, body = make_http_request(f"/api/continuous/{i}")
                    if status != 200:
                        errors.append(f"Continuous HTTP {i}: status {status}")
                    time.sleep(0.05)
            except Exception as e:
                errors.append(f"Continuous HTTP error: {e}")

        def cycling_ws():
            """Rapidly open and close WS connections"""
            try:
                for i in range(5):
                    if stop.is_set():
                        break
                    ws = make_ws_connection()
                    msg = f"cycle-{i}".encode()
                    ws.sendall(ws_frame(msg))
                    echoed = read_ws_frame(ws)
                    if echoed != msg:
                        errors.append(f"Cycling WS {i}: mismatch")
                    # Alternate between clean and abrupt close
                    if i % 2 == 0:
                        ws.sendall(ws_frame(b"", opcode=0x8))
                        ws.close()
                    else:
                        ws.close()
                    time.sleep(0.1)
            except Exception as e:
                errors.append(f"Cycling WS error: {e}")

        t1 = threading.Thread(target=continuous_http)
        t2 = threading.Thread(target=cycling_ws)
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)
        stop.set()

        assert not errors, f"Cycling errors: {errors}"
