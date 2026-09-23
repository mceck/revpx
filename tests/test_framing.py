#!/usr/bin/env python3
"""
Request-framing strictness tests for revpx.

revpx strips client-supplied Forwarded / X-Forwarded-* / X-Real-IP headers
only on the header blocks it recognises as request heads. Any byte it
classifies as body (chunk data, trailers, Content-Length payload) is passed
through verbatim. If revpx and the backend disagree on where a request ends,
the bytes revpx forwards as "body" can be parsed by the backend as a new
request whose spoofed forwarded headers were never stripped.

Lenient parsers (e.g. Go net/http) accept bare LF line terminators in
headers, chunk-size lines and trailers. revpx must therefore reject
ambiguous framing (bare LF, stray CR, obs-fold, malformed field names)
instead of passing it through.

The backend here is a raw TCP socket that records every byte it receives,
so the assertions do not depend on any particular backend parser.
"""

import asyncio
import os
import socket
import ssl
import sys
import threading
import time
from typing import List, Optional

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_revpx import RevPxProxy, TEST_DOMAIN  # noqa: E402


# Distinct ports so this file can run in parallel with the others.
HTTPS_PORT = 16443
HTTP_PORT = 16480
BACKEND_PORT = 16400

SPOOFED_IP = b"6.6.6.6"

pytestmark = pytest.mark.asyncio


class RawCaptureBackend:
    """TCP backend that records raw bytes and answers every connection once."""

    RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

    def __init__(self, port: int):
        self.port = port
        self.captured: List[bytes] = []
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        if self._sock:
            self._sock.close()

    def reset(self):
        with self._lock:
            self.captured.clear()

    def all_bytes(self) -> bytes:
        with self._lock:
            return b"".join(self.captured)

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket):
        data = b""
        conn.settimeout(0.3)
        try:
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            if data:
                conn.sendall(self.RESPONSE)
        except OSError:
            pass
        finally:
            with self._lock:
                self.captured.append(data)
            conn.close()


@pytest_asyncio.fixture(scope="module")
async def backend():
    server = RawCaptureBackend(BACKEND_PORT)
    await asyncio.to_thread(server.start)
    yield server
    await asyncio.to_thread(server.stop)


@pytest_asyncio.fixture(scope="module")
async def proxy(backend):
    p = RevPxProxy(https_port=HTTPS_PORT, http_port=HTTP_PORT, backend_port=BACKEND_PORT)
    await p.start()
    yield p
    await p.stop()


@pytest.fixture(autouse=True)
def reset_backend(backend):
    backend.reset()
    yield


async def send_raw(data: bytes, timeout: float = 3.0) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", HTTPS_PORT, ssl=ctx, server_hostname=TEST_DOMAIN
    )
    try:
        writer.write(data)
        await writer.drain()
        response = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=deadline - time.monotonic())
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            response += chunk
        return response
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def status_of(response: bytes) -> Optional[int]:
    if not response.startswith(b"HTTP/1.1 "):
        return None
    return int(response[9:12])


async def settle(backend: RawCaptureBackend) -> bytes:
    # Backend handler records bytes after a short idle period.
    await asyncio.sleep(0.5)
    return backend.all_bytes()


H = f"Host: {TEST_DOMAIN}".encode()

SMUGGLED = (
    b"GET /admin HTTP/1.1\r\n" + H + b"\r\n"
    b"X-Forwarded-For: " + SPOOFED_IP + b"\r\n"
    b"X-Real-IP: " + SPOOFED_IP + b"\r\n\r\n"
)


# ============================================================================
# Smuggling via chunked framing
# ============================================================================

class TestChunkedFramingSmuggling:
    async def test_trailer_terminated_by_bare_lf(self, proxy, backend):
        """A bare-LF-terminated trailer section must not hide a second request."""
        payload = (
            b"POST / HTTP/1.1\r\n" + H + b"\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"0\r\n\n" + SMUGGLED
        )
        response = await send_raw(payload)
        seen = await settle(backend)
        assert SPOOFED_IP not in seen, f"spoofed header reached backend unstripped:\n{seen!r}"
        assert status_of(response) == 400

    async def test_last_chunk_bare_lf(self, proxy, backend):
        """`0\\n\\n` is a complete message for lenient parsers."""
        payload = (
            b"POST / HTTP/1.1\r\n" + H + b"\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"0\n\n" + SMUGGLED
        )
        response = await send_raw(payload)
        seen = await settle(backend)
        assert SPOOFED_IP not in seen, f"spoofed header reached backend unstripped:\n{seen!r}"
        assert status_of(response) == 400

    async def test_trailer_field_bare_lf(self, proxy, backend):
        payload = (
            b"POST / HTTP/1.1\r\n" + H + b"\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"0\r\nX-Trailer: a\n\r\n" + SMUGGLED
        )
        response = await send_raw(payload)
        seen = await settle(backend)
        assert SPOOFED_IP not in seen, f"spoofed header reached backend unstripped:\n{seen!r}"
        assert status_of(response) == 400

    @pytest.mark.parametrize("size_line", [
        b"5\n",          # bare LF
        b"5\r\r\n",      # stray CR
        b"\r\n",         # empty chunk size
        b"5 x\r\n",      # garbage after BWS, not an extension
        b"5\r;ext\r\n",  # CR inside the size line
    ])
    async def test_malformed_chunk_size_line_rejected(self, proxy, backend, size_line):
        payload = (
            b"POST / HTTP/1.1\r\n" + H + b"\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + size_line + b"hello\r\n0\r\n\r\n"
        )
        response = await send_raw(payload)
        assert status_of(response) == 400, response

    @pytest.mark.parametrize("size_line", [
        b"5\r\n",
        b"5;name=value\r\n",
        b"5 ;name\r\n",
        b"0005\r\n",
    ])
    async def test_valid_chunk_size_lines_accepted(self, proxy, backend, size_line):
        payload = (
            b"POST / HTTP/1.1\r\n" + H + b"\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + size_line + b"hello\r\n0\r\nX-Trailer: t\r\n\r\n"
        )
        response = await send_raw(payload)
        assert status_of(response) == 200, response
        seen = await settle(backend)
        assert b"hello" in seen


# ============================================================================
# Smuggling via header-block framing
# ============================================================================

class TestHeaderFramingSmuggling:
    async def test_bare_lf_header_block_rejected(self, proxy, backend):
        """
        A lenient backend ends the first request at `\\n\\n`, revpx only at
        `\\r\\n\\r\\n`. The first request then reaches the backend without any
        revpx-injected X-Forwarded-For, and the rest is parsed as a new request.
        """
        payload = (
            b"GET / HTTP/1.1\n" + H + b"\n\n"
            + SMUGGLED
        )
        response = await send_raw(payload)
        seen = await settle(backend)
        assert SPOOFED_IP not in seen, f"spoofed header reached backend unstripped:\n{seen!r}"
        assert status_of(response) == 400
        assert b"GET / HTTP/1.1" not in seen

    async def test_bare_lf_in_keepalive_second_request(self, proxy, backend):
        payload = (
            b"GET /one HTTP/1.1\r\n" + H + b"\r\n\r\n"
            b"GET /two HTTP/1.1\n" + H + b"\n\n"
            + SMUGGLED
        )
        response = await send_raw(payload)
        seen = await settle(backend)
        assert SPOOFED_IP not in seen, f"spoofed header reached backend unstripped:\n{seen!r}"
        assert b"GET /two" not in seen

    @pytest.mark.parametrize("header", [
        b"Transfer-Encoding : chunked",     # whitespace before colon
        b"X-Foo: a\r\n\tX-Continued: b",   # obs-fold
        b"X-Foo: a\r\n X-Continued: b",
        b"Bad Name: value",                 # space inside field name
        b"NoColonHere",
        b": empty-name",
    ])
    async def test_malformed_field_lines_rejected(self, proxy, backend, header):
        payload = b"GET / HTTP/1.1\r\n" + H + b"\r\n" + header + b"\r\n\r\n"
        response = await send_raw(payload)
        seen = await settle(backend)
        assert status_of(response) == 400, response
        assert b"GET / HTTP/1.1" not in seen

    async def test_forwarded_headers_still_stripped_on_valid_request(self, proxy, backend):
        payload = (
            b"GET / HTTP/1.1\r\n" + H + b"\r\n"
            b"x-forwarded-for: " + SPOOFED_IP + b"\r\n"
            b"X-Real-IP: " + SPOOFED_IP + b"\r\n"
            b"Forwarded: for=" + SPOOFED_IP + b"\r\n\r\n"
        )
        response = await send_raw(payload)
        seen = await settle(backend)
        assert status_of(response) == 200, response
        assert SPOOFED_IP not in seen
        assert b"X-Forwarded-For: 127.0.0.1" in seen
