#!/usr/bin/env python3
"""
Multipart-specific tests for revpx.

Targets the user-reported bug where proxying multipart/form-data PUT/POST
requests intermittently produces:
  - Rack::Multipart::EmptyContentError on the backend, or
  - Puma::HttpParserError ("Invalid HTTP format ... non-SSL Puma?")

Two suspected bugs in src/revpx.h:

  Bug A — find_headers_end on body remnants:
    forward_client_bytes() uses a single backend->buf for both header
    accumulation and (transiently) just-copied body bytes. When a single
    forward_client_bytes() invocation contains both the *end* of a request
    body AND the *start* of the next request, the body bytes from iter A
    stay in backend->buf and iter B's find_headers_end() scans them too.
    Multipart bodies contain CRLFCRLF (between part headers and part data),
    so find_headers_end() returns a position INSIDE the body, then
    forward_client_handle_complete_header() injects forwarded headers
    into what are actually body bytes and forwards garbage.

  Bug B — backend_reset_buffer after partial flush:
    forward_client_handle_complete_header() calls flush_buffer() then
    backend_reset_buffer() unconditionally. If flush_buffer() returned
    early on EAGAIN/WANT_WRITE (kernel TCP send buffer full), the
    unsent header bytes are then ZEROED by reset_buffer(). The body
    bytes that follow end up appended to a partial header, producing
    a malformed request that Puma rejects.

Tests aim to be deterministic where possible (pipelining triggers Bug A
directly, slow-reading backend exposes Bug B), with a stress section that
re-runs scenarios many times to surface anything intermittent.
"""

import asyncio
import hashlib
import json
import os
import random
import socket
import ssl
import sys
import threading
import time
from typing import Optional

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_revpx import (  # noqa: E402
    BackendServer,
    ProxyClient,
    RevPxProxy,
    TEST_DOMAIN,
    PROJECT_ROOT,
    CERT_FILE,
    KEY_FILE,
)


# Distinct ports so this file can run in parallel with the others.
HTTPS_PORT = 17443
HTTP_PORT = 17480
BACKEND_PORT = 17400


pytestmark = pytest.mark.asyncio


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


# ============================================================================
# Helpers
# ============================================================================

def make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def open_tls(host: str = TEST_DOMAIN, port: int = HTTPS_PORT):
    ctx = make_ssl_ctx()
    return await asyncio.open_connection(
        "127.0.0.1", port, ssl=ctx, server_hostname=host
    )


async def read_one_response(reader: asyncio.StreamReader, leftover: bytes = b""):
    """Read exactly one HTTP/1.1 response. Returns (status, headers, body, leftover).

    Interim 1xx responses (e.g. 100 Continue) are skipped — they are valid HTTP
    informational responses that precede the final response.
    """
    response = leftover
    while True:
        while b"\r\n\r\n" not in response:
            chunk = await reader.read(8192)
            if not chunk:
                raise ConnectionError(
                    f"connection closed before response headers; got {len(response)} bytes: {response[:200]!r}"
                )
            response += chunk

        head_end = response.index(b"\r\n\r\n") + 4
        head_raw = response[:head_end].decode(errors="replace")
        status_line = head_raw.split("\r\n", 1)[0]
        parts = status_line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise ValueError(f"malformed status line: {status_line!r}")
        status = int(parts[1])

        # 1xx interim (except 101 which switches protocols and isn't a normal response):
        # skip and read the next one. The interim response has no body.
        if 100 <= status < 200 and status != 101:
            response = response[head_end:]
            continue
        break

    body = response[head_end:]

    headers = {}
    for line in head_raw.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    chunked = headers.get("Transfer-Encoding", "").lower() == "chunked"
    content_length = int(headers.get("Content-Length", 0)) if not chunked else None

    if chunked:
        # Decode chunked progressively.
        decoded = b""
        buf = body
        done = False
        while not done:
            while True:
                idx = buf.find(b"\r\n")
                if idx >= 0:
                    break
                more = await reader.read(8192)
                if not more:
                    raise ConnectionError("connection closed mid-chunked-size")
                buf += more
            size_line = buf[:idx]
            size = int(size_line.split(b";")[0], 16)
            buf = buf[idx + 2:]
            if size == 0:
                # consume final CRLF after 0-chunk and any trailers
                while b"\r\n" not in buf:
                    more = await reader.read(8192)
                    if not more:
                        break
                    buf += more
                done = True
                # Drop trailing CRLF if present
                if buf.startswith(b"\r\n"):
                    buf = buf[2:]
                break
            while len(buf) < size + 2:
                more = await reader.read(8192)
                if not more:
                    raise ConnectionError("connection closed mid-chunk-data")
                buf += more
            decoded += buf[:size]
            buf = buf[size + 2:]
        return status, headers, decoded, buf

    cl = content_length or 0
    while len(body) < cl:
        chunk = await reader.read(8192)
        if not chunk:
            break
        body += chunk

    leftover = body[cl:]
    body = body[:cl]
    return status, headers, body, leftover


def build_multipart(boundary: str, fields: dict) -> bytes:
    """Build a multipart/form-data body. Mirrors the iOS scenario from the bug report."""
    parts = []
    for name, value in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            f'Content-Disposition: form-data; name="{name}"\r\n'.encode()
        )
        parts.append(b"\r\n")
        if isinstance(value, str):
            parts.append(value.encode())
        else:
            parts.append(value)
        parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)


def http_request(
    method: str,
    path: str,
    body: bytes,
    *,
    content_type: Optional[str] = None,
    keep_alive: bool = True,
    extra_headers: Optional[dict] = None,
    host: str = TEST_DOMAIN,
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1\r\n", f"Host: {host}\r\n"]
    if content_type:
        lines.append(f"Content-Type: {content_type}\r\n")
    if body or method in ("POST", "PUT", "PATCH"):
        lines.append(f"Content-Length: {len(body)}\r\n")
    lines.append(f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n")
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}\r\n")
    lines.append("\r\n")
    return "".join(lines).encode() + body


def assert_clean_response(status: int, headers: dict, body: bytes, label: str):
    assert status == 200, f"{label}: expected 200, got {status}; body={body[:300]!r}"


# ============================================================================
# 1. TestMultipartBasic — sanity: single multipart works
# ============================================================================

class TestMultipartBasic:
    """Sanity checks: a plain multipart PUT/POST should always succeed."""

    async def test_multipart_put_text_fields_only(self, client):
        """Replicate the iOS scenario from the bug report.

        Mobile app log:
          PUT /v1/app_user_helmets/182 with fields:
              {purchasedAt: 2026-03-29T00:00:00.000Z, sync_image_processing: true}
          and files: []

        A multipart PUT with text-only fields, no files. Single isolated request.
        """
        boundary = "----alamofire.boundary.abcd1234"
        body = build_multipart(boundary, {
            "purchasedAt": "2026-03-29T00:00:00.000Z",
            "sync_image_processing": "true",
        })
        ct = f"multipart/form-data; boundary={boundary}"
        status, _, resp_body = await client.request(
            "PUT", "/v1/app_user_helmets/182",
            headers={"Content-Type": ct},
            body=body,
        )
        assert status == 200, f"single isolated multipart PUT must succeed; got {status}"
        data = json.loads(resp_body)
        assert data["body_length"] == len(body)
        assert data["body_hash"] == hashlib.md5(body).hexdigest()
        assert data["headers"]["Content-Type"] == ct

    async def test_multipart_post_small(self, client):
        boundary = "BBBB"
        body = build_multipart(boundary, {"x": "1", "y": "two"})
        status, _, resp_body = await client.request(
            "POST", "/upload",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            body=body,
        )
        assert status == 200
        data = json.loads(resp_body)
        assert data["body_hash"] == hashlib.md5(body).hexdigest()


# ============================================================================
# 2. TestMultipartKeepalive — same TLS connection, multiple requests
# ============================================================================

class TestMultipartKeepalive:
    """Multipart requests on a keep-alive TLS connection.

    Each subsequent request opens a fresh write, but client OS may coalesce
    bytes with whatever leftover the proxy holds, which is the trigger for
    Bug A. Also stresses the 'reuse same backend across requests' path.
    """

    async def test_multipart_then_get(self, proxy):
        """Multipart PUT, read response, then GET on same connection."""
        boundary = "----b1"
        body = build_multipart(boundary, {"a": "value-a", "b": "value-b"})
        reader, writer = await open_tls()
        try:
            writer.write(http_request(
                "PUT", "/v1/items/1", body,
                content_type=f"multipart/form-data; boundary={boundary}",
            ))
            await writer.drain()
            s1, _, b1, leftover = await read_one_response(reader)
            assert_clean_response(s1, {}, b1, "PUT multipart")
            d1 = json.loads(b1)
            assert d1["body_length"] == len(body)
            assert d1["body_hash"] == hashlib.md5(body).hexdigest()

            writer.write(http_request("GET", "/v1/items/1", b"", keep_alive=False))
            await writer.drain()
            s2, _, b2, _ = await read_one_response(reader, leftover)
            assert_clean_response(s2, {}, b2, "GET after multipart")
            d2 = json.loads(b2)
            assert d2["path"] == "/v1/items/1"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_many_multipart_keepalive(self, proxy):
        """Sequentially send many multipart PUTs on the SAME TLS connection.

        Stresses backend connection reuse and request boundary tracking.
        Loops a lot to surface intermittent timing issues.
        """
        reader, writer = await open_tls()
        try:
            leftover = b""
            for i in range(40):
                boundary = f"----loop{i}"
                fields = {
                    "purchasedAt": f"2026-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}T00:00:00.000Z",
                    "sync_image_processing": "true" if i % 2 == 0 else "false",
                    "n": str(i),
                }
                body = build_multipart(boundary, fields)
                writer.write(http_request(
                    "PUT", f"/v1/app_user_helmets/{i}", body,
                    content_type=f"multipart/form-data; boundary={boundary}",
                ))
                await writer.drain()
                status, _, resp_body, leftover = await asyncio.wait_for(
                    read_one_response(reader, leftover), timeout=10
                )
                assert status == 200, (
                    f"iteration {i}: status={status}; "
                    f"body[:200]={resp_body[:200]!r}"
                )
                d = json.loads(resp_body)
                assert d["body_length"] == len(body), f"iteration {i}: body length mismatch"
                assert d["body_hash"] == hashlib.md5(body).hexdigest(), (
                    f"iteration {i}: body hash mismatch — proxy corrupted body bytes"
                )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 3. TestMultipartPipelinedNextRequest — Bug A trigger
# ============================================================================

class TestMultipartPipelinedNextRequest:
    """Pipeline a multipart request immediately followed by another request.

    This is the deterministic trigger for Bug A: in the same TCP/TLS write,
    client sends [Req1 multipart with CRLFCRLF in body][Req2]. The proxy's
    forward_client_bytes() processes Req1's body in iter A then iter B
    starts header parsing, but find_headers_end() scans the WHOLE
    backend->buf — including the just-copied body bytes that contain
    CRLFCRLF between part headers and part data.
    """

    async def test_multipart_put_pipelined_with_get(self, proxy):
        """Multipart PUT immediately followed by a GET, single TLS write."""
        boundary = "----webkitformboundary7MA4YWxkTrZu0gW"
        body = build_multipart(boundary, {
            "purchasedAt": "2026-03-29T00:00:00.000Z",
            "sync_image_processing": "true",
        })
        # CRLFCRLF MUST be present inside the multipart body — that's the trigger.
        assert b"\r\n\r\n" in body, "test invariant: multipart body must contain CRLFCRLF"

        pipelined = (
            http_request(
                "PUT", "/v1/app_user_helmets/182", body,
                content_type=f"multipart/form-data; boundary={boundary}",
            )
            + http_request("GET", "/v1/app_user_helmets/182", b"", keep_alive=False)
        )

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            s1, _, b1, leftover = await asyncio.wait_for(
                read_one_response(reader), timeout=10
            )
            assert s1 == 200, (
                f"Req1 (multipart PUT) returned {s1}. "
                f"This indicates the proxy mangled the request before it reached the backend.\n"
                f"Response body: {b1[:400]!r}"
            )
            d1 = json.loads(b1)
            assert d1["path"] == "/v1/app_user_helmets/182"
            assert d1["body_hash"] == hashlib.md5(body).hexdigest(), (
                "Req1 body was corrupted — backend received different bytes than client sent. "
                "This is consistent with Bug A: forward_client_bytes treating multipart "
                "body bytes as the start of headers for a fake request."
            )

            s2, _, b2, _ = await asyncio.wait_for(
                read_one_response(reader, leftover), timeout=10
            )
            assert s2 == 200, (
                f"Req2 (GET) returned {s2}. "
                f"This indicates the proxy lost or corrupted the second request after a "
                f"multipart body — likely the result of find_headers_end matching CRLFCRLF "
                f"inside Req1's multipart body and then mis-parsing the rest.\n"
                f"Response body: {b2[:400]!r}"
            )
            d2 = json.loads(b2)
            assert d2["path"] == "/v1/app_user_helmets/182"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_multipart_post_pipelined_with_multipart(self, proxy):
        """Two multipart POSTs back-to-back in one TLS write."""
        b1 = "----b1xxx"
        b2 = "----b2yyy"
        body1 = build_multipart(b1, {"x": "first", "y": "value-1"})
        body2 = build_multipart(b2, {"x": "second", "y": "value-2"})

        pipelined = (
            http_request(
                "POST", "/upload/1", body1,
                content_type=f"multipart/form-data; boundary={b1}",
            )
            + http_request(
                "POST", "/upload/2", body2,
                content_type=f"multipart/form-data; boundary={b2}",
                keep_alive=False,
            )
        )

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            s1, _, rb1, leftover = await asyncio.wait_for(read_one_response(reader), timeout=10)
            assert s1 == 200, f"first multipart POST: status={s1}, body={rb1[:300]!r}"
            d1 = json.loads(rb1)
            assert d1["body_hash"] == hashlib.md5(body1).hexdigest()
            assert d1["path"] == "/upload/1"

            s2, _, rb2, _ = await asyncio.wait_for(read_one_response(reader, leftover), timeout=10)
            assert s2 == 200, f"second multipart POST: status={s2}, body={rb2[:300]!r}"
            d2 = json.loads(rb2)
            assert d2["body_hash"] == hashlib.md5(body2).hexdigest()
            assert d2["path"] == "/upload/2"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_post_with_crlfcrlf_body_pipelined_with_get(self, proxy):
        """Minimal Bug A trigger: any POST whose body literally contains CRLFCRLF."""
        # Crafted body that mimics a multipart structure: contains CRLFCRLF
        # between "part headers" and "part data". No actual multipart Content-Type;
        # this is a controlled minimal repro of Bug A.
        body = (
            b"--BOUND\r\n"
            b"Content-Disposition: form-data; name=\"x\"\r\n"
            b"\r\n"   # <-- the dangerous CRLFCRLF inside the body
            b"hello-world\r\n"
            b"--BOUND--\r\n"
        )
        assert b"\r\n\r\n" in body

        pipelined = (
            http_request(
                "POST", "/crlf-body", body,
                content_type="application/octet-stream",
            )
            + http_request("GET", "/after", b"", keep_alive=False)
        )

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            s1, _, rb1, leftover = await asyncio.wait_for(read_one_response(reader), timeout=10)
            assert s1 == 200, (
                f"POST with CRLFCRLF body got status={s1}. body={rb1[:300]!r}"
            )
            d1 = json.loads(rb1)
            assert d1["path"] == "/crlf-body"
            assert d1["body_hash"] == hashlib.md5(body).hexdigest()

            s2, _, rb2, _ = await asyncio.wait_for(read_one_response(reader, leftover), timeout=10)
            assert s2 == 200, (
                f"GET after CRLFCRLF body got status={s2}. body={rb2[:300]!r}"
            )
            d2 = json.loads(rb2)
            assert d2["path"] == "/after"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 4. TestMultipartFragmentation — small TLS records / split sends
# ============================================================================

class TestMultipartFragmentation:
    """Send the multipart request split across many small writes/records.

    Each writer.write() typically becomes its own TLS record, which means
    the proxy will see multiple SSL_read() boundaries within a single
    request. Designed to surface ordering/reassembly bugs.
    """

    async def test_multipart_byte_by_byte(self, proxy):
        """Send a multipart PUT one byte at a time. Slow but catches re-entry bugs."""
        boundary = "----frag1"
        body = build_multipart(boundary, {"k": "value-with-some-bytes"})
        request = http_request(
            "PUT", "/frag", body,
            content_type=f"multipart/form-data; boundary={boundary}",
            keep_alive=False,
        )

        reader, writer = await open_tls()
        try:
            for i, byte in enumerate(request):
                writer.write(bytes([byte]))
                if i % 64 == 0:
                    await writer.drain()
                    # Tiny pause every 64 bytes to encourage TLS records to flush.
                    await asyncio.sleep(0.001)
            await writer.drain()

            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader), timeout=15
            )
            assert status == 200, f"byte-by-byte multipart: status={status}, body={resp_body[:300]!r}"
            d = json.loads(resp_body)
            assert d["body_hash"] == hashlib.md5(body).hexdigest()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_multipart_split_at_crlfcrlf_body_boundary(self, proxy):
        """Split the request specifically at the CRLFCRLF inside the body.

        Probes whether the proxy ever scans backend->buf for CRLFCRLF after
        already having advanced to body-forwarding mode.
        """
        boundary = "----splitB"
        body = build_multipart(boundary, {"a": "first-value", "b": "second-value"})
        request = http_request(
            "PUT", "/split-body", body,
            content_type=f"multipart/form-data; boundary={boundary}",
            keep_alive=False,
        )

        # Find each CRLFCRLF position inside the body (the part-header separators).
        positions = []
        head_end = request.index(b"\r\n\r\n") + 4
        i = head_end
        while True:
            j = request.find(b"\r\n\r\n", i)
            if j == -1:
                break
            positions.append(j + 4)
            i = j + 4
        assert positions, "test invariant: body should have CRLFCRLF inside"

        reader, writer = await open_tls()
        try:
            cursor = 0
            for split in positions:
                writer.write(request[cursor:split])
                await writer.drain()
                await asyncio.sleep(0.005)
                cursor = split
            writer.write(request[cursor:])
            await writer.drain()

            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader), timeout=15
            )
            assert status == 200, (
                f"split-at-CRLFCRLF multipart: status={status}, body={resp_body[:300]!r}"
            )
            d = json.loads(resp_body)
            assert d["body_hash"] == hashlib.md5(body).hexdigest()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 5. TestMultipartLargeBody — body crosses 32KB buffer boundary
# ============================================================================

class TestMultipartLargeBody:
    """Multipart with body sizes around the proxy's RP_BUF_SIZE (32KB)."""

    @pytest.mark.parametrize("file_size", [
        1024,            # small
        16 * 1024,       # half buffer
        31 * 1024,       # just below buffer
        32 * 1024 + 1,   # just over buffer (forces split read)
        100 * 1024,      # several reads
        500 * 1024,      # half a megabyte
    ])
    async def test_multipart_with_file(self, client, file_size):
        boundary = "----largefile"
        random.seed(file_size)
        file_bytes = bytes(random.randrange(256) for _ in range(file_size))
        body = build_multipart(boundary, {
            "metadata": "some-metadata-string",
            "file": file_bytes,
        })
        status, _, resp_body = await client.request(
            "POST", "/large-multipart",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            body=body,
            timeout=30,
        )
        assert status == 200, f"file_size={file_size}: status={status}; body={resp_body[:300]!r}"
        d = json.loads(resp_body)
        assert d["body_length"] == len(body), f"file_size={file_size}: backend received {d['body_length']} != client sent {len(body)}"
        assert d["body_hash"] == hashlib.md5(body).hexdigest(), (
            f"file_size={file_size}: backend body hash differs from client. "
            "Proxy corrupted bytes in transit."
        )

    async def test_multipart_pipelined_large_body_with_get(self, proxy):
        """Large multipart POST + GET in the same write — exercises the path
        where the body spans many proxy reads, then iter B inside the LAST
        forward_client_bytes() picks up the next request's headers."""
        boundary = "----largepipe"
        random.seed(42)
        file_bytes = bytes(random.randrange(256) for _ in range(80 * 1024))
        body = build_multipart(boundary, {"file": file_bytes, "name": "x"})

        pipelined = (
            http_request(
                "POST", "/big-pipe/1", body,
                content_type=f"multipart/form-data; boundary={boundary}",
            )
            + http_request("GET", "/after-big-pipe", b"", keep_alive=False)
        )

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            s1, _, rb1, leftover = await asyncio.wait_for(read_one_response(reader), timeout=20)
            assert s1 == 200, f"large multipart pipelined: status={s1}, body={rb1[:300]!r}"
            d1 = json.loads(rb1)
            assert d1["body_length"] == len(body)
            assert d1["body_hash"] == hashlib.md5(body).hexdigest()

            s2, _, rb2, _ = await asyncio.wait_for(read_one_response(reader, leftover), timeout=20)
            assert s2 == 200, f"GET after large multipart: status={s2}, body={rb2[:300]!r}"
            d2 = json.loads(rb2)
            assert d2["path"] == "/after-big-pipe"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 6. TestMultipartConcurrent — parallel clients
# ============================================================================

class TestMultipartConcurrent:
    """Many concurrent TLS connections each sending multipart simultaneously."""

    async def test_concurrent_multipart_uploads(self, proxy):
        async def one_upload(i: int):
            boundary = f"----conc{i}"
            random.seed(i + 1000)
            blob = bytes(random.randrange(256) for _ in range(8 * 1024))
            body = build_multipart(boundary, {
                "id": str(i),
                "tag": f"tag-{i}",
                "blob": blob,
            })
            c = ProxyClient(port=HTTPS_PORT)
            status, _, resp_body = await c.request(
                "PUT", f"/conc/{i}",
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                body=body,
                timeout=30,
            )
            return i, status, resp_body, body

        results = await asyncio.gather(*(one_upload(i) for i in range(16)))
        for i, status, resp_body, body in results:
            assert status == 200, f"client {i}: status={status}, body={resp_body[:200]!r}"
            d = json.loads(resp_body)
            assert d["body_length"] == len(body), f"client {i}: backend body length mismatch"
            assert d["body_hash"] == hashlib.md5(body).hexdigest(), (
                f"client {i}: body hash mismatch — bytes corrupted under concurrency"
            )


# ============================================================================
# 7. TestMultipartPartialFlushBackend — Bug B trigger
# ============================================================================

class TestMultipartPartialFlushBackend:
    """Run a slow-reading backend so the proxy's TCP send buffer fills up.

    Targets Bug B (forward_client_handle_complete_header → flush_buffer →
    backend_reset_buffer): if the kernel can't accept all the modified
    headers in one write, backend_reset_buffer wipes the unsent header
    bytes, then the body bytes follow into a partial header. Puma rejects
    the malformed request.

    To make this deterministic we use a local raw-socket backend that
    accepts the connection, shrinks its receive buffer to a small size
    via SO_RCVBUF, and sleeps before draining. That keeps the proxy's
    write-side blocked long enough to manifest a partial flush.
    """

    async def test_multipart_against_slow_backend(self):
        slow_port = 17501
        slow_domain = "slowmultipart.localhost"
        https_port = 17543
        http_port = 17580

        backend_state: dict = {"received": None, "error": None, "request_line": None}

        def backend_worker():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Keep listen-side rcvbuf small so accepted sockets inherit it.
            try:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            except OSError:
                pass
            srv.bind(("127.0.0.1", slow_port))
            srv.listen(1)
            srv.settimeout(10.0)

            try:
                conn, _ = srv.accept()
            except Exception as exc:
                backend_state["error"] = f"accept failed: {exc!r}"
                srv.close()
                return

            try:
                # Stall long enough to force the proxy → backend write side to block.
                time.sleep(0.5)

                conn.settimeout(15.0)
                received = b""
                while b"\r\n\r\n" not in received:
                    chunk = conn.recv(4096)
                    if not chunk:
                        backend_state["error"] = "connection closed before headers complete"
                        return
                    received += chunk
                    # Keep stalling between reads to amplify partial-flush window.
                    time.sleep(0.01)

                head_end = received.index(b"\r\n\r\n") + 4
                headers_raw = received[:head_end].decode(errors="ignore")
                backend_state["request_line"] = headers_raw.split("\r\n", 1)[0]

                cl = 0
                for line in headers_raw.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        cl = int(line.split(":", 1)[1].strip())
                        break

                body = received[head_end:]
                while len(body) < cl:
                    chunk = conn.recv(min(4096, cl - len(body)))
                    if not chunk:
                        backend_state["error"] = (
                            f"connection closed mid-body: got {len(body)}/{cl} bytes"
                        )
                        return
                    body += chunk

                backend_state["received"] = body

                resp_obj = {
                    "received": len(body),
                    "declared": cl,
                    "body_hash": hashlib.md5(body).hexdigest(),
                }
                resp_body = json.dumps(resp_obj).encode()
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(resp_body)}\r\n".encode()
                    + b"Content-Type: application/json\r\n"
                    + b"Connection: close\r\n\r\n"
                    + resp_body
                )
            except Exception as exc:
                backend_state["error"] = f"backend exception: {exc!r}"
            finally:
                conn.close()
                srv.close()

        t = threading.Thread(target=backend_worker, daemon=True)
        t.start()

        from test_edge_cases import async_start_revpx, async_stop_process  # noqa: E402

        config_file = os.path.join(PROJECT_ROOT, "tests", "test_multipart_slow_config.json")
        config = [{
            "domain": slow_domain,
            "port": str(slow_port),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
        }]
        with open(config_file, "w") as f:
            json.dump(config, f)

        proc = await async_start_revpx(config_file, https_port=https_port, http_port=http_port)

        try:
            boundary = "----slowmp"
            random.seed(7)
            file_bytes = bytes(random.randrange(256) for _ in range(64 * 1024))
            body = build_multipart(boundary, {
                "purchasedAt": "2026-03-29T00:00:00.000Z",
                "sync_image_processing": "true",
                "file": file_bytes,
            })
            request = http_request(
                "PUT", "/v1/app_user_helmets/182", body,
                content_type=f"multipart/form-data; boundary={boundary}",
                keep_alive=False,
                host=slow_domain,
            )

            ctx = make_ssl_ctx()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", https_port, ssl=ctx, server_hostname=slow_domain
            )
            try:
                writer.write(request)
                await writer.drain()

                status, _, resp_body, _ = await asyncio.wait_for(
                    read_one_response(reader), timeout=30
                )
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            t.join(timeout=10.0)

            assert backend_state["error"] is None, (
                f"backend error (probably caused by malformed proxy → backend traffic): "
                f"{backend_state['error']}; request_line={backend_state['request_line']!r}"
            )
            assert backend_state["request_line"] is not None
            assert backend_state["request_line"].startswith("PUT /v1/app_user_helmets/182"), (
                f"backend saw a corrupted request line: {backend_state['request_line']!r}; "
                "this is what Puma reports as 'Invalid HTTP format' under the multipart bug"
            )
            assert backend_state["received"] is not None and len(backend_state["received"]) == len(body), (
                f"backend received {len(backend_state['received']) if backend_state['received'] else 0} body bytes; "
                f"expected {len(body)}. Indicates Bug B (partial header flush dropped, body bytes "
                f"end up in a malformed request) or another truncation."
            )
            assert backend_state["received"] == body, (
                "backend body bytes differ from client-sent bytes"
            )

            assert status == 200, f"client got status={status}; resp_body[:300]={resp_body[:300]!r}"
            result = json.loads(resp_body)
            assert result["received"] == len(body)
            assert result["body_hash"] == hashlib.md5(body).hexdigest()
        finally:
            await async_stop_process(proc, timeout=5.0)
            if os.path.exists(config_file):
                os.remove(config_file)
            t.join(timeout=2.0)


# ============================================================================
# 8. TestMultipartStress — soak test, catches intermittent failures
# ============================================================================

class TestMultipartStress:
    """Repeat various multipart scenarios many times to surface flakiness.

    The user described the bug as "non sistematico" (non-systematic /
    intermittent). Iterating with varied sizes, varied boundaries, and
    different connection patterns is the practical way to catch it.
    """

    async def test_repeat_pipelined_multipart_get(self, proxy):
        """Run the pipelined-multipart-then-GET scenario many times in a row."""
        ITERATIONS = 25
        for it in range(ITERATIONS):
            boundary = f"----stress{it}-{random.randint(0, 1 << 30)}"
            random.seed(it)
            extra = random.randrange(0, 4096)
            body = build_multipart(boundary, {
                "purchasedAt": f"2026-{(it % 12) + 1:02d}-15T00:00:00.000Z",
                "sync_image_processing": "true",
                "padding": "x" * extra,
            })
            pipelined = (
                http_request(
                    "PUT", f"/v1/app_user_helmets/{it}", body,
                    content_type=f"multipart/form-data; boundary={boundary}",
                )
                + http_request("GET", f"/follow-up/{it}", b"", keep_alive=False)
            )

            reader, writer = await open_tls()
            try:
                writer.write(pipelined)
                await writer.drain()

                s1, _, rb1, leftover = await asyncio.wait_for(
                    read_one_response(reader), timeout=15
                )
                assert s1 == 200, f"iter {it}: PUT status={s1}, body={rb1[:300]!r}"
                d1 = json.loads(rb1)
                assert d1["body_hash"] == hashlib.md5(body).hexdigest(), (
                    f"iter {it}: PUT body corrupted"
                )

                s2, _, rb2, _ = await asyncio.wait_for(
                    read_one_response(reader, leftover), timeout=15
                )
                assert s2 == 200, f"iter {it}: GET status={s2}, body={rb2[:300]!r}"
                d2 = json.loads(rb2)
                assert d2["path"] == f"/follow-up/{it}"
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def test_random_multipart_workload(self, proxy):
        """Send many multipart requests with randomized sizes and field counts.

        Each iteration uses its own TLS connection (the existing test
        BackendServer is single-threaded HTTPServer, so a long-lived shared
        keep-alive would block one-shot iterations from being served). 30%
        of iterations pipeline a GET behind the multipart request to keep
        exercising the Bug A path under varied data shapes.
        """
        random.seed(20260507)
        ITERATIONS = 30

        for it in range(ITERATIONS):
            boundary = f"----rnd{it}-{random.randint(0, 1 << 24)}"
            fields = {}
            for j in range(random.randint(1, 5)):
                fields[f"f{j}"] = "v" * random.randint(0, 200)
            if random.random() < 0.4:
                fields["blob"] = bytes(random.randrange(256) for _ in range(random.randint(0, 40 * 1024)))
            body = build_multipart(boundary, fields)

            pipeline_after = random.random() < 0.3
            method = "PUT" if random.random() < 0.5 else "POST"

            req = http_request(
                method,
                f"/rnd/{it}",
                body,
                content_type=f"multipart/form-data; boundary={boundary}",
                keep_alive=pipeline_after,
            )
            if pipeline_after:
                req += http_request(
                    "GET",
                    f"/rnd/follow/{it}",
                    b"",
                    keep_alive=False,
                )

            reader, writer = await open_tls()
            try:
                writer.write(req)
                await writer.drain()
                s1, _, rb1, leftover = await asyncio.wait_for(
                    read_one_response(reader), timeout=20
                )
                assert s1 == 200, (
                    f"iter {it} (pipeline_after={pipeline_after}, body_size={len(body)}): "
                    f"status={s1}, body={rb1[:300]!r}"
                )
                d1 = json.loads(rb1)
                assert d1["body_hash"] == hashlib.md5(body).hexdigest(), (
                    f"iter {it} (body_size={len(body)}): body corrupted"
                )
                if pipeline_after:
                    s2, _, rb2, _ = await asyncio.wait_for(
                        read_one_response(reader, leftover), timeout=20
                    )
                    assert s2 == 200, f"iter {it} pipelined GET: status={s2}, body={rb2[:300]!r}"
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


# ============================================================================
# 9. TestPipelinedDeepChain — 3+ pipelined multipart requests
# ============================================================================

class TestPipelinedDeepChain:
    """Multiple multipart requests pipelined in a single TLS write.

    Each one has CRLFCRLF inside its body (multipart). After Bug A fix,
    forward_client_replay_leftover gets called once per request boundary,
    chaining recursively. Verifies the chain works for 3, 5, 8 requests.
    """

    @pytest.mark.parametrize("count", [3, 5, 8])
    async def test_chain_pipelined_multiparts(self, proxy, count):
        bodies = []
        pipelined = b""
        for i in range(count):
            boundary = f"----chain{i}"
            body = build_multipart(boundary, {
                "purchasedAt": f"2026-{(i % 12) + 1:02d}-15T00:00:00.000Z",
                "sync_image_processing": "true",
                "n": str(i),
            })
            bodies.append(body)
            pipelined += http_request(
                "PUT",
                f"/v1/chain/{i}",
                body,
                content_type=f"multipart/form-data; boundary={boundary}",
                keep_alive=(i < count - 1),
            )

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            leftover = b""
            for i in range(count):
                status, _, resp_body, leftover = await asyncio.wait_for(
                    read_one_response(reader, leftover), timeout=15
                )
                assert status == 200, (
                    f"chain[{i}]: status={status}, body={resp_body[:300]!r}; "
                    f"chain depth {count}"
                )
                d = json.loads(resp_body)
                assert d["path"] == f"/v1/chain/{i}", f"chain[{i}]: wrong path"
                assert d["body_hash"] == hashlib.md5(bodies[i]).hexdigest(), (
                    f"chain[{i}]: body corrupted at depth {count}"
                )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 10. TestPipelinedMixedEncoding — CL + chunked mixed in pipelining
# ============================================================================

class TestPipelinedMixedEncoding:
    """Pipeline a Content-Length multipart with a chunked multipart and vice versa.

    The proxy uses different code paths for CL vs chunked. Mixing them in
    pipelining tests both paths' replay_leftover handling.
    """

    async def test_cl_multipart_then_chunked_request(self, proxy):
        b1 = "----mixedA"
        body1 = build_multipart(b1, {"a": "first", "b": "second"})

        # Chunked second request: chunked body equivalent of "hello-chunked"
        chunk_data = b"hello-chunked"
        chunked_body = f"{len(chunk_data):x}\r\n".encode() + chunk_data + b"\r\n0\r\n\r\n"
        req2 = (
            f"POST /chunked-after HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + chunked_body

        pipelined = http_request(
            "PUT", "/cl-multipart", body1,
            content_type=f"multipart/form-data; boundary={b1}",
        ) + req2

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            s1, _, rb1, leftover = await asyncio.wait_for(read_one_response(reader), timeout=10)
            assert s1 == 200, f"CL multipart: status={s1}, body={rb1[:300]!r}"
            d1 = json.loads(rb1)
            assert d1["body_hash"] == hashlib.md5(body1).hexdigest()

            s2, _, rb2, _ = await asyncio.wait_for(read_one_response(reader, leftover), timeout=10)
            assert s2 == 200, f"chunked after multipart: status={s2}, body={rb2[:300]!r}"
            d2 = json.loads(rb2)
            assert d2["path"] == "/chunked-after"
            assert d2["body_length"] == len(chunk_data)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_chunked_multipart_then_cl_request(self, proxy):
        """Chunked multipart first, then a CL-based request after."""
        b1 = "----mixedB"
        body1 = build_multipart(b1, {"x": "value-x"})
        # Wrap multipart body in a single chunk
        chunked = f"{len(body1):x}\r\n".encode() + body1 + b"\r\n0\r\n\r\n"

        req1 = (
            f"PUT /chunked-multipart HTTP/1.1\r\n"
            f"Host: {TEST_DOMAIN}\r\n"
            f"Content-Type: multipart/form-data; boundary={b1}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + chunked

        body2 = b"plain-body-after"
        req2 = http_request(
            "POST", "/cl-after-chunked", body2,
            content_type="text/plain",
            keep_alive=False,
        )

        reader, writer = await open_tls()
        try:
            writer.write(req1 + req2)
            await writer.drain()

            s1, _, rb1, leftover = await asyncio.wait_for(read_one_response(reader), timeout=10)
            assert s1 == 200, f"chunked multipart: status={s1}, body={rb1[:300]!r}"
            d1 = json.loads(rb1)
            assert d1["body_hash"] == hashlib.md5(body1).hexdigest(), (
                "chunked multipart body got corrupted"
            )

            s2, _, rb2, _ = await asyncio.wait_for(read_one_response(reader, leftover), timeout=10)
            assert s2 == 200, f"CL after chunked: status={s2}, body={rb2[:300]!r}"
            d2 = json.loads(rb2)
            assert d2["path"] == "/cl-after-chunked"
            assert d2["body_hash"] == hashlib.md5(body2).hexdigest()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 11. TestPipelinedDifferentMethods — HEAD/OPTIONS/DELETE after multipart
# ============================================================================

class TestPipelinedDifferentMethods:
    """Pipeline multipart with no-body methods following.

    HEAD/OPTIONS/DELETE typically have no body, so the request boundary is
    just the headers. Tests that the proxy correctly handles the transition
    after a multipart body.
    """

    @pytest.mark.parametrize("method", ["HEAD", "OPTIONS", "DELETE", "GET"])
    async def test_multipart_then_no_body_method(self, proxy, method):
        boundary = f"----{method.lower()}-after"
        body = build_multipart(boundary, {"k": "value-with-some-content"})

        pipelined = http_request(
            "PUT", "/upload-then-other", body,
            content_type=f"multipart/form-data; boundary={boundary}",
        ) + http_request(method, "/follow", b"", keep_alive=False)

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            s1, _, rb1, leftover = await asyncio.wait_for(read_one_response(reader), timeout=10)
            assert s1 == 200, f"multipart: status={s1}, body={rb1[:300]!r}"
            d1 = json.loads(rb1)
            assert d1["body_hash"] == hashlib.md5(body).hexdigest()

            s2, _, rb2, _ = await asyncio.wait_for(read_one_response(reader, leftover), timeout=10)
            assert s2 == 200, f"{method} after multipart: status={s2}, body={rb2[:300]!r}"
            # HEAD and OPTIONS have empty bodies in our test BackendHandler;
            # only assert on the JSON echo for methods that produce one.
            if method not in ("HEAD", "OPTIONS"):
                d2 = json.loads(rb2)
                assert d2["method"] == method, f"backend saw method={d2['method']}, expected {method}"
                assert d2["path"] == "/follow"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 12. TestPipelinedCl0First — empty body request before multipart
# ============================================================================

class TestPipelinedCl0First:
    """A POST/PUT with Content-Length: 0, pipelined before a multipart.

    Probes the CL=0 boundary handling: req_body_left starts at 0, the
    "body forwarding" loop should not consume bytes that belong to
    the next request.
    """

    async def test_cl_zero_post_then_multipart(self, proxy):
        boundary = "----cl0after"
        body = build_multipart(boundary, {"after": "cl-zero"})

        pipelined = (
            (
                f"POST /cl-zero HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode()
            + http_request(
                "PUT", "/multi-after-cl0", body,
                content_type=f"multipart/form-data; boundary={boundary}",
                keep_alive=False,
            )
        )

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            s1, _, rb1, leftover = await asyncio.wait_for(read_one_response(reader), timeout=10)
            assert s1 == 200, f"CL=0 POST: status={s1}, body={rb1[:300]!r}"
            d1 = json.loads(rb1)
            assert d1["body_length"] == 0, f"CL=0 must have empty body, got {d1['body_length']}"
            assert d1["path"] == "/cl-zero"

            s2, _, rb2, _ = await asyncio.wait_for(read_one_response(reader, leftover), timeout=10)
            assert s2 == 200, f"multipart after CL=0: status={s2}, body={rb2[:300]!r}"
            d2 = json.loads(rb2)
            assert d2["path"] == "/multi-after-cl0"
            assert d2["body_hash"] == hashlib.md5(body).hexdigest(), (
                "multipart body corrupted after CL=0 request"
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 13. TestMultipartChunkedTransferEncoding — multipart over chunked
# ============================================================================

class TestMultipartChunkedTransferEncoding:
    """Multipart body sent with Transfer-Encoding: chunked instead of CL."""

    async def test_chunked_multipart_basic(self, client):
        boundary = "----chmp"
        body = build_multipart(boundary, {
            "purchasedAt": "2026-03-29T00:00:00.000Z",
            "sync_image_processing": "true",
        })
        # Single chunk wrap
        chunked = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"

        # Custom request because we need TE: chunked instead of CL
        ctx = make_ssl_ctx()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", HTTPS_PORT, ssl=ctx, server_hostname=TEST_DOMAIN
        )
        try:
            req = (
                f"PUT /chunked-mp HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + chunked
            writer.write(req)
            await writer.drain()

            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader), timeout=10
            )
            assert status == 200, f"chunked multipart: status={status}, body={resp_body[:300]!r}"
            d = json.loads(resp_body)
            assert d["body_hash"] == hashlib.md5(body).hexdigest()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_chunked_multipart_many_small_chunks(self, proxy):
        """Send the multipart body broken into many small chunks (each < 64 bytes).

        Probes advance_chunked() while bytes inside chunks contain CRLFCRLF.
        """
        boundary = "----chmpsplit"
        body = build_multipart(boundary, {
            "field1": "v" * 200,
            "field2": "w" * 200,
            "field3": "x" * 200,
        })
        chunked = b""
        i = 0
        while i < len(body):
            n = min(64, len(body) - i)
            chunked += f"{n:x}\r\n".encode() + body[i:i + n] + b"\r\n"
            i += n
        chunked += b"0\r\n\r\n"

        ctx = make_ssl_ctx()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", HTTPS_PORT, ssl=ctx, server_hostname=TEST_DOMAIN
        )
        try:
            req = (
                f"PUT /chunked-mp-many HTTP/1.1\r\n"
                f"Host: {TEST_DOMAIN}\r\n"
                f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + chunked
            writer.write(req)
            await writer.drain()

            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader), timeout=10
            )
            assert status == 200, f"many-chunks multipart: status={status}, body={resp_body[:300]!r}"
            d = json.loads(resp_body)
            assert d["body_hash"] == hashlib.md5(body).hexdigest()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 14. TestMultipartSpecialBodyContent — bodies with HTTP-looking bytes
# ============================================================================

class TestMultipartSpecialBodyContent:
    """Multipart bodies whose content includes bytes that LOOK like HTTP.

    A robust proxy must not be confused by the *content* of the body,
    no matter what bytes it carries. These tests use legitimate clients
    that nonetheless place HTTP-request-looking bytes inside multipart
    parts (e.g., uploading a .http file, or text containing CRLF + headers).
    """

    async def test_body_contains_http_request_line(self, client):
        boundary = "----httpinside"
        sneaky_field_value = (
            b"GET /admin HTTP/1.1\r\n"
            b"Host: backend.internal\r\n"
            b"X-Smuggled: yes\r\n"
            b"\r\n"
            b"this is field value content"
        )
        body = build_multipart(boundary, {
            "metadata": "ok",
            "sneaky": sneaky_field_value,
        })
        status, _, resp_body = await client.request(
            "PUT", "/sneaky",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            body=body,
        )
        assert status == 200, f"status={status}, body={resp_body[:300]!r}"
        d = json.loads(resp_body)
        assert d["body_hash"] == hashlib.md5(body).hexdigest()
        # Verify the backend really received the full body and only one request
        assert d["path"] == "/sneaky", (
            f"backend saw path={d['path']!r}; the embedded GET line must NOT be "
            "treated as a separate request"
        )

    async def test_body_contains_all_byte_values(self, client):
        boundary = "----allbytes"
        all_bytes = bytes(range(256))
        body = build_multipart(boundary, {
            "metadata": "x",
            "blob": all_bytes * 100,  # 25.6KB of every byte value
        })
        status, _, resp_body = await client.request(
            "POST", "/allbytes",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            body=body,
            timeout=15,
        )
        assert status == 200, f"status={status}, body={resp_body[:300]!r}"
        d = json.loads(resp_body)
        assert d["body_hash"] == hashlib.md5(body).hexdigest()

    async def test_body_with_http_inside_pipelined(self, proxy):
        """Body has HTTP-request-looking bytes AND request is pipelined."""
        boundary = "----httpinsidepl"
        body = build_multipart(boundary, {
            "log": (
                b"PUT /v1/admin HTTP/1.1\r\n"
                b"Host: evil.example.com\r\n"
                b"Content-Length: 999\r\n"
                b"\r\n"
                b"injected body"
            ),
        })
        pipelined = http_request(
            "POST", "/inject", body,
            content_type=f"multipart/form-data; boundary={boundary}",
        ) + http_request("GET", "/legit-after", b"", keep_alive=False)

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            s1, _, rb1, leftover = await asyncio.wait_for(read_one_response(reader), timeout=10)
            assert s1 == 200, f"sneaky multipart: status={s1}, body={rb1[:300]!r}"
            d1 = json.loads(rb1)
            assert d1["path"] == "/inject", (
                f"backend saw path={d1['path']!r}; embedded PUT must not be parsed"
            )
            assert d1["body_hash"] == hashlib.md5(body).hexdigest()

            s2, _, rb2, _ = await asyncio.wait_for(read_one_response(reader, leftover), timeout=10)
            assert s2 == 200, f"legit GET: status={s2}, body={rb2[:300]!r}"
            d2 = json.loads(rb2)
            assert d2["path"] == "/legit-after"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 15. TestMultipartLongBoundary — very long boundary strings
# ============================================================================

class TestMultipartLongBoundary:
    """RFC allows boundary values up to 70 chars. Some clients use long
    randomized boundaries. The proxy should pass them through without issue."""

    async def test_70_char_boundary(self, client):
        boundary = "a" * 70
        body = build_multipart(boundary, {"k": "v"})
        status, _, resp_body = await client.request(
            "PUT", "/longbound",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            body=body,
        )
        assert status == 200
        d = json.loads(resp_body)
        assert d["body_hash"] == hashlib.md5(body).hexdigest()


# ============================================================================
# 16. TestMultipartExpect100Continue — Expect: 100-continue
# ============================================================================

class TestMultipartExpect100Continue:
    """Some HTTP clients send `Expect: 100-continue` for large uploads.

    The proxy must forward the headers, the backend may respond 100 Continue,
    that interim 1xx must reach the client, and the body that follows must
    flow through correctly. Python's HTTPServer in our test fixture does
    NOT itself emit a 100 Continue, so the body is sent regardless. The
    test verifies the proxy doesn't misframe the request when the
    Expect header is present.
    """

    async def test_expect_100_with_body_sent_immediately(self, proxy):
        boundary = "----expect100"
        body = build_multipart(boundary, {
            "purchasedAt": "2026-03-29T00:00:00.000Z",
            "sync_image_processing": "true",
        })
        # Use custom path because ProxyClient doesn't skip interim 1xx responses,
        # and the test BackendHandler auto-emits "100 Continue" before the body.
        req = http_request(
            "PUT", "/expect100", body,
            content_type=f"multipart/form-data; boundary={boundary}",
            extra_headers={"Expect": "100-continue"},
            keep_alive=False,
        )
        reader, writer = await open_tls()
        try:
            writer.write(req)
            await writer.drain()
            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader), timeout=10
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        assert status == 200, f"Expect:100 multipart: status={status}, body={resp_body[:300]!r}"
        d = json.loads(resp_body)
        assert d["body_hash"] == hashlib.md5(body).hexdigest()
        # Header forwarded to the backend?
        assert d["headers"].get("Expect") == "100-continue"


# ============================================================================
# 17. TestMultipartBodyAtBufferEdge — body sizes at buffer boundary
# ============================================================================

class TestMultipartBodyAtBufferEdge:
    """Body sizes that align exactly with the proxy's RP_BUF_SIZE (32KB)."""

    @pytest.mark.parametrize("body_size", [
        32 * 1024 - 100,   # body ends just before buffer fill
        32 * 1024,         # body exactly fills buffer
        32 * 1024 + 100,   # body forces second read
    ])
    async def test_multipart_body_around_buffer(self, client, body_size):
        boundary = "----bufedge"
        # Generate body that ends up close to body_size after multipart wrapping
        random.seed(body_size)
        # We don't aim for exact size, just close enough to stress the boundary.
        blob_size = max(0, body_size - 500)
        blob = bytes(random.randrange(256) for _ in range(blob_size))
        body = build_multipart(boundary, {"name": "x", "blob": blob})
        status, _, resp_body = await client.request(
            "PUT", "/bufedge",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            body=body,
            timeout=15,
        )
        assert status == 200, f"body_size~{body_size}: status={status}, body={resp_body[:300]!r}"
        d = json.loads(resp_body)
        assert d["body_length"] == len(body), (
            f"body_size~{body_size}: backend received {d['body_length']} != client sent {len(body)}"
        )
        assert d["body_hash"] == hashlib.md5(body).hexdigest()

    async def test_pipelined_body_at_buffer_edge(self, proxy):
        """Body size + headers sized so Req2 falls right at the buffer boundary."""
        boundary = "----edgepipe"
        # Aim for: headers (~600) + body fills near 31KB so Req2 starts late
        blob = b"X" * (30 * 1024)
        body = build_multipart(boundary, {"blob": blob, "name": "x"})

        pipelined = http_request(
            "PUT", "/edge", body,
            content_type=f"multipart/form-data; boundary={boundary}",
        ) + http_request("GET", "/edge-after", b"", keep_alive=False)

        reader, writer = await open_tls()
        try:
            writer.write(pipelined)
            await writer.drain()

            s1, _, rb1, leftover = await asyncio.wait_for(read_one_response(reader), timeout=15)
            assert s1 == 200, f"edge multipart: status={s1}, body={rb1[:300]!r}"
            d1 = json.loads(rb1)
            assert d1["body_hash"] == hashlib.md5(body).hexdigest()

            s2, _, rb2, _ = await asyncio.wait_for(read_one_response(reader, leftover), timeout=10)
            assert s2 == 200, f"edge GET after: status={s2}, body={rb2[:300]!r}"
            d2 = json.loads(rb2)
            assert d2["path"] == "/edge-after"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 18. TestMultipartConnectionClose — Connection: close behavior
# ============================================================================

class TestMultipartConnectionClose:
    """Multipart with Connection: close header. The connection must terminate
    cleanly without losing the body or response."""

    async def test_multipart_connection_close(self, proxy):
        boundary = "----connclose"
        body = build_multipart(boundary, {
            "purchasedAt": "2026-03-29T00:00:00.000Z",
            "sync_image_processing": "true",
        })
        ctx = make_ssl_ctx()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", HTTPS_PORT, ssl=ctx, server_hostname=TEST_DOMAIN
        )
        try:
            req = http_request(
                "PUT", "/conn-close", body,
                content_type=f"multipart/form-data; boundary={boundary}",
                keep_alive=False,
            )
            writer.write(req)
            await writer.drain()

            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader), timeout=10
            )
            assert status == 200, f"connection close multipart: status={status}, body={resp_body[:300]!r}"
            d = json.loads(resp_body)
            assert d["body_hash"] == hashlib.md5(body).hexdigest()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 19. TestPcapScenario — exact reproduction of the user-reported bug
# ============================================================================

class TestPcapScenario:
    """Reproduces the scenario captured in /tmp/revpx.pcap from a real
    Dart-based mobile client.

    Sequence over a single keep-alive TLS connection:
      1) several GETs and a JSON PUT (warm-up)
      2) a multipart PUT with:
          - very long Authorization Bearer JWT (~1.3KB)
          - boundary string from the actual capture
          - body 374 bytes with CRLFCRLF between part-headers and part-data

    The captured bug: the proxy injected X-Forwarded-* headers TWO MORE
    TIMES inside the multipart body — one per part — at exactly the
    CRLFCRLF positions. The captured proxy was a stale binary built
    BEFORE the Bug A fix. With the fix in place, this test must produce
    a clean request to the backend and a 200 response.
    """

    async def test_long_auth_then_multipart(self, proxy):
        # Long opaque JWT-like string (~1.3KB) similar to the captured one.
        big_jwt = (
            "eyJ" + "A" * 256 + "." + "B" * 700 + "." + "C" * 300
        )
        boundary = "dart-http-boundary-A3D_5XQnWSQSZ.Q+GCiKomLp+Ql17JXvTPozNCYUrJY8VxDs.6L"
        body = build_multipart(boundary, {
            "purchasedAt": "2026-03-29T00:00:00.000Z",
            "sync_image_processing": "true",
        })

        reader, writer = await open_tls()
        try:
            leftover = b""

            # 1) warm-up: a few GETs + JSON PUT (mirrors the pcap timeline)
            warmup_reqs = [
                ("GET", "/v1/app_user_helmets/182/health_profiles", b"", None),
                ("GET", "/v1/sellers?filter%5Bvisible_in_app%5D=true&page%5Bsize%5D=all", b"", None),
                ("PUT", "/v1/app_user_helmets/182",
                 b'{"purchaseType":"ecommerce"}', "application/json"),
                ("GET", "/v1/sellers?page%5Bsize%5D=all", b"", None),
            ]
            for method, path, body_bytes, ctype in warmup_reqs:
                req = http_request(
                    method, path, body_bytes,
                    content_type=ctype,
                    keep_alive=True,
                    extra_headers={
                        "user-agent": "Dart/3.11 (dart:io)",
                        "authorization": f"Bearer {big_jwt}",
                        "accept-encoding": "gzip",
                    },
                )
                writer.write(req)
                await writer.drain()
                status, _, _, leftover = await asyncio.wait_for(
                    read_one_response(reader, leftover), timeout=10
                )
                assert status == 200, f"warm-up {method} {path}: status={status}"

            # 2) the failing request from the pcap
            req = http_request(
                "PUT", "/v1/app_user_helmets/182", body,
                content_type=f"multipart/form-data; boundary={boundary}",
                keep_alive=False,
                extra_headers={
                    "user-agent": "Dart/3.11 (dart:io)",
                    "authorization": f"Bearer {big_jwt}",
                    "accept-encoding": "gzip",
                },
            )
            writer.write(req)
            await writer.drain()

            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader, leftover), timeout=15
            )
            assert status == 200, (
                f"multipart PUT after long-auth warmup got status={status}; "
                f"this would be the regression of the user-reported bug. "
                f"body={resp_body[:300]!r}"
            )
            d = json.loads(resp_body)
            assert d["path"] == "/v1/app_user_helmets/182"
            assert d["body_hash"] == hashlib.md5(body).hexdigest(), (
                "backend body bytes differ — proxy mangled the multipart body. "
                "This is the exact symptom that caused Rack::Multipart::EmptyContentError."
            )
            # Sanity: the auth header reached the backend whole (case-insensitive
            # because the Dart client sends "authorization", lowercase).
            auth = next(
                (v for k, v in d["headers"].items() if k.lower() == "authorization"),
                "",
            )
            assert auth.startswith("Bearer eyJ"), (
                f"Authorization header was truncated/lost during forwarding; got {auth[:80]!r}"
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_long_auth_multipart_split_send(self, proxy):
        """Same scenario but write the request in many small chunks so the
        proxy receives it across multiple SSL_read boundaries. Mirrors how
        a TLS implementation can fragment a single large request."""
        big_jwt = (
            "eyJ" + "A" * 256 + "." + "B" * 700 + "." + "C" * 300
        )
        boundary = "dart-http-boundary-Q+GCiKomLp+Ql17JXvTPozNCYUrJY8VxDs"
        body = build_multipart(boundary, {
            "purchasedAt": "2026-03-29T00:00:00.000Z",
            "sync_image_processing": "true",
        })
        req = http_request(
            "PUT", "/v1/app_user_helmets/182", body,
            content_type=f"multipart/form-data; boundary={boundary}",
            keep_alive=False,
            extra_headers={
                "user-agent": "Dart/3.11 (dart:io)",
                "authorization": f"Bearer {big_jwt}",
            },
        )

        reader, writer = await open_tls()
        try:
            # Chunk sizes mimic the proxy's pcap pattern: 422 / 1124 / 295 / 331 / 82.
            chunk_sizes = [422, 1124, 295, 331, 82]
            cursor = 0
            for size in chunk_sizes:
                end = min(cursor + size, len(req))
                writer.write(req[cursor:end])
                await writer.drain()
                await asyncio.sleep(0.001)
                cursor = end
                if cursor >= len(req):
                    break
            if cursor < len(req):
                writer.write(req[cursor:])
                await writer.drain()

            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader), timeout=15
            )
            assert status == 200, (
                f"split-send multipart: status={status}, body={resp_body[:300]!r}"
            )
            d = json.loads(resp_body)
            assert d["body_hash"] == hashlib.md5(body).hexdigest()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ============================================================================
# 20. TestPartialHeaderEpolloutFlush — Bug C
# ============================================================================

class TestPartialHeaderEpolloutFlush:
    """Bug C: when a multipart request's headers split across multiple TLS
    records such that the first SSL_read returns the request line + initial
    headers WITHOUT the terminating CRLFCRLF yet, the proxy used to:
      1) Buffer those bytes in backend->buf (no flush, since
         req_parsing_header=true).
      2) Return from forward_client_bytes.
      3) proxy_data's loop then saw `dst->len > 0` and registered EPOLLOUT,
         which fired and FLUSHED the partial headers to the backend WITHOUT
         X-Forwarded-* injection.
      4) The next SSL_read brought the rest of headers — but with
         backend->buf empty, the proxy treated those bytes as a complete
         "request" of their own. parse_content_length_headers found no
         Content-Length there (it was in the already-flushed first chunk),
         so req_body_left=0, req_need_header=true.
      5) Multipart body bytes arriving next were treated as a fresh request,
         and every CRLFCRLF inside the multipart body (between part-headers
         and part-data) triggered another inject_forwarded_headers call.

    Reproduces with the dart client; this test confirms the proxy now keeps
    header bytes buffered until \\r\\n\\r\\n arrives instead of flushing them
    via EPOLLOUT when partial.
    """

    async def test_headers_split_in_two_records_then_body(self, proxy):
        # Build a request large enough that the test's chunk size (~422 bytes)
        # is meaningfully partial — needs an Authorization header big enough
        # to push the request past several records' worth.
        big_jwt = (
            "eyJ" + "A" * 256 + "." + "B" * 700 + "." + "C" * 300
        )
        boundary = "dart-http-boundary-mCOFupO5Ow9-XTJ22NHdFmK0GFCDDLdkzqePbrehX6RBa1Ia2UW"
        body = build_multipart(boundary, {
            "purchasedAt": "2026-03-29T00:00:00.000Z",
            "sync_image_processing": "true",
        })
        req = http_request(
            "PUT", "/v1/app_user_helmets/182", body,
            content_type=f"multipart/form-data; boundary={boundary}",
            keep_alive=False,
            extra_headers={
                "user-agent": "Dart/3.11 (dart:io)",
                "authorization": f"Bearer {big_jwt}",
            },
        )

        # Find the offset of \r\n\r\n (end of headers) and split the headers
        # at a point BEFORE that, so the first write has no header terminator.
        header_end = req.index(b"\r\n\r\n") + 4
        # Pick a split mid-way through the long Authorization JWT so the first
        # chunk lacks any \r\n at the very end.
        split_at = 422
        assert split_at < header_end - 200, "test invariant: split must be inside headers"

        reader, writer = await open_tls()
        try:
            # Chunk 1: partial headers, NO \r\n\r\n yet.
            writer.write(req[:split_at])
            await writer.drain()
            # Tiny pause to encourage the kernel to deliver this as its own TLS
            # record + give the proxy event loop a chance to schedule EPOLLOUT
            # on the backend (the moment the pre-fix bug bites).
            await asyncio.sleep(0.05)
            # Chunk 2: rest of the request (headers tail + body).
            writer.write(req[split_at:])
            await writer.drain()

            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader), timeout=15
            )
            assert status == 200, (
                f"partial-header-then-body: status={status}, body={resp_body[:300]!r}"
            )
            d = json.loads(resp_body)
            assert d["path"] == "/v1/app_user_helmets/182"
            assert d["body_hash"] == hashlib.md5(body).hexdigest(), (
                "body corrupted — proxy emitted X-Forwarded-* into the multipart body "
                "(Bug C: partial header was flushed via EPOLLOUT before injection)"
            )
            ct = next(
                (v for k, v in d["headers"].items() if k.lower() == "content-type"),
                "",
            )
            assert ct.startswith("multipart/form-data"), (
                f"backend saw unexpected content-type: {ct!r}"
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @pytest.mark.parametrize("split_at", [50, 100, 200, 300, 422, 600, 900, 1200])
    async def test_split_at_various_offsets(self, proxy, split_at):
        """Same scenario across several header-split offsets."""
        big_jwt = "eyJ" + "A" * 256 + "." + "B" * 700 + "." + "C" * 300
        boundary = "----varied"
        body = build_multipart(boundary, {"k": "v" * 50})
        req = http_request(
            "PUT", "/v1/x", body,
            content_type=f"multipart/form-data; boundary={boundary}",
            keep_alive=False,
            extra_headers={
                "user-agent": "Dart/3.11 (dart:io)",
                "authorization": f"Bearer {big_jwt}",
            },
        )
        header_end = req.index(b"\r\n\r\n") + 4
        if split_at >= header_end:
            pytest.skip(f"split_at={split_at} is past header end ({header_end})")

        reader, writer = await open_tls()
        try:
            writer.write(req[:split_at])
            await writer.drain()
            await asyncio.sleep(0.03)
            writer.write(req[split_at:])
            await writer.drain()

            status, _, resp_body, _ = await asyncio.wait_for(
                read_one_response(reader), timeout=15
            )
            assert status == 200, (
                f"split_at={split_at}: status={status}, body={resp_body[:200]!r}"
            )
            d = json.loads(resp_body)
            assert d["body_hash"] == hashlib.md5(body).hexdigest(), (
                f"split_at={split_at}: body corrupted"
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
