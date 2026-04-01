#!/usr/bin/env python3
"""
Tests for path-based routing and URL rewriting in revpx reverse proxy.

Covers:
- Path prefix routing to different backends
- URL rewriting (prefix replacement)
- Fallback to default backend when no rule matches
- Keep-alive with URL rewriting
- Rule ordering (first match wins)
- Partial path segment matching prevention (/api vs /apiary)
"""

import asyncio
import json
import os
import socket
import ssl
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
    TEST_DOMAIN,
    PROJECT_ROOT,
    REVPX_BINARY,
    CERT_FILE,
    KEY_FILE,
)

pytestmark = pytest.mark.asyncio

# Use unique ports to avoid conflicts with other test modules
ROUTE_HTTPS_PORT = 20443
ROUTE_HTTP_PORT = 20480
ROUTE_BACKEND_DEFAULT_PORT = 20400
ROUTE_BACKEND_API_PORT = 20401
ROUTE_BACKEND_STATIC_PORT = 20402


class TaggingHandler(BaseHTTPRequestHandler):
    """Backend handler that tags responses with its identity and echoes the request path."""

    protocol_version = "HTTP/1.1"
    server_tag = "unknown"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def _handle(self):
        te = self.headers.get("Transfer-Encoding", "")
        if "chunked" in te.lower():
            body = b""
            while True:
                line = self.rfile.readline().strip()
                if not line:
                    break
                try:
                    chunk_size = int(line.split(b";")[0], 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    while True:
                        trailer = self.rfile.readline()
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    break
                body += self.rfile.read(chunk_size)
                self.rfile.readline()
        else:
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl) if cl > 0 else b""

        resp = json.dumps({
            "backend": self.server_tag,
            "path": self.path,
            "method": self.command,
            "body_length": len(body),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def make_handler(tag):
    """Create a handler class with a specific tag."""
    class H(TaggingHandler):
        server_tag = tag
    return H


class TaggedBackend:
    def __init__(self, port, tag):
        self.port = port
        self.tag = tag
        self.server = None
        self.thread = None

    def start(self):
        self.server = HTTPServer(("127.0.0.1", self.port), make_handler(self.tag))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.1)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server = None
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None


class RoutingProxy:
    """Proxy configured with routing rules via JSON config."""

    def __init__(self, config, https_port=ROUTE_HTTPS_PORT, http_port=ROUTE_HTTP_PORT):
        self.https_port = https_port
        self.http_port = http_port
        self.config = config
        self.process = None
        self.config_file = None

    async def _wait_until_ready(self, timeout=10.0):
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if self.process and self.process.returncode is not None:
                stdout, stderr = await self.process.communicate()
                raise RuntimeError(
                    f"revpx exited:\nstdout: {stdout.decode()}\nstderr: {stderr.decode()}"
                )
            try:
                with socket.create_connection(("127.0.0.1", self.https_port), timeout=0.25):
                    return
            except OSError:
                await asyncio.sleep(0.05)
        raise RuntimeError(f"revpx did not become ready on port {self.https_port}")

    async def start(self):
        self.config_file = os.path.join(
            PROJECT_ROOT, "tests",
            f"test_routing_config_{os.getpid()}_{self.https_port}.json",
        )
        with open(self.config_file, "w") as f:
            json.dump(self.config, f)

        env = os.environ.copy()
        env["REVPX_PORT"] = str(self.https_port)
        env["REVPX_PORT_PLAIN"] = str(self.http_port)

        self.process = await asyncio.create_subprocess_exec(
            REVPX_BINARY, "-f", self.config_file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=PROJECT_ROOT,
            env=env,
        )
        await self._wait_until_ready()

    async def stop(self):
        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
            self.process = None
        if self.config_file and os.path.exists(self.config_file):
            os.remove(self.config_file)
            self.config_file = None


# ============================================================================
# Fixtures
# ============================================================================

@pytest_asyncio.fixture(scope="module")
async def backends():
    """Start three backend servers with different tags."""
    default = TaggedBackend(ROUTE_BACKEND_DEFAULT_PORT, "default")
    api = TaggedBackend(ROUTE_BACKEND_API_PORT, "api")
    static = TaggedBackend(ROUTE_BACKEND_STATIC_PORT, "static")

    await asyncio.to_thread(default.start)
    await asyncio.to_thread(api.start)
    await asyncio.to_thread(static.start)

    yield {"default": default, "api": api, "static": static}

    await asyncio.to_thread(default.stop)
    await asyncio.to_thread(api.stop)
    await asyncio.to_thread(static.stop)


@pytest_asyncio.fixture(scope="module")
async def routing_proxy(backends):
    """Proxy with path-based routing rules."""
    config = [{
        "domain": TEST_DOMAIN,
        "port": str(ROUTE_BACKEND_DEFAULT_PORT),
        "cert_file": CERT_FILE,
        "key_file": KEY_FILE,
        "rules": [
            {
                "match": "/api",
                "port": str(ROUTE_BACKEND_API_PORT),
            },
            {
                "match": "/static",
                "port": str(ROUTE_BACKEND_STATIC_PORT),
            },
        ],
    }]
    p = RoutingProxy(config)
    await p.start()
    yield p
    await p.stop()


@pytest_asyncio.fixture(scope="module")
async def rewrite_proxy(backends):
    """Proxy with URL rewriting rules."""
    config = [{
        "domain": TEST_DOMAIN,
        "port": str(ROUTE_BACKEND_DEFAULT_PORT),
        "cert_file": CERT_FILE,
        "key_file": KEY_FILE,
        "rules": [
            {
                "match": "/api/v2",
                "rewrite": "/v2",
                "port": str(ROUTE_BACKEND_API_PORT),
            },
            {
                "match": "/api",
                "rewrite": "/internal",
                "port": str(ROUTE_BACKEND_API_PORT),
            },
            {
                "match": "/assets",
                "rewrite": "/public/assets",
                "port": str(ROUTE_BACKEND_STATIC_PORT),
            },
            {
                "match": "/strip",
                "rewrite": "",
                "port": str(ROUTE_BACKEND_API_PORT),
            },
        ],
    }]
    # Use different ports for the rewrite proxy so both can run
    p = RoutingProxy(config, https_port=ROUTE_HTTPS_PORT + 100, http_port=ROUTE_HTTP_PORT + 100)
    await p.start()
    yield p
    await p.stop()


@pytest.fixture
def client(routing_proxy):
    return ProxyClient(port=ROUTE_HTTPS_PORT)


@pytest.fixture
def rewrite_client(rewrite_proxy):
    return ProxyClient(port=ROUTE_HTTPS_PORT + 100)


# ============================================================================
# Path-based routing tests
# ============================================================================

class TestPathRouting:
    """Test that requests are routed to the correct backend based on path prefix."""

    @pytest.mark.asyncio
    async def test_api_path_routes_to_api_backend(self, client):
        """Requests to /api/* should go to the api backend."""
        status, headers, body = await client.request("GET", "/api/users")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"
        assert data["path"] == "/api/users"

    @pytest.mark.asyncio
    async def test_api_exact_path(self, client):
        """Request to exactly /api should match the api rule."""
        status, headers, body = await client.request("GET", "/api")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"

    @pytest.mark.asyncio
    async def test_static_path_routes_to_static_backend(self, client):
        """Requests to /static/* should go to the static backend."""
        status, headers, body = await client.request("GET", "/static/style.css")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "static"
        assert data["path"] == "/static/style.css"

    @pytest.mark.asyncio
    async def test_unmatched_path_routes_to_default(self, client):
        """Requests that don't match any rule go to the default backend."""
        status, headers, body = await client.request("GET", "/index.html")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "default"
        assert data["path"] == "/index.html"

    @pytest.mark.asyncio
    async def test_root_path_routes_to_default(self, client):
        """Root path / should go to default backend."""
        status, headers, body = await client.request("GET", "/")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "default"

    @pytest.mark.asyncio
    async def test_partial_match_not_matched(self, client):
        """'/apiary' should NOT match the '/api' rule (partial segment)."""
        status, headers, body = await client.request("GET", "/apiary")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "default"

    @pytest.mark.asyncio
    async def test_api_with_query_string(self, client):
        """/api?key=value should match the /api rule."""
        status, headers, body = await client.request("GET", "/api?key=value")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"

    @pytest.mark.asyncio
    async def test_post_routed_correctly(self, client):
        """POST requests should also be routed by path."""
        status, headers, body = await client.request(
            "POST", "/api/data", body=b'{"key":"value"}'
        )
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"
        assert data["method"] == "POST"
        assert data["body_length"] == 15


# ============================================================================
# URL rewriting tests
# ============================================================================

class TestUrlRewriting:
    """Test that URLs are rewritten correctly before forwarding to backend."""

    @pytest.mark.asyncio
    async def test_basic_rewrite(self, rewrite_client):
        """/api/users should be rewritten to /internal/users."""
        status, headers, body = await rewrite_client.request("GET", "/api/users")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"
        assert data["path"] == "/internal/users"

    @pytest.mark.asyncio
    async def test_longer_prefix_matches_first(self, rewrite_client):
        """/api/v2/items should match /api/v2 rule (first match), not /api."""
        status, headers, body = await rewrite_client.request("GET", "/api/v2/items")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"
        assert data["path"] == "/v2/items"

    @pytest.mark.asyncio
    async def test_rewrite_with_different_backend(self, rewrite_client):
        """/assets/img.png should be rewritten to /public/assets/img.png on static backend."""
        status, headers, body = await rewrite_client.request("GET", "/assets/img.png")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "static"
        assert data["path"] == "/public/assets/img.png"

    @pytest.mark.asyncio
    async def test_strip_prefix(self, rewrite_client):
        """/strip/path should be rewritten to /path (prefix stripped)."""
        status, headers, body = await rewrite_client.request("GET", "/strip/path")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"
        assert data["path"] == "/path"

    @pytest.mark.asyncio
    async def test_no_rewrite_for_unmatched(self, rewrite_client):
        """Unmatched paths should not be rewritten."""
        status, headers, body = await rewrite_client.request("GET", "/other/page")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "default"
        assert data["path"] == "/other/page"

    @pytest.mark.asyncio
    async def test_rewrite_exact_match(self, rewrite_client):
        """/api should be rewritten to /internal."""
        status, headers, body = await rewrite_client.request("GET", "/api")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"
        assert data["path"] == "/internal"

    @pytest.mark.asyncio
    async def test_rewrite_with_query_string(self, rewrite_client):
        """/api/search?q=test should be rewritten to /internal/search?q=test."""
        status, headers, body = await rewrite_client.request("GET", "/api/search?q=test")
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"
        assert data["path"] == "/internal/search?q=test"

    @pytest.mark.asyncio
    async def test_rewrite_post_with_body(self, rewrite_client):
        """POST with body should be rewritten and body preserved."""
        payload = b'{"data": "test"}'
        status, headers, body = await rewrite_client.request(
            "POST", "/api/submit", body=payload
        )
        assert status == 200
        data = json.loads(body)
        assert data["backend"] == "api"
        assert data["path"] == "/internal/submit"
        assert data["body_length"] == len(payload)


# ============================================================================
# No-rules backward compatibility test
# ============================================================================

class TestNoRulesCompat:
    """Test that domains without rules work exactly as before."""

    @pytest_asyncio.fixture(scope="class")
    async def compat_backend(self):
        b = TaggedBackend(ROUTE_BACKEND_DEFAULT_PORT + 10, "compat")
        await asyncio.to_thread(b.start)
        yield b
        await asyncio.to_thread(b.stop)

    @pytest_asyncio.fixture(scope="class")
    async def compat_proxy(self, compat_backend):
        config = [{
            "domain": TEST_DOMAIN,
            "port": str(ROUTE_BACKEND_DEFAULT_PORT + 10),
            "cert_file": CERT_FILE,
            "key_file": KEY_FILE,
            # No "rules" key at all
        }]
        p = RoutingProxy(config, https_port=ROUTE_HTTPS_PORT + 200, http_port=ROUTE_HTTP_PORT + 200)
        await p.start()
        yield p
        await p.stop()

    @pytest.fixture
    def compat_client(self, compat_proxy):
        return ProxyClient(port=ROUTE_HTTPS_PORT + 200)

    @pytest.mark.asyncio
    async def test_all_paths_go_to_same_backend(self, compat_client):
        """Without rules, all paths go to the single backend."""
        for path in ["/", "/api/users", "/static/file.css", "/anything"]:
            status, headers, body = await compat_client.request("GET", path)
            assert status == 200
            data = json.loads(body)
            assert data["backend"] == "compat"
            assert data["path"] == path
