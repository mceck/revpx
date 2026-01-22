#!/usr/bin/env python3
"""
Backend server for testing revpx reverse proxy.
This server provides various endpoints to test different scenarios
that could trigger content-length mismatches or body corruption.
"""

import argparse
import hashlib
import json
import os
import random
import string
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True


class TestBackendHandler(BaseHTTPRequestHandler):
    """HTTP request handler for testing various proxy scenarios."""

    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def _send_response(self, body: bytes, content_type: str = 'application/octet-stream',
                       status: int = 200, headers: dict = None, chunked: bool = False):
        """Send HTTP response with proper headers."""
        self.send_response(status)
        self.send_header('Content-Type', content_type)

        if headers:
            for key, value in headers.items():
                self.send_header(key, value)

        if chunked:
            self.send_header('Transfer-Encoding', 'chunked')
        else:
            self.send_header('Content-Length', str(len(body)))

        self.end_headers()

        if chunked:
            self._send_chunked(body)
        else:
            self.wfile.write(body)

    def _send_chunked(self, body: bytes, chunk_size: int = 1024):
        """Send body using chunked transfer encoding."""
        offset = 0
        while offset < len(body):
            chunk = body[offset:offset + chunk_size]
            chunk_header = f'{len(chunk):x}\r\n'.encode()
            self.wfile.write(chunk_header)
            self.wfile.write(chunk)
            self.wfile.write(b'\r\n')
            offset += chunk_size
        # Final chunk
        self.wfile.write(b'0\r\n\r\n')

    def _generate_payload(self, size: int, pattern: str = 'random') -> bytes:
        """Generate a payload of specified size with checksum."""
        if pattern == 'random':
            data = os.urandom(size - 64)  # Reserve space for checksum
        elif pattern == 'sequential':
            data = bytes([(i % 256) for i in range(size - 64)])
        elif pattern == 'ascii':
            chars = string.ascii_letters + string.digits
            data = ''.join(random.choice(chars) for _ in range(size - 64)).encode()
        else:
            data = (pattern * ((size - 64) // len(pattern) + 1))[:size - 64].encode()

        # Add SHA256 checksum at the end for verification
        checksum = hashlib.sha256(data).hexdigest().encode()
        return data + checksum

    def do_GET(self):
        """Handle GET requests."""
        path = self.path.split('?')[0]
        query_params = {}
        if '?' in self.path:
            query_string = self.path.split('?')[1]
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = value

        # Health check
        if path == '/health':
            self._send_response(b'OK', 'text/plain')
            return

        # Echo headers
        if path == '/echo-headers':
            headers_dict = dict(self.headers)
            body = json.dumps(headers_dict, indent=2).encode()
            self._send_response(body, 'application/json')
            return

        # Generate payload of specific size
        if path == '/payload':
            size = int(query_params.get('size', '1024'))
            pattern = query_params.get('pattern', 'random')
            chunked = query_params.get('chunked', 'false').lower() == 'true'
            delay = float(query_params.get('delay', '0'))

            if delay > 0:
                time.sleep(delay)

            body = self._generate_payload(size, pattern)
            self._send_response(body, chunked=chunked)
            return

        # Slow response - sends data in chunks with delays
        if path == '/slow':
            size = int(query_params.get('size', '10240'))
            delay = float(query_params.get('delay', '0.1'))
            chunk_size = int(query_params.get('chunk', '1024'))

            body = self._generate_payload(size, 'sequential')
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()

            offset = 0
            while offset < len(body):
                chunk = body[offset:offset + chunk_size]
                self.wfile.write(chunk)
                self.wfile.flush()
                offset += chunk_size
                if offset < len(body):
                    time.sleep(delay)
            return

        # Large payload test - multiple sizes
        if path == '/large':
            sizes = [
                32 * 1024,       # 32KB (buffer size)
                64 * 1024,       # 64KB
                128 * 1024,      # 128KB
                256 * 1024,      # 256KB
                512 * 1024,      # 512KB
                1024 * 1024,     # 1MB
            ]
            size = int(query_params.get('size', str(sizes[0])))
            body = self._generate_payload(size, 'sequential')
            self._send_response(body)
            return

        # Exact buffer boundary test
        if path == '/boundary':
            # Test payloads near buffer boundaries (RP_BUF_SIZE = 32768)
            offset = int(query_params.get('offset', '0'))
            base_size = 32768  # RP_BUF_SIZE
            size = base_size + offset
            body = self._generate_payload(size, 'sequential')
            self._send_response(body)
            return

        # Multiple responses on same connection (keep-alive test)
        if path == '/keepalive':
            body = b'keepalive-response'
            self._send_response(body, 'text/plain')
            return

        # JSON response
        if path == '/json':
            size = int(query_params.get('size', '1024'))
            data = {
                'size': size,
                'data': 'x' * (size - 50),
                'checksum': hashlib.sha256(('x' * (size - 50)).encode()).hexdigest()
            }
            body = json.dumps(data).encode()
            self._send_response(body, 'application/json')
            return

        # Streaming chunked response
        if path == '/stream':
            chunks = int(query_params.get('chunks', '10'))
            chunk_size = int(query_params.get('chunk_size', '1024'))
            delay = float(query_params.get('delay', '0.01'))

            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            total_data = b''
            for i in range(chunks):
                chunk_data = os.urandom(chunk_size)
                total_data += chunk_data
                chunk_header = f'{len(chunk_data):x}\r\n'.encode()
                self.wfile.write(chunk_header)
                self.wfile.write(chunk_data)
                self.wfile.write(b'\r\n')
                self.wfile.flush()
                if delay > 0 and i < chunks - 1:
                    time.sleep(delay)

            # Final chunk with checksum in trailer
            self.wfile.write(b'0\r\n\r\n')
            return

        # WebSocket upgrade endpoint
        if path == '/ws':
            if self.headers.get('Upgrade', '').lower() == 'websocket':
                key = self.headers.get('Sec-WebSocket-Key', '')
                import base64
                accept = base64.b64encode(
                    hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
                ).decode()

                self.send_response(101, 'Switching Protocols')
                self.send_header('Upgrade', 'websocket')
                self.send_header('Connection', 'Upgrade')
                self.send_header('Sec-WebSocket-Accept', accept)
                self.end_headers()

                # Simple WebSocket echo - read frame and echo back
                try:
                    while True:
                        header = self.rfile.read(2)
                        if len(header) < 2:
                            break

                        opcode = header[0] & 0x0F
                        masked = (header[1] & 0x80) != 0
                        payload_len = header[1] & 0x7F

                        if payload_len == 126:
                            payload_len = int.from_bytes(self.rfile.read(2), 'big')
                        elif payload_len == 127:
                            payload_len = int.from_bytes(self.rfile.read(8), 'big')

                        if masked:
                            mask = self.rfile.read(4)
                            payload = bytearray(self.rfile.read(payload_len))
                            for i in range(len(payload)):
                                payload[i] ^= mask[i % 4]
                        else:
                            payload = self.rfile.read(payload_len)

                        # Echo back
                        response = bytearray([0x81])  # FIN + text frame
                        if len(payload) < 126:
                            response.append(len(payload))
                        elif len(payload) < 65536:
                            response.append(126)
                            response.extend(len(payload).to_bytes(2, 'big'))
                        else:
                            response.append(127)
                            response.extend(len(payload).to_bytes(8, 'big'))
                        response.extend(payload)
                        self.wfile.write(bytes(response))
                        self.wfile.flush()

                        if opcode == 8:  # Close frame
                            break
                except Exception:
                    pass
                return

            self._send_response(b'WebSocket upgrade required', status=400)
            return

        # Default response
        self._send_response(b'OK', 'text/plain')

    def do_POST(self):
        """Handle POST requests - echo back with verification."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        path = self.path.split('?')[0]

        # Echo endpoint - returns what was sent
        if path == '/echo':
            response = {
                'received_length': len(body),
                'content_length_header': content_length,
                'sha256': hashlib.sha256(body).hexdigest(),
                'match': len(body) == content_length
            }
            self._send_response(json.dumps(response).encode(), 'application/json')
            return

        # Large upload test
        if path == '/upload':
            checksum = hashlib.sha256(body).hexdigest()
            response = {
                'size': len(body),
                'checksum': checksum,
                'expected_size': content_length,
                'valid': len(body) == content_length
            }
            self._send_response(json.dumps(response).encode(), 'application/json')
            return

        # Echo with same body size response
        if path == '/mirror':
            self._send_response(body)
            return

        self._send_response(b'OK', 'text/plain')

    def do_PUT(self):
        """Handle PUT requests."""
        self.do_POST()


def run_server(port: int, host: str = '0.0.0.0'):
    """Start the test backend server."""
    server = ThreadedHTTPServer((host, port), TestBackendHandler)
    print(f'Backend server running on http://{host}:{port}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.shutdown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test backend server for revpx')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    args = parser.parse_args()

    run_server(args.port, args.host)
