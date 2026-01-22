#!/usr/bin/env python3
"""Simple test to debug one size at a time."""

import socket
import ssl
import sys

HOST = 'test.localhost'
PORT = 8443

def test_post(size, with_delay=False):
    """Send a POST request with specified body size."""
    import time
    body = b'X' * size

    headers = (
        f"POST /mirror HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    print(f"Header size: {len(headers)} bytes")
    print(f"Body size: {len(body)} bytes")
    print(f"Total size: {len(headers) + len(body)} bytes")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        ssl_sock = ctx.wrap_socket(sock, server_hostname=HOST)

        if with_delay:
            ssl_sock.sendall(headers)
            time.sleep(0.01)
            ssl_sock.sendall(body)
        else:
            ssl_sock.sendall(headers + body)

        response = b''
        while True:
            chunk = ssl_sock.recv(8192)
            if not chunk:
                break
            response += chunk

        ssl_sock.close()

        if b'HTTP/' in response:
            status_line = response.split(b'\r\n')[0].decode()
            status_code = int(status_line.split()[1])
            print(f"Response: {status_line}")

            if status_code == 200:
                if b'\r\n\r\n' in response:
                    resp_body = response.split(b'\r\n\r\n', 1)[1]
                    print(f"Response body size: {len(resp_body)}")
                    if len(resp_body) == size:
                        print("PASS")
                        return True
                    else:
                        print(f"FAIL: Expected {size}, got {len(resp_body)}")
            else:
                print(f"FAIL: Status {status_code}")
        else:
            print("FAIL: Invalid response")

        return False

    except Exception as e:
        print(f"FAIL: {e}")
        return False

if __name__ == '__main__':
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    with_delay = '--delay' in sys.argv
    test_post(size, with_delay)
