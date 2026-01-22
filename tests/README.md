# RevPx Test Suite

Comprehensive test suite for the revpx reverse proxy.

## Quick Start

```bash
# Build revpx first
./nob

# Generate test certificate if needed
mkcert test.localhost

# Run quick tests
./tests/run_tests.sh

# Or manually:
python3 tests/backend_server.py -p 9999 &
REVPX_PORT=8443 REVPX_PORT_PLAIN=8880 ./build/revpx test.localhost 9999 test.localhost.pem test.localhost-key.pem &
PROXY_HTTPS_PORT=8443 BACKEND_PORT=9999 python3 tests/quick_tests.py
```

## Test Files

- `backend_server.py` - Mock backend server with various test endpoints
- `quick_tests.py` - Quick functional tests
- `test_revpx.py` - Full unittest-based test suite
- `test_post_investigation.py` - POST request issue investigation
- `test_timing_investigation.py` - Timing-related issue investigation
- `test_final_comprehensive.py` - Final comprehensive test suite

## Test Endpoints (Backend Server)

- `/health` - Health check
- `/payload?size=N&chunked=true&pattern=random` - Generate payload of size N
- `/slow?size=N&delay=0.1&chunk=1024` - Slow response
- `/echo` - Echo POST body with verification
- `/echo-headers` - Return received headers as JSON
- `/mirror` - Mirror POST body back
- `/stream?chunks=N&chunk_size=M` - Streaming chunked response
- `/ws` - WebSocket echo endpoint

## Known Issues

### 1. POST Request Timing Issue

**Symptom**: POST requests with large bodies (>= 32KB) fail with connection errors or corrupted responses when the entire request (headers + body) is sent at once.

**Root Cause**: The `forward_client_bytes()` function in revpx has a buffer management issue. When all data arrives simultaneously:
1. The entire request is read into the client buffer during header parsing
2. When forwarding to backend, the buffer fills up while still in header-parsing mode
3. This triggers a 431 "Request Header Fields Too Large" error

**Affected Scenarios**:
- Fast clients sending large POST requests
- HTTP libraries that send header+body in a single TCP packet
- High-throughput scenarios

**Workaround**: Send HTTP headers first, then body with a small delay (~10ms):
```python
ssl_sock.sendall(request_header)
time.sleep(0.01)  # Small delay
ssl_sock.sendall(body)
```

**Test Results**:
| Send Mode | 32KB | 64KB | 100KB | 128KB |
|-----------|------|------|-------|-------|
| All at once | FAIL | FAIL | FAIL | FAIL |
| Header then body (no delay) | PASS | FAIL | FAIL | FAIL |
| Header then body (10ms delay) | PASS | PASS | PASS | PASS |
| Chunked body | PASS | PASS | PASS | PASS |

### 2. Buffer Size Constraints

- `RP_BUF_SIZE` is 32768 bytes (32KB)
- Requests exceeding buffer capacity during header parsing will fail
- GET responses handle large payloads correctly (streaming)

## Configuration

Environment variables:
- `PROXY_HTTPS_PORT` - HTTPS port (default: 8443)
- `PROXY_HTTP_PORT` - HTTP port (default: 8880)
- `BACKEND_PORT` - Backend server port (default: 9999)

## Test Categories

1. **Basic Functionality**
   - Health checks
   - HTTP->HTTPS redirect
   - Header forwarding (X-Forwarded-For, X-Real-IP, etc.)

2. **Large Payload Handling**
   - Various sizes from 1KB to 5MB
   - Buffer boundary tests (32KB, 64KB, 96KB)
   - Chunked transfer encoding

3. **POST Request Tests**
   - Small to large bodies
   - With timing workaround

4. **Concurrency Tests**
   - Multiple concurrent requests
   - Keep-alive connections

5. **Edge Cases**
   - Slow backend responses
   - Buffer boundary crossings
   - Rapid sequential requests
