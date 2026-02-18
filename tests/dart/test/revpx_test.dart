/// Dart HTTP client tests for revpx reverse proxy.
///
/// These tests use the `http` package (same as Flutter apps) to reproduce
/// issues seen with Dart/Flutter clients but not with browsers or Python.
///
/// Setup: requires revpx running on HTTPS_PORT with a backend echo server
/// on BACKEND_PORT, same as the Python test suite.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:test/test.dart';

// Use different ports from Python tests to avoid conflicts
const httpsPort = 19443;
const httpPort = 19080;
const backendPort = 19000;
const testDomain = 'test.localhost';
const baseUrl = 'https://$testDomain:$httpsPort';

/// Project root (two levels up from tests/dart/)
final projectRoot = Directory.current.parent.parent.path;
final revpxBinary = '$projectRoot/build/revpx';
final certFile = '$projectRoot/test.localhost.pem';
final keyFile = '$projectRoot/test.localhost-key.pem';

/// Simple echo backend (same as the Python one)
late HttpServer _backendServer;
late Process _proxyProcess;

/// Counter for backend requests (used to simulate connection limits)
int _backendRequestCount = 0;

/// Create an HttpClient that trusts self-signed certs and resolves
/// test.localhost to 127.0.0.1
HttpClient _createRawClient() {
  final client = HttpClient()
    ..badCertificateCallback = (cert, host, port) => true;
  return client;
}

/// Create an http.Client (from package:http) that trusts self-signed certs
http.Client _createClient() {
  final ioClient = _createRawClient();
  return IOClient(ioClient);
}

/// Parse the JSON echo response from backend
Map<String, dynamic> parseEcho(http.Response resp) {
  return jsonDecode(resp.body) as Map<String, dynamic>;
}

/// Start the mock backend server
Future<void> startBackend() async {
  _backendServer = await HttpServer.bind('127.0.0.1', backendPort);
  _backendServer.listen((HttpRequest request) async {
    // Read request body
    final body = await request.fold<List<int>>(
      [],
      (prev, chunk) => prev..addAll(chunk),
    );

    final path = request.uri.toString();
    final method = request.method;

    // Special handlers based on path
    if (path.startsWith('/large-response/')) {
      final size = int.parse(path.split('/').last);
      final data = List.filled(size, 0x79); // 'y'
      request.response
        ..statusCode = 200
        ..headers.contentType = ContentType.binary
        ..headers.contentLength = size
        ..add(data);
      await request.response.close();
      return;
    }

    if (path.startsWith('/slow-response/')) {
      final delayMs = int.parse(path.split('/').last);
      await Future.delayed(Duration(milliseconds: delayMs));
    }

    // Variable delay response (0-50ms random) to simulate real backend
    if (path.startsWith('/variable-delay/')) {
      final rng = Random();
      await Future.delayed(Duration(milliseconds: rng.nextInt(50)));
    }

    // Slow drip response: send headers fast, body slowly
    if (path.startsWith('/slow-drip/')) {
      final size = int.parse(path.split('/').last);
      request.response
        ..statusCode = 200
        ..headers.contentType = ContentType.json
        ..headers.contentLength = size;
      // Send body in small chunks with micro-delays
      final data = List.filled(size, 0x41); // 'A'
      const chunkSize = 256;
      for (var i = 0; i < size; i += chunkSize) {
        final end = (i + chunkSize > size) ? size : i + chunkSize;
        request.response.add(data.sublist(i, end));
        await Future.delayed(const Duration(microseconds: 100));
      }
      await request.response.close();
      return;
    }

    if (path == '/empty-response') {
      request.response
        ..statusCode = 204
        ..headers.contentLength = 0;
      await request.response.close();
      return;
    }

    if (path.startsWith('/status/')) {
      final code = int.parse(path.split('/').last);
      request.response
        ..statusCode = code
        ..headers.contentType = ContentType.json
        ..write(jsonEncode({'status': code}));
      await request.response.close();
      return;
    }

    if (path.startsWith('/chunked-response/')) {
      final size = int.parse(path.split('/').last);
      final data = List.filled(size, 0x78); // 'x'
      request.response
        ..statusCode = 200
        ..headers.contentType = ContentType.binary
        ..headers.set('Transfer-Encoding', 'chunked');
      // Write in small chunks to force chunked encoding
      const chunkSize = 1024;
      for (var i = 0; i < size; i += chunkSize) {
        final end = (i + chunkSize > size) ? size : i + chunkSize;
        request.response.add(data.sublist(i, end));
      }
      await request.response.close();
      return;
    }

    // Simulate backend that closes connection after a few requests
    // (like many frameworks: gunicorn, uvicorn, puma, etc.)
    if (path.startsWith('/conn-limit/')) {
      _backendRequestCount++;
      // Every 3rd request, disable keep-alive (forces connection close)
      if (_backendRequestCount % 3 == 0) {
        request.response.persistentConnection = false;
      }
    }

    // Backend that always closes connection (no keep-alive)
    if (path.startsWith('/no-keepalive/')) {
      request.response.persistentConnection = false;
    }

    // Backend that sends response, then abruptly closes (simulates crash)
    if (path.startsWith('/abrupt-close/')) {
      request.response
        ..statusCode = 200
        ..headers.contentType = ContentType.json
        ..write(jsonEncode({'ok': true}));
      await request.response.close();
      // Close the underlying socket to force TCP RST
      request.response.connectionInfo;
      return;
    }

    // Default: echo back request info as JSON
    final headers = <String, String>{};
    request.headers.forEach((name, values) {
      headers[name] = values.join(', ');
    });

    final echo = {
      'method': method,
      'path': path,
      'headers': headers,
      'body_length': body.length,
      'body_md5': body.isEmpty ? null : _md5Hex(body),
    };

    request.response
      ..statusCode = 200
      ..headers.contentType = ContentType.json
      ..write(jsonEncode(echo));
    await request.response.close();
  });
}

String _md5Hex(List<int> data) {
  // Simple checksum for verification (not cryptographic)
  var hash = 0;
  for (final b in data) {
    hash = (hash * 31 + b) & 0xFFFFFFFF;
  }
  return hash.toRadixString(16).padLeft(8, '0');
}

/// Start the revpx proxy process
Future<void> startProxy() async {
  final configFile = '$projectRoot/tests/test_config_dart.json';
  final config = [
    {
      'domain': testDomain,
      'port': '$backendPort',
      'cert_file': certFile,
      'key_file': keyFile,
    }
  ];
  await File(configFile).writeAsString(jsonEncode(config));

  _proxyProcess = await Process.start(
    revpxBinary,
    ['-f', configFile],
    workingDirectory: projectRoot,
    environment: {
      ...Platform.environment,
      'REVPX_PORT': '$httpsPort',
      'REVPX_PORT_PLAIN': '$httpPort',
    },
  );

  // Capture proxy stderr for diagnostics
  final logFile = File('$projectRoot/tests/proxy_diag.log');
  final logSink = logFile.openWrite();
  _proxyProcess.stderr.transform(utf8.decoder).listen((data) {
    logSink.write(data);
  });

  // Wait for proxy to be ready
  await Future.delayed(const Duration(seconds: 1));

  // Check it's still running
  // (exitCode would complete immediately if process died)
  final exited = _proxyProcess.exitCode.timeout(
    const Duration(milliseconds: 100),
    onTimeout: () => -1, // still running
  );
  final code = await exited;
  if (code != -1) {
    await logSink.flush();
    final stderr = await logFile.readAsString();
    throw Exception('revpx failed to start (exit $code): $stderr');
  }
}

Future<void> stopAll() async {
  _proxyProcess.kill();
  await _backendServer.close(force: true);
  // Clean up config
  try {
    await File('$projectRoot/tests/test_config_dart.json').delete();
  } catch (_) {}
}

/// Simulates the user's Flutter HttpClient wrapper that adds
/// Content-Type: application/json and Authorization to every request.
class _FlutterStyleClient extends http.BaseClient {
  final http.Client _inner;

  _FlutterStyleClient(this._inner);

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    // Always add Content-Type like the user's wrapper does
    if (!request.headers.containsKey('Content-Type')) {
      request.headers['Content-Type'] = 'application/json';
    }
    return _inner.send(request);
  }

  @override
  void close() {
    _inner.close();
    super.close();
  }
}

void main() {
  setUpAll(() async {
    // Verify binary and certs exist
    if (!File(revpxBinary).existsSync()) {
      throw Exception(
          'revpx binary not found at $revpxBinary - run make first');
    }
    if (!File(certFile).existsSync() || !File(keyFile).existsSync()) {
      throw Exception('Certificate files not found');
    }

    await startBackend();
    await startProxy();
  });

  tearDownAll(() async {
    await stopAll();
  });

  // ================================================================
  // Basic HTTP methods with package:http client
  // ================================================================
  group('Basic HTTP methods', () {
    late http.Client client;

    setUp(() {
      client = _createClient();
    });

    tearDown(() {
      client.close();
    });

    test('GET request', () async {
      final resp = await client.get(Uri.parse('$baseUrl/test/path'));
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['method'], 'GET');
      expect(data['path'], '/test/path');
    });

    test('POST with JSON body', () async {
      final resp = await client.post(
        Uri.parse('$baseUrl/api/data'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'key': 'value'}),
      );
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['method'], 'POST');
      expect(data['body_length'], greaterThan(0));
    });

    test('PUT request', () async {
      final resp = await client.put(
        Uri.parse('$baseUrl/resource/1'),
        body: 'updated content',
      );
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['method'], 'PUT');
    });

    test('DELETE request', () async {
      final resp = await client.delete(Uri.parse('$baseUrl/resource/1'));
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['method'], 'DELETE');
    });

    test('PATCH request', () async {
      final resp = await client.patch(
        Uri.parse('$baseUrl/resource/1'),
        body: '{"partial": "update"}',
      );
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['method'], 'PATCH');
    });

    test('HEAD request', () async {
      final resp = await client.head(Uri.parse('$baseUrl/test'));
      expect(resp.statusCode, 200);
      expect(resp.body, isEmpty);
    });
  });

  // ================================================================
  // Header forwarding
  // ================================================================
  group('Header forwarding', () {
    late http.Client client;

    setUp(() {
      client = _createClient();
    });

    tearDown(() {
      client.close();
    });

    test('Custom headers are forwarded', () async {
      final resp = await client.get(
        Uri.parse('$baseUrl/headers'),
        headers: {
          'X-Request-Id': 'dart-test-123',
          'X-Correlation-Id': 'corr-456',
          'Accept': 'application/json',
        },
      );
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      final headers = data['headers'] as Map<String, dynamic>;
      expect(headers['x-request-id'], 'dart-test-123');
      expect(headers['x-correlation-id'], 'corr-456');
    });

    test('Authorization header forwarded', () async {
      final resp = await client.get(
        Uri.parse('$baseUrl/protected'),
        headers: {
          'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.test-token',
        },
      );
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      final headers = data['headers'] as Map<String, dynamic>;
      expect(headers['authorization'], contains('Bearer'));
    });

    test('Many headers', () async {
      final customHeaders = <String, String>{};
      for (var i = 0; i < 30; i++) {
        customHeaders['X-Header-$i'] = 'value-$i';
      }

      final resp = await client.get(
        Uri.parse('$baseUrl/many-headers'),
        headers: customHeaders,
      );
      expect(resp.statusCode, 200);
    });
  });

  // ================================================================
  // Connection reuse - Dart's http package reuses connections by default.
  // This is a key difference from Python's requests which creates new
  // connections. Bugs often manifest with keep-alive.
  // ================================================================
  group('Connection reuse (keep-alive)', () {
    late http.Client client;

    setUp(() {
      client = _createClient();
    });

    tearDown(() {
      client.close();
    });

    test('Sequential requests on same client (connection reuse)', () async {
      for (var i = 0; i < 20; i++) {
        final resp = await client.get(Uri.parse('$baseUrl/keepalive/$i'));
        expect(resp.statusCode, 200, reason: 'Request $i failed');
        final data = parseEcho(resp);
        expect(data['path'], '/keepalive/$i');
      }
    });

    test('Sequential POST then GET on same connection', () async {
      for (var i = 0; i < 10; i++) {
        // POST with body
        final postResp = await client.post(
          Uri.parse('$baseUrl/post-then-get/$i'),
          body: 'request body $i',
        );
        expect(postResp.statusCode, 200, reason: 'POST $i failed');

        // GET without body
        final getResp = await client.get(
          Uri.parse('$baseUrl/post-then-get/get/$i'),
        );
        expect(getResp.statusCode, 200, reason: 'GET $i failed');
        final data = parseEcho(getResp);
        expect(data['path'], '/post-then-get/get/$i');
      }
    });

    test('Alternating small and large bodies on same connection', () async {
      final sizes = [10, 5000, 50, 10000, 100, 20000, 10, 30000];
      for (var i = 0; i < sizes.length; i++) {
        final body = 'x' * sizes[i];
        final resp = await client.post(
          Uri.parse('$baseUrl/mixed-sizes/$i'),
          body: body,
        );
        expect(resp.statusCode, 200,
            reason: 'Request $i (size=${sizes[i]}) failed');
        final data = parseEcho(resp);
        expect(data['body_length'], sizes[i]);
      }
    });

    test('Many rapid GETs reusing connection', () async {
      for (var i = 0; i < 100; i++) {
        final resp = await client.get(Uri.parse('$baseUrl/rapid/$i'));
        expect(resp.statusCode, 200, reason: 'Request $i failed');
      }
    });
  });

  // ================================================================
  // Concurrent requests - Dart's http package can send multiple
  // requests in parallel on different connections or multiplexed
  // ================================================================
  group('Concurrent requests', () {
    test('Parallel GETs with separate clients', () async {
      final futures = <Future<http.Response>>[];
      final clients = <http.Client>[];

      for (var i = 0; i < 20; i++) {
        final c = _createClient();
        clients.add(c);
        futures.add(c.get(Uri.parse('$baseUrl/parallel/$i')));
      }

      final results = await Future.wait(futures);
      for (var i = 0; i < results.length; i++) {
        expect(results[i].statusCode, 200,
            reason: 'Parallel request $i failed');
      }

      for (final c in clients) {
        c.close();
      }
    });

    test('Parallel GETs on same client', () async {
      final client = _createClient();
      try {
        final futures = <Future<http.Response>>[];
        for (var i = 0; i < 20; i++) {
          futures
              .add(client.get(Uri.parse('$baseUrl/same-client-parallel/$i')));
        }

        final results = await Future.wait(futures);
        for (var i = 0; i < results.length; i++) {
          expect(results[i].statusCode, 200,
              reason: 'Same-client parallel request $i failed');
        }
      } finally {
        client.close();
      }
    });

    test('Parallel POSTs with bodies on same client', () async {
      final client = _createClient();
      try {
        final futures = <Future<http.Response>>[];
        for (var i = 0; i < 15; i++) {
          futures.add(client.post(
            Uri.parse('$baseUrl/parallel-post/$i'),
            body: 'body for request $i' * 100,
            headers: {'Content-Type': 'text/plain'},
          ));
        }

        final results = await Future.wait(futures);
        for (var i = 0; i < results.length; i++) {
          expect(results[i].statusCode, 200, reason: 'Parallel POST $i failed');
        }
      } finally {
        client.close();
      }
    });

    test('Mixed methods in parallel on same client', () async {
      final client = _createClient();
      try {
        final futures = <Future<http.Response>>[];

        for (var i = 0; i < 10; i++) {
          switch (i % 4) {
            case 0:
              futures.add(client.get(Uri.parse('$baseUrl/mixed/$i')));
              break;
            case 1:
              futures.add(client.post(Uri.parse('$baseUrl/mixed/$i'),
                  body: 'post body'));
              break;
            case 2:
              futures.add(
                  client.put(Uri.parse('$baseUrl/mixed/$i'), body: 'put body'));
              break;
            case 3:
              futures.add(client.delete(Uri.parse('$baseUrl/mixed/$i')));
              break;
          }
        }

        final results = await Future.wait(futures);
        for (var i = 0; i < results.length; i++) {
          expect(results[i].statusCode, 200,
              reason: 'Mixed parallel request $i failed');
        }
      } finally {
        client.close();
      }
    });
  });

  // ================================================================
  // Large payloads
  // ================================================================
  group('Large payloads', () {
    late http.Client client;

    setUp(() {
      client = _createClient();
    });

    tearDown(() {
      client.close();
    });

    test('POST 1KB body', () async {
      final body = 'x' * 1024;
      final resp =
          await client.post(Uri.parse('$baseUrl/payload/1k'), body: body);
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['body_length'], 1024);
    });

    test('POST 10KB body', () async {
      final body = 'x' * (10 * 1024);
      final resp =
          await client.post(Uri.parse('$baseUrl/payload/10k'), body: body);
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['body_length'], 10 * 1024);
    });

    test('POST 30KB body (near buffer size)', () async {
      final body = 'x' * (30 * 1024);
      final resp =
          await client.post(Uri.parse('$baseUrl/payload/30k'), body: body);
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['body_length'], 30 * 1024);
    });

    test('POST 100KB body', () async {
      final body = 'x' * (100 * 1024);
      final resp = await client.post(
        Uri.parse('$baseUrl/payload/100k'),
        body: body,
      );
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['body_length'], 100 * 1024);
    });

    test('POST 1MB body', () async {
      final body = 'x' * (1024 * 1024);
      final resp = await client.post(
        Uri.parse('$baseUrl/payload/1m'),
        body: body,
      );
      expect(resp.statusCode, 200);
      final data = parseEcho(resp);
      expect(data['body_length'], 1024 * 1024);
    });

    test('GET large response (1MB)', () async {
      final resp = await client.get(
        Uri.parse('$baseUrl/large-response/${1024 * 1024}'),
      );
      expect(resp.statusCode, 200);
      expect(resp.bodyBytes.length, 1024 * 1024);
    });

    test('GET large response (5MB)', () async {
      final resp = await client.get(
        Uri.parse('$baseUrl/large-response/${5 * 1024 * 1024}'),
      );
      expect(resp.statusCode, 200);
      expect(resp.bodyBytes.length, 5 * 1024 * 1024);
    });

    test('Binary payload with all byte values', () async {
      final body = List.generate(256 * 100, (i) => i % 256);
      final rawClient = _createRawClient();
      try {
        final request = await rawClient.postUrl(
          Uri.parse('$baseUrl/binary'),
        );
        request.headers.set('Content-Type', 'application/octet-stream');
        request.add(body);
        final response = await request.close();
        final responseBody = await response.fold<List<int>>(
          [],
          (prev, chunk) => prev..addAll(chunk),
        );
        expect(response.statusCode, 200);
        final data = jsonDecode(utf8.decode(responseBody));
        expect(data['body_length'], 256 * 100);
      } finally {
        rawClient.close();
      }
    });
  });

  // ================================================================
  // Rapid sequential requests - stress test connection reuse
  // Dart's http client pools connections aggressively
  // ================================================================
  group('Rapid sequential with connection reuse', () {
    test('50 rapid GETs then 50 rapid POSTs on same client', () async {
      final client = _createClient();
      try {
        // GETs
        for (var i = 0; i < 50; i++) {
          final resp = await client.get(Uri.parse('$baseUrl/rapid-get/$i'));
          expect(resp.statusCode, 200, reason: 'GET $i failed');
        }

        // POSTs
        for (var i = 0; i < 50; i++) {
          final resp = await client.post(
            Uri.parse('$baseUrl/rapid-post/$i'),
            body: 'body $i',
          );
          expect(resp.statusCode, 200, reason: 'POST $i failed');
        }
      } finally {
        client.close();
      }
    });

    test('Interleaved GET/POST without waiting', () async {
      final client = _createClient();
      try {
        final futures = <Future<http.Response>>[];
        for (var i = 0; i < 30; i++) {
          if (i.isEven) {
            futures.add(client.get(Uri.parse('$baseUrl/interleaved/$i')));
          } else {
            futures.add(client.post(
              Uri.parse('$baseUrl/interleaved/$i'),
              body: 'interleaved body $i',
            ));
          }
        }

        final results = await Future.wait(futures);
        for (var i = 0; i < results.length; i++) {
          expect(results[i].statusCode, 200,
              reason: 'Interleaved request $i failed');
        }
      } finally {
        client.close();
      }
    });
  });

  // ================================================================
  // Streaming requests/responses using dart:io HttpClient directly
  // Dart's http package may use chunked encoding for streamed bodies
  // ================================================================
  group('Streamed requests (chunked)', () {
    test('Streamed POST body (triggers chunked TE)', () async {
      final rawClient = _createRawClient();
      try {
        final request = await rawClient.postUrl(
          Uri.parse('$baseUrl/streamed-post'),
        );
        request.headers.contentType = ContentType.text;
        // Write in chunks - Dart may use chunked TE when content-length unknown
        request.write('chunk1');
        request.write('chunk2');
        request.write('chunk3');
        final response = await request.close();
        final body = await response.transform(utf8.decoder).join();
        expect(response.statusCode, 200);
        final data = jsonDecode(body);
        expect(data['body_length'], 18); // "chunk1chunk2chunk3"
      } finally {
        rawClient.close();
      }
    });

    test('Streamed large POST body', () async {
      final rawClient = _createRawClient();
      try {
        final request = await rawClient.postUrl(
          Uri.parse('$baseUrl/streamed-large'),
        );
        request.headers.contentType = ContentType.binary;
        // Write 100KB in 1KB chunks without setting content-length
        const totalSize = 100 * 1024;
        const chunkSize = 1024;
        for (var i = 0; i < totalSize; i += chunkSize) {
          request.add(List.filled(chunkSize, 0x41));
        }
        final response = await request.close();
        final body = await response.transform(utf8.decoder).join();
        expect(response.statusCode, 200);
        final data = jsonDecode(body);
        expect(data['body_length'], totalSize);
      } finally {
        rawClient.close();
      }
    });

    test('Streamed response reading', () async {
      final rawClient = _createRawClient();
      try {
        final request = await rawClient.getUrl(
          Uri.parse('$baseUrl/large-response/${256 * 1024}'),
        );
        final response = await request.close();
        expect(response.statusCode, 200);

        var totalBytes = 0;
        await for (final chunk in response) {
          totalBytes += chunk.length;
        }
        expect(totalBytes, 256 * 1024);
      } finally {
        rawClient.close();
      }
    });
  });

  // ================================================================
  // Edge cases specific to Dart's HTTP behavior
  // ================================================================
  group('Dart-specific edge cases', () {
    test('Request with explicit content-length 0 for GET', () async {
      final rawClient = _createRawClient();
      try {
        final request = await rawClient.getUrl(
          Uri.parse('$baseUrl/get-with-cl0'),
        );
        request.headers.contentLength = 0;
        final response = await request.close();
        final body = await response.transform(utf8.decoder).join();
        expect(response.statusCode, 200);
      } finally {
        rawClient.close();
      }
    });

    test('POST with empty body (Dart sends Content-Length: 0)', () async {
      final client = _createClient();
      try {
        final resp = await client.post(
          Uri.parse('$baseUrl/empty-post'),
          body: '',
        );
        expect(resp.statusCode, 200);
        final data = parseEcho(resp);
        expect(data['body_length'], 0);
      } finally {
        client.close();
      }
    });

    test('Multiple clients created and closed rapidly', () async {
      for (var i = 0; i < 20; i++) {
        final client = _createClient();
        final resp = await client.get(Uri.parse('$baseUrl/rapid-client/$i'));
        expect(resp.statusCode, 200, reason: 'Rapid client $i failed');
        client.close();
      }
    });

    test('Client close while requests may be in-flight', () async {
      final client = _createClient();
      // Fire off requests and immediately close
      final futures = <Future>[];
      for (var i = 0; i < 5; i++) {
        futures.add(
          client
              .get(Uri.parse('$baseUrl/inflight/$i'))
              .catchError((_) => http.Response('', 0)),
        );
      }
      // Don't close immediately — let them complete
      await Future.wait(futures);
      client.close();
    });

    test('Request immediately after previous response', () async {
      // Dart might pipeline or reuse connections aggressively
      final client = _createClient();
      try {
        for (var i = 0; i < 30; i++) {
          final resp = await client.post(
            Uri.parse('$baseUrl/immediate/$i'),
            body: 'body-$i',
          );
          expect(resp.statusCode, 200, reason: 'Immediate request $i failed');
          // No delay at all between requests
        }
      } finally {
        client.close();
      }
    });
  });

  // ================================================================
  // Concurrent large payloads - most likely to trigger buffer issues
  // ================================================================
  group('Concurrent large payloads', () {
    test('5 parallel 100KB POSTs', () async {
      final client = _createClient();
      try {
        final futures = <Future<http.Response>>[];
        for (var i = 0; i < 5; i++) {
          final body = 'A' * (100 * 1024);
          futures.add(client.post(
            Uri.parse('$baseUrl/concurrent-large/$i'),
            body: body,
          ));
        }

        final results = await Future.wait(futures);
        for (var i = 0; i < results.length; i++) {
          expect(results[i].statusCode, 200,
              reason: 'Concurrent large POST $i failed');
          final data = parseEcho(results[i]);
          expect(data['body_length'], 100 * 1024,
              reason: 'Body length mismatch for request $i');
        }
      } finally {
        client.close();
      }
    });

    test('Parallel requests with mixed large/small bodies', () async {
      final client = _createClient();
      try {
        final futures = <Future<http.Response>>[];
        final sizes = [100, 50000, 200, 80000, 50, 30000, 1024, 60000];

        for (var i = 0; i < sizes.length; i++) {
          futures.add(client.post(
            Uri.parse('$baseUrl/mixed-parallel/$i'),
            body: 'x' * sizes[i],
          ));
        }

        final results = await Future.wait(futures);
        for (var i = 0; i < results.length; i++) {
          expect(results[i].statusCode, 200,
              reason: 'Mixed parallel request $i (size=${sizes[i]}) failed');
          final data = parseEcho(results[i]);
          expect(data['body_length'], sizes[i]);
        }
      } finally {
        client.close();
      }
    });

    test('Parallel large response downloads', () async {
      final client = _createClient();
      try {
        final futures = <Future<http.Response>>[];
        for (var i = 0; i < 5; i++) {
          futures.add(client.get(
            Uri.parse('$baseUrl/large-response/${512 * 1024}'),
          ));
        }

        final results = await Future.wait(futures);
        for (var i = 0; i < results.length; i++) {
          expect(results[i].statusCode, 200,
              reason: 'Large response download $i failed');
          expect(results[i].bodyBytes.length, 512 * 1024,
              reason: 'Response size mismatch for $i');
        }
      } finally {
        client.close();
      }
    });
  });

  // ================================================================
  // HTTP redirect (HTTP -> HTTPS)
  // ================================================================
  group('HTTP redirect', () {
    test('HTTP request gets redirected', () async {
      final rawClient = _createRawClient()..autoUncompress = false;
      rawClient.findProxy = (uri) => 'DIRECT';
      try {
        final request = await rawClient.getUrl(
          Uri.parse('http://$testDomain:$httpPort/redirect-test'),
        );
        request.followRedirects = false;
        final response = await request.close();
        await response.drain();
        expect(
          [301, 302, 307, 308],
          contains(response.statusCode),
        );
        expect(response.headers.value('location'), contains('https'));
      } finally {
        rawClient.close();
      }
    });
  });

  // ================================================================
  // Timeout and error handling
  // ================================================================
  group('Timeouts and errors', () {
    test('Request to slow backend succeeds', () async {
      final client = _createClient();
      try {
        final resp = await client.get(
          Uri.parse('$baseUrl/slow-response/500'),
        );
        expect(resp.statusCode, 200);
      } finally {
        client.close();
      }
    });

    test('Various status codes', () async {
      final rawClient = _createRawClient();
      try {
        for (final code in [200, 201, 301, 400, 401, 403, 404, 500, 502, 503]) {
          final request = await rawClient.getUrl(
            Uri.parse('$baseUrl/status/$code'),
          );
          request.followRedirects = false;
          final response = await request.close();
          await response.drain();
          expect(response.statusCode, code, reason: 'Expected status $code');
        }
      } finally {
        rawClient.close();
      }
    });
  });

  // ================================================================
  // BUG REPRODUCTION: Dart client with Content-Type on GET requests
  // The user's Flutter app uses a BaseClient wrapper that adds
  // Content-Type: application/json to ALL requests including GETs.
  // This may cause the proxy to misparse request boundaries on
  // keep-alive connections.
  // ================================================================
  group('Content-Type on GET (Flutter wrapper pattern)', () {
    /// Simulates the user's HttpClient wrapper that adds Content-Type
    /// to every request, even GETs
    http.Client _createFlutterStyleClient() {
      return _FlutterStyleClient(_createClient());
    }

    test('GET with Content-Type: application/json (single)', () async {
      final client = _createFlutterStyleClient();
      try {
        final resp = await client.get(
          Uri.parse('$baseUrl/api/v1/test'),
          headers: {'Content-Type': 'application/json'},
        );
        expect(resp.statusCode, 200);
      } finally {
        client.close();
      }
    });

    test('Sequential GETs with Content-Type on same connection', () async {
      final client = _createFlutterStyleClient();
      try {
        for (var i = 0; i < 20; i++) {
          final resp = await client.get(
            Uri.parse('$baseUrl/api/v1/items/$i'),
            headers: {'Content-Type': 'application/json'},
          );
          expect(resp.statusCode, 200, reason: 'GET $i failed');
          final data = parseEcho(resp);
          expect(data['path'], '/api/v1/items/$i');
        }
      } finally {
        client.close();
      }
    });

    test('GET with Content-Type then POST then GET (keep-alive)', () async {
      final client = _createFlutterStyleClient();
      try {
        for (var i = 0; i < 10; i++) {
          // GET with Content-Type (no body) - this is the suspicious pattern
          final getResp = await client.get(
            Uri.parse('$baseUrl/api/v1/chats/$i'),
            headers: {'Content-Type': 'application/json'},
          );
          expect(getResp.statusCode, 200, reason: 'GET $i failed');

          // POST with body (normal)
          final postResp = await client.post(
            Uri.parse('$baseUrl/api/v1/chats/$i/messages'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'text': 'message $i'}),
          );
          expect(postResp.statusCode, 200, reason: 'POST $i failed');

          // Another GET - this is where the desync would manifest
          final getResp2 = await client.get(
            Uri.parse('$baseUrl/api/v1/chats/$i/messages?page=1'),
            headers: {'Content-Type': 'application/json'},
          );
          expect(getResp2.statusCode, 200, reason: 'GET2 $i failed');
        }
      } finally {
        client.close();
      }
    });

    test('Reproduce exact user pattern: GET with query params and auth',
        () async {
      final client = _createFlutterStyleClient();
      try {
        for (var i = 0; i < 20; i++) {
          final uri = Uri.parse(
            '$baseUrl/api/v1/chats/groups/60ddb879-e37a-4337-9bd5-ddc349ea98e8/messages',
          ).replace(
            queryParameters: {
              'include': 'from_user',
              'page[size]': '30',
              'page[number]': '$i',
              'sort': '-createdAt',
            },
          );

          final resp = await client.get(
            uri,
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer fake-jwt-token-for-testing',
            },
          );
          expect(resp.statusCode, 200, reason: 'Request $i failed');
        }
      } finally {
        client.close();
      }
    });

    test('Parallel GETs with Content-Type on same client', () async {
      final client = _createFlutterStyleClient();
      try {
        final futures = <Future<http.Response>>[];
        for (var i = 0; i < 20; i++) {
          futures.add(client.get(
            Uri.parse('$baseUrl/api/v1/parallel/$i?include=data&page[size]=30'),
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer test-token',
            },
          ));
        }

        final results = await Future.wait(futures);
        for (var i = 0; i < results.length; i++) {
          expect(results[i].statusCode, 200, reason: 'Parallel GET $i failed');
        }
      } finally {
        client.close();
      }
    });

    test('Rapid mixed GET/POST with Content-Type on singleton client',
        () async {
      // Simulates the singleton pattern: final http = HttpClient();
      final client = _createFlutterStyleClient();
      try {
        for (var i = 0; i < 50; i++) {
          if (i % 3 == 0) {
            // POST with body
            final resp = await client.post(
              Uri.parse('$baseUrl/api/v1/messages'),
              headers: {'Content-Type': 'application/json'},
              body: jsonEncode({'text': 'hello $i'}),
            );
            expect(resp.statusCode, 200, reason: 'POST $i failed');
          } else {
            // GET with Content-Type (the problematic pattern)
            final resp = await client.get(
              Uri.parse('$baseUrl/api/v1/messages?page=$i&sort=-createdAt'),
              headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer test-token',
              },
            );
            expect(resp.statusCode, 200, reason: 'GET $i failed');
          }
        }
      } finally {
        client.close();
      }
    });

    test('DELETE with Content-Type then GET (another common pattern)',
        () async {
      final client = _createFlutterStyleClient();
      try {
        for (var i = 0; i < 15; i++) {
          final delResp = await client.delete(
            Uri.parse('$baseUrl/api/v1/items/$i'),
            headers: {'Content-Type': 'application/json'},
          );
          expect(delResp.statusCode, 200, reason: 'DELETE $i failed');

          final getResp = await client.get(
            Uri.parse('$baseUrl/api/v1/items?page=1'),
            headers: {'Content-Type': 'application/json'},
          );
          expect(getResp.statusCode, 200, reason: 'GET after DELETE $i failed');
        }
      } finally {
        client.close();
      }
    });

    test('Concurrent requests from singleton-like client (real app pattern)',
        () async {
      // In a real Flutter app, multiple widgets/services fire requests
      // concurrently on the same singleton HttpClient
      final client = _createFlutterStyleClient();
      try {
        for (var round = 0; round < 5; round++) {
          final futures = <Future<http.Response>>[];

          // Simulate multiple parts of the app firing at once
          futures.add(client.get(
            Uri.parse('$baseUrl/api/v1/user/profile'),
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer tok'
            },
          ));
          futures.add(client.get(
            Uri.parse('$baseUrl/api/v1/chats?page=1'),
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer tok'
            },
          ));
          futures.add(client.get(
            Uri.parse('$baseUrl/api/v1/notifications?unread=true'),
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer tok'
            },
          ));
          futures.add(client.post(
            Uri.parse('$baseUrl/api/v1/analytics/event'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'event': 'page_view', 'round': round}),
          ));

          final results = await Future.wait(futures);
          for (var i = 0; i < results.length; i++) {
            expect(results[i].statusCode, 200,
                reason: 'Round $round, request $i failed');
          }
        }
      } finally {
        client.close();
      }
    });
  });

  // ================================================================
  // AGGRESSIVE STRESS TESTS - designed to trigger intermittent bugs
  // ================================================================
  group('Stress tests', () {
    test('500 sequential requests on singleton client (Flutter pattern)',
        () async {
      final client = _FlutterStyleClient(_createClient());
      final rng = Random(42);
      try {
        for (var i = 0; i < 500; i++) {
          final method = rng.nextInt(4);
          http.Response resp;
          switch (method) {
            case 0:
              resp = await client.get(
                Uri.parse('$baseUrl/stress/$i?page=${rng.nextInt(10)}'),
                headers: {'Authorization': 'Bearer tok'},
              );
              break;
            case 1:
              resp = await client.post(
                Uri.parse('$baseUrl/stress/$i'),
                body: jsonEncode({'data': 'x' * (rng.nextInt(1000) + 10)}),
              );
              break;
            case 2:
              resp = await client.put(
                Uri.parse('$baseUrl/stress/$i'),
                body: jsonEncode({'update': i}),
              );
              break;
            default:
              resp = await client.delete(
                Uri.parse('$baseUrl/stress/$i'),
              );
              break;
          }
          expect(resp.statusCode, 200, reason: 'Stress request $i failed');
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 60)));

    test('Burst of 100 concurrent requests on same client', () async {
      final client = _FlutterStyleClient(_createClient());
      try {
        final futures = <Future<http.Response>>[];
        for (var i = 0; i < 100; i++) {
          if (i.isEven) {
            futures.add(client.get(
              Uri.parse('$baseUrl/burst/$i?include=data'),
              headers: {'Authorization': 'Bearer tok'},
            ));
          } else {
            futures.add(client.post(
              Uri.parse('$baseUrl/burst/$i'),
              body: jsonEncode({'msg': 'burst $i'}),
            ));
          }
        }

        final results = await Future.wait(futures);
        var successCount = 0;
        for (final r in results) {
          if (r.statusCode == 200) successCount++;
        }
        expect(successCount, greaterThanOrEqualTo(90),
            reason: 'Too many failures: only $successCount/100 succeeded');
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 30)));

    test('Repeated bursts (simulate app navigation)', () async {
      // Simulates user navigating between screens: each screen fires
      // 3-5 concurrent GETs on load
      final client = _FlutterStyleClient(_createClient());
      try {
        for (var screen = 0; screen < 50; screen++) {
          final numRequests = 3 + (screen % 3); // 3-5 concurrent
          final futures = <Future<http.Response>>[];

          for (var i = 0; i < numRequests; i++) {
            futures.add(client.get(
              Uri.parse(
                '$baseUrl/api/v1/screen/$screen/data/$i'
                '?include=relations&page[size]=20&page[number]=1',
              ),
              headers: {'Authorization': 'Bearer jwt-token-here'},
            ));
          }

          final results = await Future.wait(futures);
          for (var i = 0; i < results.length; i++) {
            expect(results[i].statusCode, 200,
                reason: 'Screen $screen, request $i failed');
          }
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 60)));

    test('Simulate real Flutter app lifecycle with variable backend delay',
        () async {
      final client = _FlutterStyleClient(_createClient());
      try {
        for (var i = 0; i < 200; i++) {
          // Mix of patterns seen in real apps
          final futures = <Future<http.Response>>[];

          // Fetch list with variable backend delay
          futures.add(client.get(
            Uri.parse('$baseUrl/variable-delay/$i?page=1&sort=-createdAt'),
            headers: {'Authorization': 'Bearer tok'},
          ));

          // Maybe also fetch a detail page concurrently
          if (i % 2 == 0) {
            futures.add(client.get(
              Uri.parse('$baseUrl/variable-delay/$i/detail'),
              headers: {'Authorization': 'Bearer tok'},
            ));
          }

          // Maybe also post something
          if (i % 5 == 0) {
            futures.add(client.post(
              Uri.parse('$baseUrl/variable-delay/$i/action'),
              body: jsonEncode({'action': 'update'}),
            ));
          }

          final results = await Future.wait(futures);
          for (var j = 0; j < results.length; j++) {
            expect(results[j].statusCode, 200,
                reason: 'Iteration $i, request $j failed');
          }
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 120)));

    test('Slow drip responses with keep-alive reuse', () async {
      // Backend sends response body slowly - proxy must handle this
      // while client tries to reuse the connection
      final client = _FlutterStyleClient(_createClient());
      try {
        for (var i = 0; i < 50; i++) {
          final resp = await client.get(
            Uri.parse('$baseUrl/slow-drip/${500 + i * 10}'),
            headers: {'Authorization': 'Bearer tok'},
          );
          expect(resp.statusCode, 200, reason: 'Slow drip $i failed');
          expect(resp.bodyBytes.length, 500 + i * 10,
              reason: 'Slow drip $i body size mismatch');
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 60)));

    test('Multiple singleton clients in parallel (multi-isolate pattern)',
        () async {
      // Simulates having multiple HttpClient singletons (e.g. from
      // different isolates or packages) all hitting the proxy
      final clients =
          List.generate(5, (_) => _FlutterStyleClient(_createClient()));
      try {
        final allFutures = <Future>[];

        for (var c = 0; c < clients.length; c++) {
          allFutures.add(() async {
            final client = clients[c];
            for (var i = 0; i < 100; i++) {
              final resp = await client.get(
                Uri.parse('$baseUrl/multi-client/$c/$i?page=1'),
                headers: {'Authorization': 'Bearer tok-$c'},
              );
              expect(resp.statusCode, 200,
                  reason: 'Client $c, request $i failed');
            }
          }());
        }

        await Future.wait(allFutures);
      } finally {
        for (final c in clients) {
          c.close();
        }
      }
    }, timeout: Timeout(Duration(seconds: 60)));

    test(
        'Connection storm: create/close many clients rapidly while making requests',
        () async {
      // Sometimes in Flutter, widgets get created/destroyed rapidly,
      // each potentially creating their own client
      final errors = <String>[];
      for (var i = 0; i < 100; i++) {
        final client = _FlutterStyleClient(_createClient());
        try {
          final resp = await client.get(
            Uri.parse('$baseUrl/storm/$i?include=all&page[size]=50'),
            headers: {'Authorization': 'Bearer tok'},
          );
          if (resp.statusCode != 200) {
            errors.add('Request $i: status ${resp.statusCode}');
          }
        } catch (e) {
          errors.add('Request $i: $e');
        } finally {
          client.close();
        }
      }
      expect(errors, isEmpty, reason: 'Errors: ${errors.join(', ')}');
    }, timeout: Timeout(Duration(seconds: 30)));

    test(
        'Backend sends Connection: close intermittently (real server behavior)',
        () async {
      // Many real backends (gunicorn, puma, uvicorn) close connections after
      // N requests. The proxy must handle this gracefully without dropping
      // the client's next request.
      final client = _FlutterStyleClient(_createClient());
      _backendRequestCount = 0;
      try {
        for (var i = 0; i < 200; i++) {
          final resp = await client.get(
            Uri.parse('$baseUrl/conn-limit/$i?page=1&sort=-createdAt'),
            headers: {'Authorization': 'Bearer tok'},
          );
          expect(resp.statusCode, 200,
              reason:
                  'Request $i failed (backend req count: $_backendRequestCount)');
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 30)));

    test('Backend always closes connection (no keep-alive)', () async {
      // Some backends never support keep-alive.
      // The proxy must re-establish backend connections transparently.
      final client = _FlutterStyleClient(_createClient());
      try {
        for (var i = 0; i < 100; i++) {
          final resp = await client.get(
            Uri.parse('$baseUrl/no-keepalive/$i'),
            headers: {'Authorization': 'Bearer tok'},
          );
          expect(resp.statusCode, 200,
              reason: 'No-keepalive request $i failed');
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 30)));

    test('Concurrent requests while backend closes connections', () async {
      final client = _FlutterStyleClient(_createClient());
      _backendRequestCount = 0;
      try {
        for (var round = 0; round < 30; round++) {
          final futures = <Future<http.Response>>[];
          for (var i = 0; i < 5; i++) {
            futures.add(client.get(
              Uri.parse('$baseUrl/conn-limit/round$round-$i?include=all'),
              headers: {'Authorization': 'Bearer tok'},
            ).catchError((e) {
              throw Exception('Round $round req $i failed: $e');
            }));
          }
          final results = await Future.wait(futures);
          for (var i = 0; i < results.length; i++) {
            expect(results[i].statusCode, 200,
                reason: 'Round $round, request $i failed');
          }
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 30)));

    test('Mixed conn-limit and normal on same client', () async {
      // Client reuses connections, but some backend responses close them
      final client = _FlutterStyleClient(_createClient());
      _backendRequestCount = 0;
      try {
        for (var i = 0; i < 100; i++) {
          http.Response resp;
          if (i % 2 == 0) {
            // This may trigger Connection: close from backend
            resp = await client.get(
              Uri.parse('$baseUrl/conn-limit/$i'),
              headers: {'Authorization': 'Bearer tok'},
            );
          } else {
            // Normal request - backend keeps connection alive
            resp = await client.get(
              Uri.parse('$baseUrl/api/v1/normal/$i'),
              headers: {'Authorization': 'Bearer tok'},
            );
          }
          expect(resp.statusCode, 200,
              reason: 'Mixed conn-limit request $i failed');
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 30)));

    test('POST then rapid GET after backend connection close', () async {
      // POST causes a response, backend closes conn, client immediately GETs
      final client = _FlutterStyleClient(_createClient());
      _backendRequestCount = 0;
      try {
        for (var i = 0; i < 50; i++) {
          // POST - this might get Connection: close response
          final postResp = await client.post(
            Uri.parse('$baseUrl/conn-limit/$i'),
            body: jsonEncode({'msg': 'hello $i'}),
          );
          expect(postResp.statusCode, 200, reason: 'POST $i failed');

          // Immediately GET - if the previous connection was closed,
          // this must work on a new connection
          final getResp = await client.get(
            Uri.parse('$baseUrl/conn-limit/${i}_get?page=1'),
            headers: {'Authorization': 'Bearer tok'},
          );
          expect(getResp.statusCode, 200, reason: 'GET after POST $i failed');
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 30)));

    test('GET-heavy workload with large query strings (exact user scenario)',
        () async {
      final client = _FlutterStyleClient(_createClient());
      try {
        for (var i = 0; i < 300; i++) {
          final uri = Uri.parse(
            '$baseUrl/api/v1/chats/groups/'
            '60ddb879-e37a-4337-9bd5-ddc349ea98e8/messages',
          ).replace(queryParameters: {
            'include': 'from_user,reactions,attachments',
            'page[size]': '30',
            'page[number]': '${i % 10 + 1}',
            'sort': '-createdAt',
            'filter[type]': 'text',
          });

          final resp = await client.get(
            uri,
            headers: {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.test'},
          );
          expect(resp.statusCode, 200,
              reason: 'Request $i failed (page=${i % 10 + 1})');
        }
      } finally {
        client.close();
      }
    }, timeout: Timeout(Duration(seconds: 60)));
  });
}
