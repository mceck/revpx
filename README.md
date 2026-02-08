# revpx
`revpx` is a lightweight, single-threaded reverse proxy server for development purposes.

It supports TLS/SSL termination, SNI (Server Name Indication), and can forward traffic to multiple backend services based on the requested domain name.

It is designed to be simple to configure and use.

## Usage

You can generate the SSL certificate files using [mkcert](https://github.com/FiloSottile/mkcert) or openssl.

### 1. Command-Line Arguments

You can specify domain mappings directly on the command line. Each mapping consists of a domain name, a backend port, a certificate file, and a key file.

```bash
revpx [<options>] [<domain> <port> <cert_file> <key_file> ...]
```

**Options:**

- `--help, -h`: Show the help message.
- `--file, -f <path>`: Load configuration from a JSON file.
- `--port, -p <port>`: The HTTPS port for `revpx` to listen on (default: 443).
- `--port-plain, -pp <port>`: The HTTP port for `revpx` to listen on (default: 80).

**Example:**

```bash
# Forward traffic for example.com to localhost:8080
revpx example.com 8080 /path/to/cert.pem /path/to/key.pem
```

### 2. JSON Configuration File

For more complex setups, you can use a JSON file.

**Example `revpx.example.json`:**

```json
[
  {
    "domain": "example.com",
    "port": "8080",
    "cert_file": "/path/to/example.com.pem",
    "key_file": "/path/to/example.com-key.pem"
  },
  {
    "domain": "api.example.com",
    "port": "8081",
    "cert_file": "/path/to/api.example.com.pem",
    "key_file": "/path/to/api.example.com-key.pem"
  }
]
```

Run `revpx` with the file:

```bash
revpx --file revpx.example.json
```

## Building from Source

This project depends on OpenSSL and libyaml. Make sure you have the development headers installed (e.g. `libssl-dev` and `libyaml-dev` on Debian-based systems).

```bash
# Compile the project
make
# Install the binary system-wide (optional)
make install
```

### Scripts

- `make`: Build the project
- `make test`: Build and run the tests
- `make example`: Build and run with example domain `test.localhost` on port `8080`
- `make install`: Install the binary system-wide in /usr/local/bin

### C api

```c
#include "revpx.h"
/**
 * Create a new RevPx instance.
 * @param http_port Port to listen for HTTP (will redirect to HTTPS)
 * @param https_port Port to listen for HTTPS
 */
RevPx *revpx_create(const char *http_port, const char *https_port);
/**
 * Free a RevPx instance and all associated resources.
 * @param revpx The RevPx instance to free
 */
void revpx_free(RevPx *revpx);
/**
 * Add a domain mapping to the reverse proxy.
 * @param revpx The RevPx instance
 * @param domain The domain name to match (e.g. "example.com")
 * @param host The backend host to forward to (default: "127.0.0.1")
 * @param port The backend port to forward to
 * @param cert The path to the SSL certificate file
 * @param key The path to the SSL key file
 */
bool revpx_add_domain(RevPx *revpx, const char *domain, const char *host, const char *port, const char *cert, const char *key);
/**
 * Start the reverse proxy server.
 * Listens on https_port for HTTPS and redirects HTTP traffic from http_port to HTTPS.
 * @param revpx The RevPx instance
 * @return 0 on success, non-zero on failure
 */
int revpx_run_server(RevPx *revpx);
/**
 * Set the log level for revpx. Messages with a level lower than this will be ignored.
 * Default level is RP_INFO.
 */
void revpx_set_log_level(int level);

// Example usage
int main() {
    RevPx *revpx = revpx_create("80", "443");
    revpx_add_domain(revpx, "test.localhost", NULL, "8080", "test.localhost.pem", "test.localhost-key.pem");
    revpx_run_server(revpx);
    revpx_free(revpx);
    return 0;
}
```

### Rust bindings

```bash
cargo add --git https://github.com/mceck/revpx.git
```

```rust
let revpx = revpx::RevPx::default();
revpx.add_domains(vec![revpx::DomainConfig {
    domain: "test.localhost".to_string(),
    host: None,
    port: "8080".to_string(),
    cert: "test.localhost.pem".to_string(),
    key: "test.localhost-key.pem".to_string(),
}]);
revpx.run_server();
```
