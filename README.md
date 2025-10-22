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

This project uses `nob.c` as a build system. To build the project, you need a C compiler (like `gcc` or `clang`) and OpenSSL development libraries.

```bash
# 1. Compile the build script
cc -o nob nob.c

# 2. Build the project
./nob
```

### Scripts

- `./nob`: Build the project
- `./nob update`: Update dependencies
- `./nob run [...]`: Build and run the project
- `./nob example`: Build and run with example domain `example.localhost` on port `8080`
- `./nob install`: Install the binary system-wide in /usr/local/bin

### C api

```c
#include "revpx.h"
/**
 * Create a new RevPx instance.
 */
RevPx *revpx_create(const char *http_port, const char *https_port);
/**
 * Add a domain mapping to the reverse proxy.
 */
bool revpx_add_domain(RevPx *revpx, const char *domain, const char *host, const char *port, const char *cert, const char *key);
/**
 * Start the reverse proxy server.
 * Listens on https_port for HTTPS and redirects HTTP traffic from http_port to HTTPS.
 */
void revpx_run_server(RevPx *revpx);
/**
 * Free the RevPx instance and release resources.
 */
void revpx_free(RevPx *revpx);

// Example usage
int main() {
    RevPx *revpx = revpx_create("80", "443");
    revpx_add_domain(revpx, "example.localhost", NULL, "8080", "example.localhost.pem", "example.localhost-key.pem");
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
    domain: "example.localhost".to_string(),
    host: None,
    port: "8080".to_string(),
    cert: "example.localhost.pem".to_string(),
    key: "example.localhost-key.pem".to_string(),
}]);
revpx.run_server();
```
