# revpx
Tis is just a POC made for fun.

`revpx` is a lightweight, single-threaded reverse proxy server for development purposes.

It supports TLS/SSL termination, SNI (Server Name Indication), and can forward traffic to multiple backend services based on the requested domain name. You can mount multiple backends on the same domain under different path prefixes and optionally rewrite the prefix away before forwarding.

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
    "domain": "example.localhost",
    "cert_file": "example.localhost.pem",
    "key_file": "example.localhost-key.pem",
    "routes": [
      { "path": "/", "port": "8080" },
      { "path": "/api", "port": "8081", "rewrite": true }
    ]
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
RevPx *revpx_create(const char *http_port, const char *https_port);
bool revpx_add_domain(RevPx *revpx, const char *domain, const char *host, const char *port, const char *cert, const char *key);
bool revpx_add_domain_route(RevPx *revpx, const char *domain, const char *path, const char *host, const char *port, bool rewrite_prefix);
void revpx_run_server(RevPx *revpx);
void revpx_free(RevPx *revpx);

// Example usage
int main() {
    RevPx *revpx = revpx_create("80", "443");
    revpx_add_domain(revpx, "example.localhost", NULL, "8080", "example.localhost.pem", "example.localhost-key.pem");
    revpx_add_domain_route(revpx, "example.localhost", "/api", NULL, "8081", true);
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
    port: Some("8080".to_string()),
    cert: "example.localhost.pem".to_string(),
    key: "example.localhost-key.pem".to_string(),
    routes: vec![revpx::RouteConfig {
        path: "/api".to_string(),
        port: "8081".to_string(),
        rewrite: true,
        ..Default::default()
    }],
    ..Default::default()
}]);
revpx.run_server();
```
