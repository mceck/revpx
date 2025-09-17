#include <stdio.h>
#include "revpx.h"
#define DEFAULT_PORT "443"

int main(int argc, char **argv) {
    char *port = getenv("REVPX_PORT");
    if (!port) port = DEFAULT_PORT;

    if (argc < 5 || (argc - 1) % 4 != 0) {
        log_error("Usage: %s <domain> <port> <cert_file> <key_file> ...\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i += 4) {
        const char *domain = argv[i];
        const char *port = argv[i + 1];
        const char *cert_file = argv[i + 2];
        const char *key_file = argv[i + 3];
        add_domain(domain, port, cert_file, key_file);
        log_info("Mapping domain %s to port %s\n", domain, port);
    }
    run_revpx_server(port);

    return 0;
}
