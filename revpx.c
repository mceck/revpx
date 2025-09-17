#include <stdio.h>
#include "revpx.h"
#include "argparse.h"
#define DEFAULT_PORT "443"

void print_help() {
    printf("revpx - Reverse Proxy\n");
    printf("Usage:\n");
    printf("  revpx --file <path>          Load domain mappings from JSON config file\n");
    printf("  revpx <domain> <port> <cert_file> <key_file> ...\n");
    printf("\nExamples:\n");
    printf("  revpx --file config.json\n");
    printf("  revpx example.localhost 8080 example.localhost.pem example.localhost-key.pem\n");
    printf("\nEnvironment Variables:\n");
    printf("  REVPX_PORT: Port for revpx to listen on (default: 443)\n");
}

int main(int argc, char **argv) {
    char *port = getenv("REVPX_PORT");
    if (!port) port = DEFAULT_PORT;
    // -h, --help
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_help();
        return 0;
    }
    // --file <path>
    if (argc == 3 && strcmp(argv[1], "--file") == 0) {
        if (parse_config_file(argc, argv) != 0) {
            print_help();
            return 1;
        }
    } else {
        // <domain> <port> <cert_file> <key_file> ...
        if (parse_args(argc, argv) != 0) {
            print_help();
            return 1;
        }
    }
    run_revpx_server(port);

    return 0;
}
