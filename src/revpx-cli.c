#include <stdio.h>
#define REVPX_IMPLEMENTATION
#define DS_NO_PREFIX
#include "revpx.h"
#include "argparse.h"
#define DEFAULT_PORT "443"
#define DEFAULT_PORT_PLAIN "80"

void print_help() {
    printf("revpx - Reverse Proxy\n");
    printf("revpx [<options>] [<domain> <port> <cert_file> <key_file> ...]\n");
    printf("Options:\n");
    printf("    --help/-h                 Show this help message\n");
    printf("    --file/-f <path>          Load config from JSON config file\n");
    printf("    --monade/-m <path>        Load config from Monade config file (default: ./monade.yaml)\n");
    printf("    --port/-p <port>          Https port for revpx to listen on (default: 443)\n");
    printf("    --port-plain/-pp <port>   Http port for revpx to listen on (default: 80)\n\n");
    printf("\nExamples:\n");
    printf("  revpx --file config.json\n");
    printf("  revpx example.localhost 8080 example.localhost.pem example.localhost-key.pem\n");
}

int main(int argc, const char **argv) {
    const char *sec_port = getenv("REVPX_PORT");
    const char *plain_port = getenv("REVPX_PORT_PLAIN");
    Args args = {.argc = argc, .argv = argv};
    int has_file_arg = 0;
    while (arg_next(&args)) {
        if (named_arg(&args, "help", "h")) {
            print_help();
            return 0;
        } else if (named_arg(&args, "file", "f")) {
            if (parse_config_file(args.value) != 0) {
                print_help();
                return 1;
            }
            has_file_arg = 1;
        } else if (named_arg(&args, "port", "p")) {
            sec_port = args.value;
        } else if (named_arg(&args, "port-plain", "pp")) {
            plain_port = args.value;
        } else if (named_arg(&args, "monade", "m")) {
            if (parse_monade_yaml(args.value) != 0) {
                print_help();
                return 1;
            }
            has_file_arg = 1;
        }
    }

    // <domain> <port> <cert_file> <key_file> ...
    if (!has_file_arg && parse_args(argc, argv) != 0) {
        print_help();
        return 1;
    }
    if (rp_domains.count == 0) {
        if (parse_monade_yaml(NULL) != 0) {
            print_help();
            return 1;
        }
    }
    if (!sec_port) sec_port = DEFAULT_PORT;
    if (!plain_port) plain_port = DEFAULT_PORT_PLAIN;
    revpx_run_server(plain_port, sec_port);

    revpx_free_domains();
    return 0;
}
