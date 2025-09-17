#include "revpx.h"
#define LISTEN_PORT "443"

int main(void) {
    add_domain("example.localhost", "8080", "example.localhost.pem", "example.localhost-key.pem");
    add_domain("example.test", "8000", "example.test.pem", "example.test-key.pem");
    run_revpx_server(LISTEN_PORT);

    return 0;
}
