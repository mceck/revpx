#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#define NOB_EXPERIMENTAL_DELETE_OLD
#include "nob.h"

void download_github_dep(Procs *procs, const char *repo, const char *file_path, const char *output_path) {
    char url[256];
    snprintf(url, sizeof(url), "https://raw.githubusercontent.com/%s/refs/heads/%s", repo, file_path);
    Cmd cmd = {0};
    cmd_append(&cmd, "curl", "-L", "-o", output_path, url);
    if (!cmd_run(&cmd, .async = procs)) {
        nob_log(NOB_ERROR, "Failed to download %s from %s", file_path, repo);
        exit(1);
    }
    nob_log(NOB_INFO, "Downloaded %s successfully", output_path);
}

int main(int argc, char **argv) {
    NOB_GO_REBUILD_URSELF(argc, argv);
    Cmd cmd = {0};
    Procs procs = {0};

    // UPDATE
    if (argc > 1 && (strcmp(argv[1], "update") == 0)) {
        download_github_dep(&procs, "mceck/c-stb", "main/ds.h", "ds.h");
        download_github_dep(&procs, "mceck/c-stb", "main/jsp.h", "jsp.h");
        download_github_dep(&procs, "tsoding/nob.h", "main/nob.h", "nob.h");
        return !procs_flush(&procs);
    }

    // BUILD
    cmd_append(&cmd, "cc", "-o", "revpx", "revpx.c", "-lssl", "-lcrypto", "-O2");
#if __APPLE__
    cmd_append(&cmd, "-I/opt/homebrew/include/", "-L/opt/homebrew/lib/");
#endif
    if (!cmd_run(&cmd)) {
        nob_log(NOB_ERROR, "Build failed");
        return 1;
    }

    // INSTALL
    if (argc > 1 && (strcmp(argv[1], "install") == 0)) {
        cmd_append(&cmd, "sudo", "cp", "revpx", "/usr/local/bin/revpx");
        if (!cmd_run(&cmd)) {
            nob_log(NOB_ERROR, "Install failed");
            return 1;
        }
    }

    // RUN
    if (argc > 1 && (strcmp(argv[1], "run") == 0)) {
        cmd_append(&cmd, "mkcert", "example.localhost");
        if (!cmd_run(&cmd)) {
            nob_log(NOB_ERROR, "Failed to create TLS certificates");
            return 1;
        }
#ifndef __APPLE__
        cmd_append(&cmd, "sudo");
#endif
        cmd_append(&cmd, "./revpx");
        cmd_append(&cmd, "example.localhost", "8080", "example.localhost.pem", "example.localhost-key.pem");
        if (!cmd_run(&cmd)) {
            nob_log(NOB_ERROR, "Failed to start revpx");
            return 1;
        }
    }

    return 0;
}