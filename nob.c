#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#define NOB_EXPERIMENTAL_DELETE_OLD
#include "nob.h"

void download_github_dep(Procs *procs, const char *repo, const char *file_path, const char *output_path) {
    char url[256];
    snprintf(url, sizeof(url), "https://raw.githubusercontent.com/%s/refs/heads/%s", repo, file_path);
    Cmd cmd = {0};
    cmd_append(&cmd, "curl", "-L", "-o", output_path, url);
    if (!cmd_run(&cmd, .async = procs, .stderr_path = "/dev/null")) {
        nob_log(NOB_ERROR, "Failed to download %s from %s", file_path, repo);
        exit(1);
    }
    nob_log(NOB_INFO, "Downloaded %s successfully", output_path);
}

int main(int argc, char **argv) {
    NOB_GO_REBUILD_URSELF(argc, argv);
    Cmd cmd = {0};
    Procs procs = {0};

    if (!nob_mkdir_if_not_exists("build")) {
        nob_log(NOB_ERROR, "Failed to create build directory");
        return 1;
    }

    // UPDATE
    if (argc > 1 && (strcmp(argv[1], "update") == 0)) {
        download_github_dep(&procs, "mceck/c-stb", "main/jsp.h", "src/jsp.h");
        download_github_dep(&procs, "tsoding/nob.h", "main/nob.h", "nob.h");
        if (!procs_flush(&procs)) {
            nob_log(NOB_ERROR, "Update failed");
            return 1;
        }
    }

    // BUILD
    cmd_append(&cmd, "cc", "src/revpx-srv.c", "-o", "build/revpx", "-lssl", "-lyaml", "-lcrypto", "-O2", "-Wall", "-Wextra");
#if __APPLE__
    cmd_append(&cmd, "-I/opt/homebrew/include/", "-L/opt/homebrew/lib/");
#endif
    if (!cmd_run(&cmd, .async = &procs)) {
        nob_log(NOB_ERROR, "Build failed");
        return 1;
    }

    cmd_append(&cmd, "cc", "-c", "src/revpx-lib.c", "-o", "build/revpx.o", "-O2", "-Wall", "-Wextra");
#if __APPLE__
    cmd_append(&cmd, "-I/opt/homebrew/include/");
#endif
    if (!cmd_run(&cmd, .async = &procs)) {
        nob_log(NOB_ERROR, "Build failed");
        return 1;
    }

    cmd_append(&cmd, "cc", "-shared", "src/revpx-lib.c", "-o", "build/revpx.so", "-fPIC", "-Wall", "-Wextra", "-O2", "-lssl", "-lcrypto");
#if __APPLE__
    cmd_append(&cmd, "-I/opt/homebrew/include/", "-L/opt/homebrew/lib/");
#endif
    if (!cmd_run(&cmd, .async = &procs)) {
        nob_log(NOB_ERROR, "Build failed");
        return 1;
    }

    if (!procs_flush(&procs)) {
        nob_log(NOB_ERROR, "Build failed");
        return 1;
    }

    cmd_append(&cmd, "ar", "rcs", "build/revpx.a", "build/revpx.o");
    if (!cmd_run(&cmd)) {
        nob_log(NOB_ERROR, "Library creation failed");
        return 1;
    }

    // INSTALL
    if (argc > 1 && (strcmp(argv[1], "install") == 0)) {
        cmd_append(&cmd, "sudo", "cp", "build/revpx", "/usr/local/bin/revpx");
        if (!cmd_run(&cmd)) {
            nob_log(NOB_ERROR, "Install failed");
            return 1;
        }
    }

    // RUN
    bool is_run = argc > 1 && strcmp(argv[1], "run") == 0;
    bool is_example = argc > 1 && strcmp(argv[1], "example") == 0;
    if (is_run || is_example) {
        if (is_example) {
            cmd_append(&cmd, "mkcert", "example.localhost");
            if (!cmd_run(&cmd)) {
                nob_log(NOB_ERROR, "Failed to create TLS certificates");
                return 1;
            }
        }
#ifndef __APPLE__
        cmd_append(&cmd, "sudo");
#endif
        cmd_append(&cmd, "build/revpx");
        if (is_example) {
            cmd_append(&cmd, "example.localhost", "8080", "example.localhost.pem", "example.localhost-key.pem");
        } else {
            for (int i = 2; i < argc; i++)
                cmd_append(&cmd, argv[i]);
        }
        if (!cmd_run(&cmd)) {
            nob_log(NOB_ERROR, "Failed to start revpx");
            return 1;
        }
    }

    return 0;
}