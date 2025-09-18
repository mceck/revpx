#define REVPX_IMPLEMENTATION
#define JSP_IMPLEMENTATION
#include <stdio.h>
#include "revpx.h"
#include "jsp.h"
#include "yml.h"

#define DEFAULT_PORT "443"
#define DEFAULT_PORT_PLAIN "80"

typedef enum {
    ARG_UNKNOWN,
    ARG_NAMED,
    ARG_POSITIONAL
} ArgType;

typedef struct {
    int argc;
    const char **argv;
    int index;
    ArgType type;
    const char *value;
    union {
        int position;
        const char *name;
    };
} Args;

bool arg_next(Args *args) {
    if (args->index == 0) args->index = 1; // skip program name
    if (args->index >= args->argc) return false;
    const char *arg = args->argv[args->index++];
    if (arg[0] == '-') {
        args->type = ARG_NAMED;
        args->name = arg + (arg[1] == '-' ? 2 : 1);
    } else {
        args->type = ARG_POSITIONAL;
        args->position = args->index - 1;
        args->value = arg;
    }
    return true;
}

bool flag_arg(Args *args, ...) {
    if (args->type != ARG_NAMED) return false;
    const char *arg = args->name;
    va_list va;
    va_start(va, args);
    const char *n;
    while ((n = va_arg(va, const char *))) {
        if (!n[0]) break;
        if (strcmp(arg, n) == 0) {
            va_end(va);
            return true;
        }
    }
    va_end(va);
    return false;
}

#define named_arg(args, ...) \
    (flag_arg(args, __VA_ARGS__) && ((args)->value = (args)->index < (args)->argc ? (args)->argv[(args)->index++] : ""))

bool positional_arg(Args *args) {
    return args->type == ARG_POSITIONAL;
}

char *read_entire_file(const char *path, size_t *size) {
    char *new_items = NULL;
    FILE *f = fopen(path, "rb");
    if (f == NULL) goto cleanup;
    if (fseek(f, 0, SEEK_END) < 0) goto cleanup;
    *size = ftell(f);
    if (*size < 0) goto cleanup;
    if (fseek(f, 0, SEEK_SET) < 0) goto cleanup;

    new_items = malloc(*size);
    fread(new_items, *size, 1, f);
    if (ferror(f) && new_items) {
        free(new_items);
        new_items = NULL;
        goto cleanup;
    }
cleanup:
    if (f) fclose(f);
    return new_items;
}

int parse_config_file(RevPx *revpx, const char *config_file) {
    Jsp jsp = {0};
    size_t size = 0;
    int ret = 0;
    char *content = read_entire_file(config_file, &size);
    if (!content) {
        rp_log_error("Failed to read config file %s\n", config_file);
        ret = 1;
        goto cleanup;
    }
    jsp_init(&jsp, content, size);
    ret = jsp_begin_array(&jsp);
    if (ret != 0) {
        rp_log_error("Failed to initialize JSON parser for config file %s\n", config_file);
        ret = 1;
        goto cleanup;
    };
    int len = jsp_array_length(&jsp);
    if (len <= 0) {
        rp_log_error("Config file %s is not a valid JSON array\n", config_file);
        ret = 1;
        goto cleanup;
    }
    for (int i = 0; i < len; i++) {
        if (jsp_begin_object(&jsp) != 0) {
            rp_log_error("Failed to parse object %d in config file %s\n", i, config_file);
            ret = 1;
            goto cleanup;
        }
        char domain[256], host[256], port[16], cert_file[512], key_file[512];
        while (jsp_key(&jsp) == 0) {
            if (strcmp(jsp.string, "domain") == 0) {
                if (jsp_value(&jsp) != 0 || jsp.type != JSP_TYPE_STRING) {
                    rp_log_error("Invalid 'domain' value in object %d in config file %s\n", i, config_file);
                    ret = 1;
                    goto cleanup;
                }
                strcpy(domain, jsp.string);
            } else if (strcmp(jsp.string, "port") == 0) {
                if (jsp_value(&jsp) != 0 || jsp.type != JSP_TYPE_STRING) {
                    rp_log_error("Invalid 'port' value in object %d in config file %s\n", i, config_file);
                    ret = 1;
                    goto cleanup;
                }
                strcpy(port, jsp.string);
            } else if (strcmp(jsp.string, "cert_file") == 0) {
                if (jsp_value(&jsp) != 0 || jsp.type != JSP_TYPE_STRING) {
                    rp_log_error("Invalid 'cert_file' value in object %d in config file %s\n", i, config_file);
                    ret = 1;
                    goto cleanup;
                }
                strcpy(cert_file, jsp.string);
            } else if (strcmp(jsp.string, "key_file") == 0) {
                if (jsp_value(&jsp) != 0 || jsp.type != JSP_TYPE_STRING) {
                    rp_log_error("Invalid 'key_file' value in object %d in config file %s\n", i, config_file);
                    ret = 1;
                    goto cleanup;
                }
                strcpy(key_file, jsp.string);
            } else if (strcmp(jsp.string, "host") == 0) {
                if (jsp_value(&jsp) == 0 && jsp.type == JSP_TYPE_STRING) {
                    strcpy(host, jsp.string);
                }
            } else {
                // Unknown key; skip its value
                if (jsp_skip(&jsp) != 0) {
                    rp_log_error("Failed to skip unknown key '%s' in object %d in config file %s\n", jsp.string, i, config_file);
                    ret = 1;
                    goto cleanup;
                }
            }
        }
        if (jsp_end_object(&jsp) != 0) {
            rp_log_error("Failed to end object %d in config file %s\n", i, config_file);
            ret = 1;
            goto cleanup;
        }
        revpx_add_domain(revpx, domain, host, port, cert_file, key_file);
    }
    jsp_end_array(&jsp);
cleanup:
    jsp_free(&jsp);
    if (content) free(content);
    return ret;
}

int parse_monade_yaml(RevPx *revpx, const char *yaml_file) {
    const char *home = getenv("HOME");
    int ret = 0;
    const char *yaml_path = yaml_file && yaml_file[0] ? yaml_file : "monade.yaml";
    YamlNode *yaml = parse_yaml(yaml_path);
    if (!yaml) {
        rp_log_error("Failed to parse %s\n", yaml_path);
        ret = 1;
        goto cleanup;
    }
    char project_name[256];
    for (int i = 0; i < yaml->child_count; i++) {
        YamlNode *services = yaml->children[i];
        if (strcmp(services->key, "name") == 0 && services->type == YAML_SCALAR) {
            strcpy(project_name, services->value);
            rp_log_info("Monade project name: %s\n", project_name);
            break;
        }
    }
    for (int i = 0; i < yaml->child_count; i++) {
        YamlNode *services = yaml->children[i];
        if (services->type != YAML_MAP || strcmp(services->key, "services") != 0) continue;
        for (int j = 0; j < services->child_count; j++) {
            YamlNode *service = services->children[j];
            char domains[16][256] = {0}, port[16] = {0};
            int domain_count = 0;
            for (int k = 0; k < service->child_count; k++) {
                YamlNode *c = service->children[k];
                if (strcmp(c->key, "domains") == 0) {
                    domain_count = c->child_count < 16 ? c->child_count : 16;
                    for (int k = 0; k < domain_count; k++) {
                        YamlNode *domain = c->children[k];
                        if (domain->type == YAML_SCALAR) {
                            strncpy(domains[k], domain->value, sizeof(domains[k]) - 1);
                        }
                    }
                } else if (strcmp(c->key, "port") == 0 && c->type == YAML_SCALAR) {
                    strncpy(port, c->value, sizeof(port) - 1);
                }
            }
            if (domain_count && port[0]) {
                for (int k = 0; k < domain_count; k++) {
                    char key_path[512], cert_path[512];
                    snprintf(cert_path, sizeof(cert_path), "%s/.config/monade/stacks/%s/certs/chain.pem", home, project_name);
                    snprintf(key_path, sizeof(key_path), "%s/.config/monade/stacks/%s/certs/key.pem", home, project_name);
                    revpx_add_domain(revpx, domains[k], NULL, port, cert_path, key_path);
                }
            }
        }
    }

cleanup:
    free_yaml(yaml);
    return ret;
}

int parse_args(RevPx *revpx, int argc, const char **argv) {
    Args args = {.argc = argc, .argv = argv};
    const char *buf[4];
    int idx = 0;
    while (arg_next(&args)) {
        if (positional_arg(&args)) {
            buf[idx++] = args.value;
            if (idx == 4) {
                revpx_add_domain(revpx, buf[0], NULL, buf[1], buf[2], buf[3]);
                idx = 0;
            }
        }
    }
    if (idx != 0) {
        rp_log_error("Incomplete domain mapping arguments\n");
        return 1;
    }
    return 0;
}

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
    RevPx revpx = {0};
    int has_file_arg = 0;
    while (arg_next(&args)) {
        if (named_arg(&args, "help", "h")) {
            print_help();
            return 0;
        } else if (named_arg(&args, "file", "f")) {
            if (parse_config_file(&revpx, args.value) != 0) {
                print_help();
                return 1;
            }
            has_file_arg = 1;
        } else if (named_arg(&args, "port", "p")) {
            sec_port = args.value;
        } else if (named_arg(&args, "port-plain", "pp")) {
            plain_port = args.value;
        } else if (named_arg(&args, "monade", "m")) {
            if (parse_monade_yaml(&revpx, args.value) != 0) {
                print_help();
                return 1;
            }
            has_file_arg = 1;
        }
    }

    // <domain> <port> <cert_file> <key_file> ...
    if (!has_file_arg && parse_args(&revpx, argc, argv) != 0) {
        print_help();
        return 1;
    }
    if (revpx.domain_count == 0) {
        if (parse_monade_yaml(&revpx, NULL) != 0) {
            print_help();
            return 1;
        }
    }
    if (!sec_port) sec_port = DEFAULT_PORT;
    if (!plain_port) plain_port = DEFAULT_PORT_PLAIN;
    revpx.https_port = sec_port;
    revpx.http_port = plain_port;

    revpx_run_server(&revpx);
    revpx_free(&revpx);
    return 0;
}
