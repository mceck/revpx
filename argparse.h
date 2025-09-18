#include "ds.h"
#define JSP_IMPLEMENTATION
#include "jsp.h"

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

int arg_next(Args *args) {
    if (args->index == 0) args->index = 1; // skip program name
    if (args->index >= args->argc) return 0;
    const char *arg = args->argv[args->index++];
    if (arg[0] == '-') {
        if (args->index >= args->argc) return -1;
        args->type = ARG_NAMED;
        args->name = arg + (arg[1] == '-' ? 2 : 1);
        args->value = args->argv[args->index++];
    } else {
        args->type = ARG_POSITIONAL;
        args->position = args->index - 1;
        args->value = arg;
    }
    return 1;
}

int named_arg(Args *args, ...) {
    if (args->type != ARG_NAMED) return 0;
    const char *arg = args->name;
    va_list va;
    va_start(va, args);
    const char *n;
    while ((n = va_arg(va, const char *))) {
        if (strcmp(arg, n) == 0) {
            va_end(va);
            return 1;
        }
    }
    va_end(va);
    return 0;
}

int positional_arg(Args *args) {
    return args->type == ARG_POSITIONAL ? args->position : 0;
}

int parse_config_file(int argc, const char **argv) {
    if (argc != 3) {
        log_error("Argument error\n");
        return 1;
    }
    const char *config_path = argv[2];

    StringBuilder sb = {0};
    int ret = read_entire_file(config_path, &sb);
    if (ret < 0) {
        log_error("Failed to read config file %s\n", config_path);
        return 1;
    }
    Jsp jsp = {0};
    jsp_init(&jsp, sb.items, sb.count);
    ret = jsp_begin_array(&jsp);
    if (ret != 0) {
        log_error("Failed to initialize JSON parser for config file %s\n", config_path);
        ret = 1;
        goto cleanup;
    };
    int len = jsp_array_length(&jsp);
    if (len <= 0) {
        log_error("Config file %s is not a valid JSON array\n", config_path);
        ret = 1;
        goto cleanup;
    }
    for (int i = 0; i < len; i++) {
        if (jsp_begin_object(&jsp) != 0) {
            log_error("Failed to parse object %d in config file %s\n", i, config_path);
            ret = 1;
            goto cleanup;
        }
        char domain[256], host[256], port[16], cert_file[512], key_file[512];
        while (jsp_key(&jsp) == 0) {
            if (strcmp(jsp.string, "domain") == 0) {
                if (jsp_value(&jsp) != 0 || jsp.type != JSP_TYPE_STRING) {
                    log_error("Invalid 'domain' value in object %d in config file %s\n", i, config_path);
                    ret = 1;
                    goto cleanup;
                }
                strcpy(domain, jsp.string);
            } else if (strcmp(jsp.string, "port") == 0) {
                if (jsp_value(&jsp) != 0 || jsp.type != JSP_TYPE_STRING) {
                    log_error("Invalid 'port' value in object %d in config file %s\n", i, config_path);
                    ret = 1;
                    goto cleanup;
                }
                strcpy(port, jsp.string);
            } else if (strcmp(jsp.string, "cert_file") == 0) {
                if (jsp_value(&jsp) != 0 || jsp.type != JSP_TYPE_STRING) {
                    log_error("Invalid 'cert_file' value in object %d in config file %s\n", i, config_path);
                    ret = 1;
                    goto cleanup;
                }
                strcpy(cert_file, jsp.string);
            } else if (strcmp(jsp.string, "key_file") == 0) {
                if (jsp_value(&jsp) != 0 || jsp.type != JSP_TYPE_STRING) {
                    log_error("Invalid 'key_file' value in object %d in config file %s\n", i, config_path);
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
                    log_error("Failed to skip unknown key '%s' in object %d in config file %s\n", jsp.string, i, config_path);
                    ret = 1;
                    goto cleanup;
                }
            }
        }
        if (jsp_end_object(&jsp) != 0) {
            log_error("Failed to end object %d in config file %s\n", i, config_path);
            ret = 1;
            goto cleanup;
        }
        add_domain(domain, host, port, cert_file, key_file);
        log_info("Mapping domain %s to port %s\n", domain, port);
    }
    jsp_end_array(&jsp);
cleanup:
    jsp_free(&jsp);
    da_free(&sb);
    return ret;
}

int parse_args(int argc, const char **argv) {
    Args args = {.argc = argc, .argv = argv};
    const char *buf[4];
    int idx = 0;
    while (arg_next(&args)) {
        if (positional_arg(&args)) {
            buf[idx++] = args.value;
            if (idx == 4) {
                add_domain(buf[0], NULL, buf[1], buf[2], buf[3]);
                log_info("Mapping domain %s to port %s\n", buf[0], buf[1]);
                idx = 0;
            }
        }
    }
    if (idx != 0) {
        log_error("Incomplete domain mapping arguments\n");
        return 1;
    }
    return 0;
}