#include "ds.h"
#define JSP_IMPLEMENTATION
#include "jsp.h"

int parse_config_file(int argc, char **argv) {
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

int parse_args(int argc, char **argv) {
    if (argc < 5 || (argc - 1) % 4 != 0) {
        log_error("Argument error\n");
        return 1;
    }
    for (int i = 1; i < argc; i += 4) {
        const char *domain = argv[i];
        const char *backend_port = argv[i + 1];
        const char *cert_file = argv[i + 2];
        const char *key_file = argv[i + 3];
        add_domain(domain, NULL, backend_port, cert_file, key_file);
        log_info("Mapping domain %s to port %s\n", domain, backend_port);
    }
    return 0;
}