/*
 * Minimal YAML parser
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE 1024

typedef enum { YAML_SCALAR,
               YAML_LIST,
               YAML_MAP } YamlType;

typedef struct YamlNode {
    char *key;
    char *value;
    YamlType type;
    struct YamlNode **children;
    int child_count;
} YamlNode;

// --- Utility
static char *trim(char *s) {
    while (isspace((unsigned char)*s))
        s++;
    if (*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';
    return s;
}

static YamlNode *new_node(const char *key, const char *value, YamlType type) {
    YamlNode *n = calloc(1, sizeof(YamlNode));
    if (key) n->key = strdup(key);
    if (value) n->value = strdup(value);
    n->type = type;
    return n;
}

static void add_child(YamlNode *parent, YamlNode *child) {
    parent->children = realloc(parent->children, sizeof(YamlNode *) * (parent->child_count + 1));
    parent->children[parent->child_count++] = child;
}

// --- Parsing
YamlNode *parse_yaml(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("fopen");
        return NULL;
    }
    char line[MAX_LINE];
    YamlNode *root = new_node(NULL, NULL, YAML_MAP);
    YamlNode *stack[64];
    int indents[64];
    int depth = 0;

    stack[0] = root;
    indents[0] = -1;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || strlen(trim(line)) == 0) continue;
        int indent = 0;
        while (line[indent] == ' ')
            indent++;
        char *content = trim(line);

        while (depth > 0 && indent <= indents[depth])
            depth--;

        if (content[0] == '-') {
            // list
            char *val = trim(content + 1);
            YamlNode *n = new_node(NULL, val, YAML_SCALAR);
            add_child(stack[depth], n);
        } else {
            // key: value
            char *colon = strchr(content, ':');
            if (!colon) continue;
            *colon = '\0';
            char *key = trim(content);
            char *val = trim(colon + 1);

            YamlNode *n;
            if (*val) {
                n = new_node(key, val, YAML_SCALAR);
            } else {
                n = new_node(key, NULL, YAML_MAP);
            }
            add_child(stack[depth], n);

            if (!*val) {
                depth++;
                stack[depth] = n;
                indents[depth] = indent;
            }
        }
    }
    fclose(f);
    return root;
}

// --- Debug print
void print_yaml(YamlNode *n, int indent) {
    for (int i = 0; i < indent; i++)
        printf("  ");
    if (n->key) printf("%s: ", n->key);
    if (n->value)
        printf("%s\n", n->value);
    else
        printf("\n");
    for (int i = 0; i < n->child_count; i++) {
        print_yaml(n->children[i], indent + 1);
    }
}

// --- Free
void free_yaml(YamlNode *n) {
    if (!n) return;
    free(n->key);
    free(n->value);
    for (int i = 0; i < n->child_count; i++) {
        free_yaml(n->children[i]);
    }
    free(n->children);
    free(n);
}
