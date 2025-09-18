/**
 * Simple JSON stream parser
 * https://github.com/mceck/c-stb
 *
 * Example:
```c
#define JSP_IMPLEMENTATION
#include "jsp.h"

const char *json = "{\"name\": \"John\", \"age\": 30, \"is_student\": false, \"array\": [\"item1\", 2, true]}";
...
    Jsp jsp = {0};
    jsp_sinit(&jsp, json);
    jsp_begin_object(&jsp);
    while(jsp_key(&jsp) == 0) {
        if (strcmp(jsp.string, "name") == 0) {
            jsp_value(&jsp);
            printf("Name: %s\n", jsp.string);
        } else if (strcmp(jsp.string, "age") == 0) {
            jsp_value(&jsp);
            printf("Age: %.0f\n", jsp.number);
        } else if (strcmp(jsp.string, "is_student") == 0) {
            jsp_value(&jsp);
            printf("Is student: %s\n", jsp.boolean ? "true" : "false");
        } else if (strcmp(jsp.string, "array") == 0) {
            jsp_begin_array(&jsp);
            while (jsp_value(&jsp) == 0) {
                if (jsp.type == JSP_TYPE_STRING) {
                    printf("Array item (string): %s\n", jsp.string);
                } else if (jsp.type == JSP_TYPE_NUMBER) {
                    printf("Array item (number): %.2f\n", jsp.number);
                } else if (jsp.type == JSP_TYPE_BOOLEAN) {
                    printf("Array item (boolean): %s\n", jsp.boolean ? "true" : "false");
                }
            }
            jsp_end_array(&jsp);
        } else {
            jsp_value(&jsp); // skip other values
        }
    }
    jsp_end_object(&jsp);
    jsp_free(&jsp);
```
 */

#ifndef JSP_H_
#define JSP_H_

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define JSP_SMIN_CAPACITY 32
#ifndef JSP_MAX_NESTING
#define JSP_MAX_NESTING 64
#endif
#ifndef JSP_REALLOC
#define JSP_REALLOC realloc
#endif
#ifndef JSP_FREE
#define JSP_FREE free
#endif

typedef enum {
    JSP_OK,
    JSP_OBJECT,
    JSP_ARRAY,
    JSP_KEY
} JspState;

typedef enum {
    JSP_TYPE_STRING,
    JSP_TYPE_NUMBER,
    JSP_TYPE_BOOLEAN,
    JSP_TYPE_NULL,
    JSP_TYPE_ARRAY,
    JSP_TYPE_OBJECT,
    JSP_TYPE_UNKNOWN
} JspType;

struct jsp_string {
    char *items;
    size_t count;
    size_t capacity;
};

typedef struct {
    const char *buffer;
    size_t off;
    size_t length;
    JspState state[JSP_MAX_NESTING];
    int level;
    JspType type;
    struct jsp_string _sb;
    union {
        char *string;
        double number;
        bool boolean;
    };
} Jsp;

/**
 * Initialize the JSP parser with a buffer and its length.
 * Returns 0 on success, -1 on failure.
 */
int jsp_init(Jsp *jsp, const char *buffer, size_t length);
#define jsp_sinit(jsp, cstr) jsp_init(jsp, cstr, strlen(cstr))

/**
 * Try parse a JSON object start.
 * Returns 0 on success, -1 on failure.
 */
int jsp_begin_object(Jsp *jsp);
/**
 * Try parse a JSON object end.
 * Returns 0 on success, -1 on failure.
 */
int jsp_end_object(Jsp *jsp);
/**
 * Try parse a JSON array start.
 * Returns 0 on success, -1 on failure.
 */
int jsp_begin_array(Jsp *jsp);
/**
 * Try parse a JSON array end.
 * Returns 0 on success, -1 on failure.
 */
int jsp_end_array(Jsp *jsp);
/**
 * Get the length of a JSON array.
 * Returns the number of elements in the array, or -1 on failure.
 */
int jsp_array_length(Jsp *jsp);
/**
 * Try parse a key in a JSON object.
 * Returns 0 on success, -1 on failure.
 */
int jsp_key(Jsp *jsp);
/**
 * Try parse a value (string, number, boolean, null) in a JSON object or array.
 * Returns 0 on success, -1 on failure.
 */
int jsp_value(Jsp *jsp);
/**
 * Free JSP resources.
 */
void jsp_free(Jsp *jsp);
/**
 * Skip to the next value in the JSON stream.
 * Returns 0 on success, -1 on failure.
 */
int jsp_skip(Jsp *jsp);

#ifdef JSP_IMPLEMENTATION

// Dynamic string functions
static void jsp_srealloc(struct jsp_string *sb, size_t size) {
    if (size <= sb->capacity) return;
    size_t new_cap = sb->capacity ? sb->capacity : JSP_SMIN_CAPACITY;
    while (new_cap < size)
        new_cap *= 2;
    sb->items = JSP_REALLOC(sb->items, new_cap);
    assert(sb->items != NULL);
    sb->capacity = new_cap;
}
static void jsp_sappend(struct jsp_string *sb, char c) {
    jsp_srealloc(sb, sb->count + 2);
    sb->items[sb->count] = c;
    if (c != '\0') sb->count++;
}

// Helper functions for parsing
static int jsp_skip_whitespace(Jsp *jsp) {
    while (jsp->off < jsp->length && isspace(jsp->buffer[jsp->off]))
        jsp->off++;
    return 0;
}
static int jsp_skip_char(Jsp *jsp, char c) {
    if (jsp->off < jsp->length && jsp->buffer[jsp->off] == c) {
        jsp->off++;
        return 0;
    }
    return -1;
}
static int jsp_skip_maybe(Jsp *jsp, char c) {
    if (jsp->off == jsp->length) return 0;
    if (jsp->off < jsp->length) {
        if (jsp->buffer[jsp->off] == c) jsp->off++;
        return 0;
    }
    return -1;
}

static int jsp_skip_end(Jsp *jsp) {
    if (jsp_skip_whitespace(jsp)) return -1;
    if (jsp->state[jsp->level] == JSP_KEY) {
        if (jsp_skip_char(jsp, ':')) return -1;
    } else if (jsp_skip_maybe(jsp, ',')) {
        return -1;
    }
    return jsp_skip_whitespace(jsp);
}

// Parse string value
static int jsp_parse_str(Jsp *jsp) {
    size_t idx = jsp->off;
    size_t len = 0;
    if (jsp->buffer[idx++] != '"') return -1;
    const char *ptr = jsp->buffer + idx;
    jsp->_sb.count = 0;
    while (true) {
        if (idx >= jsp->length) return -1;
        if (jsp->buffer[idx] == '"') {
            if (len > 0) {
                jsp_srealloc(&jsp->_sb, jsp->_sb.count + len + 1);
                memcpy(jsp->_sb.items + jsp->_sb.count, ptr, len);
                jsp->_sb.count += len;
            }
            jsp->_sb.items[jsp->_sb.count] = '\0';
            jsp->off = idx + 1;
            jsp->string = jsp->_sb.items;
            return 0;
        }
        if (jsp->buffer[idx] == '\\') {
            if (len > 0) {
                jsp_srealloc(&jsp->_sb, jsp->_sb.count + len + 5);
                memcpy(jsp->_sb.items + jsp->_sb.count, ptr, len);
                jsp->_sb.count += len;
                len = 0;
            }
            idx++;
            if (idx >= jsp->length) return -1;
            if (jsp->buffer[idx] == 'n') {
                jsp_sappend(&jsp->_sb, '\n');
            } else if (jsp->buffer[idx] == 't') {
                jsp_sappend(&jsp->_sb, '\t');
            } else if (jsp->buffer[idx] == '\\' || jsp->buffer[idx] == '"') {
                jsp_sappend(&jsp->_sb, jsp->buffer[idx]);
            } else if (jsp->buffer[idx] == 'u') {
                // Unicode escape \uXXXX
                if (idx + 4 >= jsp->length) return -1;
                char hex[5] = {0};
                memcpy(hex, jsp->buffer + idx + 1, 4);
                char *endptr;
                long codepoint = strtol(hex, &endptr, 16);
                if (*endptr != '\0' || codepoint < 0 || codepoint > 0x10FFFF) return -1;
                // Convert codepoint to UTF-8
                if (codepoint <= 0x7F) {
                    jsp_sappend(&jsp->_sb, (char)codepoint);
                } else if (codepoint <= 0x7FF) {
                    jsp_sappend(&jsp->_sb, (char)(0xC0 | ((codepoint >> 6) & 0x1F)));
                    jsp_sappend(&jsp->_sb, (char)(0x80 | (codepoint & 0x3F)));
                } else if (codepoint <= 0xFFFF) {
                    jsp_sappend(&jsp->_sb, (char)(0xE0 | ((codepoint >> 12) & 0x0F)));
                    jsp_sappend(&jsp->_sb, (char)(0x80 | ((codepoint >> 6) & 0x3F)));
                    jsp_sappend(&jsp->_sb, (char)(0x80 | (codepoint & 0x3F)));
                } else {
                    jsp_sappend(&jsp->_sb, (char)(0xF0 | ((codepoint >> 18) & 0x07)));
                    jsp_sappend(&jsp->_sb, (char)(0x80 | ((codepoint >> 12) & 0x3F)));
                    jsp_sappend(&jsp->_sb, (char)(0x80 | ((codepoint >> 6) & 0x3F)));
                    jsp_sappend(&jsp->_sb, (char)(0x80 | (codepoint & 0x3F)));
                }
                idx += 4;
            }
            ptr = jsp->buffer + idx + 1;
        } else {
            len++;
        }
        idx++;
    }
    return -1;
}

// Parse number value
static int jsp_parse_number(Jsp *jsp) {
    size_t idx = jsp->off;
    char *endptr;
    jsp->number = strtod(jsp->buffer + idx, &endptr);
    if (endptr == jsp->buffer + idx) return -1;
    jsp->off = endptr - jsp->buffer;
    return 0;
}

// Parse boolean value
static int jsp_parse_boolean(Jsp *jsp) {
    size_t idx = jsp->off;
    int ret = -1;
    if (idx + 4 <= jsp->length && strncmp(jsp->buffer + idx, "true", 4) == 0) {
        jsp->boolean = true;
        jsp->off += 4;
        ret = 0;
    }
    if (idx + 5 <= jsp->length && strncmp(jsp->buffer + idx, "false", 5) == 0) {
        jsp->boolean = false;
        jsp->off += 5;
        ret = 0;
    }

    return ret;
}

// Parse null value
static int jsp_parse_null(Jsp *jsp) {
    size_t idx = jsp->off;
    if (idx + 4 <= jsp->length && strncmp(jsp->buffer + idx, "null", 4) == 0) {
        jsp->off += 4;
        return 0;
    }
    return -1;
}

// Zero the return values
static void jsp_zero_ret(Jsp *jsp) {
    jsp->_sb.count = 0;
    jsp->string = NULL;
    jsp->number = 0;
    jsp->boolean = false;
}

// Infer the type of the next value
int jsp_infer_type(Jsp *jsp) {
    if (jsp->off >= jsp->length) return -1;
    char c = jsp->buffer[jsp->off];
    if (c == '"') {
        jsp->type = JSP_TYPE_STRING;
        return 0;
    }
    if (c == 't' || c == 'f') {
        jsp->type = JSP_TYPE_BOOLEAN;
        return 0;
    }
    if (c == 'n') {
        jsp->type = JSP_TYPE_NULL;
        return 0;
    }
    if (c == '-' || isdigit(c)) {
        jsp->type = JSP_TYPE_NUMBER;
        return 0;
    }
    if (c == '{') {
        jsp->type = JSP_TYPE_OBJECT;
        return 0;
    }
    if (c == '[') {
        jsp->type = JSP_TYPE_ARRAY;
        return 0;
    }
    return -1;
}

int jsp_init(Jsp *jsp, const char *buffer, size_t length) {
    if (!jsp || !buffer || length == 0) return -1;
    jsp->buffer = buffer;
    jsp->length = length;
    jsp->off = 0;
    jsp->level = 0;
    jsp->state[0] = JSP_OK;
    if (jsp_skip_whitespace(jsp)) return -1;
    return 0;
}

int jsp_begin_object(Jsp *jsp) {
    if (jsp->state[jsp->level] == JSP_OBJECT) return -1;
    if (jsp_skip_char(jsp, '{')) return -1;
    if (jsp_skip_whitespace(jsp)) return -1;
    jsp->state[++jsp->level] = JSP_OBJECT;
    return 0;
}

int jsp_end_object(Jsp *jsp) {
    if (jsp->state[jsp->level] != JSP_OBJECT || jsp->level <= 0) return -1;
    if (jsp_skip_whitespace(jsp)) return -1;
    if (jsp_skip_char(jsp, '}')) return -1;
    if (jsp_skip_end(jsp)) return -1;
    jsp->level--;
    if (jsp->state[jsp->level] == JSP_KEY) {
        if (jsp->level <= 0) return -1;
        jsp->level--;
    }
    if (jsp->level == 0) jsp->state[0] = JSP_OK;
    return 0;
}

int jsp_begin_array(Jsp *jsp) {
    if (jsp->state[jsp->level] == JSP_OBJECT) return -1;
    if (jsp_skip_char(jsp, '[')) return -1;
    if (jsp_skip_whitespace(jsp)) return -1;
    jsp->state[++jsp->level] = JSP_ARRAY;
    return 0;
}

int jsp_end_array(Jsp *jsp) {
    if (jsp->state[jsp->level] != JSP_ARRAY || jsp->level <= 0) return -1;
    if (jsp_skip_whitespace(jsp)) return -1;
    if (jsp_skip_char(jsp, ']')) return -1;
    if (jsp_skip_end(jsp)) return -1;
    jsp->level--;
    if (jsp->state[jsp->level] == JSP_KEY) {
        if (jsp->level <= 0) return -1;
        jsp->level--;
    }
    if (jsp->level == 0) jsp->state[0] = JSP_OK;
    return 0;
}

int jsp_array_length(Jsp *jsp) {
    if (jsp->state[jsp->level] != JSP_ARRAY) return -1;
    int len = 0;
    size_t off = jsp->off;
    while (jsp_skip(jsp) == 0)
        len++;

    jsp->off = off;
    return len;
}

int jsp_key(Jsp *jsp) {
    if (jsp->state[jsp->level] != JSP_OBJECT) return -1;
    if (jsp_parse_str(jsp)) return -1;
    jsp->state[++jsp->level] = JSP_KEY;
    if (jsp_skip_end(jsp)) return -1;
    return 0;
}

int jsp_value(Jsp *jsp) {
    if (jsp->state[jsp->level] != JSP_KEY && jsp->state[jsp->level] != JSP_ARRAY)
        return -1;
    if (jsp_infer_type(jsp)) return -1;
    jsp_zero_ret(jsp);
    int ret = 0;
    switch (jsp->type) {
    case JSP_TYPE_STRING:
        ret = jsp_parse_str(jsp);
        break;
    case JSP_TYPE_NUMBER:
        ret = jsp_parse_number(jsp);
        break;
    case JSP_TYPE_BOOLEAN:
        ret = jsp_parse_boolean(jsp);
        break;
    case JSP_TYPE_NULL:
        ret = jsp_parse_null(jsp);
        break;
    default:
        ret = -1;
    }
    if (!ret) {
        if (jsp->state[jsp->level] == JSP_KEY) jsp->level--;
        if (jsp_skip_end(jsp)) return -1;
    }
    return ret;
}

int jsp_skip(Jsp *jsp) {
    int ret = jsp_value(jsp);
    if (ret) {
        if (jsp->type == JSP_TYPE_OBJECT) {
            ret = jsp_begin_object(jsp);
            if (ret) return ret;
            while (jsp_key(jsp) == 0) {
                ret = jsp_skip(jsp);
                if (ret) break;
            }
            ret = jsp_end_object(jsp);
        } else if (jsp->type == JSP_TYPE_ARRAY) {
            ret = jsp_begin_array(jsp);
            if (ret) return ret;
            while (true) {
                ret = jsp_skip(jsp);
                if (ret) break;
            }
            ret = jsp_end_array(jsp);
        }
        if (!ret && jsp->state[jsp->level] == JSP_KEY) jsp->level--;
    }
    return ret;
}

void jsp_free(Jsp *jsp) {
    if (jsp->_sb.items) {
        JSP_FREE(jsp->_sb.items);
        jsp->_sb.items = NULL;
        jsp->_sb.count = 0;
        jsp->_sb.capacity = 0;
    }
}
#endif // JSP_IMPLEMENTATION
#endif // JSP_H_