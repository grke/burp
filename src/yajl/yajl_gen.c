/*
 * Copyright (c) 2007-2014, Lloyd Hilaiel <me@lloyd.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * Interface to YAJL's JSON generation facilities.
 **/

#include "yajl/yajl_gen.h"
#include "yajl_buf.h"
#include "yajl_encode.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdarg.h>

typedef enum {
    yajl_gen_start,
    yajl_gen_map_start,
    yajl_gen_map_key,
    yajl_gen_map_val,
    yajl_gen_array_start,
    yajl_gen_in_array,
    yajl_gen_complete,
    yajl_gen_error
} yajl_gen_state;

struct yajl_gen_t
{
    unsigned int flags;
    unsigned int depth;
    const char * indentString;
    yajl_gen_state state[YAJL_MAX_DEPTH];
    yajl_print_t print;
    void * ctx; /* yajl_buf */
    /* memory allocation routines */
    yajl_alloc_funcs alloc;
};

/*+ configure a yajl generator
 *
 * int yajl_gen_config
 * Returns zero in case of errors, non-zero otherwise
 *
 * yajl_gen g
 * handle for a generator object (from yajl_alloc())
 *
 * yajl_gen_option opt
 * A generator option (see enum yajl_gen_option)
 *
 * ...
 * a possible parameter for opt
 *
 * Allows the caller to modify the options of a yajl generator.
 +*/
int
yajl_gen_config(yajl_gen g, yajl_gen_option opt, ...)
{
    int rv = 1;
    va_list ap;
    va_start(ap, opt);

    switch(opt) {
        case yajl_gen_beautify:
        case yajl_gen_validate_utf8:
        case yajl_gen_escape_solidus:
            if (va_arg(ap, int)) g->flags |= opt;
            else g->flags &= ~opt;
            break;
        case yajl_gen_indent_string: {
            const char *indent = va_arg(ap, const char *);
            g->indentString = indent;
            for (; *indent; indent++) {
                if (*indent != '\n'
                    && *indent != '\v'
                    && *indent != '\f'
                    && *indent != '\t'
                    && *indent != '\r'
                    && *indent != ' ')
                {
                    g->indentString = NULL;
                    rv = 0;
                }
            }
            break;
        }
        case yajl_gen_print_callback:
            yajl_buf_free(g->ctx);
            g->print = va_arg(ap, const yajl_print_t);
            g->ctx = va_arg(ap, void *);
            break;
        default:
            rv = 0;
    }

    va_end(ap);

    return rv;
}



/*+ allocate a generator handle
 *
 * yajl_gen yajl_gen_alloc
 * returns an allocated generator handle on success, NULL on failure (e.g. due
 * to invalid parameters or an allocation failure).  Must be freed by passing it
 * to yajl_gen_free().
 *
 * const yajl_alloc_funcs *afs
 * an optional pointer to a structure which allows the client to overide the
 * memory allocation used by this yajl generator.  May be NULL, in which case
 * the standard malloc(), free(), and realloc() will be used.
 *
 * Note:  All yajl generators assume the current locale is "C", and in
 * particular that LC_NUMERIC is set to "C", as otherwise (e.g. if the current
 * locale does not use a period ('.') as the "decimal_point" character) the
 * generated JSON may not be parseable (e.g. if it contains any decimal
 * numbers).
 +*/
yajl_gen
yajl_gen_alloc(const yajl_alloc_funcs *afs)
{
    yajl_gen g = NULL;
    yajl_alloc_funcs afsBuffer;

    /* first order of business is to set up memory allocation routines */
    if (afs != NULL) {
        if (afs->malloc == NULL || afs->realloc == NULL || afs->free == NULL) {
            return NULL;
        }
    } else {
        yajl_set_default_alloc_funcs(&afsBuffer);
        afs = &afsBuffer;
    }

    g = (yajl_gen) YA_MALLOC(afs, sizeof(struct yajl_gen_t));
    if (!g) {
        return NULL;
    }
    memset((void *) g, 0, sizeof(struct yajl_gen_t));
    /* copy in pointers to allocation routines */
    g->alloc = *afs;

    g->print = (yajl_print_t) &yajl_buf_append;
    g->ctx = yajl_buf_alloc(&(g->alloc));
    g->indentString = "    ";

    return g;
}

/*+ Reset the generator state.
 *
 * void yajl_gen_reset
 *
 * yajl_gen g
 * A handle to a yajl generator (from yajl_gen_alloc()).
 *
 * const char *sep
 * An optional separator string to be inserted to separate the next entity.
 *
 * Allows a caller to generate multiple JSON entities in a single stream.
 *
 * The "sep" string will be inserted to separate the previously generated entity
 * from the next; NULL means "no separation" of entites (callers beware,
 * generating multiple JSON numbers without a separator, for instance, will
 * result in ambiguous unparseble output)
 *
 * Note:  this call will not clear yajl's output buffer.  This may be
 * accomplished explicitly by calling yajl_gen_clear().
 +*/
void
yajl_gen_reset(yajl_gen g, const char * sep)
{
    g->depth = 0;
    memset((void *) &(g->state), 0, sizeof(g->state));
    if (sep != NULL) {
        g->print(g->ctx, sep, strlen(sep));
    }
}

/*+ free a generator handle +*/
void
yajl_gen_free(yajl_gen g)
{
    if (g->print == (yajl_print_t) &yajl_buf_append) {
        yajl_buf_free((yajl_buf) g->ctx);
    }
    YA_FREE(&(g->alloc), g);
}

#define INSERT_SEP                                                      \
    if (g->state[g->depth] == yajl_gen_map_key ||                       \
        g->state[g->depth] == yajl_gen_in_array) {                      \
        g->print(g->ctx, ",", (size_t) 1);                              \
        if ((g->flags & yajl_gen_beautify)) {                           \
            g->print(g->ctx, "\n", (size_t) 1);                         \
        }                                                               \
    } else if (g->state[g->depth] == yajl_gen_map_val) {                \
        g->print(g->ctx, ":", (size_t) 1);                              \
        if ((g->flags & yajl_gen_beautify))  {                          \
            g->print(g->ctx, " ", (size_t) 1);                          \
        }                                                               \
   }

#define INSERT_WHITESPACE                                               \
    if ((g->flags & yajl_gen_beautify)) {                               \
        if (g->state[g->depth] != yajl_gen_map_val) {                   \
            unsigned int _i;                                            \
            for (_i=0;_i<g->depth;_i++) {                               \
                g->print(g->ctx,                                        \
                         g->indentString,                               \
                         (size_t) strlen(g->indentString));             \
            }                                                           \
        }                                                               \
    }

#define ENSURE_NOT_KEY                                  \
    if (g->state[g->depth] == yajl_gen_map_key ||       \
        g->state[g->depth] == yajl_gen_map_start)  {    \
        return yajl_gen_keys_must_be_strings;           \
    }                                                   \

/* check that we're not complete, or in error state.  in a valid state
 * to be generating */
#define ENSURE_VALID_STATE                        \
    if (g->state[g->depth] == yajl_gen_error) {   \
        return yajl_gen_in_error_state;                     \
    } else if (g->state[g->depth] == yajl_gen_complete) {   \
        return yajl_gen_generation_complete;                \
    }

#define INCREMENT_DEPTH                                                 \
    if (++(g->depth) >= YAJL_MAX_DEPTH) {                               \
        return yajl_max_depth_exceeded;                                 \
    }

#define DECREMENT_DEPTH                                                 \
    if (--(g->depth) >= YAJL_MAX_DEPTH) {                               \
        return yajl_gen_generation_complete;                            \
    }


#define APPENDED_ATOM \
    switch (g->state[g->depth]) {                   \
        case yajl_gen_start:                        \
            g->state[g->depth] = yajl_gen_complete; \
            break;                                  \
        case yajl_gen_map_start:                    \
        case yajl_gen_map_key:                      \
            g->state[g->depth] = yajl_gen_map_val;  \
            break;                                  \
        case yajl_gen_array_start:                  \
            g->state[g->depth] = yajl_gen_in_array; \
            break;                                  \
        case yajl_gen_map_val:                      \
            g->state[g->depth] = yajl_gen_map_key;  \
            break;                                  \
        default:                                    \
            break;                                  \
    }

#define FINAL_NEWLINE                                                   \
    if ((g->flags & yajl_gen_beautify) && g->state[g->depth] == yajl_gen_complete) { \
        g->print(g->ctx, "\n", (size_t) 1);                             \
    }

yajl_gen_status
yajl_gen_integer(yajl_gen g, long long int number)
{
    char i[32];
    int len;

    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    len = sprintf(i, "%lld", number);
    if (len < 0) {                     /* highly unlikely, perhaps impossible */
        return yajl_gen_invalid_number;
    }
    g->print(g->ctx, i, (size_t) len);
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

#if defined(_WIN32) || defined(WIN32)
#include <float.h>
#define isnan _isnan
#define isinf !_finite
#endif

#if !defined(DBL_DIG)
# if defined(__DBL_DIG__)
#  define DBL_DIG	__DBL_DIG__
# else
#  define DBL_DIG	15		/* assumes binary64 IEEE 754 double */
# endif
#endif

/*+
 *  generate a floating point number.  number may not be infinity or
 *  NaN, as these have no representation in JSON.  In these cases the
 *  generator will return 'yajl_gen_invalid_number'
 +*/
yajl_gen_status
yajl_gen_double(yajl_gen g, double number)
{
    char i[32];
    int len;

    ENSURE_VALID_STATE; ENSURE_NOT_KEY;
    if (isnan(number) || isinf(number)) return yajl_gen_invalid_number;
    INSERT_SEP; INSERT_WHITESPACE;
    len = sprintf(i, "%.*g", DBL_DIG, number); /* xxx in theory we could/should
                                                * use DBL_DECIMAL_DIG for pure
                                                * serialization, but what about
                                                * to JSON readers that might not
                                                * be using IEEE 754 binary64 for
                                                * numbers? */
    if (len < 0) {                    /* highly unlikely, or even impossible? */
        return yajl_gen_invalid_number;
    }
    /*
     * xxx perhaps forcing decimal notation should be controlled by a
     * runtime-configurable option?
     */
    if (strspn(i, "0123456789-") == strlen(i)) {
        strcat(i, ".0");
    }
    g->print(g->ctx, i, (size_t) len);
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_number(yajl_gen g, const char * s, size_t l)
{
    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    g->print(g->ctx, s, l);
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_string(yajl_gen g, const unsigned char * str,
                size_t len)
{
    /*
     * if validation is enabled, check that the string is valid utf8
     * XXX: This checking could be done a little faster, in the same pass as
     * the string encoding
     */
    if (g->flags & yajl_gen_validate_utf8) {
        if (!yajl_string_validate_utf8(str, len)) {
            return yajl_gen_invalid_string;
        }
    }
    ENSURE_VALID_STATE; INSERT_SEP; INSERT_WHITESPACE;
    g->print(g->ctx, "\"", (size_t) 1);
    yajl_string_encode(g->print, g->ctx, str, len, g->flags & yajl_gen_escape_solidus);
    g->print(g->ctx, "\"", (size_t) 1);
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_null(yajl_gen g)
{
    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    g->print(g->ctx, "null", strlen("null"));
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_bool(yajl_gen g, int boolean)
{
    const char * val = boolean ? "true" : "false";

    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    g->print(g->ctx, val, (size_t)strlen(val));
    APPENDED_ATOM;
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_map_open(yajl_gen g)
{
    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    INCREMENT_DEPTH;

    g->state[g->depth] = yajl_gen_map_start;
    g->print(g->ctx, "{", (size_t) 1);
    if ((g->flags & yajl_gen_beautify)) {
        g->print(g->ctx, "\n", (size_t) 1);
    }
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_map_close(yajl_gen g)
{
    ENSURE_VALID_STATE;
    DECREMENT_DEPTH;

    if ((g->flags & yajl_gen_beautify)) {
        g->print(g->ctx, "\n", (size_t) 1);
    }
    APPENDED_ATOM;
    INSERT_WHITESPACE;
    g->print(g->ctx, "}", (size_t) 1);
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_array_open(yajl_gen g)
{
    ENSURE_VALID_STATE; ENSURE_NOT_KEY; INSERT_SEP; INSERT_WHITESPACE;
    INCREMENT_DEPTH;
    g->state[g->depth] = yajl_gen_array_start;
    g->print(g->ctx, "[", (size_t) 1);
    if ((g->flags & yajl_gen_beautify)) {
        g->print(g->ctx, "\n", (size_t) 1);
    }
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

yajl_gen_status
yajl_gen_array_close(yajl_gen g)
{
    ENSURE_VALID_STATE;
    DECREMENT_DEPTH;
    if ((g->flags & yajl_gen_beautify)) {
        g->print(g->ctx, "\n", (size_t) 1);
    }
    APPENDED_ATOM;
    INSERT_WHITESPACE;
    g->print(g->ctx, "]", (size_t) 1);
    FINAL_NEWLINE;
    return yajl_gen_status_ok;
}

/*+
 *  access the null terminated generator buffer.  If incrementally
 *  outputing JSON, one should call yajl_gen_clear to clear the
 *  buffer.  This allows stream generation.
 +*/
yajl_gen_status
yajl_gen_get_buf(yajl_gen g, const unsigned char ** buf,
                 size_t * len)
{
    if (g->print != (yajl_print_t) &yajl_buf_append) {
        return yajl_gen_no_buf;
    }
    *buf = yajl_buf_data((yajl_buf) g->ctx);
    *len = yajl_buf_len((yajl_buf) g->ctx);
    return yajl_gen_status_ok;
}


/*+
 *  clear yajl's output buffer, but maintain all internal generation
 *  state.  This function will not "reset" the generator state, and is
 *  intended to enable incremental JSON outputing.
 +*/
void
yajl_gen_clear(yajl_gen g)
{
    if (g->print == (yajl_print_t) &yajl_buf_append) {
        yajl_buf_clear((yajl_buf) g->ctx);
    }
}
