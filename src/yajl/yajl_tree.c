/*
 * Copyright (c) 2010-2011  Florian Forster  <ff at octo.it>
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
 * Parses JSON data and returns the data in tree form.
 *
 * Writtan by Florian Forster
 *
 * August 2010
 *
 * This interface makes quick parsing and extraction of smallish JSON docs
 * trivial, as shown in the following example:
 *
 * +html+ <a href="../example/parse_config.c.html#file">example/parse_config.c</a><br>
 **/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "yajl/yajl_tree.h"
#include "yajl/yajl_parse.h"

#include "yajl_parser.h"

#if defined(_WIN32) || defined(WIN32)
#define snprintf sprintf_s
#endif

#define STATUS_CONTINUE 1
#define STATUS_ABORT    0

yajl_alloc_funcs *yajl_tree_parse_afs = NULL;

struct stack_elem_s;
typedef struct stack_elem_s stack_elem_t;
struct stack_elem_s
{
    char * key;
    yajl_val value;
    stack_elem_t *next;
};

struct context_s
{
    stack_elem_t *stack;
    yajl_val root;
    char *errbuf;
    size_t errbuf_size;
};
typedef struct context_s context_t;

#define RETURN_ERROR(ctx,retval,...) {                                  \
        if ((ctx)->errbuf != NULL)                                      \
            snprintf ((ctx)->errbuf, (ctx)->errbuf_size, __VA_ARGS__);  \
        return (retval);                                                \
    }

static yajl_val value_alloc (yajl_type type)
{
    yajl_val v;

    v = YA_MALLOC(yajl_tree_parse_afs, sizeof(*v));
    if (v == NULL) return (NULL);
    memset (v, 0, sizeof (*v));
    v->type = type;

    return (v);
}

/* note:  value_free() is actually just yajl_tree_free() */

static void yajl_object_free (yajl_val v)
{
    size_t i;

    assert(YAJL_IS_OBJECT(v));

    for (i = 0; i < v->u.object.len; i++)
    {
        /* __UNCONST() */
        YA_FREE(yajl_tree_parse_afs, (void *)(uintmax_t)(const void *) v->u.object.keys[i]);
        v->u.object.keys[i] = NULL;
        yajl_tree_free (v->u.object.values[i]);
        v->u.object.values[i] = NULL;
    }

    if (v->u.object.keys != NULL) {
        YA_FREE(yajl_tree_parse_afs, (void*) v->u.object.keys);
    }
    if (v->u.object.values != NULL) {
        YA_FREE(yajl_tree_parse_afs, v->u.object.values);
    }
    YA_FREE(yajl_tree_parse_afs, v);
}

static void yajl_array_free (yajl_val v)
{
    size_t i;

    assert(YAJL_IS_ARRAY(v));

    for (i = 0; i < v->u.array.len; i++)
    {
        yajl_tree_free (v->u.array.values[i]);
        v->u.array.values[i] = NULL;
    }

    YA_FREE(yajl_tree_parse_afs, v->u.array.values);
    YA_FREE(yajl_tree_parse_afs, v);
}

/*
 * Parsing nested objects and arrays is implemented using a stack. When a new
 * object or array starts (a curly or a square opening bracket is read), an
 * appropriate value is pushed on the stack. When the end of the object is
 * reached (an appropriate closing bracket has been read), the value is popped
 * off the stack and added to the enclosing object using "context_add_value".
 */
static int context_push(context_t *ctx, yajl_val v)
{
    stack_elem_t *stack;

    stack = YA_MALLOC(yajl_tree_parse_afs, sizeof(*stack));
    if (stack == NULL)
        RETURN_ERROR (ctx, ENOMEM, "Out of memory");
    memset (stack, 0, sizeof (*stack));

    assert ((ctx->stack == NULL)
            || YAJL_IS_OBJECT (v)
            || YAJL_IS_ARRAY (v));

    stack->value = v;
    stack->next = ctx->stack;
    ctx->stack = stack;

    return (0);
}

static yajl_val context_pop(context_t *ctx)
{
    stack_elem_t *stack;
    yajl_val v;

    if (ctx->stack == NULL)
        RETURN_ERROR (ctx, NULL, "context_pop: "
                      "Bottom of stack reached prematurely");

    stack = ctx->stack;
    ctx->stack = stack->next;

    v = stack->value;

    if (stack->key != NULL) {
        YA_FREE(yajl_tree_parse_afs, stack->key);
    }
    YA_FREE(yajl_tree_parse_afs, stack);

    return (v);
}

static int object_add_keyval(context_t *ctx,
                             yajl_val obj, char *key, yajl_val value)
{
    const char **tmpk;
    yajl_val *tmpv;

    /* We're checking for NULL in "context_add_value" or its callers. */
    assert (ctx != NULL);
    assert (obj != NULL);
    assert (key != NULL);
    assert (value != NULL);

    /* We're assuring that "obj" is an object in "context_add_value". */
    assert(YAJL_IS_OBJECT(obj));

    tmpk = YA_REALLOC(yajl_tree_parse_afs,
                      (void *) obj->u.object.keys,
                      sizeof(*(obj->u.object.keys)) * (obj->u.object.len + 1));
    if (tmpk == NULL)
        RETURN_ERROR(ctx, ENOMEM, "Out of memory");
    obj->u.object.keys = tmpk;

    tmpv = YA_REALLOC(yajl_tree_parse_afs,
                      obj->u.object.values,
                      sizeof (*obj->u.object.values) * (obj->u.object.len + 1));
    if (tmpv == NULL)
        RETURN_ERROR(ctx, ENOMEM, "Out of memory");
    obj->u.object.values = tmpv;

    obj->u.object.keys[obj->u.object.len] = key;
    obj->u.object.values[obj->u.object.len] = value;
    obj->u.object.len++;

    return (0);
}

static int array_add_value (context_t *ctx,
                            yajl_val array, yajl_val value)
{
    yajl_val *tmp;

    /* We're checking for NULL pointers in "context_add_value" or its
     * callers. */
    assert (ctx != NULL);
    assert (array != NULL);
    assert (value != NULL);

    /* "context_add_value" will only call us with array values. */
    assert(YAJL_IS_ARRAY(array));

    tmp = YA_REALLOC(yajl_tree_parse_afs,
                     array->u.array.values,
                     sizeof(*(array->u.array.values)) * (array->u.array.len + 1));
    if (tmp == NULL)
        RETURN_ERROR(ctx, ENOMEM, "Out of memory");
    array->u.array.values = tmp;
    array->u.array.values[array->u.array.len] = value;
    array->u.array.len++;

    return 0;
}

/*
 * Add a value to the value on top of the stack or the "root" member in the
 * context if the end of the parsing process is reached.
 */
static int context_add_value (context_t *ctx, yajl_val v)
{
    /* We're checking for NULL values in all the calling functions. */
    assert (ctx != NULL);
    assert (v != NULL);

    /*
     * There are three valid states in which this function may be called:
     *   - There is no value on the stack => This is the only value. This is the
     *     last step done when parsing a document. We assign the value to the
     *     "root" member and return.
     *   - The value on the stack is an object. In this case store the key on the
     *     stack or, if the key has already been read, add key and value to the
     *     object.
     *   - The value on the stack is an array. In this case simply add the value
     *     and return.
     */
    if (ctx->stack == NULL)
    {
        assert (ctx->root == NULL);
        ctx->root = v;
        return (0);
    }
    else if (YAJL_IS_OBJECT (ctx->stack->value))
    {
        if (ctx->stack->key == NULL)
        {
            if (!YAJL_IS_STRING (v))
                RETURN_ERROR (ctx, EINVAL, "context_add_value: "
                              "Object key is not a string (%#04x)",
                              v->type);

            ctx->stack->key = v->u.string;
            v->u.string = NULL;
            YA_FREE(yajl_tree_parse_afs, v);
            return (0);
        }
        else /* if (ctx->key != NULL) */
        {
            char * key;

            key = ctx->stack->key;
            ctx->stack->key = NULL;
            return (object_add_keyval (ctx, ctx->stack->value, key, v));
        }
    }
    else if (YAJL_IS_ARRAY (ctx->stack->value))
    {
        return (array_add_value (ctx, ctx->stack->value, v));
    }
    else
    {
        RETURN_ERROR (ctx, EINVAL, "context_add_value: Cannot add value to "
                      "a value of type %#04x (not a composite type)",
                      ctx->stack->value->type);
    }
}

static int handle_string (void *ctx,
                          const unsigned char *string, size_t string_length)
{
    yajl_val v;

    v = value_alloc (yajl_t_string);
    if (v == NULL)
        RETURN_ERROR ((context_t *) ctx, STATUS_ABORT, "Out of memory");

    v->u.string = YA_MALLOC(yajl_tree_parse_afs, string_length + 1);
    if (v->u.string == NULL)
    {
        YA_FREE(yajl_tree_parse_afs, v);
        RETURN_ERROR ((context_t *) ctx, STATUS_ABORT, "Out of memory");
    }
    memcpy(v->u.string, string, string_length);
    v->u.string[string_length] = 0;

    return ((context_add_value (ctx, v) == 0) ? STATUS_CONTINUE : STATUS_ABORT);
}

static int handle_number (void *ctx, const char *string, size_t string_length)
{
    yajl_val v;
    char *endptr;

    v = value_alloc(yajl_t_number);
    if (v == NULL) {
        RETURN_ERROR((context_t *) ctx, STATUS_ABORT, "Out of memory");
    }
    v->u.number.r = YA_MALLOC(yajl_tree_parse_afs, string_length + 1);
    if (v->u.number.r == NULL) {
        YA_FREE(yajl_tree_parse_afs, v);
        RETURN_ERROR((context_t *) ctx, STATUS_ABORT, "Out of memory");
    }
    memcpy(v->u.number.r, string, string_length);
    v->u.number.r[string_length] = 0;

    v->u.number.flags = 0;

    errno = 0;
    v->u.number.i = yajl_parse_integer((const unsigned char *) v->u.number.r,
                                       strlen(v->u.number.r));
    if (errno == 0)
        v->u.number.flags |= YAJL_NUMBER_INT_VALID;

    endptr = NULL;
    errno = 0;
    v->u.number.d = strtod(v->u.number.r, &endptr);
    if ((errno == 0) && (endptr != NULL) && (*endptr == 0))
        v->u.number.flags |= YAJL_NUMBER_DOUBLE_VALID;

    return ((context_add_value(ctx, v) == 0) ? STATUS_CONTINUE : STATUS_ABORT);
}

static int handle_start_map (void *ctx)
{
    yajl_val v;

    v = value_alloc(yajl_t_object);
    if (v == NULL)
        RETURN_ERROR ((context_t *) ctx, STATUS_ABORT, "Out of memory");

    v->u.object.keys = NULL;
    v->u.object.values = NULL;
    v->u.object.len = 0;

    return ((context_push (ctx, v) == 0) ? STATUS_CONTINUE : STATUS_ABORT);
}

static int handle_end_map (void *ctx)
{
    yajl_val v;

    v = context_pop (ctx);
    if (v == NULL)
        return (STATUS_ABORT);

    return ((context_add_value (ctx, v) == 0) ? STATUS_CONTINUE : STATUS_ABORT);
}

static int handle_start_array (void *ctx)
{
    yajl_val v;

    v = value_alloc(yajl_t_array);
    if (v == NULL)
        RETURN_ERROR ((context_t *) ctx, STATUS_ABORT, "Out of memory");

    v->u.array.values = NULL;
    v->u.array.len = 0;

    return ((context_push (ctx, v) == 0) ? STATUS_CONTINUE : STATUS_ABORT);
}

static int handle_end_array (void *ctx)
{
    yajl_val v;

    v = context_pop (ctx);
    if (v == NULL)
        return (STATUS_ABORT);

    return ((context_add_value (ctx, v) == 0) ? STATUS_CONTINUE : STATUS_ABORT);
}

static int handle_boolean (void *ctx, int boolean_value)
{
    yajl_val v;

    v = value_alloc (boolean_value ? yajl_t_true : yajl_t_false);
    if (v == NULL)
        RETURN_ERROR ((context_t *) ctx, STATUS_ABORT, "Out of memory");

    return ((context_add_value (ctx, v) == 0) ? STATUS_CONTINUE : STATUS_ABORT);
}

static int handle_null (void *ctx)
{
    yajl_val v;

    v = value_alloc (yajl_t_null);
    if (v == NULL)
        RETURN_ERROR ((context_t *) ctx, STATUS_ABORT, "Out of memory");

    return ((context_add_value (ctx, v) == 0) ? STATUS_CONTINUE : STATUS_ABORT);
}

/*
 * Public functions
 */
/*+
 * Parse a string.
 *
 * Parses a null-terminated string containing JSON data.
 *
 * Returns a pointer to a yajl_val object which is the top-level value (root of
 * the parse tree) or NULL on error.
 *
 * The memory pointed to must be freed using yajl_tree_free().  In case of an
 * error, a null terminated message describing the error in more detail is
 * stored in error_buffer if it is not NULL.
 +*/
yajl_val yajl_tree_parse (const char *input, /*+ Pointer to a null-terminated
                                              *  utf8 string containing JSON
                                              *  data. +*/
                          char *error_buffer, /*+ Pointer to a buffer in which
                                               * an error message will be stored
                                               * if yajl_tree_parse() fails, or
                                               * NULL. The buffer will be
                                               * initialized before parsing, so
                                               * its content will be destroyed
                                               * even if yajl_tree_parse()
                                               * succeeds. +*/
                          size_t error_buffer_size) /*+ Size of the memory area
                                                     * pointed to by
                                                     * error_buffer_size.  If
                                                     * error_buffer_size is
                                                     * NULL, this argument is
                                                     * ignored. +*/
{
    /* pointers to parsing callbacks */
    static const yajl_callbacks callbacks =
        {
            /* null        = */ handle_null,
            /* boolean     = */ handle_boolean,
            /* integer     = */ NULL,
            /* double      = */ NULL,
            /* number      = */ handle_number,
            /* string      = */ handle_string,
            /* start map   = */ handle_start_map,
            /* map key     = */ handle_string,
            /* end map     = */ handle_end_map,
            /* start array = */ handle_start_array,
            /* end array   = */ handle_end_array
        };

    yajl_handle handle;
    yajl_status status;
    context_t ctx = { NULL, NULL, NULL, 0 };
    bool undo_afs = false;

    ctx.errbuf = error_buffer;
    ctx.errbuf_size = error_buffer_size;

    if (error_buffer != NULL)
        memset (error_buffer, 0, error_buffer_size);

    handle = yajl_alloc(&callbacks, yajl_tree_parse_afs, &ctx);
    if (yajl_tree_parse_afs == NULL) {
        undo_afs = true;
        yajl_tree_parse_afs = &handle->alloc;
    }
    yajl_config(handle, yajl_allow_comments, 1);

    status = yajl_parse(handle,
                        (const unsigned char *) input,
                        strlen (input));
    if (status == yajl_status_ok) {
        status = yajl_complete_parse(handle);
    }
    if (status != yajl_status_ok) {
        if (error_buffer != NULL && error_buffer_size > 0) {
            char *ies;

            ies = (char *) yajl_get_error(handle, 1,
                                          (const unsigned char *) input,
                                          strlen(input));
            snprintf(error_buffer, error_buffer_size, "%s", ies);
            YA_FREE(&(handle->alloc), ies);
        }
        while (ctx.stack) {
            yajl_tree_free(context_pop(&ctx));
        }
        if (ctx.root) {
            yajl_tree_free(ctx.root);
        }
        yajl_free(handle);
        if (undo_afs) {
            yajl_tree_parse_afs = NULL;
        }
        return NULL;
    }

    if (ctx.root == NULL) {
        if (error_buffer != NULL && error_buffer_size > 0) {
            snprintf(error_buffer, error_buffer_size, "parse OK, but nothing to return");
        }
    }
    yajl_free(handle);
    if (undo_afs) {
        yajl_tree_parse_afs = NULL;
    }

    return (ctx.root);
}

/*+
 * Access a nested value inside a tree.
 *
 * Returns a pointer to the found value, or NULL if we came up empty.
 +*/
/*
 * Future Ideas:  it'd be nice to move path to a string and implement support for
 * a teeny tiny micro language here, so you can extract array elements, do things
 * like .first and .last, even .length.  Inspiration from JSONPath and css selectors?
 * No it wouldn't be fast, but that's not what this API is about.
 */
yajl_val yajl_tree_get(yajl_val n,      /*+ the node under which you'd like to extract values. +*/
                       const char ** path, /*+ A null terminated array of strings, each the name of an object key +*/
                       yajl_type type)     /*+ the yajl_type of the object you seek, or yajl_t_any if any will do. +*/
{
    if (!path) return NULL;
    while (n && *path) {
        size_t i;
        size_t len;

        if (n->type != yajl_t_object) return NULL;
        len = n->u.object.len;
        for (i = 0; i < len; i++) {
            if (!strcmp(*path, n->u.object.keys[i])) {
                n = n->u.object.values[i];
                break;
            }
        }
        if (i == len) return NULL;
        path++;
    }
    if (n && type != yajl_t_any && type != n->type) n = NULL;
    return n;
}

/*+
 * Free a parse tree returned by yajl_tree_parse().
 +*/
void yajl_tree_free (yajl_val v)        /*+ Pointer to a JSON value returned by
                                         * "yajl_tree_parse".  Passing NULL is
                                         * valid and results in a no-op. +*/
{
    if (v == NULL) return;

    if (YAJL_IS_STRING(v))
    {
        YA_FREE(yajl_tree_parse_afs, v->u.string);
        YA_FREE(yajl_tree_parse_afs, v);
    }
    else if (YAJL_IS_NUMBER(v))
    {
        YA_FREE(yajl_tree_parse_afs, v->u.number.r);
        YA_FREE(yajl_tree_parse_afs, v);
    }
    else if (YAJL_IS_OBJECT(v))
    {
        yajl_object_free(v);
    }
    else if (YAJL_IS_ARRAY(v))
    {
        yajl_array_free(v);
    }
    else /* if (yajl_t_true or yajl_t_false or yajl_t_null) */
    {
        YA_FREE(yajl_tree_parse_afs, v);
    }
}
