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
 * default memory allocation routines for yajl which use malloc(3), realloc(3),
 * and free(3)
 *
 * Serious users of YAJL should replace these with error checking and handling
 * variants.  Implementations of yaf->realloc should check for sz==0 and fault
 * on that as well.
 **/

#include "yajl_alloc.h"
#include <stdlib.h>

/*+
 * a private wrapper around malloc(3)
 +*/
static void * yajl_internal_malloc(void *ctx, size_t sz)
{
    (void)ctx;
    return malloc(sz);
}

/*+
 * a private wrapper around realloc(3)
 +*/
static void * yajl_internal_realloc(void *ctx, void * previous,
                                    size_t sz)
{
    (void)ctx;
    return realloc(previous, sz);
}

/*+
 * a private wrapper around free(3)
 +*/
static void yajl_internal_free(void *ctx, void * ptr)
{
    (void)ctx;
    free(ptr);
}

/*+
 * Set the allocator function pointers in <yaf> to private functions which call
 * the default malloc(3), realloc(3), and free(3) functions.
 +*/
void yajl_set_default_alloc_funcs(yajl_alloc_funcs * yaf)
{
    yaf->malloc = yajl_internal_malloc;
    yaf->free = yajl_internal_free;
    yaf->realloc = yajl_internal_realloc;
    yaf->ctx = NULL;
}

