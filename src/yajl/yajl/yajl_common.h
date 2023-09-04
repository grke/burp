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
 * Common declarations to allow the client to use a custom allocator.
 *
 * Serious users of YAJL should provide error checking and handling variants.
 **/

#ifndef __YAJL_COMMON_H__
#define __YAJL_COMMON_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YAJL_MAX_DEPTH 128

/*
 * msft dll export gunk.  To build a DLL on windows, you must define WIN32,
 * YAJL_SHARED, and YAJL_BUILD.  To use a shared DLL, you must define
 * YAJL_SHARED and WIN32
 */
#if (defined(_WIN32) || defined(WIN32)) && defined(YAJL_SHARED)
#  ifdef YAJL_BUILD
#    define YAJL_API __declspec(dllexport)
#  else
#    define YAJL_API __declspec(dllimport)
#  endif
#else
#  if defined(__GNUC__) && (__GNUC__ * 100 + __GNUC_MINOR__) >= 303
#    define YAJL_API __attribute__ ((visibility("default")))
#  else
#    define YAJL_API
#  endif
#endif

/*+
 * A pointer to a malloc() function.
 +*/
typedef void *(*yajl_malloc_func)(void *ctx, size_t sz);

/*+
 * A pointer to a free() function.
 +*/
typedef void (*yajl_free_func)(void *ctx, void *ptr);

/*+
 * A pointer to a realloc() function.  Should also invoke error handling action
 * if sz==0.
 +*/
typedef void *(*yajl_realloc_func)(void *ctx, void *ptr, size_t sz);

/*+
 *  A structure which can be passed to yajl_*_alloc routines to allow the
 *  client to specify memory allocation functions to be used.
 *
 *  These functions should check for and handle any allocation errors, including
 *  considering requests to (*.realloc)() for zero bytes (sz==0) as an error.
 +*/
typedef struct
{
    yajl_malloc_func malloc;	/*+ pointer to a function that can allocate
                                 *  uninitialized memory
                                +*/
    yajl_realloc_func realloc;	/*+ pointer to a function that can resize memory
                                 *  allocations (should also treat sz==0 as an
                                 *  error condition)
                                +*/
    yajl_free_func free;		/*+ pointer to a function that can free memory
                                 *  allocated using the (*.realloc)() function
                                 *  or the (*.malloc)() function
                                +*/
    void *ctx;					/*+ a context pointer that will be passed to
                                 *  each of the above allocation routines
                                +*/
    /* xxx consider adding an optional error() call too! */
} yajl_alloc_funcs;

#ifdef __cplusplus
}
#endif

#endif
