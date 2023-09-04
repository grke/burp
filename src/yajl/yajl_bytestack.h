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

/*
 * A header only implementation of a simple stack of bytes, used in YAJL
 * to maintain parse state.
 */

#ifndef __YAJL_BYTESTACK_H__
#define __YAJL_BYTESTACK_H__

#include "yajl/yajl_common.h"

#define YAJL_BS_INC 128

/*
 * n.b.:  Currently the items on the stack are always yajl_state values, but
 * since that's an enum, and thus the size of an int, it maybe wastes too much
 * space?  Anyway we can be sure the values are always way less than 2^CHAR_BIT
 * so an unsigned char is lots big enough.
 */
typedef struct yajl_bytestack_t {
    unsigned char * stack;
    size_t size;
    size_t used;
    yajl_alloc_funcs * yaf;
} yajl_bytestack;

/* xxx these could/should(?) be inline functions now we're at c99 */

/* initialize a bytestack */
#define yajl_bs_init(obs, _yaf) {                                       \
        (obs).stack = NULL;                                             \
        (obs).size = 0;                                                 \
        (obs).used = 0;                                                 \
        (obs).yaf = (_yaf);                                             \
    }


/* initialize a bytestack */
#define yajl_bs_free(obs)                                               \
    if ((obs).stack) (obs).yaf->free((obs).yaf->ctx, (obs).stack);

#define yajl_bs_current(obs)                                            \
    (assert((obs).used > 0), (obs).stack[(obs).used - 1])

#define yajl_bs_push(obs, byte) {                                       \
    if (((obs).size - (obs).used) == 0) {                               \
        (obs).size += YAJL_BS_INC;                                      \
        (obs).stack = (obs).yaf->realloc((obs).yaf->ctx,                \
                                         (void *) (obs).stack, (obs).size); \
    }                                                                   \
    (obs).stack[((obs).used)++] = (unsigned char) (byte);               \
}

/* removes the top item of the stack, returns nothing */
#define yajl_bs_pop(obs) { ((obs).used)--; }

#define yajl_bs_set(obs, byte)                                          \
    (obs).stack[((obs).used) - 1] = (unsigned char) (byte);


#endif
