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

#include "yajl_buf.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define YAJL_BUF_INIT_SIZE 2048

struct yajl_buf_t {
    size_t len;
    size_t used;
    unsigned char * data;
    yajl_alloc_funcs * alloc;
};

static
void yajl_buf_ensure_available(yajl_buf buf, size_t want)
{
    size_t need;

    assert(buf != NULL);

    /* first call */
    if (buf->data == NULL) {
        assert(buf->used == 0);
        assert(buf->len == 0);
        buf->len = YAJL_BUF_INIT_SIZE;
        buf->data = (unsigned char *) YA_MALLOC(buf->alloc, buf->len);
#if 0
        memset((void *) buf->data, 0, buf->len);
#else  /* it's really just a string, albiet UTF-8.... */
        buf->data[0] = 0;
#endif
    }

    need = buf->len;

    while (need > 0 && want >= (need - buf->used)) {
        /* XXX <<=1 is too aggressive!  but it "wraps" nicely to zero... */
        need <<= 1;
    }
    assert(need >= buf->len);
    if (need != buf->len) {
        buf->data = (unsigned char *) YA_REALLOC(buf->alloc, buf->data, need);
        buf->len = need;
    }
}

/*+ allocate a new buffer +*/
yajl_buf yajl_buf_alloc(yajl_alloc_funcs * alloc)
{
    yajl_buf b = YA_MALLOC(alloc, sizeof(struct yajl_buf_t));
    memset((void *) b, 0, sizeof(struct yajl_buf_t));
    b->alloc = alloc;
    return b;
}

/*+ free the buffer +*/
void yajl_buf_free(yajl_buf buf)
{
    assert(buf != NULL);
    if (buf->data) {
        YA_FREE(buf->alloc, buf->data);
    }
    YA_FREE(buf->alloc, buf);
}

/*+ append a number of bytes to the buffer +*/
void yajl_buf_append(yajl_buf buf, const void * data, size_t len)
{
    yajl_buf_ensure_available(buf, len);
    if (len > 0) {
        assert(data != NULL);
        memcpy(buf->data + buf->used, data, len);
        buf->used += len;
        buf->data[buf->used] = 0;
    }
}

/*+ empty the buffer +*/
void yajl_buf_clear(yajl_buf buf)
{
    buf->used = 0;
    if (buf->data) {
        buf->data[buf->used] = 0;
    }
}

/*+ get a pointer to the beginning of the buffer +*/
const unsigned char * yajl_buf_data(yajl_buf buf)
{
    return buf->data;
}

/*+ get the length of the buffer +*/
size_t yajl_buf_len(yajl_buf buf)
{
    return buf->used;
}

/*+ truncate the buffer +*/
void
yajl_buf_truncate(yajl_buf buf, size_t len)
{
    assert(len <= buf->used);
    buf->used = len;
}
