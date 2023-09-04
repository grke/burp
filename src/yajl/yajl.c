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

#include "yajl/yajl_parse.h"
#include "yajl_lex.h"
#include "yajl_parser.h"
#include "yajl_alloc.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

const char *
yajl_status_to_string(yajl_status stat)
{
    const char * statStr = "unknown";
    switch (stat) {
        case yajl_status_ok:
            statStr = "ok, no error";
            break;
        case yajl_status_client_canceled:
            statStr = "client canceled parse";
            break;
        case yajl_status_error:
            statStr = "parse error";
            break;
    }
    return statStr;
}

/*+ allocate a parser handle
 *
 * yajl_handle yajl_alloc
 * Returns a handle to a newly allocated "yajl" JSON parser, or NULL on failure.
 * Must be freed by passing it to yajl_free().
 *
 * const yajl_callbacks *callbacks
 * a yajl callbacks structure specifying the functions to call when different
 * JSON entities are encountered in the input text.  May be NULL, which is only
 * useful for validation.
 *
 * yajl_alloc_funcs *afs
 * memory allocation functions, may be NULL in which case the standard malloc(),
 * free(), and realloc() will be used.
 *
 * void *ctx
 * a user-specified context pointer that will be passed to the callback
 * functions.
 *
 * Note:  The yajl parser assumes the locale is "C", and in particular that
 * LC_NUMERIC is set to "C", as otherwise (e.g. if the current locale does not
 * use a period ('.') as the "decimal_point" character) the parser may not be
 * able to convert decimal numbers (assuming the host implementation of
 * strtod(3) does respect the current locale settings for the process).
 +*/
yajl_handle
yajl_alloc(const yajl_callbacks * callbacks,
           const yajl_alloc_funcs * afs,
           void * ctx)
{
    yajl_handle hand = NULL;
    yajl_alloc_funcs afsBuffer;

    /* first order of business is to set up memory allocation routines */
    if (afs != NULL) {
        if (afs->malloc == NULL || afs->realloc == NULL || afs->free == NULL)
        {
            return NULL;
        }
    } else {
        yajl_set_default_alloc_funcs(&afsBuffer);
        afs = &afsBuffer;
    }

    hand = (yajl_handle) YA_MALLOC(afs, sizeof(struct yajl_handle_t));

    /* copy in pointers to allocation routines */
    hand->alloc = *afs;

    hand->callbacks = callbacks;
    hand->ctx = ctx;
    hand->lexer = NULL;
    hand->bytesConsumed = 0;
    hand->decodeBuf = yajl_buf_alloc(&(hand->alloc));
    hand->flags	    = 0;
    yajl_bs_init(hand->stateStack, &(hand->alloc));
    yajl_bs_push(hand->stateStack, yajl_state_start);

    return hand;
}

/*+
 * allow the modification of parser options subsequent to handle allocation (via
 * yajl_alloc)
 *
 *  \returns zero in case of errors, non-zero otherwise
 +*/
int
yajl_config(yajl_handle h, yajl_option opt, ...)
{
    int rv = 1;
    va_list ap;
    va_start(ap, opt);

    switch(opt) {
        case yajl_allow_comments:
        case yajl_dont_validate_strings:
        case yajl_allow_trailing_garbage:
        case yajl_allow_multiple_values:
        case yajl_allow_partial_values:
            if (va_arg(ap, int)) h->flags |= opt;
            else h->flags &= ~opt;
            break;
        default:
            rv = 0;
    }
    va_end(ap);

    return rv;
}

/*+ free a parser handle +*/
void
yajl_free(yajl_handle handle)
{
    yajl_bs_free(handle->stateStack);
    yajl_buf_free(handle->decodeBuf);
    if (handle->lexer) {
        yajl_lex_free(handle->lexer);
        handle->lexer = NULL;
    }
    YA_FREE(&(handle->alloc), handle);
}

/*+
 * Parse some json!
 *
 *  \param hand - a handle to the json parser allocated with yajl_alloc
 *
 *  \param jsonText - a pointer to the UTF8 json text to be parsed
 *
 *  \param jsonTextLength - the length, in bytes, of input text
 +*/
yajl_status
yajl_parse(yajl_handle hand, const unsigned char * jsonText,
           size_t jsonTextLen)
{
    yajl_status status;

    /* lazy allocation of the lexer */
    if (hand->lexer == NULL) {
        hand->lexer = yajl_lex_alloc(&(hand->alloc),
                                     (int) hand->flags & yajl_allow_comments,
                                     !(hand->flags & yajl_dont_validate_strings));
    }

    status = yajl_do_parse(hand, jsonText, jsonTextLen);
    return status;
}


/*+
 * Parse any remaining buffered json.
 *
 * Since yajl is a stream-based parser, without an explicit end of input, yajl
 * sometimes can't decide if content at the end of the stream is valid or not.
 * For example, if "1" has been fed in, yajl can't know whether another digit is
 * next or some character that would terminate the integer token.
 *
 *  \param hand - a handle to the json parser allocated with yajl_alloc
 +*/
yajl_status
yajl_complete_parse(yajl_handle hand)
{
    /* The lexer is lazy allocated in the first call to parse.  If parse is
     * never called, then no data was provided to parse at all.  This is a
     * "premature EOF" error unless yajl_allow_partial_values is specified.
     * allocating the lexer now is the simplest possible way to handle this
     * case while preserving all the other semantics of the parser
     * (multiple values, partial values, etc). */
    if (hand->lexer == NULL) {
        hand->lexer = yajl_lex_alloc(&(hand->alloc),
                                     (int) hand->flags & yajl_allow_comments,
                                     !(hand->flags & yajl_dont_validate_strings));
    }

    return yajl_do_finish(hand);
}

/*+
 * get an error string describing the state of the parse.
 *
 * If verbose is non-zero, the message will include the JSON text where the
 * error occurred, along with an arrow pointing to the specific char.
 *
 *  \returns A dynamically allocated string will be returned which should be
 *  freed with yajl_free_error
 +*/
unsigned char *
yajl_get_error(yajl_handle hand, int verbose,
               const unsigned char * jsonText, size_t jsonTextLen)
{
    return yajl_render_error_string(hand, jsonText, jsonTextLen, verbose);
}

/*+
 * get the amount of data consumed from the last chunk passed to YAJL.
 *
 * In the case of a successful parse this can help you understand if
 * the entire buffer was consumed (which will allow you to handle
 * "junk at end of input").
 *
 * In the event an error is encountered during parsing, this function
 * affords the client a way to get the offset into the most recent
 * chunk where the error occurred.  0 will be returned if no error
 * was encountered.
 +*/
size_t
yajl_get_bytes_consumed(yajl_handle hand)
{
    if (!hand) return 0;
    else return hand->bytesConsumed;
}


/*+ free an error returned from yajl_get_error +*/
void
yajl_free_error(yajl_handle hand, unsigned char * str)
{
    /* use memory allocation functions if set */
    YA_FREE(&(hand->alloc), str);
}

/* XXX: add utility routines to parse from file */
