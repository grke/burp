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
 * A JSON text lexical analyzer.
 *
 * Common and shared declarations for the lexer.
 **/

#ifndef __YAJL_LEX_H__
#define __YAJL_LEX_H__

#include "yajl/yajl_common.h"

typedef enum {
    yajl_tok_bool,
    yajl_tok_colon,
    yajl_tok_comma,
    yajl_tok_eof,
    yajl_tok_error,
    yajl_tok_left_brace,
    yajl_tok_left_bracket,
    yajl_tok_null,
    yajl_tok_right_brace,
    yajl_tok_right_bracket,

    /*+ we differentiate between integers and doubles to allow the
     * parser to interpret the number without re-scanning +*/
    yajl_tok_integer,
    yajl_tok_double,

    /*+ we differentiate between strings which require further processing,
     * and strings that do not +*/
    yajl_tok_string,
    yajl_tok_string_with_escapes,

    /*+ comment tokens are not currently returned to the parser, ever +*/
    yajl_tok_comment
} yajl_tok;

typedef struct yajl_lexer_t * yajl_lexer;

yajl_lexer yajl_lex_alloc(yajl_alloc_funcs * alloc,
                          /* bool */ int allowComments,
                          /* bool */ int validateUTF8);
void yajl_lex_free(yajl_lexer lexer);
yajl_tok yajl_lex_lex(yajl_lexer lexer, const unsigned char * jsonText,
                      size_t jsonTextLen, size_t * offset,
                      const unsigned char ** outBuf, size_t * outLen);
yajl_tok yajl_lex_peek(yajl_lexer lexer, const unsigned char * jsonText,
                       size_t jsonTextLen, size_t offset);


typedef enum {
    yajl_lex_e_ok = 0,
    yajl_lex_string_invalid_utf8,
    yajl_lex_string_invalid_escaped_char,
    yajl_lex_string_invalid_json_char,
    yajl_lex_string_invalid_hex_char,
    yajl_lex_invalid_char,
    yajl_lex_invalid_string,
    yajl_lex_missing_integer_after_decimal,
    yajl_lex_missing_integer_after_exponent,
    yajl_lex_missing_integer_after_minus,
    yajl_lex_unallowed_comment
} yajl_lex_error;

const char * yajl_lex_error_to_string(yajl_lex_error error);
yajl_lex_error yajl_lex_get_error(yajl_lexer lexer);
size_t yajl_lex_current_line(yajl_lexer lexer);
size_t yajl_lex_current_char(yajl_lexer lexer);

#endif
