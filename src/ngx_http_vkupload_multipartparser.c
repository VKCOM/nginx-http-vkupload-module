#include "ngx_http_vkupload_multipartparser.h"

#include <ngx_core.h>
#include <limits.h>

#define SP (u_char) ' '
#define HT (u_char) '\t'
#define HYPHEN (u_char) '-'

#define CALLBACK_NOTIFY(NAME)                               \
    if (callbacks->on_##NAME != NULL) {                     \
        if ((rc = callbacks->on_##NAME(parser)) != NGX_OK)  \
            goto error;                                     \
    }

#define CALLBACK_DATA(NAME, P, S)                                                                           \
    if (callbacks->on_##NAME != NULL) {                                                                     \
        if ((rc = callbacks->on_##NAME(parser, & (ngx_str_t) { .data = (u_char *) P, .len = S })) != 0) {   \
            goto error;                                                                                     \
        }                                                                                                   \
    }

#define CALLBACK_HEADER(NAME, N, NL, V, VL)                            \
    if (callbacks->on_##NAME != NULL) {                                \
        if ((rc = callbacks->on_##NAME(parser,                         \
            & (ngx_str_t) { .data = (u_char *) N, .len = NL },         \
            & (ngx_str_t) { .data = (u_char *) V, .len = VL })) != 0)  \
        {                                                              \
            goto error;                                                \
        }                                                              \
    }

typedef enum {
    ngx_mp_st_preamble,
    ngx_mp_st_preamble_hy_hy,
    ngx_mp_st_first_boundary,
    ngx_mp_st_header_field_start,
    ngx_mp_st_header_field,
    ngx_mp_st_header_value_start,
    ngx_mp_st_header_value,
    ngx_mp_st_header_value_cr,
    ngx_mp_st_headers_done,
    ngx_mp_st_data,
    ngx_mp_st_data_cr,
    ngx_mp_st_data_cr_lf,
    ngx_mp_st_data_cr_lf_hy,
    ngx_mp_st_data_boundary_start,
    ngx_mp_st_data_boundary,
    ngx_mp_st_data_boundary_done,
    ngx_mp_st_data_boundary_done_cr_lf,
    ngx_mp_st_data_boundary_done_hy_hy,
    ngx_mp_st_epilogue,
} ngx_mp_state_e;

/* Header field name as defined by rfc 2616. Also lowercases them.
 *     field-name   = token
 *     token        = 1*<any CHAR except CTLs or tspecials>
 *     CTL          = <any US-ASCII control character (octets 0 - 31) and DEL (127)>
 *     tspecials    = "(" | ")" | "<" | ">" | "@"
 *                  | "," | ";" | ":" | "\" | DQUOTE
 *                  | "/" | "[" | "]" | "?" | "="
 *                  | "{" | "}" | SP | HT
 *     DQUOTE       = <US-ASCII double-quote mark (34)>
 *     SP           = <US-ASCII SP, space (32)>
 *     HT           = <US-ASCII HT, horizontal-tab (9)>
 */
static const char header_field_chars[UCHAR_MAX] = {
/*  0 nul   1 soh   2 stx   3 etx   4 eot   5 enq   6 ack   7 bel   */
    0,      0,      0,      0,      0,      0,      0,      0,
/*  8 bs    9 ht    10 nl   11 vt   12 np   13 cr   14 so   15 si   */
    0,      0,      0,      0,      0,      0,      0,      0,
/*  16 dle  17 dc1  18 dc2  19 dc3  20 dc4  21 nak  22 syn  23 etb  */
    0,      0,      0,      0,      0,      0,      0,      0,
/*  24 can  25 em   26 sub  27 esc  28 fs   29 gs   30 rs   31 us   */
    0,      0,      0,      0,      0,      0,      0,      0,
/*  32 sp   33 !    34 "    35 #    36 $    37 %    38 &    39 '    */
    0,      '!',    0,      '#',    '$',    '%',    '&',    '\'',
/*  40 (    41 )    42 *    43 +    44 ,    45 -    46 .    47 /    */
    0,      0,      '*',    '+',    0,      '-',    '.',    0,
/*  48 0    49 1    50 2    51 3    52 4    53 5    54 6    55 7    */
    '0',    '1',    '2',    '3',    '4',    '5',    '6',    '7',
/*  56 8    57 9    58 :    59 ;    60 <    61 =    62 >    63 ?    */
    '8',    '9',    0,      0,      0,      0,      0,      0,
/*  64 @    65 A    66 B    67 C    68 D    69 E    70 F    71 G    */
    0,      'A',    'B',    'C',    'D',    'E',    'F',    'G',
/*  72 H    73 I    74 J    75 K    76 L    77 M    78 N    79 O    */
    'H',    'I',    'J',    'K',    'L',    'M',    'N',    'O',
/*  80 P    81 Q    82 R    83 S    84 T    85 U    86 V    87 W    */
    'P',    'Q',    'R',    'S',    'T',    'U',    'V',    'W',
/*  88 X    89 Y    90 Z    91 [    92 \    93 ]    94 ^    95 _    */
    'X',    'Y',    'Z',     0,     0,      0,      '^',    '_',
/*  96 `    97 a    98 b    99 c    100 d   101 e   102 f   103 g   */
    '`',    'a',    'b',    'c',    'd',    'e',    'f',    'g',
/*  104 h   105 i   106 j   107 k   108 l   109 m   110 n   111 o   */
    'h',    'i',    'j',    'k',    'l',    'm',    'n',    'o',
/*  112 p   113 q   114 r   115 s   116 t   117 u   118 v   119 w   */
    'p',    'q',    'r',    's',    't',    'u',    'v',    'w',
/*  120 x   121 y   122 z   123 {   124 |   125 }   126 ~   127 del */
    'x',    'y',    'z',    0,      '|',     0,     '~',    0
};

void
ngx_http_vkupload_multipartparser_init(ngx_http_vkupload_multipartparser_t *parser, const ngx_str_t *boundary)
{
    memset(parser, 0, sizeof(*parser));

    parser->boundary = *boundary;
    parser->state = ngx_mp_st_preamble;
}

void
ngx_http_vkupload_multipartparser_callbacks_init(ngx_http_vkupload_multipartparser_callbacks_t *callbacks)
{
    memset(callbacks, 0, sizeof(*callbacks));
}

ngx_int_t
ngx_http_vkupload_multipartparser_execute(ngx_http_vkupload_multipartparser_t *parser,
    ngx_http_vkupload_multipartparser_callbacks_t *callbacks, ngx_buf_t *buf)
{
    const u_char  *mark;
    u_char         c;

    ngx_int_t rc = NGX_OK;

    for (; buf->pos < buf->last; ++buf->pos) {
        c = *(buf->pos);

reexecute:
        switch (parser->state) {
            case ngx_mp_st_preamble:
                if (c == HYPHEN) {
                    parser->state = ngx_mp_st_preamble_hy_hy;
                }

                // else ignore everything before first boundary
                break;

            case ngx_mp_st_preamble_hy_hy:
                if (c == HYPHEN) {
                    parser->state = ngx_mp_st_first_boundary;
                } else {
                    parser->state = ngx_mp_st_preamble;
                }

                break;

            case ngx_mp_st_first_boundary:
                if (parser->index == parser->boundary.len) {
                    if (c != CR) {
                        goto error;
                    }

                    parser->index++;
                    break;
                }

                if (parser->index == parser->boundary.len + 1) {
                    if (c != LF) {
                        goto error;
                    }

                    CALLBACK_NOTIFY(body_begin);
                    CALLBACK_NOTIFY(part_begin);

                    parser->index = 0;
                    parser->state = ngx_mp_st_header_field_start;
                    break;
                }

                if (c == parser->boundary.data[parser->index]) {
                    parser->index++;
                    break;
                }

                goto error;

            case ngx_mp_st_header_field_start:
                if (c == CR) {
                    parser->state = ngx_mp_st_headers_done;
                    break;
                }

                parser->state = ngx_mp_st_header_field;
                parser->header_name_len = 0;

                // fallthrough;

            case ngx_mp_st_header_field:
                while (buf->pos < buf->last) {
                    c = *(buf->pos);

                    if (header_field_chars[c] == 0) {
                        break;
                    }

                    if (parser->header_name_len < VKUPLOAD_MULTIPARTPARSER_HEADER_NAME_BUFFER_SIZE) {
                        parser->header_name[parser->header_name_len++] = c;
                    }

                    ++buf->pos;
                }

                if (c == (u_char) ':') {
                    parser->state = ngx_mp_st_header_value_start;
                    break;
                }

                if (buf->pos == buf->last) {
                    goto error;
                }

                goto error;

            case ngx_mp_st_header_value_start:
                if (c == SP || c == HT) {
                    break;
                }

                parser->state = ngx_mp_st_header_value;
                parser->header_value_len = 0;
                // fallthrough;

            case ngx_mp_st_header_value:
                while (buf->pos < buf->last) {
                    c = *(buf->pos);

                    if (c == CR) {
                        CALLBACK_HEADER(header, parser->header_name, parser->header_name_len,
                            parser->header_value, parser->header_value_len);

                        parser->state = ngx_mp_st_header_value_cr;
                        break;
                    }

                    if (parser->header_value_len < VKUPLOAD_MULTIPARTPARSER_HEADER_VALUE_BUFFER_SIZE) {
                        parser->header_value[parser->header_value_len++] = c;
                    }

                    ++buf->pos;
                }

                if (buf->pos == buf->last) {
                    goto error;
                }

                break;

            case ngx_mp_st_header_value_cr:
                if (c == LF) {
                    parser->state = ngx_mp_st_header_field_start;
                    break;
                }

                goto error;

            case ngx_mp_st_headers_done:
                if (c == LF) {
                    CALLBACK_NOTIFY(headers_complete);
                    parser->state = ngx_mp_st_data;
                    break;
                }

                goto error;

            case ngx_mp_st_data:
                mark = buf->pos;

                while (buf->pos < buf->last) {
                    c = *(buf->pos);

                    if (c == CR) {
                        if ((buf->last - buf->pos) < (ptrdiff_t) (sizeof("\r\n--") - 1) ||
                            (buf->pos[1] == '\n' && buf->pos[2] == '-' && buf->pos[3] == '-'))
                        {
                            parser->state = ngx_mp_st_data_cr;
                            break;
                        }
                    }

                    ++buf->pos;
                }

                if (buf->pos > mark) {
                    CALLBACK_DATA(data, mark, buf->pos - mark);
                }

                if (buf->pos == buf->last) {
                    goto error;
                }

                break;

            case ngx_mp_st_data_cr:
                if (c == LF) {
                    parser->state = ngx_mp_st_data_cr_lf;
                    break;
                }

                CALLBACK_DATA(data, "\r", 1);
                parser->state = ngx_mp_st_data;

                goto reexecute;

            case ngx_mp_st_data_cr_lf:
                if (c == HYPHEN) {
                    parser->state = ngx_mp_st_data_cr_lf_hy;
                    break;
                }

                CALLBACK_DATA(data, "\r\n", 2);
                parser->state = ngx_mp_st_data;

                goto reexecute;

            case ngx_mp_st_data_cr_lf_hy:
                if (c == HYPHEN) {
                    parser->state = ngx_mp_st_data_boundary_start;
                    break;
                }

                CALLBACK_DATA(data, "\r\n-", 3);
                parser->state = ngx_mp_st_data;

                goto reexecute;

            case ngx_mp_st_data_boundary_start:
                parser->index = 0;
                parser->state = ngx_mp_st_data_boundary;
                // fallthrough;

            case ngx_mp_st_data_boundary:
                if (parser->index == parser->boundary.len) {
                    parser->index = 0;
                    parser->state = ngx_mp_st_data_boundary_done;

                    goto reexecute;
                }

                if (c == parser->boundary.data[parser->index]) {
                    parser->index++;
                    break;
                }

                CALLBACK_DATA(data, parser->boundary.data, parser->index);
                parser->state = ngx_mp_st_data;

                goto reexecute;

            case ngx_mp_st_data_boundary_done:
                if (c == CR) {
                    parser->state = ngx_mp_st_data_boundary_done_cr_lf;
                    break;
                }

                if (c == HYPHEN) {
                    parser->state = ngx_mp_st_data_boundary_done_hy_hy;
                    break;
                }

                goto error;

            case ngx_mp_st_data_boundary_done_cr_lf:
                if (c == LF) {
                    CALLBACK_NOTIFY(part_end);
                    CALLBACK_NOTIFY(part_begin);

                    parser->state = ngx_mp_st_header_field_start;
                    break;
                }

                goto error;

            case ngx_mp_st_data_boundary_done_hy_hy:
                if (c == HYPHEN) {
                    CALLBACK_NOTIFY(part_end);
                    CALLBACK_NOTIFY(body_end);

                    parser->state = ngx_mp_st_epilogue;
                    break;
                }

                goto error;

            case ngx_mp_st_epilogue:
                // Must be ignored according to rfc 1341.
                break;
        }
    }

error:
    return rc;
}
