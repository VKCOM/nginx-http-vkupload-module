#ifndef _NGX_HTTP_VKUPLOAD_MULTIPARTPARSER_H_INCLUDED_
#define _NGX_HTTP_VKUPLOAD_MULTIPARTPARSER_H_INCLUDED_

#include <ngx_core.h>

#define VKUPLOAD_MULTIPARTPARSER_HEADER_NAME_BUFFER_SIZE 128
#define VKUPLOAD_MULTIPARTPARSER_HEADER_VALUE_BUFFER_SIZE 256

typedef struct ngx_http_vkupload_multipartparser_s ngx_http_vkupload_multipartparser_t;
typedef struct ngx_http_vkupload_multipartparser_callbacks_s ngx_http_vkupload_multipartparser_callbacks_t;

typedef ngx_int_t (*ngx_http_vkupload_multipart_pt) (ngx_http_vkupload_multipartparser_t *parser);
typedef ngx_int_t (*ngx_http_vkupload_multipart_data_pt) (ngx_http_vkupload_multipartparser_t *parser, const ngx_str_t *data);
typedef ngx_int_t (*ngx_http_vkupload_multipart_header_pt) (ngx_http_vkupload_multipartparser_t *parser, const ngx_str_t *name, const ngx_str_t *value);

struct ngx_http_vkupload_multipartparser_s {
    void       *data;

    ngx_str_t   boundary;

    uint16_t    index;
    uint16_t    state;

    u_char      header_name[VKUPLOAD_MULTIPARTPARSER_HEADER_NAME_BUFFER_SIZE];
    uint16_t    header_name_len;

    u_char      header_value[VKUPLOAD_MULTIPARTPARSER_HEADER_VALUE_BUFFER_SIZE];
    uint16_t    header_value_len;
};

struct ngx_http_vkupload_multipartparser_callbacks_s {
    ngx_http_vkupload_multipart_pt        on_body_begin;
    ngx_http_vkupload_multipart_pt        on_part_begin;
    ngx_http_vkupload_multipart_header_pt on_header;
    ngx_http_vkupload_multipart_pt        on_headers_complete;
    ngx_http_vkupload_multipart_data_pt   on_data;
    ngx_http_vkupload_multipart_pt        on_part_end;
    ngx_http_vkupload_multipart_pt        on_body_end;
};

void ngx_http_vkupload_multipartparser_init(ngx_http_vkupload_multipartparser_t *parser, const ngx_str_t *boundary);
void ngx_http_vkupload_multipartparser_callbacks_init(ngx_http_vkupload_multipartparser_callbacks_t *callbacks);

ngx_int_t ngx_http_vkupload_multipartparser_execute(ngx_http_vkupload_multipartparser_t *parser,
    ngx_http_vkupload_multipartparser_callbacks_t *callbacks, ngx_buf_t *buf);

#endif
