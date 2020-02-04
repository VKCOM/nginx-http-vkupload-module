#ifndef _NGX_HTTP_VKUPLOAD_HEADERPARSER_H_INCLUDED_
#define _NGX_HTTP_VKUPLOAD_HEADERPARSER_H_INCLUDED_

#include <ngx_core.h>

#define str_equal(str, len, static_string) \
    ((len) == (sizeof(static_string) - 1) && \
        ngx_strncasecmp((str), (u_char *) (static_string), (sizeof(static_string) - 1)) == 0)

typedef enum {
    ngx_http_vkupload_content_type_st_unknown,
    ngx_http_vkupload_content_type_st_multipart
} ngx_http_vkupload_content_type_e;

typedef enum {
    ngx_http_vkupload_content_disposition_st_unknown,
    ngx_http_vkupload_content_disposition_st_form_data,
    ngx_http_vkupload_content_disposition_st_attachment
} ngx_http_vkupload_content_disposition_e;

typedef struct {
    size_t  start;
    size_t  end;
    size_t  total;
} ngx_http_vkupload_content_range_t;

ngx_int_t ngx_http_vkupload_headerparser_session_id(ngx_str_t *session_id, const ngx_str_t *value);
ngx_int_t ngx_http_vkupload_headerparser_content_type(ngx_http_vkupload_content_type_e *type,
    ngx_str_t *boundary, const ngx_str_t *content_type);
ngx_int_t ngx_http_vkupload_headerparser_content_disposition(ngx_http_vkupload_content_disposition_e *type,
    ngx_str_t *filename, ngx_str_t *name, const ngx_str_t *content_disposition);
ngx_int_t ngx_http_vkupload_headerparser_content_range(ngx_http_vkupload_content_range_t *range, const ngx_str_t *content_range);

#endif
