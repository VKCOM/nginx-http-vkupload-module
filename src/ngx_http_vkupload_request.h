#ifndef _NGX_HTTP_VKUPLOAD_REQUEST_H_INCLUDED_
#define _NGX_HTTP_VKUPLOAD_REQUEST_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH 16
#define NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH_STR (NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH * 2)

extern const ngx_str_t  content_disposition_header_name;
extern const ngx_str_t  content_range_header_name;
extern const ngx_str_t  content_type_header_name;
extern const ngx_str_t  session_id_header_name;

typedef struct ngx_http_vkupload_request_s  ngx_http_vkupload_request_t;

typedef ngx_int_t (*ngx_http_vkupload_request_data_pt)  (ngx_http_vkupload_request_t *upload, ngx_chain_t *in);
typedef void (*ngx_http_vkupload_request_finish_pt)  (ngx_http_vkupload_request_t *upload, ngx_int_t rc);

struct ngx_http_vkupload_request_s {
    ngx_http_request_t  *request;
    ngx_log_t           *log;

    struct {
        ngx_http_vkupload_request_data_pt    data;
        ngx_http_vkupload_request_finish_pt  finish;
    } cb;

    ngx_file_t  file;

    struct {
        u_char     md5[NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH];
        ngx_str_t  name;
        ngx_str_t  field;
        size_t     size;
    } file_info;
};

ngx_int_t ngx_http_vkupload_request_handler(ngx_http_request_t *request);
ngx_int_t ngx_http_vkupload_request_fields_init(ngx_conf_t *cf);

void ngx_http_vkupload_request_pass(ngx_http_vkupload_request_t *upload);

#endif
