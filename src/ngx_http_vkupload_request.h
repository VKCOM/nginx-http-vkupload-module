#ifndef _NGX_HTTP_VKUPLOAD_REQUEST_H_INCLUDED_
#define _NGX_HTTP_VKUPLOAD_REQUEST_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_http.h>

#include "shared_file/ngx_shared_file.h"

typedef struct ngx_http_vkupload_request_s  ngx_http_vkupload_request_t;
typedef struct ngx_http_vkupload_handler_s  ngx_http_vkupload_handler_t;

typedef ngx_int_t  (*ngx_http_vkupload_handler_conf_pt)(ngx_conf_t *cf);
typedef ngx_int_t  (*ngx_http_vkupload_handler_init_pt)(ngx_http_request_t *request, ngx_http_vkupload_request_t **vkupload_ptr);
typedef ngx_int_t  (*ngx_http_vkupload_handler_finalize_pt)(ngx_http_vkupload_request_t *vkupload, ngx_int_t rc);
typedef ngx_int_t  (*ngx_http_vkupload_handler_data_pt)(ngx_http_vkupload_request_t *vkupload, ngx_chain_t *in);

struct ngx_http_vkupload_handler_s {
    ngx_http_vkupload_handler_conf_pt      configuration;
    ngx_http_vkupload_handler_init_pt      init;
    ngx_http_vkupload_handler_finalize_pt  finalize;
    ngx_http_vkupload_handler_data_pt      data;
};

struct ngx_http_vkupload_request_s {
    ngx_http_request_t                    *request;
    ngx_http_vkupload_handler_t           *handler;

    ngx_shared_file_t                     *file;

    struct {
        ngx_str_t                          path;
        ngx_str_t                          name;
        size_t                             size;
    } variables;

    u_char                                 ctx[];
};

void       ngx_http_vkupload_request_finalize(ngx_http_vkupload_request_t *vkupload, ngx_int_t rc);
ngx_int_t  ngx_http_vkupload_request_finalize_handler(ngx_http_vkupload_request_t *vkupload, ngx_int_t rc);

ngx_int_t  ngx_http_vkupload_request_handler_register(ngx_http_vkupload_handler_t *handler, ngx_conf_t *cf);
ngx_int_t  ngx_http_vkupload_request_handler_find(ngx_http_request_t *request, ngx_http_vkupload_request_t **vkupload_ptr);

ngx_int_t  ngx_http_vkupload_request_pass(ngx_http_vkupload_request_t *vkupload);

#endif
