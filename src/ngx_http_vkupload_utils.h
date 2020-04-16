#ifndef _NGX_HTTP_VKUPLOAD_UTILS_H_INCLUDED_
#define _NGX_HTTP_VKUPLOAD_UTILS_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_list.h>
#include <ngx_hash.h>

ngx_int_t
ngx_http_vkupload_header_remove(ngx_list_t *headers_list, const ngx_str_t *name);

ngx_str_t *
ngx_http_vkupload_header_find(ngx_list_t *headers_list, const ngx_str_t *name);

ngx_int_t
ngx_http_vkupload_buf_append_kvalue(ngx_chain_t **bufs_ptr, ngx_pool_t *pool,
    const ngx_str_t *name, const ngx_str_t *value);

#endif
