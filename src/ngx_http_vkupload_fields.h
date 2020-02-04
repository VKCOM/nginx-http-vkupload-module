#ifndef _NGX_HTTP_VKUPLOAD_FIELDS_H_INCLUDED_
#define _NGX_HTTP_VKUPLOAD_FIELDS_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t
ngx_http_vkupload_request_fields_append(ngx_http_request_t *request);
ngx_int_t
ngx_http_vkupload_request_fields_init(ngx_conf_t *cf);

#endif
