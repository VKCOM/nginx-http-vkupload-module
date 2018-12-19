#ifndef _NGX_HTTP_VKUPLOAD_MODULE_H_INCLUDED_
#define _NGX_HTTP_VKUPLOAD_MODULE_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_array.h>
#include <ngx_http.h>

#define NGX_HTTP_VKUPLOAD_MODULE_VERSION "2.0.0-vk"

extern ngx_module_t  ngx_http_vkupload_module;

typedef struct {
    ngx_str_t     upload_url;
    ngx_array_t  *upload_fields;

    ngx_path_t  *upload_file_path;
    ngx_uint_t   upload_file_access;

    ngx_flag_t    multipart;
    ngx_array_t  *multipart_fields;
} ngx_http_vkupload_loc_conf_t;

typedef struct {
    ngx_table_elt_t value;

    ngx_array_t *name_lengths;
    ngx_array_t *name_values;
    ngx_array_t *value_lengths;
    ngx_array_t *value_values;
} ngx_http_vkupload_field_conf_t;

#endif
