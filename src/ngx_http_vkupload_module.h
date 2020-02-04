#ifndef _NGX_HTTP_VKUPLOAD_MODULE_H_INCLUDED_
#define _NGX_HTTP_VKUPLOAD_MODULE_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_array.h>
#include <ngx_http.h>

#include "shared_file/ngx_shared_file_manager.h"

#define NGX_HTTP_VKUPLOAD_MODULE_VERSION "3.0.0-vk"

extern ngx_module_t  ngx_http_vkupload_module;

typedef struct {
    ngx_shared_file_manager_t  *manager;

    ngx_str_t                   upload_url;
    ngx_array_t                *upload_fields;

    ngx_flag_t                  multipart;
    ngx_array_t                *multipart_fields;

    ngx_flag_t                 resumable;
    ngx_http_complex_value_t  *resumable_session_name;
} ngx_http_vkupload_loc_conf_t;

typedef struct {
    ngx_array_t                 managers;
} ngx_http_vkupload_main_conf_t;

typedef struct {
    ngx_array_t                *name_lengths;
    ngx_array_t                *name_values;
    ngx_array_t                *value_lengths;
    ngx_array_t                *value_values;

    ngx_table_elt_t             value;
} ngx_http_vkupload_key_val_t;

#endif
