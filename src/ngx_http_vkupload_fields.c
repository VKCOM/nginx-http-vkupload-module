#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_vkupload_fields.h"
#include "ngx_http_vkupload_request.h"
#include "ngx_http_vkupload_module.h"
#include "ngx_http_vkupload_utils.h"

static ngx_int_t ngx_http_vkupload_request_file_path_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_vkupload_request_file_size_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_vkupload_request_file_name_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data);

typedef struct {
    ngx_str_t                 name;
    ngx_http_get_variable_pt  get_handler;
} ngx_http_vkupload_field_t;

static ngx_http_vkupload_field_t
ngx_http_vkupload_fields[] = {
    { .name = ngx_string("vkupload_file_path"), .get_handler = ngx_http_vkupload_request_file_path_field },
    { .name = ngx_string("vkupload_file_size"), .get_handler = ngx_http_vkupload_request_file_size_field },
    { .name = ngx_string("vkupload_file_name"), .get_handler = ngx_http_vkupload_request_file_name_field },
};


ngx_int_t
ngx_http_vkupload_request_fields_append(ngx_http_request_t *request)
{
    ngx_str_t                        field_name, field_value;
    ngx_http_vkupload_key_val_t     *upload_fields;
    ngx_http_request_body_t         *request_body;
    ngx_http_vkupload_loc_conf_t    *vkupload_lconf;
    ngx_uint_t                       i;
    ngx_int_t                        rc;
    ngx_chain_t                     *cl;

    request_body = request->request_body;

    { // reset input buffers
        for (cl = request_body->bufs; cl; cl = cl->next) {
            cl->buf->last = cl->buf->start;
            cl->buf->pos = cl->buf->start;
        }
    }

    vkupload_lconf = ngx_http_get_module_loc_conf(request, ngx_http_vkupload_module);
    if(vkupload_lconf->upload_fields == NULL) {
        return NGX_OK;
    }

    upload_fields = vkupload_lconf->upload_fields->elts;

    for (i = 0; i < vkupload_lconf->upload_fields->nelts; i++) {
        if (upload_fields[i].name_lengths == NULL) {
            field_name = upload_fields[i].value.key;
        } else {
            if (ngx_http_script_run(request, &field_name, upload_fields[i].name_lengths->elts, 0,
                upload_fields[i].name_values->elts) == NULL)
            {
                return NGX_ERROR;
            }
        }

        if (upload_fields[i].value_lengths == NULL) {
            field_value = upload_fields[i].value.value;
        } else {
            if (ngx_http_script_run(request, &field_value, upload_fields[i].value_lengths->elts, 0,
                upload_fields[i].value_values->elts) == NULL)
            {
                return NGX_ERROR;
            }
        }

        rc = ngx_http_vkupload_buf_append_kvalue(&request_body->bufs, request->pool, &field_name, &field_value);

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_vkupload_request_fields_init(ngx_conf_t *cf)
{
    ngx_uint_t           i;
    ngx_http_variable_t *field;

    for (i = 0; i < (sizeof(ngx_http_vkupload_fields)/sizeof(ngx_http_vkupload_fields[0])); i++) {
        field = ngx_http_add_variable(cf, &ngx_http_vkupload_fields[i].name,
            NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH);

        if (field == NULL) {
            return NGX_ERROR;
        }

        field->get_handler = ngx_http_vkupload_fields[i].get_handler;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_request_file_path_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_vkupload_request_t  *vkupload;

    vkupload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);

    v->data = vkupload->variables.path.data;
    v->len = vkupload->variables.path.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_vkupload_request_file_size_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_vkupload_request_t  *vkupload;
    u_char                       *size_str;

    vkupload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);

    size_str = ngx_pcalloc(request->pool, NGX_OFF_T_LEN);
    if (size_str == NULL) {
        return NGX_ERROR;
    }

    v->data = size_str;
    v->len = ngx_sprintf(size_str, "%O", vkupload->variables.size) - size_str;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_request_file_name_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_vkupload_request_t  *vkupload;

    vkupload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);

    v->data = vkupload->variables.name.data;
    v->len = vkupload->variables.name.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}
