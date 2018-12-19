#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_vkupload_module.h"
#include "ngx_http_vkupload_request.h"

static void *ngx_http_vkupload_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_vkupload_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_vkupload_pass_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_set_vkupload_field_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_path_init_t ngx_http_vkupload_temp_path = {
    ngx_string(NGX_HTTP_CLIENT_TEMP_PATH), { 0, 0, 0 }
};

static ngx_command_t ngx_http_vkupload_commands[] = {
    { ngx_string("vkupload_pass"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE1,
        ngx_http_vkupload_pass_set_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    { ngx_string("vkupload_field"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE2,
        ngx_conf_set_vkupload_field_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, upload_fields),
        NULL
    },

    { ngx_string("vkupload_file_path"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE1234,
        ngx_conf_set_path_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, upload_file_path),
        NULL
    },
    { ngx_string("vkupload_file_access"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE123,
        ngx_conf_set_access_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, upload_file_access),
        NULL
    },

    { ngx_string("vkupload_multipart"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, multipart),
        NULL
    },
    { ngx_string("vkupload_multipart_field"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, multipart_fields),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_vkupload_module_ctx = {
    ngx_http_vkupload_request_fields_init,  /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_vkupload_create_loc_conf,      /* create location configuration */
    ngx_http_vkupload_merge_loc_conf        /* merge location configuration */
};

ngx_module_t ngx_http_vkupload_module = {
    NGX_MODULE_V1,
    &ngx_http_vkupload_module_ctx,    /* module context */
    ngx_http_vkupload_commands,         /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_vkupload_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_vkupload_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_vkupload_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upload_url = { NULL, 0 };
     *     conf->upload_file_path = NULL;
     */

    conf->upload_fields = NGX_CONF_UNSET_PTR;
    conf->upload_file_access = NGX_CONF_UNSET_UINT;

    conf->multipart = NGX_CONF_UNSET;
    conf->multipart_fields = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *
ngx_http_vkupload_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_vkupload_loc_conf_t  *prev = parent;
    ngx_http_vkupload_loc_conf_t  *conf = child;

    ngx_conf_merge_str_value(conf->upload_url, prev->upload_url, "");
    ngx_conf_merge_ptr_value(conf->upload_fields, prev->upload_fields, NULL);

    if (ngx_conf_merge_path_value(cf, &conf->upload_file_path, prev->upload_file_path,
        &ngx_http_vkupload_temp_path) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->upload_file_access, prev->upload_file_access, 0600);

    ngx_conf_merge_value(conf->multipart, prev->multipart, 0);
    ngx_conf_merge_ptr_value(conf->multipart_fields, prev->multipart_fields, NULL);

    return NGX_CONF_OK;
}

static char *
ngx_http_vkupload_pass_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_vkupload_loc_conf_t  *vkupload_lconf = conf;
    ngx_http_core_loc_conf_t      *http_core_lconf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    ngx_str_t *upload_url;

    if ((vkupload_lconf->upload_url.len != 0)) {
        return "is duplicate";
    }

    upload_url = &(((ngx_str_t *) cf->args->elts)[1]); 
    if (upload_url->len == 0) {
        return "empty value";
    }

    vkupload_lconf->upload_url = *upload_url;
    http_core_lconf->handler = ngx_http_vkupload_request_handler;

    return NGX_CONF_OK;
}

static char *
ngx_conf_set_vkupload_field_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_http_vkupload_field_conf_t  *field;
    ngx_int_t                        n;
    ngx_str_t                       *value;
    ngx_http_script_compile_t        sc;
    ngx_array_t                    **fields;

    fields = (ngx_array_t **) (p + cmd->offset);

    if (*fields == NGX_CONF_UNSET_PTR) {
        *fields = ngx_array_create(cf->pool, 1, sizeof(ngx_http_vkupload_field_conf_t));

        if (*fields == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    field = ngx_array_push(*fields);
    if (field == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    field->value.hash = 1;
    field->value.key = value[1];
    field->value.value = value[2];
    field->name_lengths = NULL;
    field->name_values = NULL;
    field->value_lengths = NULL;
    field->value_values = NULL;

    /*
     * Compile field name
     */
    n = ngx_http_script_variables_count(&value[1]);
    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &field->name_lengths;
        sc.values = &field->name_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Compile field value
     */
    n = ngx_http_script_variables_count(&value[2]);
    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[2];
        sc.lengths = &field->value_lengths;
        sc.values = &field->value_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
