#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#include "plugin/ngx_http_vkupload_md5.h"

#include "ngx_http_vkupload_module.h"
#include "ngx_http_vkupload_request.h"

#include "shared_file/ngx_shared_file_plugin.h"
#include "shared_file/ngx_shared_file_manager.h"
#include "shared_file/ngx_shared_file_writer.h"
#include "shared_file/ngx_shared_file.h"

#define NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH 16
#define NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH_STR NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH * 2

static ngx_int_t ngx_http_vkupload_md5_variable(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_vkupload_md5_configuration(ngx_conf_t *cf);
static ngx_int_t ngx_http_vkupload_md5_handler(ngx_shared_file_writer_t *writer, ngx_buf_t *buffer);


ngx_shared_file_plugin_t ngx_http_vkupload_md5 = {
    .configuration = ngx_http_vkupload_md5_configuration,
    .handler = ngx_http_vkupload_md5_handler,
    .need_in_memory = 1,
    .name = (ngx_str_t) ngx_string("md5")
};

typedef struct {
    ngx_md5_t  md5;
    u_char     md5_str[NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH_STR];
    ngx_int_t  complete;
} ngx_http_vkupload_md5_ctx_t;


static ngx_int_t
ngx_http_vkupload_md5_configuration(ngx_conf_t *cf)
{
    ngx_http_variable_t *field;

    field = ngx_http_add_variable(cf, & (ngx_str_t) ngx_string("vkupload_file_md5"),
            NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH);

    if (field == NULL) {
        return NGX_ERROR;
    }

    field->get_handler = ngx_http_vkupload_md5_variable;
    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_md5_handler(ngx_shared_file_writer_t *writer, ngx_buf_t *buffer)
{
    ngx_http_vkupload_md5_ctx_t  *ctx;
    ngx_shared_file_t            *file = writer->file;
    u_char                        digest[NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH];

    ctx = ngx_shared_file_plugin_ctx(file, &ngx_http_vkupload_md5);
    if (ctx == NULL) {
        if (file->node->processed_size != 0) {
            return NGX_ERROR;
        }

        ctx = ngx_slab_calloc(file->manager->pool, sizeof(ngx_http_vkupload_md5_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_shared_file_plugin_set_ctx(file, &ngx_http_vkupload_md5, ctx);
        ngx_md5_init(&ctx->md5);
    }

    if (!ngx_buf_in_memory(buffer)) {
        return NGX_ERROR;
    }

    ngx_md5_update(&ctx->md5, buffer->pos, ngx_buf_size(buffer));

    if (ngx_shared_file_is_full(file)) {
        ngx_md5_final(digest, &ctx->md5);
        ngx_hex_dump(ctx->md5_str, digest, NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH_STR);

        ctx->complete = 1;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_md5_variable(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_vkupload_request_t  *vkupload;
    ngx_http_vkupload_md5_ctx_t  *ctx;

    vkupload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);

    if (vkupload == NULL || vkupload->file == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_shared_file_plugin_ctx(vkupload->file, &ngx_http_vkupload_md5);
    if (ctx == NULL || ctx->complete == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->not_found = 0;
    v->data = ctx->md5_str;
    v->len = NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH_STR;

    return NGX_OK;
}
