#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_vkupload_request.h"
#include "ngx_http_vkupload_module.h"
#include "ngx_http_vkupload_utils.h"
#include "ngx_http_vkupload_fields.h"

#define NGX_HTTP_VKUPLOAD_HANDLERS_MAX 12

static ngx_http_vkupload_handler_t  *handlers[NGX_HTTP_VKUPLOAD_HANDLERS_MAX];
static ngx_uint_t                    handlers_count;

ngx_int_t
ngx_http_vkupload_request_pass(ngx_http_vkupload_request_t *vkupload)
{
    static const ngx_str_t         content_type_header_name = ngx_string("Content-Type");
    static const ngx_str_t         urlencoded_content_type_value = ngx_string("application/x-www-form-urlencoded");

    ngx_http_vkupload_loc_conf_t  *vkupload_lconf;
    ngx_http_request_t            *request;
    ngx_http_headers_in_t         *headers_in;
    ngx_table_elt_t               *header;
    ngx_str_t                      upload_url;
    ngx_http_request_body_t       *rb;
    ngx_chain_t                   *cl;
    ngx_int_t                      rc;

    request = vkupload->request;
    headers_in = &request->headers_in;

    vkupload_lconf = ngx_http_get_module_loc_conf(request, ngx_http_vkupload_module);
    upload_url = vkupload_lconf->upload_url;

    { // update buffer for Content-Length
        headers_in->content_length->value.len = 0;
        headers_in->content_length->value.data = ngx_palloc(request->pool, NGX_OFF_T_LEN);
        if (headers_in->content_length->value.data == NULL) {
            return NGX_ERROR;
        }
    }

    { // update Content-Type
        if (headers_in->content_type == NULL) {
            headers_in->content_type = ngx_list_push(&request->headers_in.headers);
            headers_in->content_type->key = content_type_header_name;
            headers_in->content_type->hash = 1;
        }

        headers_in->content_type->value.len = urlencoded_content_type_value.len;
        headers_in->content_type->value.data = ngx_palloc(request->pool, urlencoded_content_type_value.len);
        if (headers_in->content_type->value.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(headers_in->content_type->value.data, urlencoded_content_type_value.data,
            urlencoded_content_type_value.len);
    }

    { // Add header with module version
        header = ngx_list_push(&headers_in->headers);
        if (header == NULL) {
            return NGX_ERROR;
        }

        header->hash = 1;
        header->key.len = sizeof("Upload-Module-Version") - 1;
        header->key.data = (u_char *) "Upload-Module-Version";
        header->value.len = sizeof(NGX_HTTP_VKUPLOAD_MODULE_VERSION) - 1;
        header->value.data = (u_char *) NGX_HTTP_VKUPLOAD_MODULE_VERSION;
    }

    rc = ngx_http_vkupload_request_fields_append(request);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "%s: error append fields to body", __FUNCTION__);

        return NGX_ERROR;
    }

    { // update Content-Length
        rb = request->request_body;

        headers_in->content_length_n = 0;
        for(cl = rb->bufs ; cl ; cl = cl->next) {
            headers_in->content_length_n += (cl->buf->last - cl->buf->pos);
        }

        headers_in->content_length->value.len =
            ngx_sprintf(headers_in->content_length->value.data, "%O", headers_in->content_length_n)
                - headers_in->content_length->value.data;
    }

    if (upload_url.len > 0 && upload_url.data[0] == '@') {
        rc = ngx_http_named_location(request, &upload_url);
    } else {
        rc = ngx_http_internal_redirect(request, &upload_url, &request->args);
    }

    if (rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, ngx_errno,
            "%s: error redirect complete upload to %V", __FUNCTION__, upload_url);
    }

    return rc;
}

ngx_int_t
ngx_http_vkupload_request_finalize_handler(ngx_http_vkupload_request_t *vkupload, ngx_int_t rc)
{
    return vkupload->handler->finalize(vkupload, rc);
}

void
ngx_http_vkupload_request_finalize(ngx_http_vkupload_request_t *vkupload, ngx_int_t rc)
{
    ngx_http_request_t  *request;

    request = vkupload->request;

    rc = ngx_http_vkupload_request_finalize_handler(vkupload, rc);
    if (rc == NGX_DONE) {
        rc = NGX_OK;
    }

    ngx_http_finalize_request(request, rc);
}

ngx_int_t
ngx_http_vkupload_request_handler_register(ngx_http_vkupload_handler_t *handler, ngx_conf_t *cf)
{
    ngx_int_t  rc;

    if (handlers_count >= NGX_HTTP_VKUPLOAD_HANDLERS_MAX) {
        return NGX_ERROR;
    }

    rc = handler->configuration(cf);
    if (rc != NGX_OK) {
        return rc;
    }

    handlers[handlers_count] = handler;
    ++handlers_count;

    return NGX_OK;
}

ngx_int_t
ngx_http_vkupload_request_handler_find(ngx_http_request_t *request, ngx_http_vkupload_request_t **vkupload_ptr)
{
    ngx_http_vkupload_handler_t  *handler = NULL;
    ngx_int_t                     rc;
    ngx_uint_t                    i;

    for (i = 0; i < handlers_count; i++) {
        if (handlers[i] == NULL) {
            break;
        }

        rc = handlers[i]->init(request, vkupload_ptr);
        if (rc == NGX_DECLINED) {
            continue;
        }

        if (rc != NGX_OK) {
            return rc;
        }

        handler = handlers[i];
        break;
    }

    if (handler == NULL) {
        return NGX_DECLINED;
    }

    (*vkupload_ptr)->request = request;
    (*vkupload_ptr)->handler = handler;

    return NGX_OK;
}
