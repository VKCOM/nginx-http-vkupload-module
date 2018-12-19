#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_vkupload_request.h"
#include "ngx_http_vkupload_module.h"
#include "ngx_http_vkupload_headerparser.h"
#include "ngx_http_vkupload_utils.h"

#include "ngx_http_vkupload_multipart.h"
#include "ngx_http_vkupload_simple.h"

const ngx_str_t  content_disposition_header_name = ngx_string("Content-Disposition");
const ngx_str_t  content_range_header_name = ngx_string("Content-Range");
const ngx_str_t  content_type_header_name = ngx_string("Content-Type");
const ngx_str_t  session_id_header_name = ngx_string("Session-ID");
const ngx_str_t  urlencoded_content_type_value = ngx_string("application/x-www-form-urlencoded");

static ngx_int_t ngx_http_vkupload_request_file_path_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_vkupload_request_file_md5_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_vkupload_request_file_size_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_vkupload_request_file_name_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_vkupload_request_file_field_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data);

/* ---- Fields ----- */

typedef struct {
    ngx_str_t                 name;
    ngx_http_get_variable_pt  get_handler;
} ngx_http_vkupload_field_t;

static ngx_http_vkupload_field_t
ngx_http_vkupload_fields[] = {
    { .name = ngx_string("vkupload_file_path"), .get_handler = ngx_http_vkupload_request_file_path_field },
    { .name = ngx_string("vkupload_file_md5"), .get_handler = ngx_http_vkupload_request_file_md5_field },
    { .name = ngx_string("vkupload_file_size"), .get_handler = ngx_http_vkupload_request_file_size_field },
    { .name = ngx_string("vkupload_file_name"), .get_handler = ngx_http_vkupload_request_file_name_field },
    { .name = ngx_string("vkupload_file_field"), .get_handler = ngx_http_vkupload_request_file_field_field },
};

static ngx_int_t
ngx_http_vkupload_request_file_path_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_vkupload_request_t  *upload;

    upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);

    v->data = upload->file.name.data;
    v->len = upload->file.name.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_request_file_md5_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_vkupload_request_t  *upload;
    u_char                       *md5_str;

    upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);

    if (*upload->file_info.md5 != 0) {
        md5_str = ngx_pcalloc(request->pool, NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH_STR);
        if (md5_str == NULL) {
            return NGX_ERROR;
        }

        ngx_hex_dump(md5_str, upload->file_info.md5, NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH);

        v->data = md5_str;
        v->len = NGX_HTTP_VKUPLOAD_MD5_DIGEST_LENGTH_STR;
    } else {
        v->data = (u_char *) "";
        v->len = 0;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_vkupload_request_file_size_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_vkupload_request_t  *upload;
    u_char                       *size_str;

    upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);

    size_str = ngx_pcalloc(request->pool, NGX_OFF_T_LEN);
    if (size_str == NULL) {
        return NGX_ERROR;
    }

    v->data = size_str;
    v->len = ngx_sprintf(size_str, "%O", upload->file_info.size) - size_str;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_request_file_name_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_vkupload_request_t  *upload;

    upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);

    v->data = upload->file_info.name.data;
    v->len = upload->file_info.name.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_request_file_field_field(ngx_http_request_t *request, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_vkupload_request_t  *upload;

    upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);

    v->data = upload->file_info.field.data;
    v->len = upload->file_info.field.len;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_request_fields_append(ngx_http_request_t *request)
{
    ngx_str_t                        field_name, field_value;
    ngx_http_vkupload_field_conf_t  *upload_fields;
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


/* ---- Request ---- */

static void
ngx_http_vkupload_request_read_event_handler(ngx_http_request_t *request)
{
    ngx_http_vkupload_request_t  *upload;
    ngx_http_request_body_t      *request_body;
    ngx_int_t                     rc;
    ngx_int_t                     rc_data;

    upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);
    request_body = request->request_body;

    if (ngx_exiting || ngx_terminate) {
        upload->cb.finish(upload, NGX_HTTP_CLOSE);
        return;
    }

     for ( ;; ) {
        rc = ngx_http_read_unbuffered_request_body(request);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            upload->cb.finish(upload, rc);
            return;
        }

        if (request_body->bufs == NULL) {
            return;
        }

        rc_data = upload->cb.data(upload, request_body->bufs);
        if (rc_data != NGX_OK) {
            upload->cb.finish(upload, rc_data);
            return;
        }

        if (rc == NGX_OK) {
            upload->cb.finish(upload, NGX_OK);
            return;
        }

        request_body->bufs = NULL;
    }
}

static void
ngx_http_vkupload_request_body_handler(ngx_http_request_t *request)
{
    ngx_http_vkupload_request_t  *upload;
    ngx_http_request_body_t      *request_body;
    ngx_int_t                     rc;

    upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);
    if (upload == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto error;
    }

    request_body = request->request_body;
    if (request_body == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto error;
    }

    rc = upload->cb.data(upload, request_body->bufs);
    if (rc != NGX_OK) {
        goto error;
    }

    if (request->reading_body) {
        request->read_event_handler = ngx_http_vkupload_request_read_event_handler;
    } else {
        upload->cb.finish(upload, NGX_OK);
    }

    return;

error:
    upload->cb.finish(upload, rc);
}

static ngx_int_t
ngx_http_vkupload_request_start_options(ngx_http_request_t *request)
{
    request->headers_out.status = NGX_HTTP_OK;
    request->header_only = 1;
    request->headers_out.content_length_n = 0;
    request->allow_ranges = 0;

    return ngx_http_send_header(request);
}

ngx_int_t
ngx_http_vkupload_request_handler(ngx_http_request_t *request)
{
    ngx_int_t  rc;

    if (request->method & NGX_HTTP_OPTIONS) {
        return ngx_http_vkupload_request_start_options(request);
    }

    if (!(request->method & NGX_HTTP_POST)) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_handler: invalid request, allowed only POST or OPTIONS request");
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (request->headers_in.chunked) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_handler: invalid request, not allowed chunked request");
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (request->headers_in.content_length_n <= 0) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_handler: invalid request, not allowed request without Content-Length or empty body");
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_vkupload_request_multipart_start(request);
    if (rc == NGX_NONE) {
        rc = ngx_http_vkupload_request_simple_start(request);
    }

    if (rc != NGX_OK) {
        if (rc != NGX_NONE) {
            return rc;
        }

        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "ngx_http_vkupload_request_handler: unknown upload type request");
        return NGX_HTTP_NOT_ALLOWED;
    }

    request->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(request, ngx_http_vkupload_request_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

void
ngx_http_vkupload_request_pass(ngx_http_vkupload_request_t *upload)
{
    ngx_http_request_t       *request = upload->request;
    ngx_http_request_body_t  *rb;
    ngx_chain_t              *cl;
    ngx_int_t                 rc;
    ngx_table_elt_t          *header;

    ngx_http_vkupload_loc_conf_t  *vkupload_lconf;
    ngx_str_t                      upload_url;

    vkupload_lconf = ngx_http_get_module_loc_conf(request, ngx_http_vkupload_module);
    upload_url = vkupload_lconf->upload_url;

    rc = ngx_http_vkupload_header_remove(&request->headers_in.headers, &content_range_header_name);
     if (rc != NGX_OK) {
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rc = ngx_http_vkupload_header_remove(&request->headers_in.headers, &content_disposition_header_name);
     if (rc != NGX_OK) {
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    { // update buffer for Content-Length
        request->headers_in.content_length->value.len = 0;
        request->headers_in.content_length->value.data = ngx_palloc(request->pool, NGX_OFF_T_LEN);
        if (request->headers_in.content_length->value.data == NULL) {
            ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    { // update Content-Type
        if (request->headers_in.content_type == NULL) {
            request->headers_in.content_type = ngx_list_push(&request->headers_in.headers);
            request->headers_in.content_type->key = content_type_header_name;
            request->headers_in.content_type->hash = 1;
        }

        request->headers_in.content_type->value.len = urlencoded_content_type_value.len;
        request->headers_in.content_type->value.data = ngx_palloc(request->pool, urlencoded_content_type_value.len);
        if (request->headers_in.content_type->value.data == NULL) {
            ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memcpy(request->headers_in.content_type->value.data, urlencoded_content_type_value.data, urlencoded_content_type_value.len);
    }

    rc = ngx_http_vkupload_request_fields_append(request);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_pass: error append fields to body");

        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    {
        // Add header with module version
        header = ngx_list_push(&request->headers_in.headers);
        if (header == NULL) {
            ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        header->hash = 1;
        header->key.len = sizeof("Upload-Module-Version") - 1;
        header->key.data = (u_char *) "Upload-Module-Version";
        header->value.len = sizeof(NGX_HTTP_VKUPLOAD_MODULE_VERSION) - 1;
        header->value.data = (u_char *) NGX_HTTP_VKUPLOAD_MODULE_VERSION;
    }

    {
        rb = request->request_body;

        request->headers_in.content_length_n = 0;
        for(cl = rb->bufs ; cl ; cl = cl->next) {
            request->headers_in.content_length_n += (cl->buf->last - cl->buf->pos);
        }

        request->headers_in.content_length->value.len =
            ngx_sprintf(request->headers_in.content_length->value.data, "%O", request->headers_in.content_length_n)
                - request->headers_in.content_length->value.data;
    }

    if (upload_url.len > 0 && upload_url.data[0] == '@') {
        rc = ngx_http_named_location(request, &upload_url);
    } else {
        rc = ngx_http_internal_redirect(request, &upload_url, &request->args);
    }

    if (rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, ngx_errno,
            "ngx_http_vkupload_request_pass: error redirect complete upload to %V", upload_url);
    }

    ngx_http_finalize_request(request, rc);
}
