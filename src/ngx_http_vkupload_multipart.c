#include <ngx_config.h>
#include <ngx_http.h>
#include <ngx_core.h>
#include <ngx_md5.h>

#include "ngx_http_vkupload_multipart.h"
#include "ngx_http_vkupload_multipartparser.h"
#include "ngx_http_vkupload_headerparser.h"
#include "ngx_http_vkupload_request.h"
#include "ngx_http_vkupload_module.h"

typedef struct {
    ngx_http_vkupload_request_t  upload;

    ngx_http_vkupload_multipartparser_t            *parser;
    ngx_http_vkupload_multipartparser_callbacks_t  *parser_callbacks;

    ngx_str_t  boundary;
    ngx_md5_t  md5;

    size_t     size;
} ngx_http_vkupload_multipart_t;

static ngx_int_t
ngx_http_vkupload_multipart_request_data_handler(ngx_http_vkupload_request_t *upload, ngx_chain_t *in)
{
    ngx_http_vkupload_multipart_t  *multipart_upload = (ngx_http_vkupload_multipart_t *) upload;
    ngx_int_t                       rc = NGX_OK;

    multipart_upload = ngx_http_get_module_ctx(upload->request, ngx_http_vkupload_module);

    for (; in; in = in->next) {
        rc = ngx_http_vkupload_multipartparser_execute(multipart_upload->parser, multipart_upload->parser_callbacks, in->buf);

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, upload->log, 0,
                "ngx_http_vkupload_process_request_body: error on process data body");

            return rc;
        }
    }

    return rc;
}

static void
ngx_http_vkupload_multipart_request_finish_handler(ngx_http_vkupload_request_t *upload, ngx_int_t rc)
{
    ngx_http_vkupload_multipart_t  *multipart_upload = (ngx_http_vkupload_multipart_t *) upload;

    if (rc != NGX_OK) {
        ngx_http_finalize_request(upload->request, rc);
        return;
    }

    if (multipart_upload->size == 0) {
        ngx_log_error(NGX_LOG_WARN, upload->log, 0,
                "ngx_http_vkupload_multipart_request_finish_handler: empty field data");

        ngx_http_finalize_request(upload->request, NGX_HTTP_BAD_REQUEST);
        return;
    }

    ngx_http_vkupload_request_pass(upload);
}

static ngx_int_t
ngx_http_vkupload_multipart_parser_data_handler(ngx_http_vkupload_multipartparser_t *parser, const ngx_str_t *data)
{
    ngx_http_vkupload_multipart_t  *multipart_upload = parser->data;
    ngx_file_t                     *file = &multipart_upload->upload.file;

    if (ngx_write_file(file, data->data, data->len, file->offset) == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_md5_update(&multipart_upload->md5, data->data, data->len);
    multipart_upload->size += data->len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_multipart_parser_finish_handler(ngx_http_vkupload_multipartparser_t *parser)
{
    ngx_http_vkupload_multipart_t  *multipart_upload = parser->data;
    ngx_file_t                     *file = &multipart_upload->upload.file;
    ngx_file_info_t                 fi;

    multipart_upload->parser_callbacks->on_data = NULL;
    multipart_upload->parser_callbacks->on_part_end = NULL;

    if (ngx_fd_info(file->fd, &fi) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, file->log, 0,
                "ngx_http_vkupload_multipart_parser_finish_handler: error get file size");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    multipart_upload->upload.file_info.size = ngx_file_size(&fi);
    if (multipart_upload->upload.file_info.size != multipart_upload->size) {
        ngx_log_error(NGX_LOG_WARN, file->log, 0,
                "ngx_http_vkupload_multipart_parser_finish_handler: error write all data");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (multipart_upload->size) {
        ngx_md5_final(multipart_upload->upload.file_info.md5, &multipart_upload->md5);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_multipart_parser_header_handler(ngx_http_vkupload_multipartparser_t *parser,
    const ngx_str_t *name, const ngx_str_t *value)
{
    ngx_http_vkupload_multipart_t  *multipart_upload = parser->data;
    ngx_http_request_t             *request = multipart_upload->upload.request;
    ngx_http_vkupload_loc_conf_t   *vkupload_lconf = ngx_http_get_module_loc_conf(request, ngx_http_vkupload_module);

    ngx_int_t  rc;
    ngx_uint_t i;

    ngx_http_vkupload_content_disposition_e content_disposition;

    ngx_str_t   filename;
    ngx_str_t   fieldname;
    ngx_str_t  *multipart_fields;

    if (!str_equal(name->data, name->len, "content-disposition")) {
        return NGX_OK;
    }

    rc = ngx_http_vkupload_headerparser_content_disposition(&content_disposition, &filename, &fieldname, value);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, multipart_upload->upload.log, 0,
            "ngx_http_vkupload_multipart_header: error parse header %V: %V", name, value);
        return rc;
    }

    if ((content_disposition != ngx_http_vkupload_content_disposition_st_form_data &&
        content_disposition != ngx_http_vkupload_content_disposition_st_attachment))
    {
        return NGX_OK;
    }

    multipart_fields = vkupload_lconf->multipart_fields->elts;

    for (i = 0; i < vkupload_lconf->multipart_fields->nelts; i++) {
        if (multipart_fields[i].len != fieldname.len ||
            ngx_strncasecmp(multipart_fields[i].data, fieldname.data, fieldname.len) != 0)
        {
            continue;
        }

        if (filename.len) {
            multipart_upload->upload.file_info.name.data = ngx_pstrdup(request->pool, &filename);
            multipart_upload->upload.file_info.name.len = filename.len;
        }

        if (fieldname.len) {
            multipart_upload->upload.file_info.field.data = ngx_pstrdup(request->pool, &fieldname);
            multipart_upload->upload.file_info.field.len = fieldname.len;
        }

        multipart_upload->parser_callbacks->on_header = NULL;
        multipart_upload->parser_callbacks->on_part_end = ngx_http_vkupload_multipart_parser_finish_handler;
        multipart_upload->parser_callbacks->on_data = ngx_http_vkupload_multipart_parser_data_handler;

        multipart_upload->upload.file.log = request->pool->log;
        multipart_upload->upload.file.fd = NGX_INVALID_FILE;

        rc = ngx_create_temp_file(&multipart_upload->upload.file,
            vkupload_lconf->upload_file_path, request->pool, 1, 0, vkupload_lconf->upload_file_access);
        if (rc != NGX_OK) {
            if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_EACCES) {
                ngx_log_error(NGX_LOG_WARN,  multipart_upload->upload.file.log, ngx_errno,
                    "ngx_pw_file_open: error create tmp file \"%V\"", &multipart_upload->upload.file.name);
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, multipart_upload->upload.log, 0,
        "ngx_http_vkupload_multipart_header: unknown multipart field %V", value);

    return NGX_OK;
}

ngx_int_t
ngx_http_vkupload_request_multipart_start(ngx_http_request_t *request)
{
    ngx_http_vkupload_loc_conf_t      *vkupload_lconf = ngx_http_get_module_loc_conf(request, ngx_http_vkupload_module);
    ngx_http_vkupload_multipart_t     *multipart_upload;
    ngx_int_t                          rc;
    ngx_str_t                          boundary;
    ngx_http_vkupload_content_type_e   content_type = ngx_http_vkupload_content_type_st_unknown;

    if (request->headers_in.content_type == NULL) {
        return NGX_NONE;
    }

    rc = ngx_http_vkupload_headerparser_content_type(&content_type,
        &boundary, &request->headers_in.content_type->value);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_raw_start: invalid header Content-Type: %V", &request->headers_in.content_type->value);

        return rc;
    }

    if (content_type != ngx_http_vkupload_content_type_st_multipart) {
        return NGX_NONE;
    }

    if (boundary.len == 0) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_handler: missed boundary field in Content-Type: multipart/form-data");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (!vkupload_lconf->multipart) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_handler: multipart requests not enabled");
        return NGX_HTTP_NOT_ALLOWED;
    }

    multipart_upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);
    if (multipart_upload != NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    multipart_upload = ngx_pcalloc(request->pool, sizeof(ngx_http_vkupload_multipart_t));
    if (multipart_upload == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(request, multipart_upload, ngx_http_vkupload_module);

    multipart_upload->upload.request = request;
    multipart_upload->upload.log = request->connection->log;

    multipart_upload->upload.cb.data = ngx_http_vkupload_multipart_request_data_handler;
    multipart_upload->upload.cb.finish = ngx_http_vkupload_multipart_request_finish_handler;

    multipart_upload->parser = ngx_pcalloc(request->pool, sizeof(ngx_http_vkupload_multipartparser_t));
    if (multipart_upload->parser == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    multipart_upload->parser_callbacks = ngx_pcalloc(request->pool, sizeof(ngx_http_vkupload_multipartparser_callbacks_t));
    if (multipart_upload->parser_callbacks == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    multipart_upload->boundary = boundary;
    ngx_http_vkupload_multipartparser_init(multipart_upload->parser, &multipart_upload->boundary);

    multipart_upload->parser->data = multipart_upload;
    multipart_upload->parser_callbacks->on_header = ngx_http_vkupload_multipart_parser_header_handler;

    multipart_upload->upload.file.log = request->pool->log;
    multipart_upload->upload.file.fd = NGX_INVALID_FILE;

    ngx_md5_init(&multipart_upload->md5);

    return NGX_OK;
}
