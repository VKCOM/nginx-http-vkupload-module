#include <ngx_config.h>
#include <ngx_http.h>
#include <ngx_core.h>
#include <ngx_md5.h>

#include "ngx_http_vkupload_simple.h"
#include "ngx_http_vkupload_headerparser.h"
#include "ngx_http_vkupload_request.h"
#include "ngx_http_vkupload_module.h"
#include "ngx_http_vkupload_utils.h"

typedef struct {
    ngx_http_vkupload_request_t  upload;

    ngx_md5_t  md5;
    size_t     size;
} ngx_http_vkupload_simple_t;

static ngx_int_t
ngx_http_vkupload_simple_request_data_handler(ngx_http_vkupload_request_t *upload, ngx_chain_t *in)
{
    ngx_http_vkupload_simple_t  *simple_upload = (ngx_http_vkupload_simple_t *) upload;
    ngx_file_t                  *file = &simple_upload->upload.file;

    u_char  *data;
    size_t   data_len;

     for (; in; in = in->next) {
        data = in->buf->pos;
        data_len = ngx_buf_size(in->buf);

        if (ngx_write_file(file, data, data_len, file->offset) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, upload->log, ngx_errno,
                "ngx_http_vkupload_simple_request_data_handler: error write data to file");

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_md5_update(&simple_upload->md5, data, data_len);
        simple_upload->size += data_len;

        in->buf->pos = in->buf->last;
    }

    return NGX_OK;
}

static void
ngx_http_vkupload_simple_request_finish_handler(ngx_http_vkupload_request_t *upload, ngx_int_t rc)
{
    ngx_http_vkupload_simple_t  *simple_upload = (ngx_http_vkupload_simple_t *) upload;
    ngx_file_t                  *file = &simple_upload->upload.file;
    ngx_file_info_t              fi;

    if (rc != NGX_OK) {
        ngx_http_finalize_request(upload->request, rc);
        return;
    }

    if (simple_upload->size == 0) {
        ngx_log_error(NGX_LOG_WARN, upload->log, 0,
                "ngx_http_vkupload_simple_request_finish_handler: empty field data");

        ngx_http_finalize_request(upload->request, NGX_HTTP_BAD_REQUEST);
        return;
    }

    if (ngx_fd_info(file->fd, &fi) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, file->log, 0,
                "ngx_http_vkupload_simple_request_finish_handler: error get file size");

        ngx_http_finalize_request(upload->request, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    simple_upload->upload.file_info.size = ngx_file_size(&fi);
    if (simple_upload->upload.file_info.size != simple_upload->size) {
        ngx_log_error(NGX_LOG_WARN, file->log, 0,
                "ngx_http_vkupload_simple_request_finish_handler: error write all data");

        ngx_http_finalize_request(upload->request, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    ngx_md5_final(simple_upload->upload.file_info.md5, &simple_upload->md5);
    ngx_http_vkupload_request_pass(upload);
}

ngx_int_t
ngx_http_vkupload_request_simple_start(ngx_http_request_t *request)
{
    ngx_http_vkupload_loc_conf_t             *vkupload_lconf = ngx_http_get_module_loc_conf(request, ngx_http_vkupload_module);
    ngx_http_vkupload_simple_t               *simple_upload;
    ngx_str_t                                *content_disposition_header;
    ngx_str_t                                 filename, fieldname;
    ngx_http_vkupload_content_disposition_e   content_disposition = ngx_http_vkupload_content_disposition_st_unknown;
    ngx_int_t                                 rc;

    content_disposition_header = ngx_http_vkupload_header_find(request, &content_disposition_header_name);
    if (content_disposition_header == NULL) {
        return NGX_NONE;
    }

    rc = ngx_http_vkupload_headerparser_content_disposition(&content_disposition,
        &filename, &fieldname, content_disposition_header);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_simple_start: error parser Content-Disposition: %V", content_disposition_header);

        return NGX_HTTP_BAD_REQUEST;
    }

    if (content_disposition != ngx_http_vkupload_content_disposition_st_form_data &&
        content_disposition != ngx_http_vkupload_content_disposition_st_attachment)
    {
        return NGX_NONE;
    }

    if (request->headers_in.content_range != NULL) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_simple_start: not allow partial reuqest without Session-ID header");

        return NGX_HTTP_BAD_REQUEST;
    }

    simple_upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);
    if (simple_upload != NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    simple_upload = ngx_pcalloc(request->pool, sizeof(ngx_http_vkupload_simple_t));
    if (simple_upload == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(request, simple_upload, ngx_http_vkupload_module);

    simple_upload->upload.request = request;
    simple_upload->upload.log = request->connection->log;

    simple_upload->upload.cb.data = ngx_http_vkupload_simple_request_data_handler;
    simple_upload->upload.cb.finish = ngx_http_vkupload_simple_request_finish_handler;

    simple_upload->upload.file.log = request->pool->log;
    simple_upload->upload.file.fd = NGX_INVALID_FILE;

    simple_upload->upload.file_info.name = filename;
    simple_upload->upload.file_info.field = fieldname;

    ngx_md5_init(&simple_upload->md5);

    rc = ngx_create_temp_file(&simple_upload->upload.file,
        vkupload_lconf->upload_file_path, request->pool, 1, 0, vkupload_lconf->upload_file_access);
    if (rc != NGX_OK) {
        if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_EACCES) {
            ngx_log_error(NGX_LOG_WARN,  simple_upload->upload.log, ngx_errno,
                "ngx_pw_file_open: error create tmp file \"%V\"", &simple_upload->upload.file.name);
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}
