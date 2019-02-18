#include <ngx_config.h>
#include <ngx_http.h>
#include <ngx_core.h>

#include "ngx_http_vkupload_resumable.h"
#include "ngx_http_vkupload_module.h"
#include "ngx_http_vkupload_request.h"
#include "ngx_http_vkupload_utils.h"
#include "ngx_http_vkupload_headerparser.h"
#include "ngx_shared_file.h"

typedef struct {
    ngx_http_vkupload_request_t   upload;
    ngx_shared_file_session_t    *session;
} ngx_http_vkupload_resumable_t;

static ngx_int_t
ngx_http_vkupload_resumable_request_data_handler(ngx_http_vkupload_request_t *upload, ngx_chain_t *in)
{
    ngx_http_vkupload_resumable_t  *resumable_upload = (ngx_http_vkupload_resumable_t *) upload;
    ngx_int_t                       rc;

    for (; in; in = in->next) {
        rc = ngx_shared_file_write(resumable_upload->session, in->buf->pos, ngx_buf_size(in->buf));
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, upload->log, 0,
                "ngx_http_vkupload_resumable_request_data_handler: error on process data body");

            return rc;
        }

        in->buf->pos = in->buf->last;
    }

    return NGX_OK;
}

static void
ngx_http_vkupload_resumable_request_finish_handler(ngx_http_vkupload_request_t *upload, ngx_int_t request_status)
{
    ngx_http_vkupload_resumable_t  *resumable_upload = (ngx_http_vkupload_resumable_t *) upload;
    ngx_str_t                       ranges;
    ngx_int_t                       rc;
    ngx_table_elt_t                *content_range_header;
    ngx_buf_t                      *b;
    ngx_chain_t                     out;

    ngx_shared_file_close(resumable_upload->session);

    rc = ngx_shared_file_session_md5_calc(resumable_upload->session);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, upload->log, 0,
            "ngx_http_vkupload_resumable_request_finish_handler: error calc md5");

        ngx_http_finalize_request(upload->request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (request_status != NGX_OK) {
        ngx_http_finalize_request(upload->request, rc);
        return;
    }

    if (ngx_shared_file_is_completed(resumable_upload->session)) {
        resumable_upload->upload.file_info.size = ngx_shared_file_get_total_size(resumable_upload->session);
        ngx_shared_file_md5_final(resumable_upload->session, resumable_upload->upload.file_info.md5);

        ngx_shared_file_remove(resumable_upload->session);
        ngx_http_vkupload_request_pass(upload);
        return;
    }

    rc = ngx_shared_file_get_ranges(resumable_upload->session, &ranges);
    if (rc != NGX_OK || ranges.len == 0) {
        ngx_log_error(NGX_LOG_WARN, upload->log, 0,
            "ngx_http_vkupload_resumable_request_finish_handler: error build ranges for partial response");

        ngx_http_finalize_request(upload->request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    upload->request->headers_out.status = NGX_HTTP_CREATED;
    upload->request->headers_out.content_length_n = ranges.len;

    content_range_header = ngx_list_push(&upload->request->headers_out.headers);
    if (content_range_header == NULL) {
        ngx_http_finalize_request(upload->request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    content_range_header->hash = 1;
    content_range_header->key = (ngx_str_t) ngx_string("Range");
    content_range_header->value = ranges;

    rc = ngx_http_send_header(upload->request);
    if (rc == NGX_ERROR || rc > NGX_OK || upload->request->header_only) {
        ngx_http_finalize_request(upload->request, rc);
        return;
    }

    b = ngx_calloc_buf(upload->request->pool);
    if (b == NULL) {
        ngx_http_finalize_request(upload->request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    out.buf = b;
    out.next = NULL;

    b->start = b->pos = ranges.data;
    b->end = b->last = ranges.data + ranges.len;
    b->memory = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    ngx_http_finalize_request(upload->request, ngx_http_output_filter(upload->request, &out));
}

ngx_int_t
ngx_http_vkupload_request_resumable_start(ngx_http_request_t *request)
{
    ngx_http_vkupload_loc_conf_t            *vkupload_lconf = ngx_http_get_module_loc_conf(request, ngx_http_vkupload_module);
    ngx_http_vkupload_resumable_t           *resumable_upload;
    ngx_shared_file_session_t               *session;
    ngx_shared_file_manager_t               *manager = vkupload_lconf->resumable_session_shmem->data;
    
    ngx_str_t                               *session_id_header, *content_disposition_header;
    ngx_str_t                                session_id, filename, fieldname;
    ngx_int_t                                rc;

    ngx_http_vkupload_content_range_t        range;
    ngx_http_vkupload_content_disposition_e  content_disposition;

    content_disposition_header = ngx_http_vkupload_header_find(request, &content_disposition_header_name);
    if (content_disposition_header == NULL) {
        return NGX_NONE;
    }

    rc = ngx_http_vkupload_headerparser_content_disposition(&content_disposition,
        &filename, &fieldname, content_disposition_header);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_resumable_start: error parser Content-Disposition: %V", content_disposition_header);

        return NGX_HTTP_BAD_REQUEST;
    }

    if (content_disposition != ngx_http_vkupload_content_disposition_st_form_data &&
        content_disposition != ngx_http_vkupload_content_disposition_st_attachment)
    {
        return NGX_NONE;
    }

    session_id_header = ngx_http_vkupload_header_find(request, &session_id_header_name);
    if (session_id_header == NULL) {
        return NGX_NONE;
    }

    rc = ngx_http_vkupload_headerparser_session_id(&session_id, session_id_header);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_resumable_start: error parse header Session-ID: %V", session_id_header);
        return NGX_HTTP_BAD_REQUEST;
    }

    if (request->headers_in.content_length_n == 0) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "ngx_http_vkupload_request_resumable_start: not allow empty body");

        return NGX_HTTP_BAD_REQUEST;
    }

    if (request->headers_in.content_range != NULL) {
        rc = ngx_http_vkupload_headerparser_content_range(&range, &request->headers_in.content_range->value);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "ngx_http_vkupload_request_resumable_start: error parse header Content-Range: %V", &request->headers_in.content_range->value);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (((range.end - range.start) + 1) != (size_t) request->headers_in.content_length_n) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "ngx_http_vkupload_request_resumable_start: incorrect range %uz-%uz/%uz with Content-Length: %z",
                range.start, range.end, range.total, request->headers_in.content_length_n);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (range.total && ((size_t) request->headers_in.content_length_n > range.total)) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "ngx_http_vkupload_request_resumable_start: incorrect total in range %uz-%uz/%uz with Content-Length: %z",
                range.start, range.end, range.total, request->headers_in.content_length_n);
            return NGX_HTTP_BAD_REQUEST;
        }
    } else {
        range.start = 0;
        range.end = request->headers_in.content_length_n - 1;
        range.total = request->headers_in.content_length_n;
    }

    resumable_upload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);
    if (resumable_upload != NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    resumable_upload = ngx_pcalloc(request->pool, sizeof(ngx_http_vkupload_resumable_t));
    if (resumable_upload == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(request, resumable_upload, ngx_http_vkupload_module);

    resumable_upload->upload.request = request;
    resumable_upload->upload.log = request->connection->log;

    resumable_upload->upload.file_info.name = filename;
    resumable_upload->upload.file_info.field = fieldname;

    resumable_upload->upload.cb.data = ngx_http_vkupload_resumable_request_data_handler;
    resumable_upload->upload.cb.finish = ngx_http_vkupload_resumable_request_finish_handler;

    session = ngx_pcalloc(request->pool, sizeof(ngx_shared_file_session_t));
    if (session == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    session->pool = request->pool;
    session->log = request->connection->log;
    session->file = &resumable_upload->upload.file;
    session->manager = manager;

    rc = ngx_shared_file_open(session, &session_id, range.total, range.start, range.end);
    if (rc != NGX_OK) {
        return rc;
    }

    resumable_upload->session = session;
    return NGX_OK;
}
