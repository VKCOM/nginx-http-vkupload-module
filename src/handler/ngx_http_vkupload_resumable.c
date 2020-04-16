#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_vkupload_resumable.h"
#include "ngx_http_vkupload_request.h"
#include "ngx_http_vkupload_module.h"
#include "ngx_http_vkupload_utils.h"

#include "parser/ngx_http_vkupload_headerparser.h"

#include "shared_file/ngx_shared_file.h"
#include "shared_file/ngx_shared_file_writer.h"

static ngx_int_t  ngx_http_vkupload_resumable_handler_conf(ngx_conf_t *cf);
static ngx_int_t  ngx_http_vkupload_resumable_handler_init(ngx_http_request_t *request, ngx_http_vkupload_request_t **vkupload_ptr);
static ngx_int_t  ngx_http_vkupload_resumable_handler_finalize(ngx_http_vkupload_request_t *vkupload, ngx_int_t rc);
static ngx_int_t  ngx_http_vkupload_resumable_handler_data(ngx_http_vkupload_request_t *vkupload, ngx_chain_t *in);

typedef struct {
    ngx_shared_file_writer_t  *writer;

    ngx_str_t                  filename;
    ngx_str_t                  fieldname;
} ngx_http_vkupload_resumable_t;

ngx_http_vkupload_handler_t ngx_http_vkupload_resumable_handler = {
    .configuration = ngx_http_vkupload_resumable_handler_conf,
    .init = ngx_http_vkupload_resumable_handler_init,
    .finalize = ngx_http_vkupload_resumable_handler_finalize,
    .data = ngx_http_vkupload_resumable_handler_data,
};

static ngx_int_t
ngx_http_vkupload_resumable_handler_conf(ngx_conf_t *cf)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_resumable_handler_init(ngx_http_request_t *request, ngx_http_vkupload_request_t **vkupload_ptr)
{
    ngx_str_t                         *content_disposition_header, *session_id_header, *content_range_header;
    ngx_str_t                          filename, fieldname, session_id;
    ngx_int_t                          rc;

    ngx_http_vkupload_loc_conf_t      *vkupload_lconf;
    ngx_http_vkupload_request_t       *vkupload;
    ngx_http_vkupload_resumable_t     *resumable;

    ngx_http_vkupload_content_disposition_e  content_disposition;
    ngx_http_vkupload_content_range_t        range;

    ngx_str_null(&filename);
    ngx_str_null(&fieldname);
    ngx_str_null(&session_id);

    ngx_memzero(&range, sizeof(ngx_http_vkupload_content_range_t));
    content_disposition = ngx_http_vkupload_content_disposition_st_unknown;

    vkupload_lconf = ngx_http_get_module_loc_conf(request, ngx_http_vkupload_module);

    if (!(request->method & NGX_HTTP_POST)) {
        return NGX_DECLINED;
    }

    content_disposition_header = ngx_http_vkupload_header_find(request, & (ngx_str_t) ngx_string("content-disposition"));
    if (content_disposition_header == NULL) {
        return NGX_DECLINED;
    }

    rc = ngx_http_vkupload_headerparser_content_disposition(&content_disposition,
        &filename, &fieldname, content_disposition_header);
    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (content_disposition != ngx_http_vkupload_content_disposition_st_attachment) {
        return NGX_DECLINED;
    }

    if (request->headers_in.chunked) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (request->headers_in.content_length_n <= 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    session_id_header = ngx_http_vkupload_header_find(request, & (ngx_str_t) ngx_string("session-id"));
    if (session_id_header) {
        rc = ngx_http_vkupload_headerparser_session_id(&session_id, session_id_header);
        if (rc != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }

        // TODO: complex value
    }

    content_range_header = ngx_http_vkupload_header_find(request, & (ngx_str_t) ngx_string("content-range"));
    if (content_range_header) {
        rc = ngx_http_vkupload_headerparser_content_range(&range, content_range_header);
        if (rc != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }

        if (session_id.len == 0) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "%s: partial data without session-id header", __FUNCTION__);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (((range.end - range.start) + 1) != (size_t) request->headers_in.content_length_n) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "%s: incorrect range %uz-%uz/%uz with Content-Length: %z", __FUNCTION__,
                range.start, range.end, range.total, request->headers_in.content_length_n);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (range.total && ((size_t) request->headers_in.content_length_n > range.total)) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "%s: incorrect total in range %uz-%uz/%uz with Content-Length: %z", __FUNCTION__,
                range.start, range.end, range.total, request->headers_in.content_length_n);
            return NGX_HTTP_BAD_REQUEST;
        }
    } else {
        range.start = 0;
        range.end = request->headers_in.content_length_n - 1;
        range.total = request->headers_in.content_length_n;
    }

    vkupload = ngx_pcalloc(request->pool, sizeof(ngx_http_vkupload_request_t) + sizeof(ngx_http_vkupload_resumable_t));
    if (vkupload == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    resumable = (ngx_http_vkupload_resumable_t *) vkupload->ctx;

    resumable->filename = filename;
    resumable->fieldname = fieldname;

    vkupload->file = ngx_pcalloc(request->pool, sizeof(ngx_shared_file_t));
    if (vkupload->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    vkupload->file->pool = request->pool;
    vkupload->file->log = request->connection->log;
    vkupload->file->manager = vkupload_lconf->manager;

    rc = ngx_shared_file_open(vkupload->file, session_id.len ? &session_id : NULL);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_shared_file_set_total(vkupload->file, range.total, range.start, (range.end - range.start + 1));
    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    resumable->writer = ngx_pcalloc(request->pool, sizeof(ngx_shared_file_writer_t));
    if (resumable->writer == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    resumable->writer->file = vkupload->file;

    rc = ngx_shared_file_writer_open(resumable->writer, range.start, (range.end - range.start + 1));
    if (rc != NGX_OK) {
        return rc;
    }

    *vkupload_ptr = vkupload;
    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_resumable_handler_finalize(ngx_http_vkupload_request_t *vkupload, ngx_int_t rc)
{
    ngx_http_request_t                *request;
    ngx_http_vkupload_resumable_t     *resumable;
    ngx_str_t                          partial_response;
    ngx_table_elt_t                   *header;
    ngx_buf_t                         *b;
    ngx_chain_t                        out;

    request = vkupload->request;
    resumable = (ngx_http_vkupload_resumable_t *) vkupload->ctx;

    ngx_shared_file_writer_close(resumable->writer);
    resumable->writer = NULL;

    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_shared_file_complete_if_uploaded(vkupload->file) != NGX_OK) {
        rc = ngx_shared_file_parts_to_string(request->pool, &partial_response, &vkupload->file->node->parts,
            vkupload->file->node->linar_size, vkupload->file->node->total_size, vkupload->file->node->total_known);
        if (rc != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        header = ngx_list_push(&request->headers_out.headers);
        if (header == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        header->hash = 1;
        header->key = (ngx_str_t) ngx_string("Range");
        header->value = partial_response;

        request->headers_out.status = NGX_HTTP_CREATED;
        request->headers_out.content_length_n = partial_response.len;

        rc = ngx_http_send_header(request);
        if (rc == NGX_ERROR || rc > NGX_OK || request->header_only) {
            return rc;
        }

        b = ngx_calloc_buf(request->pool);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        out.buf = b;
        out.next = NULL;

        b->start = b->pos = partial_response.data;
        b->end = b->last = partial_response.data + partial_response.len;
        b->memory = 1;
        b->last_buf = 1;
        b->last_in_chain = 1;

        return ngx_http_output_filter(request, &out);
    }

    vkupload->variables.path = vkupload->file->node->path;
    vkupload->variables.name = resumable->filename;
    vkupload->variables.size = vkupload->file->node->total_size;

    rc = ngx_http_vkupload_header_remove(&request->headers_in.headers, & (ngx_str_t) ngx_string("content-disposition"));
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_vkupload_header_remove(&request->headers_in.headers, & (ngx_str_t) ngx_string("content-range"));
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_vkupload_header_remove(&request->headers_in.headers, & (ngx_str_t) ngx_string("session-id"));
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_vkupload_request_pass(vkupload);
}

static ngx_int_t
ngx_http_vkupload_resumable_handler_data(ngx_http_vkupload_request_t *vkupload, ngx_chain_t *in)
{
    ngx_http_vkupload_resumable_t  *resumable;
    ngx_int_t                       rc;

    resumable = (ngx_http_vkupload_resumable_t *) vkupload->ctx;

    for (; in; in = in->next) {
        rc = ngx_shared_file_write(resumable->writer, in->buf->pos, ngx_buf_size(in->buf));
        if (rc != NGX_OK) {
            return rc;
        }

        in->buf->pos = in->buf->last;
    }

    return NGX_OK;
}
