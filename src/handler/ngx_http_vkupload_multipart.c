#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_vkupload_multipart.h"
#include "ngx_http_vkupload_request.h"
#include "ngx_http_vkupload_module.h"

#include "parser/ngx_http_vkupload_headerparser.h"
#include "parser/ngx_http_vkupload_multipartparser.h"

#include "shared_file/ngx_shared_file.h"
#include "shared_file/ngx_shared_file_writer.h"

static ngx_int_t  ngx_http_vkupload_multipart_handler_conf(ngx_conf_t *cf);
static ngx_int_t  ngx_http_vkupload_multipart_handler_init(ngx_http_request_t *request, ngx_http_vkupload_request_t **vkupload_ptr);
static ngx_int_t  ngx_http_vkupload_multipart_handler_finalize(ngx_http_vkupload_request_t *vkupload, ngx_int_t rc);
static ngx_int_t  ngx_http_vkupload_multipart_handler_data(ngx_http_vkupload_request_t *vkupload, ngx_chain_t *in);

static ngx_int_t  ngx_http_vkupload_multipart_parser_header_handler(ngx_http_vkupload_multipartparser_t *parser,
    const ngx_str_t *name, const ngx_str_t *value);
static ngx_int_t  ngx_http_vkupload_multipart_parser_data_handler(ngx_http_vkupload_multipartparser_t *parser,
    const ngx_str_t *data);
static ngx_int_t  ngx_http_vkupload_multipart_parser_finish_handler(ngx_http_vkupload_multipartparser_t *parser);

typedef struct {
    ngx_http_vkupload_multipartparser_t             parser;
    ngx_http_vkupload_multipartparser_callbacks_t   callbacks;

    ngx_shared_file_writer_t                       *writer;

    size_t                                          size;
    ngx_str_t                                       filename;
    ngx_str_t                                       fieldname;
} ngx_http_vkupload_multipart_t;

ngx_http_vkupload_handler_t ngx_http_vkupload_multipart_handler = {
    .configuration = ngx_http_vkupload_multipart_handler_conf,
    .init = ngx_http_vkupload_multipart_handler_init,
    .finalize = ngx_http_vkupload_multipart_handler_finalize,
    .data = ngx_http_vkupload_multipart_handler_data,
};

static ngx_int_t
ngx_http_vkupload_multipart_handler_conf(ngx_conf_t *cf)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_multipart_handler_init(ngx_http_request_t *request, ngx_http_vkupload_request_t **vkupload_ptr)
{
    ngx_http_vkupload_request_t       *vkupload;
    ngx_http_vkupload_multipart_t     *multipart;
    ngx_http_vkupload_content_type_e   content_type;
    ngx_str_t                          boundary;
    ngx_int_t                          rc;

    if (!(request->method & NGX_HTTP_POST)) {
        return NGX_DECLINED;
    }

    if (request->headers_in.content_type == NULL) {
        return NGX_DECLINED;
    }

    rc = ngx_http_vkupload_headerparser_content_type(&content_type,
        &boundary, &request->headers_in.content_type->value);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "%s: invalid header Content-Type: %V",__FUNCTION__, &request->headers_in.content_type->value);

        return NGX_HTTP_BAD_REQUEST;
    }

    if (content_type != ngx_http_vkupload_content_type_st_multipart) {
        return NGX_DECLINED;
    }

    if (boundary.len == 0) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "%s: missed boundary field in Content-Type: multipart/form-data", __FUNCTION__);

        return NGX_HTTP_BAD_REQUEST;
    }

    if (request->headers_in.chunked) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (request->headers_in.content_length_n <= 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    vkupload = ngx_pcalloc(request->pool, sizeof(ngx_http_vkupload_request_t) + sizeof(ngx_http_vkupload_multipart_t));
    if (vkupload == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    multipart = (ngx_http_vkupload_multipart_t *) vkupload->ctx;

    ngx_http_vkupload_multipartparser_init(&multipart->parser, &boundary);

    multipart->parser.data = vkupload;
    multipart->callbacks.on_header = ngx_http_vkupload_multipart_parser_header_handler;

    *vkupload_ptr = vkupload;
    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_multipart_handler_finalize(ngx_http_vkupload_request_t *vkupload, ngx_int_t rc)
{
    ngx_http_request_t                *request;
    ngx_http_vkupload_multipart_t     *multipart;

    request = vkupload->request;
    multipart = (ngx_http_vkupload_multipart_t *) vkupload->ctx;

    if (multipart->writer) {
        goto error;
    }

    if (rc != NGX_OK) {
        goto error;
    }

    if (vkupload->file == NULL || multipart->size == 0) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "%s: empty field data", __FUNCTION__);

        goto error;
    }

    if (ngx_shared_file_complete_if_uploaded(vkupload->file) != NGX_OK) {
        goto error;
    }

    vkupload->variables.path = vkupload->file->node->path;
    vkupload->variables.name = multipart->filename;
    vkupload->variables.size = multipart->size;

    return ngx_http_vkupload_request_pass(vkupload);

error:
    if (multipart->writer) {
        ngx_shared_file_writer_close(multipart->writer);
        multipart->writer = NULL;
    }

    if (vkupload->file && vkupload->file->node) {
        vkupload->file->node->error = 1;

        ngx_shared_file_close(vkupload->file);
        vkupload->file = NULL;
    }


    return NGX_HTTP_BAD_REQUEST;
}

static ngx_int_t
ngx_http_vkupload_multipart_handler_data(ngx_http_vkupload_request_t *vkupload, ngx_chain_t *in)
{
    ngx_http_request_t                *request;
    ngx_http_vkupload_multipart_t     *multipart;
    ngx_int_t                          rc = NGX_OK;

    request = vkupload->request;
    multipart = (ngx_http_vkupload_multipart_t *) vkupload->ctx;

    for (; in; in = in->next) {
        rc = ngx_http_vkupload_multipartparser_execute(&multipart->parser, &multipart->callbacks, in->buf);

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "%s: error on process data body", __FUNCTION__);

            return rc;
        }
    }

    return NGX_OK;
}

/** ---- multipart parser ---- **/

static ngx_int_t
ngx_http_vkupload_multipart_parser_header_handler(ngx_http_vkupload_multipartparser_t *parser,
    const ngx_str_t *name, const ngx_str_t *value)
{
    ngx_http_vkupload_request_t              *vkupload;
    ngx_http_vkupload_multipart_t            *multipart;
    ngx_http_request_t                       *request;
    ngx_http_vkupload_loc_conf_t             *vkupload_lconf;

    ngx_http_vkupload_content_disposition_e   content_disposition;
    ngx_str_t                                 filename;
    ngx_str_t                                 fieldname;
    ngx_str_t                                *multipart_fields;

    ngx_int_t                                 rc;
    ngx_uint_t                                i;

    vkupload = parser->data;
    request = vkupload->request;
    multipart = (ngx_http_vkupload_multipart_t *) vkupload->ctx;

    vkupload_lconf = ngx_http_get_module_loc_conf(request, ngx_http_vkupload_module);

    if (!str_equal(name->data, name->len, "content-disposition")) {
        return NGX_OK;
    }

    rc = ngx_http_vkupload_headerparser_content_disposition(&content_disposition, &filename, &fieldname, value);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "%s: error parse header %V: %V", __FUNCTION__, name, value);

        return NGX_HTTP_BAD_REQUEST;
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
            multipart->filename.data = ngx_pstrdup(request->pool, &filename);
            if (multipart->filename.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            multipart->filename.len = filename.len;
        }

        if (fieldname.len) {
            multipart->fieldname.data = ngx_pstrdup(request->pool, &fieldname);
            if (multipart->fieldname.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            multipart->fieldname.len = fieldname.len;
        }

        multipart->callbacks.on_header = NULL;
        multipart->callbacks.on_part_end = ngx_http_vkupload_multipart_parser_finish_handler;
        multipart->callbacks.on_data = ngx_http_vkupload_multipart_parser_data_handler;

        vkupload->file = ngx_pcalloc(request->pool, sizeof(ngx_shared_file_t));
        if (vkupload->file == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        vkupload->file->pool = request->pool;
        vkupload->file->log = request->connection->log;
        vkupload->file->manager = vkupload_lconf->manager;

        rc = ngx_shared_file_open(vkupload->file, NULL);
        if (rc != NGX_OK) {
            return rc;
        }

        multipart->writer = ngx_pcalloc(request->pool, sizeof(ngx_shared_file_writer_t));
        if (multipart->writer == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        multipart->writer->file = vkupload->file;

        rc = ngx_shared_file_writer_open(multipart->writer, 0, NGX_MAX_SIZE_T_VALUE);
        if (rc != NGX_OK) {
            return rc;
        }

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
        "%s: unknown multipart field %V", __FUNCTION__, value);

    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_multipart_parser_data_handler(ngx_http_vkupload_multipartparser_t *parser, const ngx_str_t *data)
{
    ngx_http_vkupload_request_t              *vkupload;
    ngx_http_vkupload_multipart_t            *multipart;
    ngx_int_t                        rc;

    vkupload = parser->data;
    multipart = (ngx_http_vkupload_multipart_t *) vkupload->ctx;

    rc = ngx_shared_file_write(multipart->writer, data->data, data->len);
    if (rc != NGX_OK) {
        return rc;
    }

    multipart->size += data->len;
    return NGX_OK;
}

static ngx_int_t
ngx_http_vkupload_multipart_parser_finish_handler(ngx_http_vkupload_multipartparser_t *parser)
{
    ngx_http_vkupload_request_t              *vkupload;
    ngx_http_vkupload_multipart_t            *multipart;
    ngx_int_t                                 rc;

    vkupload = parser->data;
    multipart = (ngx_http_vkupload_multipart_t *) vkupload->ctx;

    multipart->callbacks.on_data = NULL;
    multipart->callbacks.on_part_end = NULL;

    rc = ngx_shared_file_set_total(vkupload->file, multipart->size, 0, multipart->size);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_shared_file_writer_close(multipart->writer);
    multipart->writer = NULL;

    return NGX_OK;
}
