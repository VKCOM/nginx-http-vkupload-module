#include "ngx_http_vkupload_headerparser.h"

#include <ngx_core.h>
#include <ngx_http.h>
#include <ctype.h>

#define str_starts_with(str, end, static_string) \
    ((size_t) ((end) - (str)) >= (sizeof(static_string) - 1) && \
        ngx_strncasecmp((str), (u_char *) (static_string), (sizeof(static_string) - 1)) == 0)

#define str_find_str(str, end, static_string) \
    ngx_strlcasestrn((str), (end) - 1, (u_char *) (static_string), sizeof(static_string) - 2)

#define str_find_char(str, end, c) \
    (u_char *) memchr((str), (c), ((end) - (str)))

#define str_validate(str, end) \
    if ((str) == NULL || (str) >= (end)) { \
        return NGX_HTTP_BAD_REQUEST; \
    }

ngx_int_t
ngx_http_vkupload_headerparser_session_id(ngx_str_t *session_id, const ngx_str_t *value)
{
    size_t  i;

    if (value->len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    for (i = 0; i < value->len; i++) {
        char c = value->data[i];

        if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || c == '_' || c == '-'|| c == '.'|| c == '/'|| c == '='|| c == '+'))
        {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    *session_id = *value;
    return NGX_OK;
}


ngx_int_t
ngx_http_vkupload_headerparser_content_type(ngx_http_vkupload_content_type_e *type,
    ngx_str_t *boundary, const ngx_str_t *content_type)
{
    u_char  *mime_type_end_ptr;
    u_char  *boundary_start_ptr;
    u_char  *boundary_end_ptr;

    u_char  *content_type_start = content_type->data;
    u_char  *content_type_end = content_type->data + content_type->len;

    ngx_int_t  boundary_quoted = 0;

    *type = ngx_http_vkupload_content_type_st_unknown;
    *boundary = (ngx_str_t) ngx_null_string;

    if (content_type->len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (str_starts_with(content_type_start, content_type_end, "multipart/")) {
        *type = ngx_http_vkupload_content_type_st_multipart;

        mime_type_end_ptr = str_find_char(content_type_start, content_type_end, ';');
        str_validate(mime_type_end_ptr, content_type_end);

        boundary_start_ptr = str_find_str(mime_type_end_ptr, content_type_end, "boundary=");
        str_validate(boundary_start_ptr, content_type_end);

        boundary_start_ptr += sizeof("boundary=") - 1;
        str_validate(boundary_start_ptr, content_type_end);

        if (*boundary_start_ptr == '"') {
            boundary_quoted = 1;

            ++boundary_start_ptr; // skip "
            str_validate(boundary_start_ptr, content_type_end);
        }

        if (boundary_quoted) {
            boundary_end_ptr = str_find_char(boundary_start_ptr, content_type_end, '"');
            str_validate(boundary_end_ptr, content_type_end);
        } else {
            boundary_end_ptr = boundary_start_ptr;

            while (boundary_end_ptr < content_type_end && *boundary_end_ptr != ' ' && *boundary_end_ptr != ';') {
                ++boundary_end_ptr;
            }
        }

        if (boundary_start_ptr == boundary_end_ptr) {
            return NGX_HTTP_BAD_REQUEST;
        }

        boundary->data = boundary_start_ptr;
        boundary->len = (boundary_end_ptr - boundary_start_ptr);
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_vkupload_headerparser_content_disposition(ngx_http_vkupload_content_disposition_e *type,
    ngx_str_t *filename, ngx_str_t *name, const ngx_str_t *content_disposition)
{
    u_char  *filename_start;
    u_char  *filename_end;

    u_char  *name_start;
    u_char  *name_end;

    u_char  *disposition_start = content_disposition->data;
    u_char  *disposition_end = content_disposition->data + content_disposition->len;

    *filename = (ngx_str_t) ngx_null_string;
    *name = (ngx_str_t) ngx_null_string;

    if (str_starts_with(disposition_start, disposition_end, "form-data")) {
        *type = ngx_http_vkupload_content_disposition_st_attachment;
    } else if (str_starts_with(disposition_start, disposition_end, "attachment")) {
        *type = ngx_http_vkupload_content_disposition_st_attachment;
    } else {
        return NGX_HTTP_BAD_REQUEST;
    }

    filename_start = str_find_str(disposition_start, disposition_end, "filename=");
    if (filename_start) {
        filename_start += sizeof("filename=") - 1;
        str_validate(filename_start, disposition_end);

        if (*filename_start == '"') {
            ++filename_start;
            str_validate(filename_start, disposition_end);

            filename_end = str_find_char(filename_start, disposition_end, '"');
            str_validate(filename_end, disposition_end);
        } else {
            filename_end = filename_start;

            while (filename_end < disposition_end && *filename_end != ' ' && *filename_end != ';') {
                ++filename_end;
            }
        }

        if (filename_start != filename_end) {
            filename->data = filename_start;
            filename->len = filename_end - filename_start;
        }
    }

    name_start = str_find_str(disposition_start, disposition_end, "name=");
    if (name_start) {
        name_start += sizeof("name=") - 1;
        str_validate(name_start, disposition_end);

        if (*name_start == '"') {
            ++name_start;
            str_validate(name_start, disposition_end);

            name_end = str_find_char(name_start, disposition_end, '"');
            str_validate(name_end, disposition_end);
        } else {
            name_end = name_start;

            while (name_end < disposition_end && *name_end != ' ' && *name_end != ';') {
                ++name_end;
            }
        }

        if (name_start != name_end) {
            name->data = name_start;
            name->len = name_end - name_start;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_vkupload_headerparser_content_range(ngx_http_vkupload_content_range_t *range, const ngx_str_t *content_range)
{
    ngx_int_t  total_unknown = 0;

    u_char  *range_start = content_range->data;
    u_char  *range_end = content_range->data + content_range->len;
    u_char  *pos;

    size_t  from = 0;
    size_t  to = 0;
    size_t  total = 0;

    size_t  *field = &from;

    ngx_memzero(range, sizeof(*range));

    if (!str_starts_with(range_start, range_end, "bytes ")) {
        return NGX_HTTP_BAD_REQUEST;
    }

    pos = range_start + sizeof("bytes ") - 1;

    while (pos < range_end) {
        if (*pos >= '0' && *pos <= '9') {
            (*field) = (*field) * 10 + (*pos - '0');
        } else if (*pos == '-') {
            if(field != &from) {
                return NGX_HTTP_BAD_REQUEST;
            }

            field = &to;
            pos++;

            continue;
        } else if (*pos == '/') {
            if(field != &to) {
                return NGX_HTTP_BAD_REQUEST;
            }

            field = &total;
            pos++;

            continue;
        } else if (*pos == '*') {
            if(field != &total) {
                return NGX_HTTP_BAD_REQUEST;
            }

            total_unknown = 1;
            pos++;

            break;
        } else {
            return NGX_HTTP_BAD_REQUEST;
        }

        pos++;
    }

    if (field != &total || (total_unknown && total != 0) || (!total_unknown && total == 0)) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (from > to
       || (!total_unknown && from >= total)
       || (!total_unknown && to >= total))
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    range->start = from;
    range->end = to;
    range->total = total;

    return NGX_OK;
}
