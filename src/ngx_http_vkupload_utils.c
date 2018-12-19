#include <ngx_core.h>
#include <ngx_list.h>
#include <ngx_hash.h>
#include <ngx_http.h>

#include "ngx_http_vkupload_utils.h"

static ngx_int_t
ngx_http_vkupload_header_remove_index(ngx_list_t *l, ngx_list_part_t *cur, ngx_uint_t i)
{
    ngx_table_elt_t  *data;
    ngx_list_part_t  *new, *part;

    data = cur->elts;

    if (i == 0) {
        cur->elts = (char *) cur->elts + l->size;
        cur->nelts--;

        if (cur == l->last) {
            if (cur->nelts == 0) {
                part = &l->part;

                if (part == cur) {
                    cur->elts = (char *) cur->elts - l->size;
                    /* do nothing */

                } else {
                    while (part->next != cur) {
                        if (part->next == NULL) {
                            return NGX_ERROR;
                        }
                        part = part->next;
                    }

                    l->last = part;
                    part->next = NULL;

                    l->nalloc = part->nelts;
                }
            } else {
                l->nalloc--;
            }

            return NGX_OK;
        }

        if (cur->nelts == 0) {
            part = &l->part;

            if (part == cur) {
                if (l->last == cur->next) {
                    l->part = *(cur->next);
                    l->last = part;
                    l->nalloc = part->nelts;

                } else {
                    l->part = *(cur->next);
                }

            } else {
                while (part->next != cur) {
                    if (part->next == NULL) {
                        return NGX_ERROR;
                    }
                    part = part->next;
                }

                part->next = cur->next;
            }

            return NGX_OK;
        }

        return NGX_OK;
    }

    if (i == cur->nelts - 1) {
        cur->nelts--;

        if (cur == l->last) {
            l->nalloc = cur->nelts;
        }

        return NGX_OK;
    }

    new = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
    if (new == NULL) {
        return NGX_ERROR;
    }

    new->elts = &data[i + 1];
    new->nelts = cur->nelts - i - 1;
    new->next = cur->next;

    cur->nelts = i;
    cur->next = new;
    if (cur == l->last) {
        l->last = new;
        l->nalloc = new->nelts;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_vkupload_header_remove(ngx_list_t *headers_list, const ngx_str_t *name)
{
    ngx_uint_t  i;
    ngx_int_t   rc = NGX_OK;

    ngx_list_part_t  *part;
    ngx_table_elt_t  *headers;

retry:
    part = &headers_list->part;
    headers = part->elts;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            headers = part->elts;
            i = 0;
        }

        if (headers[i].key.len == name->len && ngx_strncasecmp(headers[i].key.data, name->data, name->len) == 0) {
            rc = ngx_http_vkupload_header_remove_index(headers_list, part, i);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            goto retry;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_vkupload_buf_append_kvalue(ngx_chain_t **bufs_ptr, ngx_pool_t *pool, const ngx_str_t *name, const ngx_str_t *value)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    uintptr_t escaped_value_len;
    ssize_t buffer_len;

    escaped_value_len = value->len + (2 * ngx_escape_uri(NULL, value->data, value->len, NGX_ESCAPE_ARGS));
    if (escaped_value_len == 0) {
        return NGX_OK;
    }

    buffer_len = escaped_value_len + name->len + 1 /* = */ + 1 /* & */;
    cl = *bufs_ptr;

    if (cl && cl->buf &&
        ngx_buf_size(cl->buf) == 0 && // is empty
        buffer_len <= (cl->buf->end - cl->buf->last)) // size to small
    {
        *bufs_ptr = cl = cl->next; // remove empty small buffer
    }

    if (cl && cl->buf && buffer_len <= (cl->buf->end - cl->buf->last)) {
        b = cl->buf;
    } else {
        b = ngx_create_temp_buf(pool, escaped_value_len + name->len + 1 /* = */ + 1 /* & */);
        if (b == NULL) {
            return NGX_ERROR;
        }

        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        if (*bufs_ptr == NULL) {
            b->last_in_chain = 1;
            b->last_buf = 1;
        } else {
            cl->next = *bufs_ptr;
        }

        *bufs_ptr = cl;
    }

    b->last = ngx_copy(b->last, name->data, name->len);
    b->last = ngx_copy(b->last, "=", 1);
    b->last = (u_char *) ngx_escape_uri(b->last, value->data, value->len, NGX_ESCAPE_ARGS);
    b->last = ngx_copy(b->last, "&", 1);

    return NGX_OK;
}

ngx_str_t *
ngx_http_vkupload_header_find(ngx_http_request_t *request, const ngx_str_t *name)
{
    ngx_http_core_main_conf_t  *http_mconf = ngx_http_get_module_main_conf(request, ngx_http_core_module);
    ngx_uint_t                  name_hash;
    ngx_http_header_t          *header;

    name_hash = ngx_hash_key_lc(name->data, name->len);
    header = ngx_hash_find(&http_mconf->headers_in_hash, name_hash, name->data, name->len);

    if (header == NULL || header->offset == 0) {
        return NULL;
    }

    return &((*((ngx_table_elt_t **) ((char *) &request->headers_in + header->offset)))->value);
}
