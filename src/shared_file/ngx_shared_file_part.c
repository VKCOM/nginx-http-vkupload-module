#include <ngx_core.h>
#include <ngx_queue.h>

#include "shared_file/ngx_shared_file_part.h"

ngx_shared_file_part_t *
ngx_shared_file_create_part(ngx_slab_pool_t *pool, size_t offset, size_t size)
{
    ngx_shared_file_part_t *part;

    part = ngx_slab_calloc(pool, sizeof(ngx_shared_file_part_t));
    if (part == NULL) {
        return NULL;
    }

    part->offset = offset;
    part->pos = offset;
    part->size = size;

    return part;
}

void
ngx_shared_file_insert_part(ngx_queue_t *parts, ngx_shared_file_part_t *part)
{
    ngx_shared_file_part_t  *part_i;
    ngx_queue_t             *part_q;

    for (part_q = ngx_queue_head(parts); part_q != ngx_queue_sentinel(parts);
            part_q = ngx_queue_next(part_q))
    {
        part_i = ngx_queue_data(part_q, ngx_shared_file_part_t, queue);

        if (part->offset <= part_i->offset) {
            break;
        }
    }

    if (part_q == ngx_queue_sentinel(parts)) {
        ngx_queue_insert_tail(parts, &part->queue);
    } else {
        part_q = part_q->prev;
        ngx_queue_insert_after(part_q, &part->queue);
    }
}

void
ngx_shared_file_complete_part(ngx_shared_file_part_t *part)
{
    part->size = (part->pos - part->offset);
    part->completed = 1;
}

size_t
ngx_shared_file_merge_parts(ngx_slab_pool_t *pool, ngx_queue_t *parts, size_t linar_size)
{
    ngx_shared_file_part_t  *part_i, *part_i_next;
    ngx_queue_t             *part_q, *part_q_next;

    // merge neighboring completed parts

    for (part_q = ngx_queue_head(parts); part_q != ngx_queue_sentinel(parts);
            part_q = ngx_queue_next(part_q))
    {
        part_i = ngx_queue_data(part_q, ngx_shared_file_part_t, queue);

        if (!part_i->completed) {
            continue;
        }

        part_q_next = ngx_queue_next(part_q);

        while (part_q_next != ngx_queue_sentinel(parts)) {
            part_i_next = ngx_queue_data(part_q_next, ngx_shared_file_part_t, queue);
            part_q_next = ngx_queue_next(part_q_next);

            if ((part_i->offset + part_i->size) < part_i_next->offset) {
                break;
            }

            if (!part_i_next->completed) {
                continue;
            }

            if ((part_i->offset + part_i->size) < (part_i_next->offset + part_i_next->size)) {
                part_i->size += (part_i_next->offset + part_i_next->size) - (part_i->offset + part_i->size);
            }

            ngx_queue_remove(&part_i_next->queue);
            ngx_slab_free(pool, part_i_next);
            part_i_next = NULL;
        }
    }

    // recalc linar size and removed no needed parts

    part_q = ngx_queue_head(parts);

    if (part_q == ngx_queue_sentinel(parts)) {
        return linar_size;
    }

    part_i = ngx_queue_data(part_q, ngx_shared_file_part_t, queue);

    if (part_i->completed && linar_size >= part_i->offset) {
        if (part_i->offset + part_i->size > linar_size) {
            linar_size = part_i->offset + part_i->size;
        }

        part_q_next = ngx_queue_next(part_q);
        if (part_q_next != ngx_queue_sentinel(parts)) {
            part_i_next = ngx_queue_data(part_q_next, ngx_shared_file_part_t, queue);

            if (!part_i_next->completed && linar_size > part_i_next->offset) {
                linar_size = part_i_next->offset;
            }
        }

        ngx_queue_remove(&part_i->queue);
        ngx_slab_free(pool, part_i);

        part_i = NULL;
    }

    return linar_size;
}

ngx_int_t
ngx_shared_file_parts_to_string(ngx_pool_t *pool, ngx_str_t *ranges, ngx_queue_t *parts,
    size_t linar_size, size_t total_size, int total_known)
{
    ngx_shared_file_part_t  *part_i;
    ngx_queue_t             *part_q;
    ngx_int_t                part_counts = 0;
    u_char                  *end;

    ngx_str_null(ranges);

    for (part_q = ngx_queue_head(parts); part_q != ngx_queue_sentinel(parts);
            part_q = ngx_queue_next(part_q))
    {
        part_i = ngx_queue_data(part_q, ngx_shared_file_part_t, queue);
        if (!part_i->completed) {
            continue;
        }

        ++part_counts;
    }

    if (linar_size > 0) {
        ++part_counts;
    }

    if (part_counts > 0) {
        ranges->data = ngx_palloc(pool, (3 * NGX_OFF_T_LEN + 1 /* - */ + 1 /* / */ + 1 /* , */) * part_counts);
        if (ranges->data == NULL) {
            return NGX_ERROR;
        }

        end = ranges->data;

        if (linar_size > 0) {
            if (total_known) {
                end = ngx_sprintf(end, "%O-%O/%O,", 0, (linar_size - 1), total_size);
            } else {
                end = ngx_sprintf(end, "%O-%O/*,", 0, (linar_size - 1));
            }
        }

        for (part_q = ngx_queue_head(parts); part_q != ngx_queue_sentinel(parts);
            part_q = ngx_queue_next(part_q))
        {
            part_i = ngx_queue_data(part_q, ngx_shared_file_part_t, queue);

            if (!part_i->completed) {
                continue;
            }

            if (total_known) {
                end = ngx_sprintf(end, "%O-%O/%O,", part_i->offset, (part_i->offset + part_i->size - 1), total_size);
            } else {
                end = ngx_sprintf(end, "%O-%O/*,", part_i->offset, (part_i->offset + part_i->size - 1));
            }
        }

        ranges->len = (end - ranges->data) - 1 /* last , */;
    }

    return NGX_OK;
}
