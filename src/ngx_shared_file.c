#include "ngx_shared_file.h"

#include <ngx_core.h>
#include <ngx_rbtree.h>
#include <ngx_queue.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#define ngx_rbtree_data(n, type, link) \
    ngx_queue_data(n, type, link)

static void
ngx_shared_file_lock(ngx_shared_file_sh_t *shfile)
{
    ngx_rwlock_wlock(&shfile->lock);
}

static void
ngx_shared_file_unlock(ngx_shared_file_sh_t *shfile)
{
    ngx_rwlock_unlock(&shfile->lock);
}

static ngx_shared_file_sh_t *
ngx_shared_file_manager_find_file_sh_locked(ngx_shared_file_manager_t *manager, ngx_str_t *id)
{
    ngx_shared_file_sh_t  *shfile;
    ngx_str_node_t        *node;

    node = ngx_str_rbtree_lookup(&manager->shtree->rbtree, id,
        ngx_murmur_hash2(id->data, id->len));

    if (node == NULL) {
        return NULL;
    }

    shfile = ngx_rbtree_data(node, ngx_shared_file_sh_t, id);
    shfile->updated_at = ngx_time();

    return shfile;
}

static ngx_shared_file_sh_t *
ngx_shared_file_manager_create_file_sh_locked(ngx_shared_file_manager_t *manager, ngx_str_t *id)
{
    ngx_shared_file_sh_t  *shfile;

    shfile = ngx_slab_calloc_locked(manager->shpool, sizeof(ngx_shared_file_sh_t));
    if (shfile == NULL) {
        return NULL;
    }

    shfile->id.node.key = ngx_murmur_hash2(id->data, id->len);
    shfile->id.str.len = id->len;
    shfile->id.str.data = ngx_slab_calloc_locked(manager->shpool, shfile->id.str.len);

    if (shfile->id.str.data == NULL) {
        ngx_slab_free_locked(manager->shpool, shfile);
        return NULL;
    }

    ngx_memcpy(shfile->id.str.data, id->data, shfile->id.str.len);

    ngx_md5_init(&shfile->md5);
    ngx_queue_init(&shfile->parts);
    ngx_rbtree_insert(&manager->shtree->rbtree, &shfile->id.node);

    shfile->created_at = ngx_time();
    shfile->updated_at = shfile->created_at;

    return shfile;
}

static void
ngx_shared_file_session_cleanup_handler(void *data)
{
    ngx_shared_file_cleanup_t  *shfile_cleanup = data;
    ngx_shared_file_manager_t  *manager = shfile_cleanup->manager;
    ngx_shared_file_sh_t       *shfile = shfile_cleanup->shfile;

    ngx_shmtx_lock(&manager->shpool->mutex);

    --shfile->uses;

    if (shfile->uses == 0 && shfile->removed) {
        if (shfile->id.node.key) {
            ngx_rbtree_delete(&manager->shtree->rbtree, &shfile->id.node);
            shfile->id.node.key = 0;
        }

        // TODO: remove parts if exists

        if (shfile->uses == 0 && shfile->id.node.key == 0) {
            if (shfile->path.len) {
                ngx_slab_free_locked(manager->shpool, shfile->path.data);

                shfile->path.data = NULL;
                shfile->path.len = 0;
            }

            if (shfile->id.str.len) {
                ngx_slab_free_locked(manager->shpool, shfile->id.str.data);

                shfile->id.str.data = NULL;
                shfile->id.str.len = 0;
            }

            ngx_slab_free_locked(manager->shpool, shfile);
        }
    }

    ngx_shmtx_unlock(&manager->shpool->mutex);
}

static void
ngx_shared_file_session_merge_parts(ngx_shared_file_session_t *session)
{
    ngx_shared_file_manager_t  *manager;
    ngx_shared_file_sh_t       *shfile;
    ngx_shared_file_part_sh_t  *shpart_i, *shpart_i_next;
    ngx_queue_t                *shpart_q, *shpart_q_next;
    size_t                      linar_size;

    manager = session->manager;
    shfile = session->shfile;

    for (shpart_q = ngx_queue_head(&shfile->parts); shpart_q != ngx_queue_sentinel(&shfile->parts);
            shpart_q = ngx_queue_next(shpart_q))
    {
        shpart_i = ngx_queue_data(shpart_q, ngx_shared_file_part_sh_t, queue);
        if (!shpart_i->completed) {
            continue;
        }

        shpart_q_next = ngx_queue_next(shpart_q);

        while (shpart_q_next != ngx_queue_sentinel(&shfile->parts)) {
            shpart_i_next = ngx_queue_data(shpart_q_next, ngx_shared_file_part_sh_t, queue);
            shpart_q_next = ngx_queue_next(shpart_q_next);

            if (!shpart_i_next->completed) {
                continue;
            }

            if ((shpart_i->end + 1) < shpart_i_next->start) {
                break;
            }

            if (shpart_i->end < shpart_i_next->end) {
                shpart_i->end = shpart_i_next->end;
            }

            ngx_queue_remove(&shpart_i_next->queue);
            ngx_slab_free(manager->shpool, shpart_i_next);
        }
    }

    shpart_q = ngx_queue_head(&shfile->parts);
    if (shpart_q != ngx_queue_sentinel(&shfile->parts)) {
        shpart_i = ngx_queue_data(shpart_q, ngx_shared_file_part_sh_t, queue);

        if (shpart_i->completed && shfile->linar_size == shpart_i->start) {
            linar_size = shpart_i->end + 1;

            shpart_q_next = ngx_queue_next(shpart_q);
            if (shpart_q_next != ngx_queue_sentinel(&shfile->parts)) {
                shpart_i_next = ngx_queue_data(shpart_q_next, ngx_shared_file_part_sh_t, queue);

                if (!shpart_i_next->completed && linar_size > shpart_i_next->start) {
                    linar_size = shpart_i_next->start;
                }
            }

            ngx_queue_remove(&shpart_i->queue);
            ngx_slab_free(manager->shpool, shpart_i);

            shfile->linar_size = linar_size;
        }
    }
}

static void
ngx_shared_file_session_finish_part(ngx_shared_file_session_t *session)
{
    ngx_shared_file_manager_t  *manager;
    ngx_shared_file_part_sh_t  *shpart;

    manager = session->manager;
    shpart = session->shpart;

    if (shpart->start >= shpart->pos) {
        ngx_queue_remove(&shpart->queue);
        ngx_slab_free(manager->shpool, shpart);

        shpart = NULL;
    } else {
        shpart->end = shpart->pos - 1;
        shpart->completed = 1;

        ngx_shared_file_session_merge_parts(session);
    }

    session->shpart = NULL;
}

ngx_int_t
ngx_shared_file_manager_init(ngx_shared_file_manager_t *manager, ngx_shm_zone_t *shzone)
{
    manager->shpool = (ngx_slab_pool_t *) shzone->shm.addr;
    if (shzone->shm.exists) {
        manager->shtree = manager->shpool->data;
        return NGX_OK;
    }

    manager->shtree = ngx_slab_calloc(manager->shpool, sizeof(ngx_shared_file_manager_sh_t));
    if (manager->shtree == NULL) {
        return NGX_ERROR;
    }

    manager->shpool->data = manager->shtree;
    ngx_rbtree_init(&manager->shtree->rbtree, &manager->shtree->sentinel, ngx_str_rbtree_insert_value);

    return NGX_OK;
}

ngx_int_t
ngx_shared_file_manager_copy(ngx_shared_file_manager_t *manager, ngx_shared_file_manager_t *manager_old)
{
    manager->shtree = manager_old->shtree;
    manager->shpool = manager_old->shpool;

    return NGX_OK;
}

ngx_int_t
ngx_shared_file_open(ngx_shared_file_session_t *session, ngx_str_t *session_id, size_t total_size, size_t start, size_t end)
{
    ngx_shared_file_manager_t  *manager;
    ngx_shared_file_sh_t       *shfile;
    ngx_shared_file_cleanup_t  *shfile_cleanup;
    ngx_pool_cleanup_t         *cln;
    ngx_pool_cleanup_file_t    *clnf;
    ngx_int_t                   rc;
    ngx_shared_file_part_sh_t  *shpart = NULL, *shpart_i;
    ngx_queue_t                *shpart_q;

    manager = session->manager;

    cln = ngx_pool_cleanup_add(session->pool, sizeof(ngx_shared_file_cleanup_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_shmtx_lock(&manager->shpool->mutex);

    shfile = ngx_shared_file_manager_find_file_sh_locked(manager, session_id);
    if (shfile == NULL) {
        shfile = ngx_shared_file_manager_create_file_sh_locked(manager, session_id);
    }

    if (shfile) {
        ++shfile->uses; // for current request

        cln->handler = ngx_shared_file_session_cleanup_handler;

        shfile_cleanup = cln->data;
        shfile_cleanup->shfile = shfile;
        shfile_cleanup->manager = manager;
    }

    ngx_shmtx_unlock(&manager->shpool->mutex);

    if (shfile == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_shared_file_lock(shfile);

    if (shfile->completed || shfile->removed) {
        ngx_shared_file_unlock(shfile);
        return NGX_HTTP_BAD_REQUEST;
    }

    if (shfile->path.data == NULL) {
        session->file->log = session->log;
        session->file->fd = NGX_INVALID_FILE;

        rc = ngx_create_temp_file(session->file, manager->file_path, session->pool,
            1 /* TODO: comment */, 0 /* TODO: comment */, manager->file_access);
        if (rc != NGX_OK) {
            ngx_shared_file_unlock(shfile);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        shfile->path.data = ngx_slab_calloc(manager->shpool, session->file->name.len + 1);
        if (shfile->path.data == NULL) {
            ngx_shared_file_unlock(shfile);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        shfile->path.len = session->file->name.len;
        ngx_memcpy(shfile->path.data, session->file->name.data, shfile->path.len);

        if (total_size) {
            shfile->total_size = total_size;
            shfile->total_known = 1;
        } else {
            
            shfile->total_size = end + 1;
        }
    } else {
        if (shfile->total_known && total_size && shfile->total_size != total_size) {
            ngx_shared_file_unlock(shfile);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (shfile->total_known && total_size == 0 && end >= shfile->total_size) {
            ngx_shared_file_unlock(shfile);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (!shfile->total_known && total_size) {
            if (end >= shfile->total_size) {
                shfile->total_size = end + 1;
            }

            if (shfile->total_size > total_size) {
                ngx_shared_file_unlock(shfile);
                return NGX_HTTP_BAD_REQUEST;
            }

            shfile->total_size = total_size;
            shfile->total_known = 1;
        }

        cln = ngx_pool_cleanup_add(session->pool, sizeof(ngx_pool_cleanup_file_t));
        if (cln == NULL) {
            ngx_shared_file_unlock(shfile);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        session->file->log = session->log;
        session->file->name = shfile->path;
        session->file->fd = ngx_open_file(session->file->name.data, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);

        if (session->file->fd == NGX_INVALID_FILE) {
            ngx_shared_file_unlock(shfile);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = ngx_pool_cleanup_file;
        clnf = cln->data;

        clnf->fd = session->file->fd;
        clnf->name = session->file->name.data;
        clnf->log = session->file->log;
    }

    // create file part

    shpart = ngx_slab_calloc(manager->shpool, sizeof(ngx_shared_file_part_sh_t));
    if (shpart == NULL) {
        ngx_shared_file_unlock(shfile);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    session->file->offset = start;
    shpart->start = start;
    shpart->pos = start;
    shpart->end = end;

    if (shpart->start < shfile->linar_size) {
        shpart->start = shfile->linar_size;
    }

    // insert part
    for (shpart_q = ngx_queue_head(&shfile->parts); shpart_q != ngx_queue_sentinel(&shfile->parts);
            shpart_q = ngx_queue_next(shpart_q))
    {
        shpart_i = ngx_queue_data(shpart_q, ngx_shared_file_part_sh_t, queue);
        if (shpart->start <= shpart_i->start) {
            break;
        }
    }

    if (shpart_q == ngx_queue_sentinel(&shfile->parts)) {
        ngx_queue_insert_tail(&shfile->parts, &shpart->queue);
    } else {
        shpart_q = shpart_q->prev;
        ngx_queue_insert_after(shpart_q, &shpart->queue);
    }

    session->shpart = shpart;
    session->shfile = shfile;

    ngx_shared_file_unlock(shfile);
    return NGX_OK;
}

ngx_int_t
ngx_shared_file_write(ngx_shared_file_session_t *session, const u_char *data, size_t length)
{
    ngx_shared_file_part_sh_t  *shpart = session->shpart;
    ngx_file_t                 *file = session->file;
    size_t                      skip = 0;

    if (shpart->pos + length > (shpart->pos + shpart->end + 1)) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (shpart->start > shpart->pos) {
        if (shpart->start > shpart->pos + length) {
            // skip write
            shpart->pos += length;
            return NGX_OK;
        }

        skip = (shpart->start - shpart->pos);
        shpart->pos += skip;
    }

    if (ngx_write_file(file, (u_char *) data + skip, length - skip, shpart->pos) == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    shpart->pos += (length - skip);
    return NGX_OK;
}

void
ngx_shared_file_close(ngx_shared_file_session_t *session)
{
    ngx_shared_file_sh_t  *shfile = session->shfile;

    ngx_shared_file_lock(shfile);
    ngx_shared_file_session_finish_part(session);

    ngx_shared_file_unlock(shfile);
}

ngx_int_t
ngx_shared_file_session_md5_calc(ngx_shared_file_session_t *session)
{
    ngx_shared_file_sh_t  *shfile = session->shfile;

    u_char                 buffer[ngx_pagesize * 12];
    size_t                 need_bytes;
    size_t                 left_bytes;
    size_t                 current_offset;
    ssize_t                readed_bytes;

    ngx_shared_file_lock(shfile);

    if (shfile->md5_processed) {
        ngx_shared_file_unlock(shfile);
        return NGX_OK;
    }

    left_bytes = (shfile->linar_size - shfile->md5_size);
    if (left_bytes == 0) {
        ngx_shared_file_unlock(shfile);
        return NGX_OK;
    }

    current_offset = shfile->md5_size;
    shfile->md5_processed = 1;

    ngx_shared_file_unlock(shfile);

    do {
        need_bytes = sizeof(buffer);

        if (left_bytes < need_bytes) {
            need_bytes = left_bytes;
        }

        readed_bytes = ngx_read_file(session->file, buffer, need_bytes, current_offset);
        if (readed_bytes <= 0) {
            return NGX_ERROR;
        }

        left_bytes -= readed_bytes;
        current_offset += readed_bytes;

        ngx_md5_update(&shfile->md5, buffer, readed_bytes);
        shfile->md5_size += readed_bytes;
    } while (left_bytes > 0);

    ngx_shared_file_lock(shfile);
    shfile->md5_processed = 0;
    ngx_shared_file_unlock(shfile);

    return NGX_OK;
}

void
ngx_shared_file_md5_final(ngx_shared_file_session_t *session, u_char result[16])
{
    ngx_shared_file_sh_t  *shfile = session->shfile;

    return ngx_md5_final(result, &shfile->md5);
}

void
ngx_shared_file_remove(ngx_shared_file_session_t *session)
{
    ngx_shared_file_sh_t  *shfile = session->shfile;

    ngx_shared_file_lock(shfile);

    shfile->removed = 1;

    ngx_shared_file_unlock(shfile);
}

ngx_int_t
ngx_shared_file_is_completed(ngx_shared_file_session_t *session)
{
    ngx_shared_file_sh_t  *shfile = session->shfile;
    ngx_int_t              completed = 0;

    ngx_shared_file_lock(shfile);
    if (shfile->total_known && shfile->linar_size == shfile->total_size && ngx_queue_empty(&shfile->parts)) {
        shfile->completed = 1;
    }

    completed = shfile->completed;
    ngx_shared_file_unlock(shfile);

    return completed;
}

size_t
ngx_shared_file_get_total_size(ngx_shared_file_session_t *session)
{
    ngx_shared_file_sh_t  *shfile = session->shfile;
    size_t                 total_size = 0;

    ngx_shared_file_lock(shfile);

    if (!shfile->removed && shfile->total_known) {
        total_size = shfile->total_size;
    }

    ngx_shared_file_unlock(shfile);
    return total_size;
}

size_t
ngx_shared_file_get_linar_size(ngx_shared_file_session_t *session)
{
    ngx_shared_file_sh_t  *shfile = session->shfile;
    size_t                 linar_size = 0;

    ngx_shared_file_lock(shfile);

    linar_size = shfile->linar_size;

    ngx_shared_file_unlock(shfile);
    return linar_size;
}


ngx_int_t
ngx_shared_file_get_ranges(ngx_shared_file_session_t *session, ngx_str_t *ranges)
{
    ngx_shared_file_sh_t       *shfile = session->shfile;
    ngx_shared_file_part_sh_t  *shpart_i;
    ngx_queue_t                *shpart_q;
    ngx_int_t                   part_counts;
    u_char                     *end;

    ngx_str_null(ranges);

    ngx_shared_file_lock(shfile);

    for (shpart_q = ngx_queue_head(&shfile->parts); shpart_q != ngx_queue_sentinel(&shfile->parts);
            shpart_q = ngx_queue_next(shpart_q))
    {
        shpart_i = ngx_queue_data(shpart_q, ngx_shared_file_part_sh_t, queue);

        if (!shpart_i->completed) {
            continue;
        }

        ++part_counts;
    }

    if (shfile->linar_size > 0) {
        ++part_counts;
    }

    if (part_counts > 0) {
        ranges->data = ngx_palloc(session->pool, (3 * NGX_OFF_T_LEN + 1 /* - */ + 1 /* / */ + 1 /* , */) * part_counts);
        if (ranges->data == NULL) {
            return NGX_ERROR;
        }

        end = ranges->data;

        if (shfile->linar_size > 0) {
            if (shfile->total_known) {
                end = ngx_sprintf(end, "%O-%O/%O,", 0, (shfile->linar_size - 1), shfile->total_size);
            } else {
                end = ngx_sprintf(end, "%O-%O/*,", 0, (shfile->linar_size - 1));
            }
        }

        for (shpart_q = ngx_queue_head(&shfile->parts); shpart_q != ngx_queue_sentinel(&shfile->parts);
            shpart_q = ngx_queue_next(shpart_q))
        {
            shpart_i = ngx_queue_data(shpart_q, ngx_shared_file_part_sh_t, queue);

            if (!shpart_i->completed) {
                continue;
            }

            if (shfile->total_known) {
                end = ngx_sprintf(end, "%O-%O/%O,", shpart_i->start, shpart_i->end, shfile->total_size);
            } else {
                end = ngx_sprintf(end, "%O-%O/*,", shpart_i->start, shpart_i->end);
            }
        }

        ranges->len = (end - ranges->data) - 1 /* last , */;
    }

    ngx_shared_file_unlock(shfile);
    return NGX_OK;
}

