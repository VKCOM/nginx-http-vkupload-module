#include <ngx_core.h>
#include <ngx_queue.h>
#include <ngx_rbtree.h>

#include "shared_file/ngx_shared_file.h"
#include "shared_file/ngx_shared_file_part.h"
#include "shared_file/ngx_shared_file_manager.h"

#define ngx_rbtree_data(n, type, link) \
    ngx_queue_data(n, type, link)

static ngx_shared_file_node_t *
ngx_shared_file_manager_find_node_locked(ngx_shared_file_manager_t *manager, ngx_str_t *id)
{
    ngx_shared_file_node_t  *node;
    ngx_str_node_t          *rbnode;

    rbnode = ngx_str_rbtree_lookup(&manager->tree->rbtree, id,
        ngx_murmur_hash2(id->data, id->len));

    if (rbnode == NULL) {
        return NULL;
    }

    node = ngx_rbtree_data(rbnode, ngx_shared_file_node_t, id);
    node->updated_at = ngx_time();
    node->timeouted = 0;

    return node;
}

static ngx_shared_file_node_t *
ngx_shared_file_manager_create_node_locked(ngx_shared_file_manager_t *manager, ngx_str_t *id)
{
    ngx_shared_file_node_t  *node;

    node = ngx_slab_calloc_locked(manager->pool, sizeof(ngx_shared_file_node_t) + (sizeof(void *) * manager->plugins_count));
    if (node == NULL) {
        return NULL;
    }

    node->id.node.key = ngx_murmur_hash2(id->data, id->len);
    node->id.str.len = id->len;
    node->id.str.data = ngx_slab_calloc_locked(manager->pool, node->id.str.len);

    if (node->id.str.data == NULL) {
        ngx_slab_free_locked(manager->pool, node);
        return NULL;
    }

    ngx_memcpy(node->id.str.data, id->data, node->id.str.len);

    ngx_queue_init(&node->parts);
    ngx_rbtree_insert(&manager->tree->rbtree, &node->id.node);

    node->created_at = ngx_time();
    node->updated_at = node->created_at;

    return node;
}

static ngx_shared_file_node_t *
ngx_shared_file_manager_create_detached_node(ngx_shared_file_manager_t *manager, ngx_pool_t *pool)
{
    ngx_shared_file_node_t  *node;
    ngx_str_t                session_id;

    session_id.data = ngx_pcalloc(pool, sizeof("#ngx_shared_file") + NGX_SIZE_T_LEN + NGX_SIZE_T_LEN);
    if (session_id.data == NULL) {
        return NULL;
    }

    session_id.len = ngx_sprintf(session_id.data, "#ngx_shared_file-%p-%ui", manager, manager->uniq)
        - session_id.data;

    manager->uniq++;

    node = ngx_pcalloc(pool, sizeof(ngx_shared_file_node_t) + (sizeof(void *) * manager->plugins_count));
    if (node == NULL) {
        return NULL;
    }

    node->id.node.key = 0;
    node->id.str = session_id;

    ngx_queue_init(&node->parts);

    node->created_at = ngx_time();
    node->updated_at = node->created_at;
    node->detached = 1;

    return node;
}

static void
ngx_shared_file_cleanup_handler(void *data)
{
    ngx_shared_file_manager_t  *manager;
    ngx_shared_file_node_t     *node;
    ngx_shared_file_t          *file = data;

    if (file->node == NULL) {
        return;
    }

    manager = file->manager;
    node = file->node;

    file->node = NULL;

    ngx_shmtx_lock(&manager->pool->mutex);
    ngx_shared_file_node_decref(manager, node);
    ngx_shmtx_unlock(&manager->pool->mutex);
}

void
ngx_shared_file_node_lock(ngx_shared_file_node_t *node)
{
    ngx_rwlock_wlock(&node->lock);
}

void
ngx_shared_file_node_unlock(ngx_shared_file_node_t *node)
{
    ngx_rwlock_unlock(&node->lock);
}

void
ngx_shared_file_node_incref(ngx_shared_file_manager_t *manager, ngx_shared_file_node_t *node)
{
    ++node->uses;
}

void
ngx_shared_file_node_decref(ngx_shared_file_manager_t *manager, ngx_shared_file_node_t *node)
{
    ngx_shared_file_part_t  *part_i;
    ngx_queue_t             *part_q;
    
    ngx_int_t                err;

    --node->uses;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
        "%s: %V (c:%d, e:%d, t:%d) - decref", __FUNCTION__, &node->id.str,
            node->completed, node->error, node->timeouted);

    if (node->uses == 0 && (node->completed || node->error || node->timeouted)) {
        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
            "%s: %V (c:%d, e:%d, t:%d) - delete node", __FUNCTION__, &node->id.str,
            node->completed, node->error, node->timeouted);

        ngx_shared_file_plugins_call_finalize(manager, node);

        if (node->detached == 0 && node->id.node.key) {
            ngx_rbtree_delete(&manager->tree->rbtree, &node->id.node);
            node->id.node.key = 0;
        }

        while ((part_q = ngx_queue_head(&node->parts)) && part_q != ngx_queue_sentinel(&node->parts)) {
            ngx_queue_remove(part_q);

            if (node->detached == 0) {
                part_i = ngx_queue_data(part_q, ngx_shared_file_part_t, queue);
                ngx_slab_free_locked(manager->pool, part_i);
            }
        }

        if (node->path.len) {
            if (node->error || node->timeouted) {
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                    "%s: %V - delete file %V", __FUNCTION__, &node->id.str, &node->path);

                if (ngx_delete_file(node->path.data) == NGX_FILE_ERROR) {
                    err = ngx_errno;

                    if (err != NGX_ENOENT) {
                        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, err,
                            "%s: error delete state file \"%V\"", __FUNCTION__, node->path);
                    }
                }
            }

            if (node->detached == 0) {
                ngx_slab_free_locked(manager->pool, node->path.data);
            }

            node->path.data = NULL;
            node->path.len = 0;
        }

        if (node->id.str.len) {
            if (node->detached == 0) {
                ngx_slab_free_locked(manager->pool, node->id.str.data);
            }

            node->id.str.data = NULL;
            node->id.str.len = 0;
        }

        if (node->detached == 0) {
            ngx_slab_free_locked(manager->pool, node);
        }
    }
}

ngx_int_t
ngx_shared_file_open(ngx_shared_file_t *file, ngx_str_t *session_id)
{
    ngx_shared_file_manager_t  *manager;
    ngx_shared_file_node_t     *node;
    ngx_pool_cleanup_t         *cln;

    manager = file->manager;

    cln = ngx_pool_cleanup_add(file->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&manager->pool->mutex);

    if (session_id == NULL) {
        node = ngx_shared_file_manager_create_detached_node(manager, file->pool);
        if (node) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                "%s: %V - create anonymus node", __FUNCTION__, &node->id.str);
        }
    } else {
        node = ngx_shared_file_manager_find_node_locked(manager, session_id);
        if (node == NULL) {
            node = ngx_shared_file_manager_create_node_locked(manager, session_id);

            if (node) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                    "%s: %V - create node", __FUNCTION__, &node->id.str);
            }
        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                "%s: %V - open node", __FUNCTION__, &node->id.str);
        }
    }

    if (node) {
        file->node = node;
        file->cleanup = cln;

        cln->handler = ngx_shared_file_cleanup_handler;
        cln->data = file;

        ngx_shared_file_node_incref(manager, node); // for current request
    }

    ngx_shmtx_unlock(&manager->pool->mutex);

    if (node == NULL) {
        if (session_id) {
            ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno,
                "%s: error allocate new shared file session for %V", __FUNCTION__, session_id);
        } else {
            ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno,
                "%s: error allocate new anonyus file session for %V", __FUNCTION__);
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_shared_file_find(ngx_shared_file_t *file, ngx_str_t *session_id)
{
    ngx_shared_file_manager_t  *manager;
    ngx_shared_file_node_t     *node;
    ngx_pool_cleanup_t         *cln;

    manager = file->manager;

    cln = ngx_pool_cleanup_add(file->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&manager->pool->mutex);

    node = ngx_shared_file_manager_find_node_locked(manager, session_id);
    if (node) {
        ngx_shared_file_node_incref(manager, node); // for current request

        file->node = node;
        file->cleanup = cln;

        cln->handler = ngx_shared_file_cleanup_handler;
        cln->data = file;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
            "%s: %V - find node", __FUNCTION__, session_id);
    }

    ngx_shmtx_unlock(&manager->pool->mutex);

    return NGX_OK;
}

void
ngx_shared_file_close(ngx_shared_file_t *file)
{
    ngx_shared_file_cleanup_handler(file);
}

ngx_int_t
ngx_shared_file_set_total(ngx_shared_file_t *file, size_t total_size, size_t part_offset, size_t part_size)
{
    ngx_shared_file_node_t  *node = file->node;
    size_t                   part_end_offset = part_offset + part_size;

    ngx_shared_file_node_lock(node);

    ngx_log_debug7(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
        "%s: %V (t: %z, tk: %d) - set total (t: %z, po: %z, ps: %z)", __FUNCTION__, &node->id.str,
        node->total_size, node->total_known,
        total_size, part_offset, part_size);

    if (total_size && total_size < part_end_offset) {
        ngx_log_error(NGX_LOG_WARN, file->log, 0,
            "%s: invalid total size in request for session %V (%zu < %zu)", __FUNCTION__, &node->id.str,
            total_size, part_end_offset);

        ngx_shared_file_node_unlock(node);
        return NGX_ERROR;
    }

    if (node->total_known && total_size && node->total_size != total_size) {
        ngx_log_error(NGX_LOG_WARN, file->log, 0,
            "%s: invalid total size in request for session %V (%zu != %zu)", __FUNCTION__, &node->id.str,
            total_size, node->total_size);

        ngx_shared_file_node_unlock(node);
        return NGX_ERROR;
    }

    if (node->total_known && total_size == 0 && part_end_offset > node->total_size) {
        ngx_log_error(NGX_LOG_WARN, file->log, 0,
            "%s: invalid range in request for session %V (%z > %z)", __FUNCTION__, &node->id.str,
            part_end_offset, part_end_offset);

        ngx_shared_file_node_unlock(node);
        return NGX_ERROR;
    }

    if (!node->total_known && total_size) {
        if (part_end_offset > node->total_size) {
            node->total_size = part_end_offset;
        }

        if (node->total_size > total_size) {
            ngx_log_error(NGX_LOG_WARN, file->log, 0,
                "%s: invalid total in request for session %V (%zu >= max:%zu)", __FUNCTION__, &node->id.str,
                total_size, node->total_size);

            ngx_shared_file_node_unlock(node);
            return NGX_ERROR;
        }

        node->total_size = total_size;
        node->total_known = 1;
    }

    if (!node->total_known && total_size == 0 && part_end_offset > node->total_size) {
        node->total_size = part_end_offset;
    }

    ngx_shared_file_node_unlock(node);
    return NGX_OK;
}

ngx_int_t
ngx_shared_file_is_full(ngx_shared_file_t *file)
{
    ngx_shared_file_node_t  *node = file->node;
    ngx_int_t                full = 0;

    ngx_shared_file_node_lock(node);

    if (node->total_known && node->linar_size == node->total_size) {
        full = 1;
    }

    ngx_shared_file_node_unlock(node);
    return full;
}

ngx_int_t
ngx_shared_file_complete_if_uploaded(ngx_shared_file_t *file)
{
    ngx_shared_file_node_t  *node = file->node;

    ngx_shared_file_node_lock(node);

    if (node->completed) {
        ngx_shared_file_node_unlock(node);
        return NGX_DECLINED;
    }

    if (node->total_known && node->linar_size == node->total_size &&
        ngx_queue_empty(&node->parts))
    {
        node->completed = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
            "%s: %V - completed", __FUNCTION__, &node->id.str);

        ngx_shared_file_plugins_call_complete(file);

        ngx_shared_file_node_unlock(node);
        return NGX_OK;
    }

    ngx_shared_file_node_unlock(node);
    return NGX_DECLINED;
}
