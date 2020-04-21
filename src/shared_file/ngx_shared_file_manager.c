#include <ngx_core.h>
#include <ngx_queue.h>
#include <ngx_rbtree.h>

#include "shared_file/ngx_shared_file_manager.h"
#include "shared_file/ngx_shared_file.h"

#define NGX_SHARED_FILE_NODES_REMOVE_BULK 128
#define NGX_SHARED_FILE_NODES_REMOVE_AFTER (60 * 30) // 30 min

ngx_int_t
ngx_shared_file_manager_init(ngx_shared_file_manager_t *manager, ngx_shm_zone_t *zone)
{
    manager->zone = zone;
    manager->pool = (ngx_slab_pool_t *) zone->shm.addr;

    if (zone->shm.exists) {
        manager->tree = manager->pool->data;
        return NGX_OK;
    }

    manager->tree = ngx_slab_calloc(manager->pool, sizeof(ngx_shared_file_tree_t));
    if (manager->tree == NULL) {
        return NGX_ERROR;
    }

    manager->pool->data = manager->tree;
    ngx_rbtree_init(&manager->tree->rbtree, &manager->tree->sentinel, ngx_str_rbtree_insert_value);

    return NGX_OK;
}

ngx_int_t
ngx_shared_file_manager_copy(ngx_shared_file_manager_t *manager, ngx_shared_file_manager_t *manager_old)
{
    manager->tree = manager_old->tree;
    manager->pool = manager_old->pool;
    manager->zone = manager_old->zone;

    return NGX_OK;
}

ngx_msec_t
ngx_shared_file_manager_handler(void *data)
{
    ngx_shared_file_manager_t  *manager = data;
    ngx_shared_file_node_t     *node;
    ngx_shared_file_node_t     *node_for_remove[NGX_SHARED_FILE_NODES_REMOVE_BULK];
    ngx_int_t                   nodes_for_remove_count = 0;
    ngx_rbtree_node_t          *rbnode, *rbroot, *rbsentinel;
    time_t                      current_time;
    ngx_int_t                   i;

    ngx_shmtx_lock(&manager->pool->mutex);

    rbsentinel = &manager->tree->sentinel;
    rbroot = manager->tree->rbtree.root;

    if (rbroot == rbsentinel) {
        ngx_shmtx_unlock(&manager->pool->mutex);
        return 20000;
    }

    current_time = ngx_time();

    for (rbnode = ngx_rbtree_min(rbroot, rbsentinel);
         rbnode;
         rbnode = ngx_rbtree_next(&manager->tree->rbtree, rbnode))
    {
        node = ngx_queue_data(rbnode, ngx_shared_file_node_t, id.node);

        if ((current_time - node->updated_at) > NGX_SHARED_FILE_NODES_REMOVE_AFTER) {
            ngx_shared_file_node_incref_locked(manager, node);

            node_for_remove[nodes_for_remove_count] = node;
            nodes_for_remove_count++;

            if (nodes_for_remove_count == NGX_SHARED_FILE_NODES_REMOVE_BULK) {
                break;
            }
        }
    }

    ngx_shmtx_unlock(&manager->pool->mutex);

    for (i = 0; i < nodes_for_remove_count; i++) {
        node = node_for_remove[i];
        node->timeouted = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
            "%s: %V - timeouted", __FUNCTION__, &node->id.str);

        ngx_shmtx_lock(&manager->pool->mutex);
        ngx_shared_file_node_decref_locked(manager, node);
        ngx_shmtx_unlock(&manager->pool->mutex);
    }

    return 20000;
}
