#ifndef _NGX_SHARED_FILE_MANAGER_H_INCLUDED_
#define _NGX_SHARED_FILE_MANAGER_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_queue.h>
#include <ngx_rbtree.h>

#include "shared_file/ngx_shared_file_plugin.h"

typedef struct ngx_shared_file_tree_s     ngx_shared_file_tree_t;
typedef struct ngx_shared_file_manager_s  ngx_shared_file_manager_t;

struct ngx_shared_file_tree_s {
    ngx_rbtree_t                       rbtree;
    ngx_rbtree_node_t                  sentinel;
};

struct ngx_shared_file_manager_s {
    ngx_shared_file_tree_t             *tree;
    ngx_slab_pool_t                    *pool;
    ngx_shm_zone_t                     *zone;

    ngx_path_t                         *path;
    ngx_uint_t                          access;

    ngx_uint_t                          uniq;

    ngx_shared_file_plugin_t           *plugins[NGX_SHARED_FILE_PLUGINS_MAX];
    ngx_int_t                           plugins_count;
    ngx_int_t                           plugins_need_in_memory;
};

ngx_int_t
ngx_shared_file_manager_init(ngx_shared_file_manager_t *manager, ngx_shm_zone_t *zone);

ngx_int_t
ngx_shared_file_manager_copy(ngx_shared_file_manager_t *manager, ngx_shared_file_manager_t *manager_old);

ngx_msec_t
ngx_shared_file_manager_handler(void *data);

#endif /* _NGX_SHARED_FILE_MANAGER_H_INCLUDED_ */
