#ifndef _NGX_SHARED_FILE_H_INCLUDED_
#define _NGX_SHARED_FILE_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_queue.h>
#include <ngx_rbtree.h>

typedef struct ngx_shared_file_manager_s  ngx_shared_file_manager_t;
typedef struct ngx_shared_file_node_s  ngx_shared_file_node_t;
typedef struct ngx_shared_file_s  ngx_shared_file_t;
typedef struct ngx_shared_file_plugin_s  ngx_shared_file_plugin_t;
typedef struct ngx_shared_file_node_plugin_s  ngx_shared_file_node_plugin_t;
typedef struct ngx_shared_file_writer_s  ngx_shared_file_writer_t;

typedef ngx_int_t (*ngx_shared_file_plugin_pt)(ngx_shared_file_writer_t *writer, ngx_shared_file_plugin_t *plugin,
    ngx_buf_t *buffer, void *ctx);

struct ngx_shared_file_node_s {
    ngx_str_node_t              id;
    ngx_queue_t                 parts;
    ngx_queue_t                 plugins;

    ngx_str_t                   path;

    size_t                      total_size;
    size_t                      linar_size;
    size_t                      processed_size;

    time_t                      created_at;
    time_t                      updated_at;

    ngx_atomic_t                lock;
    ngx_atomic_t                uses;

    unsigned                    error:1;
    unsigned                    timeouted:1;
    unsigned                    completed:1;
    unsigned                    processed:1;
    unsigned                    total_known:1;
};

struct ngx_shared_file_s {
    ngx_pool_t                 *pool;
    ngx_log_t                  *log;
    ngx_shared_file_manager_t  *manager;

    ngx_shared_file_node_t     *node;
    ngx_pool_cleanup_t         *cleanup;
};

struct ngx_shared_file_node_plugin_s {
    ngx_queue_t                 queue;
    void                       *tag;

    u_char                      data[];
};

struct ngx_shared_file_plugin_s {
    ngx_queue_t                 queue;
    ngx_shared_file_plugin_pt   handler;

    void                       *ctx;
    void                       *tag;

    ngx_shared_file_plugin_t   *next;
};

void       ngx_shared_file_node_lock(ngx_shared_file_node_t *node);
void       ngx_shared_file_node_unlock(ngx_shared_file_node_t *node);

void       ngx_shared_file_node_incref(ngx_shared_file_manager_t *manager, ngx_shared_file_node_t *node); // required shm lock
void       ngx_shared_file_node_decref(ngx_shared_file_manager_t *manager, ngx_shared_file_node_t *node); // required shm lock

ngx_int_t  ngx_shared_file_open(ngx_shared_file_t *file, ngx_str_t *session_id);
ngx_int_t  ngx_shared_file_find(ngx_shared_file_t *file, ngx_str_t *session_id);
void       ngx_shared_file_close(ngx_shared_file_t *file);

ngx_int_t  ngx_shared_file_is_uploaded(ngx_shared_file_t *file);
ngx_int_t  ngx_shared_file_set_total(ngx_shared_file_t *file, size_t total_size, size_t part_offset, size_t part_size);

ngx_int_t  ngx_shared_file_complete_if_uploaded(ngx_shared_file_t *file);

#endif /* _NGX_SHARED_FILE_H_INCLUDED_ */
