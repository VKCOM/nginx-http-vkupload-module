#ifndef _NGX_SHARED_FILE_H_INCLUDED_
#define _NGX_SHARED_FILE_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_queue.h>
#include <ngx_rbtree.h>
#include <ngx_md5.h>

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
} ngx_shared_file_manager_sh_t;

typedef struct {
    ngx_shared_file_manager_sh_t      *shtree;
    ngx_slab_pool_t                   *shpool;
    ngx_path_t                        *file_path;
    ngx_uint_t                         file_access;
} ngx_shared_file_manager_t;

typedef struct {
    ngx_str_node_t  id;
    ngx_queue_t     parts;

    ngx_str_t       path;
    size_t          total_size;
    size_t          linar_size;
    

    time_t          created_at;
    time_t          updated_at;

    ngx_atomic_t    lock;
    ngx_atomic_t    uses;

    ngx_md5_t       md5;
    size_t          md5_size;

    unsigned        completed:1;
    unsigned        removed:1;
    unsigned        total_known:1;
    unsigned        md5_processed:1;
} ngx_shared_file_sh_t;

typedef struct {
    ngx_queue_t            queue;

    size_t                 start;
    size_t                 end;
    size_t                 pos;

    unsigned               completed:1;
} ngx_shared_file_part_sh_t;

typedef struct {
    ngx_shared_file_manager_t  *manager;
    ngx_file_t                 *file;
    ngx_pool_t                 *pool;
    ngx_log_t                  *log;

    ngx_shared_file_part_sh_t  *shpart;
    ngx_shared_file_sh_t       *shfile;
} ngx_shared_file_session_t;

typedef struct {
    ngx_shared_file_sh_t       *shfile;
    ngx_shared_file_manager_t  *manager;
} ngx_shared_file_cleanup_t;

ngx_int_t ngx_shared_file_manager_init(ngx_shared_file_manager_t *manager, ngx_shm_zone_t *shzone);
ngx_int_t ngx_shared_file_manager_copy(ngx_shared_file_manager_t *manager, ngx_shared_file_manager_t *manager_old);

ngx_int_t ngx_shared_file_open(ngx_shared_file_session_t *session, ngx_str_t *session_id, size_t total_size, size_t start, size_t end);
ngx_int_t ngx_shared_file_write(ngx_shared_file_session_t *session, const u_char *data, size_t size);
void ngx_shared_file_close(ngx_shared_file_session_t *session);
void ngx_shared_file_remove(ngx_shared_file_session_t *session);

ngx_int_t ngx_shared_file_session_md5_calc(ngx_shared_file_session_t *session);
void ngx_shared_file_md5_final(ngx_shared_file_session_t *session, u_char result[16]);

size_t ngx_shared_file_get_total_size(ngx_shared_file_session_t *session);
size_t ngx_shared_file_get_linar_size(ngx_shared_file_session_t *session);
ngx_int_t ngx_shared_file_get_ranges(ngx_shared_file_session_t *session, ngx_str_t *ranges);

ngx_int_t ngx_shared_file_is_completed(ngx_shared_file_session_t *session);

#endif /* _NGX_SHARED_FILE_H_INCLUDED_ */
