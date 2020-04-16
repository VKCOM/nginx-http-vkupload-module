#ifndef _NGX_SHARED_FILE_PART_H_INCLUDED_
#define _NGX_SHARED_FILE_PART_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_queue.h>

typedef struct {
    ngx_queue_t                 queue;

    size_t                      offset;
    size_t                      size;
    size_t                      pos;

    unsigned                    completed   :1;
} ngx_shared_file_part_t;


size_t
ngx_shared_file_merge_parts(ngx_slab_pool_t *pool, ngx_queue_t *parts, size_t linar_size);

void
ngx_shared_file_complete_part(ngx_shared_file_part_t *part);

void
ngx_shared_file_insert_part(ngx_queue_t *parts, ngx_shared_file_part_t *part);

ngx_shared_file_part_t *
ngx_shared_file_create_part(ngx_slab_pool_t *pool, size_t offset, size_t size);

ngx_int_t
ngx_shared_file_parts_to_string(ngx_pool_t *pool, ngx_str_t *ranges, ngx_queue_t *parts,
    size_t linar_size, size_t total_size, int total_known);

#endif /* _NGX_SHARED_FILE_PART_H_INCLUDED_ */
