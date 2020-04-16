#ifndef _NGX_SHARED_FILE_WRITER_H_INCLUDED_
#define _NGX_SHARED_FILE_WRITER_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_queue.h>

#include "shared_file/ngx_shared_file.h"
#include "shared_file/ngx_shared_file_part.h"

typedef struct ngx_shared_file_writer_s  ngx_shared_file_writer_t;

struct ngx_shared_file_writer_s {
    ngx_shared_file_t                 *file;

    ngx_shared_file_part_t            *part;
    ngx_file_t                         stream;

    ngx_buf_t                         *buffer;
};

ngx_int_t
ngx_shared_file_writer_open(ngx_shared_file_writer_t *writer, size_t offset, size_t size);

ngx_int_t
ngx_shared_file_write(ngx_shared_file_writer_t *writer, u_char *data, size_t len);

void
ngx_shared_file_writer_close(ngx_shared_file_writer_t *writer);

#endif /* _NGX_SHARED_FILE_WRITER_H_INCLUDED_ */
