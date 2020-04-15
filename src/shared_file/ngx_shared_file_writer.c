#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_queue.h>

#include "shared_file/ngx_shared_file.h"
#include "shared_file/ngx_shared_file_part.h"
#include "shared_file/ngx_shared_file_writer.h"
#include "shared_file/ngx_shared_file_manager.h"

ngx_int_t
ngx_shared_file_writer_open(ngx_shared_file_writer_t *writer, size_t offset, size_t size)
{
    ngx_shared_file_manager_t  *manager;
    ngx_shared_file_t          *file;
    ngx_shared_file_node_t     *node;
    ngx_shared_file_part_t     *part;
    ngx_pool_cleanup_t         *cln;
    ngx_pool_cleanup_file_t    *clnf;
    ngx_int_t                   rc;

    file = writer->file;
    manager = file->manager;
    node = file->node;

    ngx_shared_file_node_lock(node);

    if (node->completed) {
        ngx_shared_file_node_unlock(node);
        return NGX_DECLINED;
    }

    if (node->path.data == NULL) {
        writer->stream.log = file->log;
        writer->stream.fd = NGX_INVALID_FILE;

        rc = ngx_create_temp_file(&writer->stream, manager->path, file->pool,
            1 /* TODO: comment */, 0 /* TODO: comment */, manager->access);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, file->log, ngx_errno,
                "%s: error create tmp file for session %V", __FUNCTION__, &node->id.str);

            ngx_shared_file_node_unlock(node);
            return NGX_ERROR;
        }

        node->path.len = writer->stream.name.len;
        node->path.data = ngx_slab_calloc(manager->pool, node->path.len + 1);
        if (node->path.data == NULL) {
            ngx_log_error(NGX_LOG_WARN, file->log, 0,
                "%s: error allocate path data for session %V", __FUNCTION__, &node->id.str);

            ngx_shared_file_node_unlock(node);
            return NGX_ERROR;
        }

        ngx_memcpy(node->path.data, writer->stream.name.data, node->path.len);
    } else {
        cln = ngx_pool_cleanup_add(file->pool, sizeof(ngx_pool_cleanup_file_t));
        if (cln == NULL) {
            ngx_shared_file_node_unlock(node);
            return NGX_ERROR;
        }

        writer->stream.log = file->log;
        writer->stream.name = node->path;
        writer->stream.fd = ngx_open_file(writer->stream.name.data, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);

        if (writer->stream.fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_WARN, file->log, 0,
                "%: error open file for session %V (%V)",
                __FUNCTION__, &node->id.str, &writer->stream.name);

            ngx_shared_file_node_unlock(node);
            return NGX_ERROR;
        }

        cln->handler = ngx_pool_cleanup_file;
        clnf = cln->data;

        clnf->fd = writer->stream.fd;
        clnf->name = writer->stream.name.data;
        clnf->log = writer->stream.log;
    }

    part = ngx_shared_file_create_part(manager->pool, offset, size);
    if (part == NULL) {
        ngx_log_error(NGX_LOG_WARN, file->log, 0,
            "ngx_shared_file_writer_open: error allocate part for session %V", &node->id.str);

        ngx_shared_file_node_unlock(node);
        return NGX_ERROR;
    }

    writer->part = part;

    ngx_shared_file_insert_part(&node->parts, part);
    ngx_shared_file_node_unlock(node);

    return NGX_OK;
}

ngx_int_t
ngx_shared_file_write(ngx_shared_file_writer_t *writer, u_char *data, size_t len)
{
    ngx_shared_file_part_t     *part = writer->part;
    ngx_shared_file_node_t     *node = writer->file->node;
    ngx_file_t                 *stream = &writer->stream;
    ngx_shared_file_manager_t  *manager = writer->file->manager;
    ngx_queue_t                *plugin_q;
    ngx_shared_file_plugin_t   *plugin;
    ngx_buf_t                   buffer;
    ngx_int_t                   rc;

    size_t                   linar_size;
    size_t                   skip = 0;

    if (part->pos + len > (part->offset + part->size)) {
        ngx_log_error(NGX_LOG_WARN, stream->log, 0,
            "%s: invalid size for write session %V", __FUNCTION__, &node->id.str);

        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_shared_file_node_lock(node);

    linar_size = node->linar_size;

    if (linar_size > part->pos) {
        if (linar_size > part->pos + len) {
            // skip write
            part->pos += len;

            ngx_shared_file_node_unlock(node);
            return NGX_OK;
        }

        skip = (linar_size - part->pos);
        part->pos += skip;

        data += skip;
        len -= skip;
    }

    ngx_shared_file_node_unlock(node);

    if (ngx_write_file(stream, (u_char *) data, len, part->pos) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, stream->log, ngx_errno,
            "%s: error write data session %V", __FUNCTION__, &node->id.str);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_shared_file_node_lock(node);

    if (!node->processed &&
        ngx_queue_head(&node->parts) == ngx_queue_last(&node->parts))
    {
        if (node->linar_size == part->pos) {
            node->processed = 1;
            node->linar_size += len;

            ngx_memzero(&buffer, sizeof(ngx_buf_t));

            buffer.file = &writer->stream;
            buffer.file_pos = part->pos;
            buffer.file_last = part->pos + len;
            buffer.start = buffer.pos = data;
            buffer.last = buffer.end = data + len;
            buffer.memory = 1;

            ngx_shared_file_node_unlock(node);

            for (plugin_q = ngx_queue_head(&manager->plugins); plugin_q != ngx_queue_sentinel(&manager->plugins);
                plugin_q = ngx_queue_next(plugin_q))
            {
                plugin = ngx_queue_data(plugin_q, ngx_shared_file_plugin_t, queue);

                rc = plugin->handler(writer, plugin, &buffer, plugin->ctx);
                if (rc != NGX_OK) {
                    return rc;
                }
            }

            ngx_shared_file_node_lock(node);

            node->processed_size += len;
            node->processed = 0;
        }
    }

    ngx_shared_file_node_unlock(node);
    part->pos += len;

    return NGX_OK;
}

void
ngx_shared_file_writer_close(ngx_shared_file_writer_t *writer)
{
    ngx_shared_file_node_t     *node = writer->file->node;
    ngx_shared_file_manager_t  *manager = writer->file->manager;

    if (writer->part == NULL) {
        return;
    }

    ngx_shared_file_node_lock(node);

    ngx_shared_file_complete_part(writer->part);
    node->linar_size = ngx_shared_file_merge_parts(manager->pool, &node->parts, node->linar_size);

    ngx_shared_file_node_unlock(node);
    writer->part = NULL;
}

ngx_int_t
ngx_shared_file_writer_call_plugin(ngx_shared_file_writer_t *writer)
{
    ngx_shared_file_node_t     *node = writer->file->node;
    ngx_shared_file_manager_t  *manager = writer->file->manager;
    ngx_queue_t                *plugin_q;
    ngx_shared_file_plugin_t   *plugin;
    ngx_buf_t                   buffer;
    ngx_int_t                   rc;

    ngx_shared_file_node_lock(node);

    if (node->processed) {
        ngx_shared_file_node_unlock(node);
        return NGX_OK;
    }

    node->processed = 1;

    while (node->linar_size > node->processed_size) {
        ngx_memzero(&buffer, sizeof(ngx_buf_t));

        buffer.in_file = 1;
        buffer.file = &writer->stream;
        buffer.file_pos = node->linar_size;
        buffer.file_last = node->linar_size + (node->linar_size - node->processed_size);

        ngx_shared_file_node_unlock(node);

        for (plugin_q = ngx_queue_head(&manager->plugins); plugin_q != ngx_queue_sentinel(&manager->plugins);
            plugin_q = ngx_queue_next(plugin_q))
        {
            plugin = ngx_queue_data(plugin_q, ngx_shared_file_plugin_t, queue);

            rc = plugin->handler(writer, plugin, &buffer, plugin->ctx);
            if (rc != NGX_OK) {
                return rc;
            }
        }

        ngx_shared_file_node_lock(node);

        node->processed_size += (buffer.file_last - buffer.file_pos);
    }

    node->processed = 0;

    ngx_shared_file_node_unlock(node);
    return NGX_OK;
}