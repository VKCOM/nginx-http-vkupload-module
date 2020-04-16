#ifndef _NGX_SHARED_FILE_PLUGIN_H_INCLUDED_
#define _NGX_SHARED_FILE_PLUGIN_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_queue.h>
#include <ngx_rbtree.h>

#include "shared_file/ngx_shared_file_writer.h"

#define NGX_SHARED_FILE_PLUGINS_MAX 32

typedef struct ngx_shared_file_plugin_s  ngx_shared_file_plugin_t;

typedef ngx_int_t (*ngx_shared_file_plugin_conf_pt)(ngx_conf_t *cf);
typedef ngx_int_t (*ngx_shared_file_plugin_handler_pt)(ngx_shared_file_writer_t *writer, ngx_buf_t *buffer);
typedef ngx_int_t (*ngx_shared_file_plugin_complete_pt)(ngx_shared_file_t *file);
typedef void      (*ngx_shared_file_plugin_finalize_pt)(ngx_shared_file_manager_t *manager, ngx_shared_file_node_t *node);

struct ngx_shared_file_plugin_s {
    ngx_shared_file_plugin_conf_pt      configuration;
    ngx_shared_file_plugin_handler_pt   handler;
    ngx_shared_file_plugin_complete_pt  complete;
    ngx_shared_file_plugin_finalize_pt  finalize;

    ngx_str_t                           name;
    ngx_flag_t                          need_in_memory;
};


ngx_int_t
ngx_shared_file_plugin_register(ngx_shared_file_plugin_t *plugin, ngx_conf_t *cf);

ngx_shared_file_plugin_t *
ngx_shared_file_plugin_find(ngx_str_t *name);

ngx_int_t
ngx_shared_file_plugin_manager_register(ngx_shared_file_manager_t *manager, ngx_shared_file_plugin_t *plugin);

ngx_int_t
ngx_shared_file_plugin_manager_index(ngx_shared_file_manager_t *manager, ngx_shared_file_plugin_t *plugin);

void *
ngx_shared_file_node_plugin_ctx(ngx_shared_file_manager_t *manager, ngx_shared_file_node_t *node, ngx_shared_file_plugin_t *plugin);

ngx_int_t
ngx_shared_file_node_plugin_set_ctx(ngx_shared_file_manager_t *manager, ngx_shared_file_node_t *node,
    ngx_shared_file_plugin_t *plugin, void *ctx);

ngx_int_t
ngx_shared_file_plugins_call_handler(ngx_shared_file_writer_t *writer, ngx_buf_t *buffer);

ngx_int_t
ngx_shared_file_plugins_call_complete(ngx_shared_file_t *file);

ngx_int_t
ngx_shared_file_plugins_call_finalize(ngx_shared_file_manager_t *manager, ngx_shared_file_node_t *node);

#endif /* _NGX_SHARED_FILE_PLUGIN_H_INCLUDED_ */
