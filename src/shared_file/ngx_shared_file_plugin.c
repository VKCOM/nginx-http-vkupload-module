#include <ngx_core.h>
#include <ngx_http.h>

#include "shared_file/ngx_shared_file_manager.h"
#include "shared_file/ngx_shared_file_plugin.h"
#include "shared_file/ngx_shared_file.h"

static ngx_shared_file_plugin_t  *plugins[NGX_SHARED_FILE_PLUGINS_MAX];
static ngx_uint_t                 plugins_count;

ngx_int_t
ngx_shared_file_plugin_register(ngx_shared_file_plugin_t *plugin, ngx_conf_t *cf)
{
    ngx_int_t  rc;

    if (plugins_count >= NGX_SHARED_FILE_PLUGINS_MAX) {
        return NGX_ERROR;
    }

    rc = plugin->configuration(cf);
    if (rc != NGX_OK) {
        return rc;
    }

    plugins[plugins_count] = plugin;
    ++plugins_count;

    return NGX_OK;
}

ngx_shared_file_plugin_t *
ngx_shared_file_plugin_find(ngx_str_t *name)
{
    ngx_shared_file_plugin_t  *plugin = NULL;
    ngx_uint_t                 i;

    for (i = 0; i < plugins_count; i++) {
        if (plugins[i] == NULL) {
            break;
        }

        if (plugins[i]->name.len == name->len &&
            ngx_strncmp(plugins[i]->name.data, name->data, name->len) == 0)
        {
            plugin = plugins[i];
            break;
        }
    }

    return plugin;
}

ngx_int_t
ngx_shared_file_plugin_manager_register(ngx_shared_file_manager_t *manager, ngx_shared_file_plugin_t *plugin)
{
    if (manager->plugins_count == NGX_SHARED_FILE_PLUGINS_MAX) {
        return NGX_ERROR;
    }

    manager->plugins[manager->plugins_count] = plugin;
    manager->plugins_count++;

    return NGX_OK;
}

ngx_int_t
ngx_shared_file_plugin_manager_index(ngx_shared_file_manager_t *manager, ngx_shared_file_plugin_t *plugin)
{
    ngx_int_t  i;

    for (i = 0; i < manager->plugins_count; i++) {
        if (manager->plugins[i] == plugin) {
            return i;
        }
    }

    return NGX_ERROR;
}

void *
ngx_shared_file_plugin_ctx(ngx_shared_file_t *file, ngx_shared_file_plugin_t *plugin)
{
    ngx_int_t  index;

    index = ngx_shared_file_plugin_manager_index(file->manager, plugin);
    if (index == NGX_ERROR) {
        return NULL;
    }

    return file->node->plugins[index];
}

ngx_int_t
ngx_shared_file_plugin_set_ctx(ngx_shared_file_t *file, ngx_shared_file_plugin_t *plugin, void *ctx)
{
    ngx_int_t  index;

    index = ngx_shared_file_plugin_manager_index(file->manager, plugin);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    file->node->plugins[index] = ctx;

    return NGX_OK;
}

ngx_int_t
ngx_shared_file_plugins_run(ngx_shared_file_writer_t *writer, ngx_buf_t *buffer)
{
    ngx_shared_file_manager_t  *manager = writer->file->manager;
    ngx_int_t                   i, rc;

    for (i = 0; i < manager->plugins_count; i++) {
        rc = manager->plugins[i]->handler(writer, manager->plugins[i], buffer);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}