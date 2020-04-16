#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_vkupload_module.h"
#include "ngx_http_vkupload_request.h"
#include "ngx_http_vkupload_fields.h"

#include "shared_file/ngx_shared_file_manager.h"
#include "shared_file/ngx_shared_file_plugin.h"

#include "handler/ngx_http_vkupload_multipart.h"
#include "handler/ngx_http_vkupload_resumable.h"

static ngx_int_t  ngx_http_vkupload_init(ngx_conf_t *cf);
static void  *ngx_http_vkupload_create_main_conf(ngx_conf_t *cf);
static void  *ngx_http_vkupload_create_loc_conf(ngx_conf_t *cf);
static char  *ngx_http_vkupload_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char  *ngx_http_vkupload_manager_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char  *ngx_http_vkupload_pass_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char  *ngx_conf_set_vkupload_key_val_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t  ngx_http_vkupload_init_zone(ngx_shm_zone_t *shzone, void *data);

static ngx_int_t  ngx_http_vkupload_request_handler(ngx_http_request_t *request);
static void  ngx_http_vkupload_request_body_handler(ngx_http_request_t *request);
static void  ngx_http_vkupload_request_read_event_handler(ngx_http_request_t *request);

static ngx_command_t ngx_http_vkupload_commands[] = {
    { ngx_string("vkupload_manager"),
        NGX_HTTP_MAIN_CONF
            |NGX_CONF_2MORE,
        ngx_http_vkupload_manager_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_vkupload_main_conf_t, managers),
        NULL
    },

    { ngx_string("vkupload_pass"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE2,
        ngx_http_vkupload_pass_set_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    { ngx_string("vkupload_field"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE2,
        ngx_conf_set_vkupload_key_val_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, upload_fields),
        NULL
    },

    { ngx_string("vkupload_multipart"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, multipart),
        NULL
    },

    { ngx_string("vkupload_multipart_field"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, multipart_fields),
        NULL
    },

    { ngx_string("vkupload_resumable"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, resumable),
        NULL
    },

    { ngx_string("vkupload_resumable_session_name"),
        NGX_HTTP_LOC_CONF
            |NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_vkupload_loc_conf_t, resumable_session_name),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_vkupload_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_vkupload_init,                 /* postconfiguration */

    ngx_http_vkupload_create_main_conf,     /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_vkupload_create_loc_conf,      /* create location configuration */
    ngx_http_vkupload_merge_loc_conf        /* merge location configuration */
};

ngx_module_t ngx_http_vkupload_module = {
    NGX_MODULE_V1,
    &ngx_http_vkupload_module_ctx,          /* module context */
    ngx_http_vkupload_commands,             /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_vkupload_init(ngx_conf_t *cf)
{
    ngx_int_t  rc;

    rc = ngx_http_vkupload_request_fields_init(cf);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_http_vkupload_request_handler_register(&ngx_http_vkupload_multipart_handler, cf);
    ngx_http_vkupload_request_handler_register(&ngx_http_vkupload_resumable_handler, cf);

    return NGX_OK;
}

static void *
ngx_http_vkupload_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_vkupload_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_vkupload_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->managers, cf->pool, 4, sizeof(ngx_shared_file_manager_t *)) != NGX_OK) {
        return NULL;
    }

    return conf;
}

static void *
ngx_http_vkupload_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_vkupload_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_vkupload_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upload_url = { NULL, 0 };
     */

    conf->manager = NGX_CONF_UNSET_PTR;
    conf->upload_fields = NGX_CONF_UNSET_PTR;

    conf->multipart = NGX_CONF_UNSET;
    conf->multipart_fields = NGX_CONF_UNSET_PTR;

    conf->resumable = NGX_CONF_UNSET;
    conf->resumable_session_name = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *
ngx_http_vkupload_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_vkupload_loc_conf_t  *prev = parent;
    ngx_http_vkupload_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->manager, prev->manager, NULL);
    ngx_conf_merge_str_value(conf->upload_url, prev->upload_url, "");
    ngx_conf_merge_ptr_value(conf->upload_fields, prev->upload_fields, NULL);

    ngx_conf_merge_value(conf->multipart, prev->multipart, 0);
    ngx_conf_merge_ptr_value(conf->multipart_fields, prev->multipart_fields, NULL);

    ngx_conf_merge_value(conf->resumable, prev->resumable, 0);
    ngx_conf_merge_ptr_value(conf->resumable_session_name, prev->resumable_session_name, NULL);

    return NGX_CONF_OK;
}

static char *
ngx_http_vkupload_pass_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_vkupload_loc_conf_t    *vkupload_lconf = conf;
    ngx_http_vkupload_main_conf_t   *vkupload_mconf = ngx_http_conf_get_module_main_conf(cf, ngx_http_vkupload_module);
    ngx_http_core_loc_conf_t        *http_core_lconf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    ngx_shared_file_manager_t      **managers, *manager = NULL;
    ngx_str_t                       *manager_name, *name, *upload_url;
    ngx_uint_t                       i;

    if (vkupload_lconf->manager != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    manager_name = &(((ngx_str_t *) cf->args->elts)[1]);
    if (manager_name->len == 0) {
        return "empty value";
    }

    if (vkupload_lconf->upload_url.len != 0) {
        return "is duplicate";
    }

    upload_url = &(((ngx_str_t *) cf->args->elts)[2]);
    if (upload_url->len == 0) {
        return "empty value";
    }

    managers = vkupload_mconf->managers.elts;

    for (i = 0; i < vkupload_mconf->managers.nelts; i++) {
        name = &managers[i]->zone->shm.name;

        if (name->len == manager_name->len
            && ngx_strncmp(name->data, manager_name->data, manager_name->len) == 0)
        {
            manager = managers[i];
            break;
        }
    }

    if (manager == NULL) {
        return "unknown manager zone";
    }

    vkupload_lconf->upload_url = *upload_url;
    vkupload_lconf->manager = manager;

    http_core_lconf->handler = ngx_http_vkupload_request_handler;

    return NGX_CONF_OK;
}

static char *
ngx_http_vkupload_manager_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *confp = conf;

    u_char                      *last, *p, chmod[5];
    ssize_t                      size;
    ngx_str_t                    s, name, *value;
    ngx_uint_t                   i, n, access;
    ngx_array_t                 *managers;
    ngx_shared_file_manager_t   *manager, **manager_ptr;
    ngx_shared_file_plugin_t    *plugin;
    ngx_path_t                  *path;
    ngx_shm_zone_t              *zone;

    name.len = 0;
    size = 0;

    access = 0644;

    manager = ngx_pcalloc(cf->pool, sizeof(ngx_shared_file_manager_t));
    if (manager == NULL) {
        return NGX_CONF_ERROR;
    }

    path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (path == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    path->name = value[1];
    if (path->name.data[path->name.len - 1] == '/') {
        path->name.len--;
    }

    if (ngx_conf_full_name(cf->cycle, &path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "access=", 7) == 0) {

            p = value[i].data + 7;
            last = value[i].data + value[i].len;

            if ((last - p) != 4 || *p != '0') {
                goto invalid_access;
            }

            ngx_memcpy(chmod, p, 4);
            chmod[4] = '\0';

            access = strtol((char *) chmod, NULL, 8);

            if (access != 0) {
                continue;
            }

        invalid_access:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid \"access\" \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[i].data, "levels=", 7) == 0) {

            p = value[i].data + 7;
            last = value[i].data + value[i].len;

            for (n = 0; n < NGX_MAX_PATH_LEVEL && p < last; n++) {

                if (*p > '0' && *p < '3') {

                    path->level[n] = *p++ - '0';
                    path->len += path->level[n] + 1;

                    if (p == last) {
                        break;
                    }

                    if (*p++ == ':' && n < NGX_MAX_PATH_LEVEL - 1 && p < last) {
                        continue;
                    }

                    goto invalid_levels;
                }

                goto invalid_levels;
            }

            if (path->len < 10 + NGX_MAX_PATH_LEVEL) {
                continue;
            }

        invalid_levels:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid \"levels\" \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (16 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "keys zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "plugins=", 8) == 0) {

            s.data = value[i].data + 8;
            s.len = value[i].data + value[i].len - s.data;

            for ( ; ; ) {
                p = (u_char *) ngx_strchr(s.data, ',');

                if (p == NULL) {
                    name.data = s.data;
                    name.len = value[i].data + value[i].len - s.data;
                } else {
                    name.data = s.data;
                    name.len = p - s.data;

                    ++p;
                }

                plugin = ngx_shared_file_plugin_find(&name);

                if (plugin == NULL) {
                    return "error";
                }

                if (ngx_shared_file_plugin_manager_register(manager, plugin) != NGX_OK) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "error register \"%V\" plugin", &name);

                    return NGX_CONF_ERROR;
                }

                if (p == NULL) {
                    break;
                }
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    path->manager = ngx_http_vkupload_manager_handler;
    path->data = manager;
    path->conf_file = cf->conf_file->file.name.data;
    path->line = cf->conf_file->line;

    manager->access = access;
    manager->path = path;
    if (ngx_add_path(cf, &manager->path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_vkupload_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    zone->init = ngx_http_vkupload_init_zone;
    zone->data = manager;
    manager->zone = zone;

    managers = (ngx_array_t *) (confp + cmd->offset);

    manager_ptr = ngx_array_push(managers);
    if (manager_ptr == NULL) {
        return NGX_CONF_ERROR;
    }

    *manager_ptr = manager;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_vkupload_init_zone(ngx_shm_zone_t *zone, void *data)
{
    ngx_shared_file_manager_t  *manager_old = data;
    ngx_shared_file_manager_t  *manager = zone->data;
    ngx_uint_t                  n;

    if (manager_old) {
        if (ngx_strcmp(manager->path->name.data, manager_old->path->name.data) != 0) {
            ngx_log_error(NGX_LOG_EMERG, zone->shm.log, 0,
                          "cache \"%V\" uses the \"%V\" cache path "
                          "while previously it used the \"%V\" cache path",
                          &zone->shm.name, &manager->path->name,
                          &manager_old->path->name);

            return NGX_ERROR;
        }

        for (n = 0; n < NGX_MAX_PATH_LEVEL; n++) {
            if (manager->path->level[n] != manager_old->path->level[n]) {
                ngx_log_error(NGX_LOG_EMERG, zone->shm.log, 0,
                              "cache \"%V\" had previously different levels",
                              &zone->shm.name);
                return NGX_ERROR;
            }
        }

        return ngx_shared_file_manager_copy(manager, manager_old);
    }

    return ngx_shared_file_manager_init(manager, zone);
}

static char *
ngx_conf_set_vkupload_key_val_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_http_vkupload_key_val_t    *field;
    ngx_int_t                        n;
    ngx_str_t                       *value;
    ngx_http_script_compile_t        sc;
    ngx_array_t                    **fields;

    fields = (ngx_array_t **) (p + cmd->offset);

    if (*fields == NGX_CONF_UNSET_PTR) {
        *fields = ngx_array_create(cf->pool, 1, sizeof(ngx_http_vkupload_key_val_t));

        if (*fields == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    field = ngx_array_push(*fields);
    if (field == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    field->value.hash = 1;
    field->value.key = value[1];
    field->value.value = value[2];
    field->name_lengths = NULL;
    field->name_values = NULL;
    field->value_lengths = NULL;
    field->value_values = NULL;

    /*
     * Compile field name
     */
    n = ngx_http_script_variables_count(&value[1]);
    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &field->name_lengths;
        sc.values = &field->name_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Compile field value
     */
    n = ngx_http_script_variables_count(&value[2]);
    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[2];
        sc.lengths = &field->value_lengths;
        sc.values = &field->value_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

/** --- handlers --- **/

static ngx_int_t
ngx_http_vkupload_request_handler(ngx_http_request_t *request)
{
    ngx_http_vkupload_request_t  *vkupload;
    ngx_int_t                     rc;

    rc = ngx_http_vkupload_request_handler_find(request, &vkupload);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_http_set_ctx(request, vkupload, ngx_http_vkupload_module);
    request->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(request, ngx_http_vkupload_request_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return ngx_http_vkupload_request_finalize_handler(vkupload, rc);
    }

    return NGX_DONE;
}

static void
ngx_http_vkupload_request_body_handler(ngx_http_request_t *request)
{
    ngx_http_vkupload_request_t  *vkupload;
    ngx_http_request_body_t      *request_body;
    ngx_int_t                     rc;

    vkupload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);
    if (vkupload == NULL) {
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    request_body = request->request_body;
    if (request_body == NULL) {
        ngx_http_vkupload_request_finalize(vkupload, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rc = vkupload->handler->data(vkupload, request_body->bufs);
    if (rc != NGX_OK) {
        ngx_http_vkupload_request_finalize(vkupload, rc);
        return;
    }

    if (request->reading_body) {
        request->read_event_handler = ngx_http_vkupload_request_read_event_handler;
    } else {
        ngx_http_vkupload_request_finalize(vkupload, NGX_OK);
        return;
    }
}

static void
ngx_http_vkupload_request_read_event_handler(ngx_http_request_t *request)
{
    ngx_http_vkupload_request_t  *vkupload;
    ngx_http_request_body_t      *request_body;
    ngx_int_t                     rc, rc_data;

    vkupload = ngx_http_get_module_ctx(request, ngx_http_vkupload_module);
    request_body = request->request_body;

    if (ngx_exiting || ngx_terminate) {
        ngx_http_vkupload_request_finalize(vkupload, NGX_HTTP_CLOSE);

        return;
    }

     for ( ;; ) {
        rc = ngx_http_read_unbuffered_request_body(request);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_http_vkupload_request_finalize(vkupload, rc);

            return;
        }

        if (request_body->bufs == NULL) {
            return;
        }

        rc_data = vkupload->handler->data(vkupload, request_body->bufs);
        if (rc_data != NGX_OK) {
            ngx_http_vkupload_request_finalize(vkupload, rc_data);

            return;
        }

        if (rc == NGX_OK) {
            ngx_http_vkupload_request_finalize(vkupload, NGX_OK);

            return;
        }

        request_body->bufs = NULL;
    }
}
