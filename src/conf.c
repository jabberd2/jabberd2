#include "conf.h"
#include <lib/xconfig.h>
#include <lib/str.h>
#include <lib/sds.h>
#include <lib/log.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <gc.h>


xconfig_t *configuration = NULL;
log_t *log_config = NULL;


void config_init(int prime)
{
    log_config = log_get(PACKAGE_NAME ".configuration");
    configuration = xconfig_new(prime, log_config);
}

struct _config_data {
    bool            ready;
    const char      *key;
    const char      *default_value;
    config_callback *callback;
    void            *data;
};

void _config_callback(const char *key, xconfig_elem_t *elem, void *data)
{
    struct _config_data * const cd = (struct _config_data *) data;
    if (cd->ready) (cd->callback)(cd->key, xconfig_elem_get_one(elem, 0, cd->default_value), cd->data, elem);
}

void *config_register(const char *key, const char *prefixes, const char *default_value, config_callback *handler, void *data)
{
    if (handler == NULL || key == NULL) return NULL;

    LOG_DEBUG(log_config, "registering %p:%p for %s:%s=%s", handler, data, (prefixes ? prefixes : ""), key, default_value);

    struct _config_data *cd = GC_MALLOC(sizeof(struct _config_data));
    cd->key = key;
    cd->default_value = default_value;
    cd->callback = handler;
    cd->data = data;

    size_t plen = j_strlen(prefixes);
    if (plen == 0) {
        cd->ready = true;
        xconfig_subscribe(configuration, key, _config_callback, cd);
    }
    else {
        int count;
        sds *tokens = sdssplitlen(prefixes, plen, ":", 1, &count);
        for (int i = 0; i < count; i++) {
            sds full_key = sdsnew(tokens[i]);
            full_key = sdscat(full_key, ".");
            full_key = sdscat(full_key, key);
            if (i == count - 1) cd->ready = true;
            xconfig_subscribe(configuration, full_key, _config_callback, cd);
        }
        sdsfreesplitres(tokens, count);
    }

    return cd;
}

void config_unregister(void *id)
{
    xconfig_unsubscribe(configuration, _config_callback, id);
}

void config_set(const char *key, const char *value)
{
    if (key == NULL) return;
    xconfig_set_one(configuration, key, 0, value);
}


bool config_load(const char *path, const char *file)
{
    return xconfig_load_file(configuration, path, file);
}
