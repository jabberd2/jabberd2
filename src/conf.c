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

static void _config_regunreg(bool reg, const char *key, const char *default_value, config_callback *handler)
{
    if (handler == NULL || (reg && key == NULL)) return;

    int count, i;
    sds *tokens, full_key;
    tokens = sdssplitlen(key, j_strlen(key), ":", 1, &count);
    for (i = 0; i < count; i++) {
        if (count == 1) {
            full_key = sdsnew(key);
        } else {
            if (i == count - 1) break;
            full_key = sdsnew(tokens[i]);
            full_key = sdscat(full_key, ".");
            full_key = sdscat(full_key, key);
        }
        if (reg)
            xconfig_subscribe(configuration, key, handler, (void *)default_value);
        else
            xconfig_unsubscribe(configuration, handler, NULL);
    }

    sdsfreesplitres(tokens, count);
}

void config_register(const char *key, const char *default_value, config_callback *handler)
{
    _config_regunreg(true, key, default_value, handler);
}

void config_unregister(config_callback *handler)
{
    _config_regunreg(false, NULL, NULL, handler);
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
