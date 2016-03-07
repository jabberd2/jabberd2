#include <src/conf.h>
#include <src/module.h>
#include <lib/log.h>

#include <assert.h>

/**
 * @file example.c
 * @brief Example core module
 */

typedef struct mod_example_instance_st
{
    mod_instance_t _;   /* "inherit" mod_instance */

    /* and add your own members */
    log4c_category_t    *log;

    /* other module instance members */

} mod_example_instance_t;

static void _conf_debug(const char *key, const char *value, void *data)
{
    mod_example_instance_t * const mi = (mod_example_instance_t *) data;
    LOG_DEBUG(mi->log, "got configuration, key '%s' value '%s'", key, value);
}


DLLEXPORT char *module_name = MOD_NAME;

DLLEXPORT bool module_recycle(mod_instance_t *_mi)
{
    mod_example_instance_t * const mi = (mod_example_instance_t *) _mi;
    LOG_TRACE(mi->log, "recycling module " MOD_NAME "[%p]", mi);

    /* release other module instance members */

    GC_FREE(mi);
    return false;
}

DLLEXPORT mod_instance_t *module_instanitate(mod_instance_t *_mi)
{
    mod_example_instance_t *mi = (mod_example_instance_t *) GC_REALLOC(_mi, sizeof(mod_example_instance_t));
    assert(mi);

    mi->log = log_get("mod." MOD_NAME);
    assert(mi->log);

    /* other module instance members initialization */

    /* example configuration subscription */
    config_register("test.foo.bar", MI(mi)->confprefixes, NULL, _conf_debug, mi);

    LOG_TRACE(mi->log, "module " MOD_NAME "[%p] instanitated", mi)
    return (mod_instance_t *) mi;
}
