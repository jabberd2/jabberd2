#include "module.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <uv.h>
#include <gc.h>
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <lib/str.h>
#include <lib/log.h>

extern const char *modules_path;

#define LOG_CATEGORY "util.module"

static void _module_release(module_t *mod)
{
    uv_dlclose(&(mod->lib));
    GC_FREE((void*)mod->lib_name);
    GC_FREE(mod);
}

module_t *module_load(xht *modules, const char *name)
{
    module_t *mod = NULL;
    char mod_fullpath[PATH_MAX];

    assert(modules);
    assert(name);

    log4c_category_t *log = log_get(LOG_CATEGORY);

    do {
        mod = xhash_get(modules, name);

        if (mod == NULL) {
            mod = (module_t *) GC_MALLOC(sizeof(module_t));

            mod->lib_name = j_strdup(name);

            if (modules_path != NULL) {
                LOG_NOTICE(log, "modules search path: %s", modules_path);
            } else {
                LOG_NOTICE(log, "modules search path undefined, using default: "LIBRARY_DIR);
            }

            snprintf(mod_fullpath, PATH_MAX, "%s/mod_%s.so", modules_path ? modules_path : LIBRARY_DIR, name);

            if (uv_dlopen(mod_fullpath, &(mod->lib))) {
                LOG_ERROR(log, "failed loading module '%s': %s", name, uv_dlerror(&(mod->lib)));
                break;
            }

            if (uv_dlsym(&(mod->lib), "module_name", (void **) &(mod->name))) {
                LOG_ERROR(log, "no module_name in module '%s': %s", name, uv_dlerror(&(mod->lib)));
                uv_dlclose(&(mod->lib));
                break;
            }

            if (uv_dlsym(&(mod->lib), "module_instanitate", (void **) &(mod->instanitate))) {
                LOG_ERROR(log, "no module_instanitate in module '%s': %s", name, uv_dlerror(&(mod->lib)));
                uv_dlclose(&(mod->lib));
                break;
            }

            if (uv_dlsym(&(mod->lib), "module_recycle", (void **) &(mod->recycle))) {
                LOG_DEBUG(log, "no module_recycle in module '%s': %s", name, uv_dlerror(&(mod->lib)));
            }

            LOG_DEBUG(log, "loaded module '%s'", name);
        }

        xhash_put(modules, mod->lib_name, (void *) mod);
        return mod;

    } while (0);

    /* error handling */
    xhash_zap(modules, name);
    _module_release(mod);
    return NULL;
}

int module_unload(xht *modules, const char *name)
{
    log4c_category_t *log = log4c_category_get(LOG_CATEGORY);
    module_t *mod = xhash_get(modules, name);

    if (!mod) {
        LOG_ERROR(log, "unload of not loaded module '%s' requested", name);
        return -1;
    }

    xhash_zap(modules, name);
    _module_release(mod);

    return 0;
}

mod_instance_t *module_new(module_t *mod, const char *id, const char *confprefixes)
{
    assert(mod);
    assert(mod->instanitate);
    mod_instance_t *mi = GC_MALLOC(sizeof(mod_instance_t));
    assert(mi);
    mi->mod = mod;
    mi->id = id;
    mi->confprefixes = confprefixes;
    mi = mod->instanitate(mi);
    assert(mi);
    return mi;
}

int module_free(mod_instance_t *mi)
{
    assert(mi);
    assert(mi->mod);
    return (mi->mod->recycle) ? mi->mod->recycle(mi) : 0;
}
