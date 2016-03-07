#ifndef INCL_UTIL_MODULE_H
#define INCL_UTIL_MODULE_H 1

#include <stdlib.h>
#include <stdbool.h>
#include <uv.h>
#include <gc.h>
#include <lib/util.h> // convinience
#include <lib/xhash.h>

#define LIBRARY_DIR "/usr/lib"

typedef struct module_st module_t;
typedef struct mod_instance_st mod_instance_t;
typedef mod_instance_t *(mod_instanitate)(mod_instance_t *mi);
typedef bool (mod_recycle)(mod_instance_t *mi);

/**
 * Loadable module type
 */
struct module_st
{
    const char      *name;          /**< name as the module wants to be known */
    const char      *lib_name;      /**< name of the dynamic library module is coming from (maintained by module loader) */
    uv_lib_t        lib;            /**< module library handle */
    mod_instanitate *instanitate;   /**< allocates new module instance */
    mod_recycle     *recycle;       /**< shutdowns and frees module instance */
};

/**
 * Single instance of module
 */
struct mod_instance_st
{
    module_t    *mod;           /**< module this is an instance of */
    const char  *id;            /**< unique id of the instance */
    const char  *confprefixes;  /**< list of configuration prefixes, separated with colon ":" */
};

#define MI(mi) ((mod_instance_t*)mi)

module_t *module_load(xht *modules, const char *name);
int module_unload(xht *modules, const char *name);
mod_instance_t *module_new(module_t *mod, const char *id, const char *confprefixes);
int module_free(mod_instance_t *mi);

#endif
