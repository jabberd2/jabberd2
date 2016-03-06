#ifndef INCL_MAIN_CONF_H
#define INCL_MAIN_CONF_H 1

#include <lib/xconfig.h>
#include <lib/str.h>
#include <stdbool.h>

typedef xconfig_callback    config_callback;

bool config_load(const char *path, const char *file);   /** loads configuration file at given path */
void config_register(const char *key, const char *default_value, config_callback *handler);  /**< registers function to listen for config value and changes */
void config_unregister(config_callback *handler);       /**< removes all module instance registrations */
void config_set(const char *key, const char *value);    /**< sets and distributes value to modules */


#define CONFIG_VAL_STRING(k, v, key, dest) \
    if (strcmp(k, key) == 0) { \
        GC_FREE((void*)dest); \
        dest = j_strdup(v);

#define CONFIG_VAL_INT(k, v, key, dest, def) \
    if (strcmp(k, key) == 0) { \
        dest = j_atoi(v, def);

#define CONFIG_VAL_BOOL(k, v, key, dest) \
    if (strcmp(k, key) == 0) { \
        dest = (j_atoi(v, 0) != 0);

#endif
