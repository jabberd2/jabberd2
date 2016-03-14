#ifndef INCL_MAIN_CONF_H
#define INCL_MAIN_CONF_H 1

#include <lib/xconfig.h>
#include <lib/str.h>
#include <stdbool.h>

typedef void (config_callback)(const char *key, const char *value, void *data, xconfig_elem_t *elem);

bool config_load(const char *path, const char *file);   /** loads configuration file at given path */
void *config_register(const char *key, const char *prefixes, const char *default_value, config_callback *handler, void *data);  /**< registers function to listen for config value and changes */
void config_unregister(void *id);       /**< removes registration of given id */
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
