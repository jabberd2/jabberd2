/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or drvify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/** @file storage/storage.h
  * @brief data structures and prototypes for the storage manager
  * @author Eugene Agafonov
  * $Date:  $
  * $Revision: $
  */

#ifndef _STORAGE_H_
#define _STORAGE_H_

#ifdef HAVE_CONFIG_H
  #include <config.h>
#endif

#include <util/pool.h>
#include <util/xhash.h>
#include <util/nad.h>
#include <util/util.h>

#ifdef _WIN32
  #ifdef _USRDLL
    #define DLLEXPORT  __declspec(dllexport)
    #define ST_API     __declspec(dllimport)
  #else
    #define DLLEXPORT  __declspec(dllimport)
    #define ST_API     __declspec(dllexport)
  #endif
#else
  #define DLLEXPORT
  #define ST_API
#endif

#ifdef __cplusplus
extern "C" {
#endif
/* Forward declarations */
typedef struct storage_st   *storage_t;


/* object sets */

/** object types */
typedef enum {
    os_type_BOOLEAN,            /**< boolean (0 or 1) */
    os_type_INTEGER,            /**< integer */
    os_type_STRING,             /**< string */
    os_type_NAD,                /**< XML */
    os_type_UNKNOWN             /**< unknown */
} os_type_t;

/** a single tuple (value) within an object */
typedef struct os_field_st {
    char        *key;           /**< field name */
    void        *val;           /**< field value */
    os_type_t   type;           /**< field type */
} *os_field_t;

typedef struct os_st        *os_t;
typedef struct os_object_st *os_object_t;

/** object set (ie group of several objects) */
struct os_st {
    pool_t      p;              /**< pool the objects are allocated from */

    os_object_t head;           /**< first object in the list */
    os_object_t tail;           /**< last object in the list */

    int         count;          /**< number of objects in this set */

    os_object_t iter;           /**< pointer for iteration */
};

/** an object */
struct os_object_st {
    /** object set this object is part of */
    os_t        os;

    /** fields (key is field name) */
    xht         hash;

    os_object_t next;           /**< next object in the list */
    os_object_t prev;           /**< previous object in the list */
};

/** create a new object set */
ST_API os_t        os_new(void);
/** free an object set */
ST_API void        os_free(os_t os);

/** number of objects in a set */
ST_API int         os_count(os_t os);

/** set iterator to first object (1 = exists, 0 = doesn't exist) */
ST_API int         os_iter_first(os_t os);

/** set iterator to next object (1 = exists, 0 = doesn't exist) */
ST_API int         os_iter_next(os_t os);

/** get the object currently under the iterator */
ST_API os_object_t os_iter_object(os_t os);

/** create a new object in this set */
ST_API os_object_t os_object_new(os_t os);
/** free an object (remove it from its set) */
ST_API void        os_object_free(os_object_t o);

/** add a field to the object */
ST_API void        os_object_put(os_object_t o, const char *key, const void *val, os_type_t type);

/** get a field from the object of type type (result in val), ret 0 == not found */
ST_API int         os_object_get(os_t os, os_object_t o, const char *key, void **val, os_type_t type, os_type_t *ot);

/** wrappers for os_object_get to avoid breaking strict-aliasing rules in gcc3 */
ST_API int         os_object_get_nad(os_t os, os_object_t o, const char *key, nad_t *val);
ST_API int         os_object_get_str(os_t os, os_object_t o, const char *key, char **val);
ST_API int         os_object_get_int(os_t os, os_object_t o, const char *key, int *val);
ST_API int         os_object_get_bool(os_t os, os_object_t o, const char *key, int *val);
ST_API int         os_object_get_time(os_t os, os_object_t o, const char *key, time_t *val);

/** wrappers for os_object_put to avoid breaking strict-aliasing rules in gcc3 */
ST_API void        os_object_put_time(os_object_t o, const char *key, const time_t *val);

/** set field iterator to first field (1 = exists, 0 = doesn't exist) */
ST_API int         os_object_iter_first(os_object_t o);
/** set field iterator to next field (1 = exists, 0 = doesn't exist) */
ST_API int         os_object_iter_next(os_object_t o);
/** extract field values from field currently under the iterator */
ST_API void        os_object_iter_get(os_object_t o, char **key, void **val, os_type_t *type);


/* storage manager */

/** storage driver return values */
typedef enum {
    st_SUCCESS,                 /**< call completed successful */
    st_FAILED,                  /**< call failed (driver internal error) */
    st_NOTFOUND,                /**< no matching objects were found */
    st_NOTIMPL                  /**< call not implemented */
} st_ret_t;

typedef struct st_driver_st *st_driver_t;

/** storage manager data */
struct storage_st {
//    sm_t        sm;             /**< sm context */
    config_t    config;         /**< config */
    log_t       log;            /**< log context */

    xht         drivers;        /**< pointers to drivers (key is driver name) */
    xht         types;          /**< pointers to drivers (key is type name) */

    st_driver_t default_drv;    /**< default driver (used when there is no module
                                     explicitly registered for a type) */
};

/** data for a single storage driver */
struct st_driver_st {
    storage_t   st;             /**< storage manager context */

    char        *name;          /**< name of driver */

#ifdef __cplusplus
    void        *_private;       /**< driver private data */
#else
    void        *private;       /**< driver private data */
#endif

    /** called to find out if this driver can handle a particular type */
    st_ret_t    (*add_type)(st_driver_t drv, const char *type);

    /** put handler */
    st_ret_t    (*put)(st_driver_t drv, const char *type, const char *owner, os_t os);
    /** get handler */
    st_ret_t    (*get)(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t *os);
    /** get custom SQL request */
    st_ret_t    (*get_custom_sql)(st_driver_t drv, const char *request, os_t *os);
    /** count handler */
    st_ret_t    (*count)(st_driver_t drv, const char *type, const char *owner, const char *filter, int *count);
    /** delete handler */
#ifdef __cplusplus
    st_ret_t    (*_delete)(st_driver_t drv, const char *type, const char *owner, const char *filter);
#else
    st_ret_t    (*delete)(st_driver_t drv, const char *type, const char *owner, const char *filter);
#endif
    /** replace handler */
    st_ret_t    (*replace)(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t os);

    /** called when driver is freed */
    void        (*free)(st_driver_t drv);
};

/** allocate a storage manager instance */
ST_API storage_t       storage_new(config_t config, log_t log);
/** free a storage manager instance */
ST_API void            storage_free(storage_t st);

/** associate this data type with this driver */
ST_API st_ret_t        storage_add_type(storage_t st, const char *driver, const char *type);

/** store objects in this set */
ST_API st_ret_t        storage_put(storage_t st, const char *type, const char *owner, os_t os);
/** get objects matching this filter */
ST_API st_ret_t        storage_get(storage_t st, const char *type, const char *owner, const char *filter, os_t *os);
/** get objects matching custom SQL query */
ST_API st_ret_t        storage_get_custom_sql(storage_t st, const char *request, os_t *os, const char *type);
/** count objects matching this filter */
ST_API st_ret_t        storage_count(storage_t st, const char *type, const char *owner, const char *filter, int *count);
/** delete objects matching this filter */
ST_API st_ret_t        storage_delete(storage_t st, const char *type, const char *owner, const char *filter);
/** replace objects matching this filter with objects in this set (atomic delete + get) */
ST_API st_ret_t        storage_replace(storage_t st, const char *type, const char *owner, const char *filter, os_t os);

/** type for the driver init function */
typedef st_ret_t (*st_driver_init_fn)(st_driver_t);


/** storage filter types */
typedef enum {
    st_filter_type_PAIR,        /**< key=value pair */
    st_filter_type_AND,         /**< and operator */
    st_filter_type_OR,          /**< or operator */
    st_filter_type_NOT          /**< not operator */
} st_filter_type_t;

typedef struct st_filter_st *st_filter_t;
/** filter abstraction */
struct st_filter_st {
    pool_t              p;      /**< pool that filter is allocated from */

    st_filter_type_t    type;   /**< type of this filter */

    char                *key;   /**< key for PAIR filters */
    char                *val;   /**< value for PAIR filters */

    st_filter_t         sub;    /**< sub-filter for operator filters */

    st_filter_t         next;   /**< next filter in a group */
};

/** create a filter abstraction from a LDAP-like filter string */
ST_API st_filter_t     storage_filter(const char *filter);

/** see if the object matches the filter */
ST_API int             storage_match(st_filter_t filter, os_object_t o, os_t os);

#ifdef __cplusplus
} // extern "C"
#endif


#endif // _STORAGE_H_

