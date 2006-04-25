/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
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

/** @file sm/storage.c
  * @brief storage manager
  * @author Robert Norris
  * $Date: 2005/06/02 06:31:10 $
  * $Revision: 1.21 $
  */

/* these functions implement a multiplexor to get calls to the correct driver
 * for the given type */

#include "sm.h"

#include <ctype.h>

/* if you add a driver, you'll need to update these arrays */
#ifdef STORAGE_DB
extern st_ret_t st_db_init(st_driver_t);
#endif
#ifdef STORAGE_FS
extern st_ret_t st_fs_init(st_driver_t);
#endif
#ifdef STORAGE_MYSQL
extern st_ret_t st_mysql_init(st_driver_t);
#endif
#ifdef STORAGE_PGSQL
extern st_ret_t st_pgsql_init(st_driver_t);
#endif
#ifdef STORAGE_ORACLE
extern st_ret_t st_oracle_init(st_driver_t);
#endif
#ifdef STORAGE_SQLITE
extern st_ret_t st_sqlite_init(st_driver_t);
#endif

static char *st_driver_names[] = {
#ifdef STORAGE_DB
    "db",
#endif
#ifdef STORAGE_FS
    "fs",
#endif
#ifdef STORAGE_MYSQL
    "mysql",
#endif
#ifdef STORAGE_PGSQL
    "pgsql",
#endif
#ifdef STORAGE_ORACLE
    "oracle",
#endif
#ifdef STORAGE_SQLITE
    "sqlite",
#endif
    NULL
};

static st_driver_init_fn st_driver_inits[] = {
#ifdef STORAGE_DB
    st_db_init,
#endif
#ifdef STORAGE_FS
    st_fs_init,
#endif
#ifdef STORAGE_MYSQL
    st_mysql_init,
#endif
#ifdef STORAGE_PGSQL
    st_pgsql_init,
#endif
#ifdef STORAGE_ORACLE
    st_oracle_init,
#endif
#ifdef STORAGE_SQLITE
    st_sqlite_init,
#endif
    NULL
};


storage_t storage_new(sm_t sm) {
    storage_t st;
    int i, j;
    config_elem_t elem;
    char *type;
    st_ret_t ret;

    st = (storage_t) malloc(sizeof(struct storage_st));
    memset(st, 0, sizeof(struct storage_st));

    st->sm = sm;
    st->drivers = xhash_new(101);
    st->types = xhash_new(101);

    /* register types declared in the config file */
    elem = config_get(sm->config, "storage.driver");
    if(elem != NULL) {
        for(i = 0; i < elem->nvalues; i++) {
            type = j_attr((const char **) elem->attrs[i], "type"); 
            for(j = 0; st_driver_names[j] != NULL; j++) {
                if(strcmp(elem->values[i], st_driver_names[j]) == 0) {
                    if(type == NULL)
                        ret = storage_add_type(st, st_driver_names[j], NULL);
                    else
                        ret = storage_add_type(st, st_driver_names[j], type);
                    /* Initialisation of storage type failed */
                    if (ret != st_SUCCESS) {
                      free(st);
                      return NULL;
                    }
                }
            }
        }
    }

    return st;
}

static void _st_driver_reaper(xht drivers, const char *driver, void *val, void *arg) {
    st_driver_t drv = (st_driver_t) val;

    (drv->free)(drv);

    free(drv);
}

void storage_free(storage_t st) {
    /* close down drivers */
    xhash_walk(st->drivers, _st_driver_reaper, NULL);

    xhash_free(st->drivers);
    xhash_free(st->types);
    free(st);
}

st_ret_t storage_add_type(storage_t st, const char *driver, const char *type) {
    st_driver_t drv;
    st_driver_init_fn init = NULL;
    int i;
    st_ret_t ret;

    /* startup, see if we've already registered this type */
    if(type == NULL) {
        log_debug(ZONE, "adding arbitrary types to driver '%s'", driver);

        /* see if we already have one */
        if(st->default_drv != NULL) {
            log_debug(ZONE, "we already have a default handler, ignoring this one");
            return st_FAILED;
        }
    } else {
        log_debug(ZONE, "adding type '%s' to driver '%s'", type, driver);

        /* see if we already have one */
        if(xhash_get(st->types, type) != NULL) {
            log_debug(ZONE, "we already have a handler for type '%s', ignoring this one");
            return st_FAILED;
        }
    }

    /* get the driver */
    drv = xhash_get(st->drivers, driver);
    if(drv == NULL) {
        log_debug(ZONE, "driver not loaded, trying to init");

        /* find the init function */
        for(i = 0; st_driver_names[i] != NULL; i++) {
            if(strcmp(driver, st_driver_names[i]) == 0) {
                init = st_driver_inits[i];
                break;
            }
        }

        /* d'oh */
        if(init == NULL) {
            log_debug(ZONE, "no init function for driver '%s'", driver);

            return st_FAILED;
        }

        /* make a new driver structure */
        drv = (st_driver_t) malloc(sizeof(struct st_driver_st));
        memset(drv, 0, sizeof(struct st_driver_st));

        drv->st = st;

        log_debug(ZONE, "calling driver initializer");

        /* init */
        if((init)(drv) == st_FAILED) {
            log_write(st->sm->log, LOG_NOTICE, "initialisation of storage driver '%s' failed", driver);
            free(drv);
            return st_FAILED;
        }

        /* add it to the drivers hash so we can find it later */
        drv->name = pstrdup(xhash_pool(st->drivers), driver);
        xhash_put(st->drivers, drv->name, (void *) drv);

        log_write(st->sm->log, LOG_NOTICE, "initialised storage driver '%s'", driver);
    }

    /* if its a default, set it up as such */
    if(type == NULL) {
        st->default_drv = drv;
        return st_SUCCESS;
    }

    /* its a real type, so let the driver know */
    if(type != NULL && (ret = (drv->add_type)(drv, type)) != st_SUCCESS) {
        log_debug(ZONE, "driver '%s' can't handle '%s' data", driver, type);
        return ret;
    }

    /* register the type */
    xhash_put(st->types, pstrdup(xhash_pool(st->types), type), (void *) drv);

    return st_SUCCESS;
}

st_ret_t storage_put(storage_t st, const char *type, const char *owner, os_t os) {
    st_driver_t drv;
    st_ret_t ret;

    log_debug(ZONE, "storage_put: type=%s owner=%s os=%X", type, owner, os);

    /* find the handler for this type */
    drv = xhash_get(st->types, type);
    if(drv == NULL) {
        /* never seen it before, so it goes to the default driver */
        drv = st->default_drv;
        if(drv == NULL) {
            log_debug(ZONE, "no driver associated with type, and no default driver");

            return st_NOTIMPL;
        }

        /* register the type */
        ret = storage_add_type(st, drv->name, type);
        if(ret != st_SUCCESS)
            return ret;
    }

    return (drv->put)(drv, type, owner, os);
}

st_ret_t storage_get(storage_t st, const char *type, const char *owner, const char *filter, os_t *os) {
    st_driver_t drv;
    st_ret_t ret;

    log_debug(ZONE, "storage_get: type=%s owner=%s filter=%s", type, owner, filter);

    /* find the handler for this type */
    drv = xhash_get(st->types, type);
    if(drv == NULL) {
        /* never seen it before, so it goes to the default driver */
        drv = st->default_drv;
        if(drv == NULL) {
            log_debug(ZONE, "no driver associated with type, and no default driver");

            return st_NOTIMPL;
        }

        /* register the type */
        ret = storage_add_type(st, drv->name, type);
        if(ret != st_SUCCESS)
            return ret;
    }

    return (drv->get)(drv, type, owner, filter, os);
}

st_ret_t storage_count(storage_t st, const char *type, const char *owner, const char *filter, int *count) {
    st_driver_t drv;
    st_ret_t ret;

    log_debug(ZONE, "storage_count: type=%s owner=%s filter=%s", type, owner, filter);

    /* find the handler for this type */
    drv = xhash_get(st->types, type);
    if(drv == NULL) {
        /* never seen it before, so it goes to the default driver */
        drv = st->default_drv;
        if(drv == NULL) {
            log_debug(ZONE, "no driver associated with type, and no default driver");
            return st_NOTIMPL;
        }

        /* register the type */
        ret = storage_add_type(st, drv->name, type);
        if(ret != st_SUCCESS)
            return ret;
    }

    return (drv->count != NULL) ? (drv->count)(drv, type, owner, filter, count) : st_NOTIMPL;
}


st_ret_t storage_delete(storage_t st, const char *type, const char *owner, const char *filter) {
    st_driver_t drv;
    st_ret_t ret;

    log_debug(ZONE, "storage_zap: type=%s owner=%s filter=%s", type, owner, filter);

    /* find the handler for this type */
    drv = xhash_get(st->types, type);
    if(drv == NULL) {
        /* never seen it before, so it goes to the default driver */
        drv = st->default_drv;
        if(drv == NULL) {
            log_debug(ZONE, "no driver associated with type, and no default driver");

            return st_NOTIMPL;
        }

        /* register the type */
        ret = storage_add_type(st, drv->name, type);
        if(ret != st_SUCCESS)
            return ret;
    }

    return (drv->delete)(drv, type, owner, filter);
}

st_ret_t storage_replace(storage_t st, const char *type, const char *owner, const char *filter, os_t os) {
    st_driver_t drv;
    st_ret_t ret;

    log_debug(ZONE, "storage_replace: type=%s owner=%s filter=%s os=%X", type, owner, filter, os);

    /* find the handler for this type */
    drv = xhash_get(st->types, type);
    if(drv == NULL) {
        /* never seen it before, so it goes to the default driver */
        drv = st->default_drv;
        if(drv == NULL) {
            log_debug(ZONE, "no driver associated with type, and no default driver");

            return st_NOTIMPL;
        }

        /* register the type */
        ret = storage_add_type(st, drv->name, type);
        if(ret != st_SUCCESS)
            return ret;
    }

    return (drv->replace)(drv, type, owner, filter, os);
}

static st_filter_t _storage_filter(pool p, const char *f, int len) {
    char *c, *key, *val, *sub;
    int vallen;
    st_filter_t res, sf;
    
    if(f[0] != '(' && f[len] != ')')
        return NULL;

    /* key/value pair */

    /* if value is numeric, then represented as is.                                      */
    /* if value is string, it is preceded by length: e.g. "key=5:abcde"                  */
    /* (needed to pass values which include a closing bracket ')', e.g. in resourcenames */

    if(isalpha(f[1])) {
        key = strdup(f+1);

        c = strchr(key, '=');
        if(c == NULL) {
		free(key);
		return NULL;
	}
        *c = '\0'; c++;

        val = c;

	/* decide whether number or string by checking for ':' before ')' */

        while (*c != ':' && *c != ')' && *c)
           c++;

        if (!*c) {
		free(key);
		return NULL;
	}

        if (*c == ':') {
                /* string */
                *c = '\0';
                vallen = atoi(val);
                c++;
                val = c;
                c += vallen;
        }

        *c = '\0';
        log_debug(ZONE, "extracted key %s val %s", key, val);

        res = pmalloco(p, sizeof(struct st_filter_st));
        res->p = p;

        res->type = st_filter_type_PAIR;
        res->key = pstrdup(p, key);
        res->val = pstrdup(p, val);

	free(key);
        return res;
    }

    /* operator */
    if(f[1] != '&' && f[1] != '|' && f[2] != '!')
        return NULL;

    res = pmalloco(p, sizeof(struct st_filter_st));
    res->p = p;

    switch(f[1]) {
        case '&': res->type = st_filter_type_AND; break;
        case '|': res->type = st_filter_type_OR; break;
        case '!': res->type = st_filter_type_NOT; break;
    }

    /* remove const for now, we will not change the string */
    c = (char *) &f[2];
    while(*c == '(') {
        sub = c;
        c = strchr(sub, ')');
        c++;

        sf = _storage_filter(p, (const char *) sub, c - sub);

        sf->next = res->sub;
        res->sub = sf;
    }

    return res;
}

st_filter_t storage_filter(const char *filter) {
    pool p;
    st_filter_t f;

    if(filter == NULL)
        return NULL;

    p = pool_new();

    f = _storage_filter(p, filter, strlen(filter));
    if(f == NULL)
        pool_free(p);

    return f;
}

int _storage_match(st_filter_t f, os_object_t o, os_t os) {
    void *val;
    os_type_t ot;
    st_filter_t scan;

    switch(f->type) {
        case st_filter_type_PAIR:
            if(!os_object_get(os, o, f->key, &val, os_type_UNKNOWN, &ot))
                return 0;

            switch(ot) {
                case os_type_BOOLEAN:
                    if((atoi(f->val) != 0) == (((int) val) != 0))
                        return 1;
                    return 0;

                case os_type_INTEGER:
                    if(atoi(f->val) == (int) val)
                        return 1;
                    return 0;

                case os_type_STRING:
                    if(strcmp(f->val, val) == 0)
                        return 1;
                    return 0;
                
                case os_type_NAD:
                    /* !!! this is hard, but probably not needed. if you need it, you implement it ;) */
                    return 1;

		case os_type_UNKNOWN:
	             return 0;
            }

            return 0;

        case st_filter_type_AND:
            for(scan = f->sub; scan != NULL; scan = scan->next)
                if(!_storage_match(scan, o, os))
                    return 0;
            return 1;

        case st_filter_type_OR:
            for(scan = f->sub; scan != NULL; scan = scan->next)
                if(_storage_match(scan, o, os))
                    return 1;
            return 0;

        case st_filter_type_NOT:
            if(_storage_match(f->sub, o, os))
                return 0;
            return 1;
    }

    return 0;
}

int storage_match(st_filter_t filter, os_object_t o, os_t os) {
    if(filter == NULL)
        return 1;

    return _storage_match(filter, o, os);
}
