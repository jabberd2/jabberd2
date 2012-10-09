/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
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

/** @file sm/storage_db.c
  * @brief berkeley db storage module
  * @author Robert Norris
  * $Date: 2005/06/02 04:48:25 $
  * $Revision: 1.26 $
  */

/*
 * !!! we must catch DB_RUNRECOVERY and call _st_db_panic(). I would argue that
 *     Berkeley should do this for all cases, not just for the process that
 *     caused the fault, but I'm not sure they see it that way. (I have asked,
 *     just waiting for a reply)
 *
 *     Sleepycat SR#7019 resolved this. There is an unreleased patch available
 *     (I have a copy) that will be in 4.2 (due in June).
 */

#include "storage.h"
#include <db.h>

/** internal structure, holds our data */
typedef struct drvdata_st {
    DB_ENV *env;

    const char *path;
    int sync;

    xht dbs;

    xht filters;
} *drvdata_t;

/** internal structure, holds a single db handle */
typedef struct dbdata_st {
    drvdata_t data;

    DB *db;
} *dbdata_t;

/* union for strict alias rules in gcc3 */
union xhashv {
  void **val;
  dbdata_t *dbd_val;
};

static st_ret_t _st_db_add_type(st_driver_t drv, const char *type) {
    drvdata_t data = (drvdata_t) drv->private;
    dbdata_t dbd;
    int err;
    
    dbd = (dbdata_t) calloc(1, sizeof(struct dbdata_st));

    dbd->data = data;

    if((err = db_create(&(dbd->db), data->env, 0)) != 0) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't create db handle: %s", db_strerror(err));
        free(dbd);
        return st_FAILED;
    }

    if((err = dbd->db->set_flags(dbd->db, DB_DUP)) != 0) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't set database for duplicate storage: %s", db_strerror(err));
        dbd->db->close(dbd->db, 0);
        free(dbd);
        return st_FAILED;
    }

    if((err = dbd->db->open(dbd->db, NULL, "sm.db", type, DB_HASH, DB_AUTO_COMMIT | DB_CREATE, 0)) != 0) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't open storage db: %s", db_strerror(err));
        dbd->db->close(dbd->db, 0);
        free(dbd);
        return st_FAILED;
    }

    xhash_put(data->dbs, type, dbd);

    return st_SUCCESS;
}

/** make a new cursor (optionally wrapped in a txn) */
static st_ret_t _st_db_cursor_new(st_driver_t drv, dbdata_t dbd, DBC **cursor, DB_TXN **txnid) {
    int err;

    if(txnid != NULL)
        if((err = dbd->data->env->txn_begin(dbd->data->env, NULL, txnid, DB_TXN_SYNC)) != 0) {
            log_write(drv->st->log, LOG_ERR, "db: couldn't begin new transaction: %s", db_strerror(err));
            return st_FAILED;
        }

    if(txnid == NULL)
        err = dbd->db->cursor(dbd->db, NULL, cursor, 0);
    else
        err = dbd->db->cursor(dbd->db, *txnid, cursor, 0);

    if(err != 0) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't create cursor: %s", db_strerror(err));
        if(txnid != NULL)
            (*txnid)->abort(*txnid);
        return st_FAILED;
    }

    return st_SUCCESS;
}

/** close down a cursor */
static st_ret_t _st_db_cursor_free(st_driver_t drv, dbdata_t dbd, DBC *cursor, DB_TXN *txnid) {
    int err;

    if((err = cursor->c_close(cursor)) != 0) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't close cursor: %s", db_strerror(err));
        if(txnid != NULL)
            txnid->abort(txnid);
        return st_FAILED;
    }

    if(txnid != NULL)
        if((err = txnid->commit(txnid, DB_TXN_SYNC)) != 0) {
            log_write(drv->st->log, LOG_ERR, "db: couldn't commit transaction: %s", db_strerror(err));
            return st_FAILED;
        }

    return st_SUCCESS;
}

static void _st_db_object_serialise(os_object_t o, char **buf, int *len) {
    char *key, *xmlstr;
    const char *xml;
    void *val;
    os_type_t ot;
    int cur = 0, xlen;

    log_debug(ZONE, "serialising object");

    *buf = NULL;
    *len = 0;

    if(os_object_iter_first(o))
        do {
            os_object_iter_get(o, &key, &val, &ot);
            
            log_debug(ZONE, "serialising key %s", key);

            ser_string_set(key, &cur, buf, len);
            ser_int_set(ot, &cur, buf, len);

            switch(ot) {
                case os_type_BOOLEAN:
                    ser_int_set(((int) (long) val) != 0, &cur, buf, len);
                    break;

                case os_type_INTEGER:
                    ser_int_set((int) (long) val, &cur, buf, len);
                    break;

                case os_type_STRING:
                    ser_string_set((char *) val, &cur, buf, len);
                    break;

                case os_type_NAD:
                    nad_print((nad_t) val, 0, &xml, &xlen);
                    xmlstr = (char *) malloc(sizeof(char) * (xlen + 1));
                    sprintf(xmlstr, "%.*s", xlen, xml);
                    ser_string_set(xmlstr, &cur, buf, len);
                    free(xmlstr);
                    break;

                case os_type_UNKNOWN:
                    break;
            }
        } while(os_object_iter_next(o));

    *len = cur;
}

static os_object_t _st_db_object_deserialise(st_driver_t drv, os_t os, const char *buf, int len) {
    os_object_t o;
    int cur;
    char *key, *sval;
    int ot;
    int ival;
    nad_t nad;

    log_debug(ZONE, "deserialising object");

    o = os_object_new(os);

    cur = 0;
    while(cur < len) {
        if(ser_string_get(&key, &cur, buf, len) != 0 || ser_int_get(&ot, &cur, buf, len) != 0) {
            log_debug(ZONE, "ran off the end of the buffer");
            return o;
        }

        log_debug(ZONE, "deserialising key %s", key);

        switch((os_type_t) ot) {
            case os_type_BOOLEAN:
                ser_int_get(&ival, &cur, buf, len);
                ival = (ival != 0);
                os_object_put(o, key, &ival, os_type_BOOLEAN);
                break;

            case os_type_INTEGER:
                ser_int_get(&ival, &cur, buf, len);
                os_object_put(o, key, &ival, os_type_INTEGER);
                break;

            case os_type_STRING:
                ser_string_get(&sval, &cur, buf, len);
                os_object_put(o, key, sval, os_type_STRING);
                free(sval);
                break;

            case os_type_NAD:
                ser_string_get(&sval, &cur, buf, len);
                nad = nad_parse(sval, strlen(sval));
                free(sval);
                if(nad == NULL) {
                    log_write(drv->st->log, LOG_ERR, "db: unable to parse stored XML - database corruption?");
                    return NULL;
                }
                os_object_put(o, key, nad, os_type_NAD);
                nad_free(nad);
                break;
  
           case os_type_UNKNOWN:
                break;
        }

        free(key);
    }

    return o;
}

static st_ret_t _st_db_put_guts(st_driver_t drv, const char *type, const char *owner, os_t os, dbdata_t dbd, DBC *c, DB_TXN *t) {
    DBT key, val;
    os_object_t o;
    char *buf;
    int len, err;

    memset(&key, 0, sizeof(DBT));
    memset(&val, 0, sizeof(DBT));

    key.data = (char *) owner;
    key.size = strlen(owner);

    if(os_iter_first(os))
        do {
            o = os_iter_object(os);
            _st_db_object_serialise(o, &buf, &len);

            val.data = buf;
            val.size = len;
        
            if((err = c->c_put(c, &key, &val, DB_KEYLAST)) != 0) {
                log_write(drv->st->log, LOG_ERR, "db: couldn't store value for type %s owner %s in storage db: %s", type, owner, db_strerror(err));
                free(buf);
                return st_FAILED;
            }

            free(buf);

        } while(os_iter_next(os));

    return st_SUCCESS;
}

static st_ret_t _st_db_put(st_driver_t drv, const char *type, const char *owner, os_t os) {
    drvdata_t data = (drvdata_t) drv->private;
    dbdata_t dbd = xhash_get(data->dbs, type);
    DBC *c;
    DB_TXN *t;
    st_ret_t ret;

    if(os_count(os) == 0)
        return st_SUCCESS;

    ret = _st_db_cursor_new(drv, dbd, &c, &t);
    if(ret != st_SUCCESS)
        return ret;

    ret = _st_db_put_guts(drv, type, owner, os, dbd, c, t);
    if(ret != st_SUCCESS) {
        t->abort(t);
        _st_db_cursor_free(drv, dbd, c, NULL);
        return st_FAILED;
    }

    return _st_db_cursor_free(drv, dbd, c, t);
}

static st_ret_t _st_db_get(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t *os) {
    drvdata_t data = (drvdata_t) drv->private;
    dbdata_t dbd = xhash_get(data->dbs, type);
    DBC *c;
    DB_TXN *t;
    st_ret_t ret;
    DBT key, val;
    st_filter_t f;
    int err;
    os_object_t o;
    char *cfilter;

    ret = _st_db_cursor_new(drv, dbd, &c, &t);
    if(ret != st_SUCCESS)
        return ret;

    f = NULL;
    if(filter != NULL) {
        f = xhash_get(data->filters, filter);
        if(f == NULL) {
            f = storage_filter(filter);
            cfilter = pstrdup(xhash_pool(data->filters), filter);
            xhash_put(data->filters, cfilter, (void *) f);
            pool_cleanup(xhash_pool(data->filters), (pool_cleanup_t) pool_free, f->p);
        }
    }

    memset(&key, 0, sizeof(DBT));
    memset(&val, 0, sizeof(DBT));

    key.data = (char *) owner;
    key.size = strlen(owner);

    *os = os_new();

    err = c->c_get(c, &key, &val, DB_SET);
    while(err == 0) {
        o = _st_db_object_deserialise(drv, *os, val.data, val.size);

        if(o != NULL && !storage_match(f, o, *os))
            os_object_free(o);

        err = c->c_get(c, &key, &val, DB_NEXT_DUP);
    }

    if(err != 0 && err != DB_NOTFOUND) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't move cursor for type %s owner %s in storage db: %s", type, owner, db_strerror(err));
        t->abort(t);
        _st_db_cursor_free(drv, dbd, c, NULL);
        os_free(*os);
        *os = NULL;
        return st_FAILED;
    }

    ret = _st_db_cursor_free(drv, dbd, c, t);
    if(ret != st_SUCCESS) {
        os_free(*os);
        *os = NULL;
        return ret;
    }

    if(os_count(*os) == 0) {
        os_free(*os);
        *os = NULL;
        return st_NOTFOUND;
    }

    return st_SUCCESS;
}

static st_ret_t _st_db_delete_guts(st_driver_t drv, const char *type, const char *owner, const char *filter, dbdata_t dbd, DBC *c, DB_TXN *t) {
    drvdata_t data = (drvdata_t) drv->private;
    DBT key, val;
    st_filter_t f;
    int err;
    os_t os;
    os_object_t o;
    char *cfilter;

    f = NULL;
    if(filter != NULL) {
        f = xhash_get(data->filters, filter);
        if(f == NULL) {
            f = storage_filter(filter);
            cfilter = pstrdup(xhash_pool(data->filters), filter);
            xhash_put(data->filters, cfilter, (void *) f);
            pool_cleanup(xhash_pool(data->filters), (pool_cleanup_t) pool_free, f->p);
        }
    }

    memset(&key, 0, sizeof(DBT));
    memset(&val, 0, sizeof(DBT));

    key.data = (char *) owner;
    key.size = strlen(owner);

    os = os_new();

    err = c->c_get(c, &key, &val, DB_SET);
    while(err == 0) {
        o = _st_db_object_deserialise(drv, os, val.data, val.size);

        if(o != NULL && storage_match(f, o, os))
            err = c->c_del(c, 0);

        if(err == 0)
            err = c->c_get(c, &key, &val, DB_NEXT_DUP);
    }

    os_free(os);

    if(err != 0 && err != DB_NOTFOUND) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't move cursor for type %s owner %s in storage db: %s", type, owner, db_strerror(err));
        return st_FAILED;
    }

    return st_SUCCESS;
}

static st_ret_t _st_db_delete(st_driver_t drv, const char *type, const char *owner, const char *filter) {
    drvdata_t data = (drvdata_t) drv->private;
    dbdata_t dbd = xhash_get(data->dbs, type);
    DBC *c;
    DB_TXN *t;
    st_ret_t ret;

    ret = _st_db_cursor_new(drv, dbd, &c, &t);
    if(ret != st_SUCCESS)
        return ret;

    ret = _st_db_delete_guts(drv, type, owner, filter, dbd, c, t);
    if(ret != st_SUCCESS) {
        t->abort(t);
        _st_db_cursor_free(drv, dbd, c, NULL);
        return st_FAILED;
    }

    return _st_db_cursor_free(drv, dbd, c, t);
}

static st_ret_t _st_db_replace(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t os) {
    drvdata_t data = (drvdata_t) drv->private;
    dbdata_t dbd = xhash_get(data->dbs, type);
    DBC *c;
    DB_TXN *t;
    st_ret_t ret;

    ret = _st_db_cursor_new(drv, dbd, &c, &t);
    if(ret != st_SUCCESS)
        return ret;

    ret = _st_db_delete_guts(drv, type, owner, filter, dbd, c, t);
    if(ret != st_SUCCESS) {
        t->abort(t);
        _st_db_cursor_free(drv, dbd, c, NULL);
        return st_FAILED;
    }

    if(os_count(os) == 0)
        return _st_db_cursor_free(drv, dbd, c, t);

    ret = _st_db_put_guts(drv, type, owner, os, dbd, c, t);
    if(ret != st_SUCCESS) {
        t->abort(t);
        _st_db_cursor_free(drv, dbd, c, NULL);
        return st_FAILED;
    }

    return _st_db_cursor_free(drv, dbd, c, t);
}

static void _st_db_free(st_driver_t drv) {
    drvdata_t data = (drvdata_t) drv->private;
    const char *key;
    int keylen;
    dbdata_t dbd;
    DB_ENV *env;
    union xhashv xhv;

    xhv.dbd_val = &dbd;
    if(xhash_iter_first(data->dbs))
        do {
            xhash_iter_get(data->dbs, &key, &keylen, xhv.val);

            log_debug(ZONE, "closing %.*s db", keylen, key);

            dbd->db->close(dbd->db, 0);
            free(dbd);
        } while(xhash_iter_next(data->dbs));

    xhash_free(data->dbs);

    xhash_free(data->filters);

    data->env->close(data->env, 0);

    /* remove db environment files if no longer in use */
    if (db_env_create(&env, 0) == 0)
        env->remove(env, data->path, 0);

    free(data);
}

/** panic function */
static void _st_db_panic(DB_ENV *env, int errval) {
    log_t log = (log_t) env->app_private;

    log_write(log, LOG_CRIT, "db: corruption detected! close all jabberd processes and run db_recover");

    exit(2);
}

st_ret_t st_init(st_driver_t drv) {
    const char *path;
    int err;
    DB_ENV *env;
    drvdata_t data;

    path = config_get_one(drv->st->config, "storage.db.path", 0);
    if(path == NULL) {
        log_write(drv->st->log, LOG_ERR, "db: no path specified in config file");
        return st_FAILED;
    }

    if((err = db_env_create(&env, 0)) != 0) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't create environment: %s", db_strerror(err));
        return st_FAILED;
    }

    if((err = env->set_paniccall(env, _st_db_panic)) != 0) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't set panic call: %s", db_strerror(err));
        return st_FAILED;
    }

    /* store the log context in case we panic */
    env->app_private = drv->st->log;

    if((err = env->open(env, path, DB_INIT_LOCK | DB_INIT_MPOOL | DB_INIT_LOG | DB_INIT_TXN | DB_CREATE, 0)) != 0) {
        log_write(drv->st->log, LOG_ERR, "db: couldn't open environment: %s", db_strerror(err));
        env->close(env, 0);
        return st_FAILED;
    }

    data = (drvdata_t) calloc(1, sizeof(struct drvdata_st));

    data->env = env;
    data->path = path;

    if(config_get_one(drv->st->config, "storage.db.sync", 0) != NULL)
        data->sync = 1;

    data->dbs = xhash_new(101);

    data->filters = xhash_new(17);

    drv->private = (void *) data;

    drv->add_type = _st_db_add_type;
    drv->put = _st_db_put;
    drv->get = _st_db_get;
    drv->replace = _st_db_replace;
    drv->delete = _st_db_delete;
    drv->free = _st_db_free;

    return st_SUCCESS;
}
