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

/* this module uses the Berkeley DB v4 (db4) to store the auth credentials */

/*
 * !!! we must catch DB_RUNRECOVERY and call _ar_db_panic(). I would argue that
 *     Berkeley should do this for all cases, not just for the process that
 *     caused the fault, but I'm not sure they see it that way. (I have asked,
 *     just waiting for a reply)
 *
 *     Sleepycat SR#7019 resolved this. There is an unreleased patch available
 *     (I have a copy) that will be in 4.2 (due in June).
 */

#include "c2s.h"
#include <db.h>

/** internal structure, holds auth credentials for one user */
typedef struct creds_st
{
    char    username[257];
    char    realm[257];
    char    password[257];
} *creds_t;

/** internal structure, holds our data */
typedef struct moddata_st
{
    DB_ENV  *env;

    const char *path;
    int     sync;

    xht     realms;
    DB      *def_realm;
} *moddata_t;

/** open/create the database for this realm */
static DB *_ar_db_get_realm_db(authreg_t ar, const char *realm)
{
    moddata_t data = (moddata_t) ar->private;
    DB *db;
    int err;

    if(realm[0] == '\0')
        db = data->def_realm;
    else
        db = xhash_get(data->realms, realm);
    if(db != NULL)
        return db;

    log_debug(ZONE, "creating new db handle for realm '%s'", realm);

    err = db_create(&db, data->env, 0);
    if(err != 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "db: couldn't create db: %s", db_strerror(err));
        return NULL;
    }

    err = db->open(db, NULL, "authreg.db", realm, DB_HASH, DB_CREATE, 0);
    if(err != 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "db: couldn't open db for realm '%s': %s", realm, db_strerror(err));
        db->close(db, 0);
        return NULL;
    }

    if(realm[0] == '\0')
        data->def_realm = db;
    else
        xhash_put(data->realms, pstrdup(xhash_pool(data->realms), realm), (void *) db);

    log_debug(ZONE, "db for realm '%s' is online", realm);

    return db;
}

/** pull a user out of the db */
static creds_t _ar_db_fetch_user(authreg_t ar, const char *username, const char *realm)
{
    DB *db;
    DBT key, val;
    int err;
    creds_t creds;

    log_debug(ZONE, "fetching auth creds for user '%s' realm '%s'", username, realm);

    db = _ar_db_get_realm_db(ar, realm);
    if(db == NULL)
        return NULL;

    memset(&key, 0, sizeof(DBT));
    memset(&val, 0, sizeof(DBT));
    
    key.data = (void*)username;
    key.size = strlen(username);

    err = db->get(db, NULL, &key, &val, 0);
    if(err == 0)
        creds = (creds_t) val.data;
    else if(err == DB_NOTFOUND)
        creds = NULL;
    else
    {
        log_write(ar->c2s->log, LOG_ERR, "db: couldn't fetch auth creds for user '%s' (realm '%s'): %s", username, realm, db_strerror(err));
        return NULL;
    }

    log_debug(ZONE, "auth creds: 0x%4X", creds);

    return creds;
}

/** store the user into the db */
static int _ar_db_store_user(authreg_t ar, creds_t creds)
{
    moddata_t data = (moddata_t) ar->private;
    DB *db;
    DBT key, val;
    int err;

    log_debug(ZONE, "storing auth creds for user '%s' realm '%s'", creds->username, creds->realm);

    db = _ar_db_get_realm_db(ar, creds->realm);
    if(db == NULL)
        return 1;

    memset(&key, 0, sizeof(DBT));
    memset(&val, 0, sizeof(DBT));
    
    key.data = creds->username;
    key.size = strlen(creds->username);

    val.data = creds;
    val.size = sizeof(struct creds_st);

    err = db->put(db, NULL, &key, &val, 0);
    if(err != 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "db: couldn't store auth creds for user '%s' (realm '%s'): %s", creds->username, creds->realm, db_strerror(err));
        return 1;
    }

    if(data->sync)
        db->sync(db, 0);

    return 0;
}

static int _ar_db_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    return (int) (long) _ar_db_fetch_user(ar, username, realm);
}

static int _ar_db_get_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    creds_t creds;

    if((creds = _ar_db_fetch_user(ar, username, realm)) == NULL)
        return 1;

    strcpy(password, creds->password);

    return 0;
}

static int _ar_db_set_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    creds_t creds;

    if((creds = _ar_db_fetch_user(ar, username, realm)) == NULL)
        return 1;

    strcpy(creds->password, password);

    if(_ar_db_store_user(ar, creds) != 0)
        return 1;

    return 0;
}

static int _ar_db_create_user(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    creds_t creds;
    int ret;

    if((creds = _ar_db_fetch_user(ar, username, realm)) != NULL)
        return 1;

    creds = (creds_t) calloc(1, sizeof(struct creds_st));

    strcpy(creds->username, username);
    strcpy(creds->realm, realm);

    ret = _ar_db_store_user(ar, creds);

    free(creds);
    return ret;
}

static int _ar_db_delete_user(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    DB *db;
    DBT key;
    int err;

    if(_ar_db_fetch_user(ar, username, realm) == NULL)
        return 1;

    db = _ar_db_get_realm_db(ar, realm);
    if(db == NULL)
        return 1;

    memset(&key, 0, sizeof(DBT));

    key.data = (void*)username;
    key.size = strlen(username);

    err = db->del(db, NULL, &key, 0);
    if(err != 0)
        log_write(ar->c2s->log, LOG_ERR, "db: couldn't delete auth creds for user '%s' (realm '%s'): %s", username, realm, db_strerror(err));

    return err;
}

static void _ar_db_free_walker(const char *key, int keylen, void *val, void *arg)
{
    DB *db = (DB *) val;

    log_debug(ZONE, "closing '%.*s' db", keylen, key);

    db->close(db, 0);
}

static void _ar_db_free(authreg_t ar)
{
    DB_ENV *env;

    moddata_t data = (moddata_t) ar->private;

    log_debug(ZONE, "db module shutting down");

    xhash_walk(data->realms, _ar_db_free_walker, NULL);

    xhash_free(data->realms);

    data->env->close(data->env, 0);

    /* remove db environment files if no longer required */
    if (db_env_create(&env, 0) == 0)
        env->remove(env, data->path, 0); 

    free(data);
}

/** panic function */
static void _ar_db_panic(DB_ENV *env, int errval)
{
    log_t log = (log_t) env->app_private;

    log_write(log, LOG_CRIT, "db: corruption detected! close all jabberd processes and run db_recover");

    exit(2);
}

/** start me up */
int ar_init(authreg_t ar)
{
    const char *path;
    int err;
    DB_ENV *env;
    moddata_t data;

    path = config_get_one(ar->c2s->config, "authreg.db.path", 0);
    if(path == NULL)
    {
        log_write(ar->c2s->log, LOG_ERR, "db: no authreg path specified in config file");
        return 1;
    }

    err = db_env_create(&env, 0);
    if(err != 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "db: couldn't create environment: %s", db_strerror(err));
        return 1;
    }

    err = env->set_paniccall(env, _ar_db_panic);
    if(err != 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "db: couldn't set panic call: %s", db_strerror(err));
        return 1;
    }

    /* store the log context in case we panic */
    env->app_private = ar->c2s->log;

    err = env->set_flags(env, DB_AUTO_COMMIT, 1);
    if(err != 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "db: couldn't set environment for automatic transaction commit: %s", db_strerror(err));
        env->close(env, 0);
        return 1;
    }

    err = env->open(env, path, DB_INIT_LOCK | DB_INIT_MPOOL | DB_INIT_LOG | DB_INIT_TXN | DB_CREATE, 0);
    if(err != 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "db: couldn't open environment: %s", db_strerror(err));
        env->close(env, 0);
        return 1;
    }

    data = (moddata_t) calloc(1, sizeof(struct moddata_st));

    data->env = env;
    data->path = path;

    if(config_get_one(ar->c2s->config, "authreg.db.sync", 0) != NULL)
        data->sync = 1;

    data->realms = xhash_new(51);

    ar->private = data;

    ar->user_exists = _ar_db_user_exists;
    ar->get_password = _ar_db_get_password;
    ar->set_password = _ar_db_set_password;
    ar->create_user = _ar_db_create_user;
    ar->delete_user = _ar_db_delete_user;
    ar->free = _ar_db_free;

    return 0;
}
