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

/**
 * @file authreg_sqlite.c
 * @brief sqlite 3 authentication code for jabberd2
 * @author Christopher Parker
 * @bug no known bugs
 */

/* Released under the GPL by Christopher Parker <parkerc@i-vsn.com>, IVSN
 * to the Jabberd project.
 */

#include "c2s.h"
#include <sqlite3.h>

typedef struct moddata_st {
    sqlite3 *db;
    int txn;
    sqlite3_stmt *user_exists_stmt;
    sqlite3_stmt *get_password_stmt;
    sqlite3_stmt *check_password_stmt;
    sqlite3_stmt *set_password_stmt;
    sqlite3_stmt *create_user_stmt;
    sqlite3_stmt *delete_user_stmt;
} *moddata_t;

static sqlite3_stmt*
_get_stmt(authreg_t ar, sqlite3 *db, sqlite3_stmt **stmt, char *sql)
{
    int res;
    if (*stmt == NULL) {
	res = sqlite3_prepare(db, sql, -1, stmt, 0);
	if (res != SQLITE_OK) {
	    log_write(ar->c2s->log, LOG_ERR, "sqlite (authreg): %s", sqlite3_errmsg(db));
	    return NULL;
	}
    }
    return *stmt;
}

/**
 * @return 1 if the user exists, 0 if not 
 */
static int
_ar_sqlite_user_exists(authreg_t ar, char *username, char *realm)
{

    sqlite3_stmt *stmt;
    char *sql =
	"SELECT username FROM authreg WHERE username = ? AND realm = ?";
    moddata_t data = (moddata_t) ar->private;
    int res, ret = 0;
    
    log_debug(ZONE, "sqlite (authreg): user exists");
    
    stmt = _get_stmt(ar, data->db, &data->user_exists_stmt, sql);
    if (stmt == NULL) {
	return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, realm, -1, SQLITE_STATIC);

    res = sqlite3_step(stmt);
    if (res == SQLITE_ROW) {
	log_debug(ZONE, "sqlite (authreg): user exists : yes");
	ret = 1;
    } else {
	log_debug(ZONE, "sqlite (authreg): user exists : no");
    }
    sqlite3_reset(stmt);
    return ret;
}

/**
 * @return 0 is password is populated, 1 if not 
 */
static int
_ar_sqlite_get_password(authreg_t ar, char *username, char *realm,
			char password[257])
{

    sqlite3_stmt *stmt;
    char *sql =
	"SELECT password FROM authreg WHERE username = ? and realm = ?";
    moddata_t data = (moddata_t) ar->private;
    int res, ret=1;
    
    log_debug(ZONE, "sqlite (authreg): get password");
    
    stmt = _get_stmt (ar, data->db, &data->get_password_stmt, sql);
    if (stmt == NULL) {
	return 1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, realm, -1, SQLITE_STATIC);
    
    res = sqlite3_step(stmt);
    if (res == SQLITE_ROW) {
	strcpy(password, (char *) sqlite3_column_text(stmt, 0));
	ret = 0;
    }
    sqlite3_reset(stmt);
    return ret;
}

/**
 * @return 0 if the given password matches the password stored in the database, !0 if not
 */
static int
_ar_sqlite_check_password(authreg_t ar, char *username, char *realm,
			  char password[257])
{

    sqlite3_stmt *stmt;
    moddata_t data = (moddata_t) ar->private;
    int res, ret=1;
    char *sql =
	"SELECT username FROM authreg WHERE username = ? AND password = ? AND realm = ?";

    log_debug(ZONE, "sqlite (authreg): check password");

    stmt = _get_stmt(ar, data->db, &data->check_password_stmt, sql);
    if (stmt == NULL) {
	return 1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, realm, -1, SQLITE_STATIC);
    
    res = sqlite3_step(stmt);
    if (res == SQLITE_ROW) {
	ret = 0;
    }
    sqlite3_reset(stmt);
    return ret;
}

/**
 * @return 0 if password is stored, 1 if not
 */
static int
_ar_sqlite_set_password(authreg_t ar, char *username, char *realm,
			char password[257])
{

    sqlite3_stmt *stmt;
    moddata_t data = (moddata_t) ar->private;
    int res, ret = 0;

    char *sql =
	"UPDATE authreg SET password = ? WHERE username = ? AND realm = ?";
    
    log_debug(ZONE, "sqlite (authreg): set password");
    
    stmt = _get_stmt(ar, data->db, &data->set_password_stmt, sql);
    if (stmt == NULL) {
	return 1;
    }

    sqlite3_bind_text(stmt, 1, password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, realm, -1, SQLITE_STATIC);
    
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE) {
	log_write(ar->c2s->log, LOG_ERR, "sqlite (authreg): %s", sqlite3_errmsg (data->db));
	ret = 1;
    }
    sqlite3_reset(stmt);
    return ret;
}

/**
 * @return 0 if user is created, 1 if not
 */
static int
_ar_sqlite_create_user(authreg_t ar, char *username, char *realm)
{
    sqlite3_stmt *stmt;
    moddata_t data = data = (moddata_t) ar->private;
    int res, ret = 0;

    char *sql =
	"INSERT INTO authreg ( username, realm ) VALUES ( ?, ? )";
    
    log_debug(ZONE, "sqlite (authreg): create user");
    
    stmt = _get_stmt(ar, data->db, &data->create_user_stmt, sql);
    if (stmt == NULL) {
	return 1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, realm, -1, SQLITE_STATIC);
    
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE) {
	log_write(ar->c2s->log, LOG_ERR, "sqlite (authreg): %s", sqlite3_errmsg (data->db));
	ret = 1;
    }
    sqlite3_reset(stmt);
    return 0;
}

/**
 * @return 0 if user is deleted, 1 if not
 */
static int
_ar_sqlite_delete_user(authreg_t ar, char *username, char *realm)
{
    sqlite3_stmt *stmt;
    moddata_t data = (moddata_t) ar->private;
    int res, ret = 0;

    char *sql = "DELETE FROM authreg WHERE username = ? AND realm = ?";
    
    log_debug(ZONE, "sqlite (authreg): delete user");
    
    stmt = _get_stmt(ar, data->db, &data->delete_user_stmt, sql);
    if (stmt == NULL) {
	return 1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, realm, -1, SQLITE_STATIC);
    
    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE) {
	log_write(ar->c2s->log, LOG_ERR, "sqlite (authreg): %s", sqlite3_errmsg (data->db));
	ret = 1;
    }
    sqlite3_reset(stmt);
    
    return ret;
}

/**
 * @return does not return
 */
static void
_ar_sqlite_free(authreg_t ar)
{
    moddata_t data = (moddata_t) ar->private;

    log_debug(ZONE, "sqlite (authreg): free");

    sqlite3_finalize(data->user_exists_stmt);
    sqlite3_finalize(data->get_password_stmt);
    sqlite3_finalize(data->check_password_stmt);
    sqlite3_finalize(data->set_password_stmt);
    sqlite3_finalize(data->create_user_stmt);
    sqlite3_finalize(data->delete_user_stmt);

    sqlite3_close(data->db);
    
    free(data);
}

DLLEXPORT int
ar_init(authreg_t ar)
{

    int ret;
    sqlite3 *db;
    moddata_t data;
    char *busy_timeout;
    char *dbname = config_get_one(ar->c2s->config, "authreg.sqlite.dbname", 0);

    log_debug(ZONE, "sqlite (authreg): start init");

    if (dbname == NULL) {
	log_write(ar->c2s->log, LOG_ERR,
		  "sqlite (authreg): invalid driver config.");
	return 1;
    }

    ret = sqlite3_open(dbname, &db);
    if (ret != SQLITE_OK) {
	log_write(ar->c2s->log, LOG_ERR,
		  "sqlite (authreg): can't open database.");
	return 1;
    }

    data = (moddata_t) calloc(1, sizeof(struct moddata_st));
    if (!data) {
	log_write(ar->c2s->log, LOG_ERR,
		  "sqlite (authreg): memory error.");
	return 1;
    }

    data->db = db;

    if (config_get_one(ar->c2s->config,
		       "authreg.sqlite.transactions", 0) != NULL) {
	data->txn = 1;
    } else {
	log_write(ar->c2s->log, LOG_WARNING,
		  "sqlite (authreg): transactions disabled");
	data->txn = 0;
    }

    busy_timeout = config_get_one(ar->c2s->config,
				  "authreg.sqlite.busy-timeout", 0);

    if (busy_timeout != NULL) {
	sqlite3_busy_timeout(db, atoi(busy_timeout));
    }

    ar->private = data;

    ar->user_exists = _ar_sqlite_user_exists;
    ar->get_password = _ar_sqlite_get_password;
    ar->check_password = _ar_sqlite_check_password;
    ar->set_password = _ar_sqlite_set_password;
    ar->create_user = _ar_sqlite_create_user;
    ar->delete_user = _ar_sqlite_delete_user;
    ar->free = _ar_sqlite_free;

    log_debug(ZONE, "sqlite (authreg): finish init");

    return 0;
}
