/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
 * Copyright (c) 2004      Christof Meerwald
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

/* Released under the GPL by Chris Parker <parkerc@i-vsn.com>, IVSN
 * to the Jabberd project.
 */

/* Modified and updated for SQLite 3 by Christof Meerwald,
 * http://cmeerw.org
 */

#include "storage.h"
#include <sqlite3.h>

/** internal structure, holds our data */
typedef struct drvdata_st {
    sqlite3 *db;
    const char *prefix;
    int txn;
} *drvdata_t;

#define BLOCKSIZE (1024)


/** internal: do and return the math and ensure it gets realloc'd */
static int _st_sqlite_realloc (void **oblocks, int len) {
    void *nblocks;
    int nlen;

    /* round up to standard block sizes */
    nlen = (((len-1)/BLOCKSIZE)+1)*BLOCKSIZE;

    /* keep trying till we get it */
    while ((nblocks = realloc(*oblocks, nlen)) == NULL) sleep (1);
    *oblocks = nblocks;

    return nlen;
}

/** this is the safety check used to make sure there's always enough mem */
#define SQLITE_SAFE(blocks, size, len) \
    if((size) >= (len)) \
	len = _st_sqlite_realloc((void**)&(blocks),(size) + 1);

#define SQLITE_SAFE_CAT(blocks, size, len, s1) \
    do { \
	SQLITE_SAFE(blocks, size + sizeof (s1) - 1, len); \
	memcpy (&blocks[size], s1, sizeof (s1)); \
	size += sizeof (s1) - 1; \
    } while (0)

#define SQLITE_SAFE_CAT3(blocks, size, len, s1, s2, s3) \
    do { \
	const unsigned int l = strlen (s2); \
	SQLITE_SAFE(blocks, size + sizeof (s1) + l + sizeof (s2) - 2, len); \
	memcpy (&blocks[size], s1, sizeof (s1) - 1); \
	memcpy (&blocks[size + sizeof (s1) - 1], s2, l); \
	memcpy (&blocks[size + sizeof (s1) - 1 + l], s3, sizeof (s3)); \
	size += sizeof (s1) + l + sizeof (s3) - 2; \
    } while (0)

static void _st_sqlite_convert_filter_recursive (st_filter_t f, char **buf,
						 int *buflen, int *nbuf) {

    st_filter_t scan;

    switch (f->type) {
     case st_filter_type_PAIR:
      SQLITE_SAFE_CAT3 ((*buf), *nbuf, *buflen,
			"( \"", f->key, "\" = ? ) ");
      break;

     case st_filter_type_AND:
      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "( ");

      for (scan = f->sub; scan != NULL; scan = scan->next) {
	  _st_sqlite_convert_filter_recursive (scan, buf,
					       buflen, nbuf);

	  if (scan->next != NULL) {
	      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "AND ");
	  }
      }

      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, ") ");

      return;

     case st_filter_type_OR:
      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "( ");

      for (scan = f->sub; scan != NULL; scan = scan->next) {
	  _st_sqlite_convert_filter_recursive (scan, buf,
					       buflen, nbuf);

	  if (scan->next != NULL) {
	      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "OR ");
	  }
      }

      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, ") ");

      return;

     case st_filter_type_NOT:
      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "( NOT ");

      _st_sqlite_convert_filter_recursive(f->sub, buf,
					  buflen, nbuf);

      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, ") ");

      return;
    }
}

static char *_st_sqlite_convert_filter (st_driver_t drv, const char *owner,
					const char *filter) {

    char *buf = NULL;
    int buflen = 0, nbuf = 0;
    st_filter_t f;


    SQLITE_SAFE_CAT (buf, nbuf, buflen, "\"collection-owner\" = ?");

    f = storage_filter (filter);
    if (f == NULL) {
	return buf;
    }

    SQLITE_SAFE_CAT (buf, nbuf, buflen, " AND ");

    _st_sqlite_convert_filter_recursive (f, &buf, &buflen, &nbuf);

    pool_free (f->p);

    return buf;
}

static void _st_sqlite_bind_filter_recursive (st_filter_t f,
					      sqlite3_stmt *stmt,
					      unsigned int bind_off) {

    st_filter_t scan;
    unsigned int i;

    switch (f->type) {
     case st_filter_type_PAIR:
      sqlite3_bind_text (stmt, bind_off, f->val, strlen (f->val),
			 SQLITE_TRANSIENT);
      break;

     case st_filter_type_AND:
      for (scan = f->sub, i = 0; scan != NULL; scan = scan->next, ++i) {
	  _st_sqlite_bind_filter_recursive (scan, stmt, bind_off + i);
      }
      return;

     case st_filter_type_OR:
      for (scan = f->sub, i = 0; scan != NULL; scan = scan->next, ++i) {
	  _st_sqlite_bind_filter_recursive (scan, stmt, bind_off + i);
      }
      return;

     case st_filter_type_NOT:
      _st_sqlite_bind_filter_recursive(f->sub, stmt, bind_off);
      return;
    }
}

static void _st_sqlite_bind_filter (st_driver_t drv, const char *owner,
				    const char *filter,
				    sqlite3_stmt *stmt,
				    unsigned int bind_off) {

    st_filter_t f;


    sqlite3_bind_text (stmt, bind_off, owner, strlen (owner),
		       SQLITE_TRANSIENT);

    f = storage_filter (filter);
    if (f == NULL) {
	return;
    }

    _st_sqlite_bind_filter_recursive (f, stmt, bind_off + 1);

    pool_free (f->p);
}

static st_ret_t _st_sqlite_add_type (st_driver_t drv, const char *type) {

    return st_SUCCESS;
}

static st_ret_t _st_sqlite_put_guts (st_driver_t drv, const char *type,
				     const char *owner, os_t os) {

    drvdata_t data = (drvdata_t) drv->private;
    char *left = NULL, *right = NULL;
    unsigned int lleft = 0, lright = 0;
    os_object_t o;
    char *key, *cval = NULL;
    void *val;
    os_type_t ot;
    const char *xml;
    int xlen;
    char tbuf[128];
    int res;

    if (os_count (os) == 0) {
	return st_SUCCESS;
    }

    if (data->prefix != NULL) {
	snprintf (tbuf, sizeof (tbuf), "%s%s", data->prefix, type);
	type = tbuf;
    }

    if (os_iter_first (os)) {
	do {

	    unsigned int i = 0;
	    unsigned int nleft = 0, nright = 0;
	    sqlite3_stmt *stmt;


	    SQLITE_SAFE_CAT3 (left, nleft, lleft,
			      "INSERT INTO \"", type,
			      "\" ( \"collection-owner\"");
	    SQLITE_SAFE_CAT (right, nright, lright, " ) VALUES ( ?");

	    o = os_iter_object (os);
	    if (os_object_iter_first(o))
		do {
		    os_object_iter_get (o, &key, &val, &ot);

		    log_debug (ZONE, "key %s val %s", key, cval);

		    SQLITE_SAFE_CAT3 (left, nleft, lleft,
				      ", \"", key, "\"");

		    SQLITE_SAFE_CAT (right, nright, lright, ", ?");

		} while (os_object_iter_next (o));

	    SQLITE_SAFE (left, nleft + nright, lleft);
	    memcpy (&left[nleft], right, nright);
	    nleft += nright;
	    free (right);
	    right = NULL;
	    lright = 0;

	    SQLITE_SAFE_CAT (left, nleft, lleft, " )");

	    log_debug (ZONE, "prepared sql: %s", left);

	    res = sqlite3_prepare (data->db, left, strlen (left), &stmt, NULL);
	    free (left);
	    left = NULL;
	    lleft = 0;
	    if (res != SQLITE_OK) {
		log_write (drv->st->log, LOG_ERR,
			   "sqlite: sql insert failed: %s",
			   sqlite3_errmsg (data->db));
		return st_FAILED;
	    }

	    sqlite3_bind_text (stmt, 1, owner, strlen (owner),
			       SQLITE_TRANSIENT);

	    o = os_iter_object (os);
	    if (os_object_iter_first(o))
		do {
		    os_object_iter_get (o, &key, &val, &ot);

		    switch(ot) {
		     case os_type_BOOLEAN:
		      sqlite3_bind_int (stmt, i + 2, val ? 1 : 0);
		      break;

		     case os_type_INTEGER:
		      sqlite3_bind_int (stmt, i + 2, (long)val); // HACK ugly hack for pointer-to-int-cast
		      break;

		     case os_type_STRING:
		      sqlite3_bind_text (stmt, i + 2,
					 (const char *) val,
					 strlen ((const char *) val),
					 SQLITE_TRANSIENT);
		      break;

		      /* !!! might not be a good idea to mark nads this way */
		     case os_type_NAD:
		      nad_print ((nad_t) val, 0, &xml, &xlen);
		      cval = (char *) malloc(sizeof(char) * (xlen + 4));
		      memcpy (&cval[3], xml, xlen + 1);
		      memcpy (cval, "NAD", 3);

		      sqlite3_bind_text (stmt, i + 2,
					 cval, xlen + 3, free);
		      break;

		     case os_type_UNKNOWN:
		     default:
		      log_write (drv->st->log, LOG_ERR, "sqlite: unknown value in query");

		    }

		    i += 1;
		} while (os_object_iter_next (o));

	    res = sqlite3_step (stmt);
	    if (res != SQLITE_DONE) {
		log_write (drv->st->log, LOG_ERR,
			   "sqlite: sql insert failed: %s",
			   sqlite3_errmsg (data->db));
		sqlite3_finalize (stmt);
		return st_FAILED;
	    }
	    sqlite3_finalize (stmt);

	} while (os_iter_next (os));
    }

    return st_SUCCESS;
}

static st_ret_t _st_sqlite_put (st_driver_t drv, const char *type,
				const char *owner, os_t os) {

    drvdata_t data = (drvdata_t) drv->private;
    int res;
    char *err_msg = NULL;

    if (os_count (os) == 0) {
	return st_SUCCESS;
    }

    if (data->txn) {

	res = sqlite3_exec (data->db,
			    "BEGIN", NULL, NULL,
			    &err_msg);
	if (res != SQLITE_OK) {
	    log_write (drv->st->log, LOG_ERR,
		       "sqlite: sql transaction begin failed: %s",
		       err_msg);
	    sqlite3_free (err_msg);
	    return st_FAILED;
	}
    }

    if (_st_sqlite_put_guts (drv, type, owner, os) != st_SUCCESS) {
	if (data->txn) {
	    res = sqlite3_exec (data->db, "ROLLBACK",
				NULL, NULL, NULL);
	}
	return st_FAILED;
    }

    if (data->txn) {

	res = sqlite3_exec (data->db, "COMMIT", NULL, NULL, &err_msg);
	if (res != SQLITE_OK) {
	    log_write (drv->st->log, LOG_ERR,
		       "sqlite: sql transaction commit failed: %s",
		       err_msg);
	    sqlite3_exec (data->db, "ROLLBACK", NULL, NULL, NULL);
	    return st_FAILED;
	}
    }
    return st_SUCCESS;
}

static st_ret_t _st_sqlite_get (st_driver_t drv, const char *type,
				const char *owner, const char *filter,
				os_t *os) {

    drvdata_t data = (drvdata_t) drv->private;
    char *cond, *buf = NULL;
    unsigned int nbuf = 0;
    unsigned int buflen = 0;
    int i;
    unsigned int num_rows = 0;
    os_object_t o;
    const char *val;
    os_type_t ot;
    int ival;
    char tbuf[128];

    sqlite3_stmt *stmt;
    int result;

    if (data->prefix != NULL) {
	snprintf (tbuf, sizeof (tbuf), "%s%s", data->prefix, type);
	type = tbuf;
    }

    cond = _st_sqlite_convert_filter (drv, owner, filter);

    SQLITE_SAFE_CAT3 (buf, nbuf, buflen,
		      "SELECT * FROM \"", type, "\" WHERE ");
    strcpy (&buf[nbuf], cond);
    strcpy (&buf[strlen(buf)], " ORDER BY \"object-sequence\"");
    free (cond);

    log_debug (ZONE, "prepared sql: %s", buf);

    result = sqlite3_prepare (data->db, buf, strlen (buf), &stmt, NULL);
    free (buf);
    if (result != SQLITE_OK) {
	return st_FAILED;
    }

    _st_sqlite_bind_filter (drv, owner, filter, stmt, 1);

    *os = os_new ();

    do {

	unsigned int num_cols;

	result = sqlite3_step (stmt);

	if (result != SQLITE_ROW) {
	    continue;
	}

	o = os_object_new (*os);
	num_cols = sqlite3_data_count (stmt);

	for (i = 0; i < num_cols; i++) {

	    const char *colname;
	    int coltype;

	    colname = sqlite3_column_name (stmt, i);

	    if (strcmp (colname, "collection-owner") == 0) {
		continue;
	    }

	    coltype = sqlite3_column_type (stmt, i);

	    if (coltype == SQLITE_NULL) {
		log_debug (ZONE, "coldata is NULL");
		continue;
	    }

	    if (coltype == SQLITE_INTEGER) {
		if (!strcmp (sqlite3_column_decltype (stmt, i), "BOOL")) {
		    ot = os_type_BOOLEAN;
		} else {
		    ot = os_type_INTEGER;
		}

		ival = sqlite3_column_int (stmt, i);
		os_object_put (o, colname, &ival, ot);

	    } else if (coltype == SQLITE3_TEXT) {
		ot = os_type_STRING;

		val = (const char*)sqlite3_column_text (stmt, i);
		os_object_put (o, colname, val, ot);

	    } else {
		log_write (drv->st->log,
			   LOG_NOTICE,
			   "sqlite: unknown field: %s:%d",
			   colname, coltype);
	    }
	}

	num_rows++;

    } while (result == SQLITE_ROW);

    sqlite3_finalize (stmt);

    if (num_rows == 0) {
        os_free(*os);
        *os = NULL;
        return st_NOTFOUND;
    }

    return st_SUCCESS;
}

static st_ret_t _st_sqlite_count (st_driver_t drv, const char *type,
				   const char *owner, const char *filter, int *count) {

    drvdata_t data = (drvdata_t) drv->private;
    char *cond, *buf = NULL;
    unsigned int nbuf = 0;
    unsigned int buflen = 0;
    char tbuf[128];
    int res, coltype;
    sqlite3_stmt *stmt;

    if (data->prefix != NULL) {
	snprintf (tbuf, sizeof (tbuf), "%s%s", data->prefix, type);
	type = tbuf;
    }

    cond = _st_sqlite_convert_filter (drv, owner, filter);
    log_debug (ZONE, "generated filter: %s", cond);

    SQLITE_SAFE_CAT3 (buf, nbuf, buflen,
		      "SELECT COUNT(*) FROM \"", type, "\" WHERE ");
    strcpy (&buf[nbuf], cond);
    free (cond);

    log_debug (ZONE, "prepared sql: %s", buf);

    res = sqlite3_prepare (data->db, buf, strlen (buf), &stmt, NULL);
    free (buf);
    if (res != SQLITE_OK) {
	return st_FAILED;
    }

    _st_sqlite_bind_filter (drv, owner, filter, stmt, 1);

    res = sqlite3_step (stmt);
    if (res != SQLITE_ROW) {
	log_write (drv->st->log, LOG_ERR,
		   "sqlite: sql select failed: %s",
		   sqlite3_errmsg (data->db));
	sqlite3_finalize (stmt);
	return st_FAILED;
    }

    coltype = sqlite3_column_type (stmt, 0);

    if (coltype != SQLITE_INTEGER) {
	log_write (drv->st->log, LOG_ERR,
		   "sqlite: weird, count() returned non integer value: %s",
		   sqlite3_errmsg (data->db));
	sqlite3_finalize (stmt);
	return st_FAILED;
    }

    *count = sqlite3_column_int (stmt, 0);

    sqlite3_finalize (stmt);

    return st_SUCCESS;
}

static st_ret_t _st_sqlite_delete (st_driver_t drv, const char *type,
				   const char *owner, const char *filter) {

    drvdata_t data = (drvdata_t) drv->private;
    char *cond, *buf = NULL;
    unsigned int nbuf = 0;
    unsigned int buflen = 0;
    char tbuf[128];
    int res;
    sqlite3_stmt *stmt;

    if (data->prefix != NULL) {
	snprintf (tbuf, sizeof (tbuf), "%s%s", data->prefix, type);
	type = tbuf;
    }

    cond = _st_sqlite_convert_filter (drv, owner, filter);
    log_debug (ZONE, "generated filter: %s", cond);

    SQLITE_SAFE_CAT3 (buf, nbuf, buflen,
		      "DELETE FROM \"", type, "\" WHERE ");
    strcpy (&buf[nbuf], cond);
    free (cond);

    log_debug (ZONE, "prepared sql: %s", buf);

    res = sqlite3_prepare (data->db, buf, strlen (buf), &stmt, NULL);
    free (buf);
    if (res != SQLITE_OK) {
	return st_FAILED;
    }

    _st_sqlite_bind_filter (drv, owner, filter, stmt, 1);

    res = sqlite3_step (stmt);
    if (res != SQLITE_DONE) {
	log_write (drv->st->log, LOG_ERR,
		   "sqlite: sql delete failed: %s",
		   sqlite3_errmsg (data->db));
	sqlite3_finalize (stmt);
	return st_FAILED;
    }
    sqlite3_finalize (stmt);

    return st_SUCCESS;
}

static st_ret_t _st_sqlite_replace (st_driver_t drv, const char *type,
				    const char *owner, const char *filter,
				    os_t os) {

    drvdata_t data = (drvdata_t) drv->private;

    int res;
    char *err_msg = NULL;

    if (data->txn) {

	res = sqlite3_exec (data->db, "BEGIN", NULL, NULL, &err_msg);
	if (res != SQLITE_OK) {
	    log_write (drv->st->log, LOG_ERR,
		       "sqlite: sql transaction begin failed: %s",
		       err_msg);
	    sqlite3_free (err_msg);
	    return st_FAILED;
	}
    }

    if (_st_sqlite_delete (drv, type, owner, filter) == st_FAILED) {
	if (data->txn) {
	    sqlite3_exec (data->db, "ROLLBACK", NULL, NULL, NULL);
	}
	return st_FAILED;
    }

    if (_st_sqlite_put_guts (drv, type, owner, os) == st_FAILED) {
	if (data->txn) {
	    sqlite3_exec (data->db, "ROLLBACK", NULL, NULL, NULL);
	}
	return st_FAILED;
    }

    if (data->txn) {

	res = sqlite3_exec (data->db, "COMMIT", NULL, NULL, &err_msg);

	if (res != SQLITE_OK) {
	    log_write (drv->st->log, LOG_ERR,
		       "sqlite: sql transaction commit failed: %s",
		       err_msg);
	    sqlite3_exec (data->db, "ROLLBACK", NULL, NULL, NULL);

	    return st_FAILED;
	}
    }

    return st_SUCCESS;
}

static void _st_sqlite_free (st_driver_t drv) {

    drvdata_t data = (drvdata_t) drv->private;

    sqlite3_close (data->db);

    free (data);
}

DLLEXPORT st_ret_t st_init(st_driver_t drv) {

    const char *dbname;
    sqlite3 *db;
    drvdata_t data;
    int ret;
    const char *busy_timeout;

    dbname = config_get_one (drv->st->config,
			     "storage.sqlite.dbname", 0);
    if (dbname == NULL) {
	log_write (drv->st->log, LOG_ERR,
		   "sqlite: invalid driver config");
	return st_FAILED;
    }

    ret = sqlite3_open (dbname, &db);
    if (ret != SQLITE_OK) {
	log_write (drv->st->log, LOG_ERR,
		   "sqlite: can't open database '%s'", dbname);
	return st_FAILED;
    }

    data = (drvdata_t) calloc (1, sizeof (struct drvdata_st));

    data->db = db;

    if (config_get_one (drv->st->config,
			"storage.sqlite.transactions", 0) != NULL) {
	data->txn = 1;
    } else {
	log_write (drv->st->log, LOG_WARNING,
		   "sqlite: transactions disabled");
    }

    busy_timeout = config_get_one (drv->st->config,
				   "storage.sqlite.busy-timeout", 0);
    if (busy_timeout != NULL) {
	sqlite3_busy_timeout (db, atoi (busy_timeout));
    }

    data->prefix = config_get_one (drv->st->config,
				   "storage.sqlite.prefix", 0);

    drv->private = (void *) data;
    drv->add_type = _st_sqlite_add_type;
    drv->put = _st_sqlite_put;
    drv->count = _st_sqlite_count;
    drv->get = _st_sqlite_get;
    drv->delete = _st_sqlite_delete;
    drv->replace = _st_sqlite_replace;
    drv->free = _st_sqlite_free;

    return st_SUCCESS;
}
