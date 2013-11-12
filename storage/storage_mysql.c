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

/** @file sm/storage_mysql.c
  * @brief mysql storage module
  * @author Robert Norris
  * $Date: 2005/06/22 20:31:22 $
  * $Revision: 1.22 $
  */

#include "storage.h"
#include <mysql.h>

/** internal structure, holds our data */
typedef struct drvdata_st {
    MYSQL *conn;

    const char *prefix;

    int txn;
} *drvdata_t;

#define FALLBACK_BLOCKSIZE (4096)

/** internal: do and return the math and ensure it gets realloc'd */
static size_t _st_mysql_realloc(char **oblocks, size_t len) {
    void *nblocks;
    size_t nlen;
    static size_t block_size = 0;

    if (block_size == 0) {
#ifdef HAVE_GETPAGESIZE
        block_size = getpagesize();
#elif defined(_SC_PAGESIZE)
        block_size = sysconf(_SC_PAGESIZE);
#elif defined(_SC_PAGE_SIZE)
        block_size = sysconf(_SC_PAGE_SIZE);    
#else
        block_size = FALLBACK_BLOCKSIZE;
#endif
    }
    /* round up to standard block sizes */
    nlen = (((len-1)/block_size)+1)*block_size;

    /* keep trying till we get it */
    while((nblocks = realloc(*oblocks, nlen)) == NULL) sleep(1);
    *oblocks = nblocks;
    return nlen;
}

/** this is the safety check used to make sure there's always enough mem */
#define MYSQL_SAFE(blocks, size, len) if((unsigned int)(size) >= (unsigned int)(len)) len = _st_mysql_realloc(&(blocks),(size + 1));

static void _st_mysql_convert_filter_recursive(st_driver_t drv, st_filter_t f, char **buf, int *buflen, int *nbuf) {
    drvdata_t data = (drvdata_t) drv->private;
    st_filter_t scan; 
    char *cval;
    int vlen;

    switch(f->type) {
        case st_filter_type_PAIR:

            /* do sql escape processing of f->val */
            cval = (char *) malloc(sizeof(char) * ((strlen((char *) f->val) * 2) + 1));
            vlen = mysql_real_escape_string(data->conn, cval, (char *) f->val, strlen((char *) f->val));

            MYSQL_SAFE((*buf), *buflen + 12 + strlen(f->key) + vlen, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "( `%s` = \'%s\' ) ", f->key, cval);
            free(cval);

            break;

        case st_filter_type_AND:
            MYSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "( ");

            for(scan = f->sub; scan != NULL; scan = scan->next) {
                _st_mysql_convert_filter_recursive(drv, scan, buf, buflen, nbuf);

                if(scan->next != NULL) {
                    MYSQL_SAFE((*buf), *buflen + 4, *buflen);
                    *nbuf += sprintf(&((*buf)[*nbuf]), "AND ");
                }
            }

            MYSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), ") ");

            return;

        case st_filter_type_OR:
            MYSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "( ");

            for(scan = f->sub; scan != NULL; scan = scan->next) {
                _st_mysql_convert_filter_recursive(drv, scan, buf, buflen, nbuf);

                if(scan->next != NULL) {
                    MYSQL_SAFE((*buf), *buflen + 3, *buflen);
                    *nbuf += sprintf(&((*buf)[*nbuf]), "OR ");
                }
            }

            MYSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), ") ");

            return;

        case st_filter_type_NOT:
            MYSQL_SAFE((*buf), *buflen + 6, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "( NOT ");

            _st_mysql_convert_filter_recursive(drv, f->sub, buf, buflen, nbuf);

            MYSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), ") ");

            return;
    }
}

static char *_st_mysql_convert_filter(st_driver_t drv, const char *owner, const char *filter) {
    char *buf = NULL;
    int buflen = 0, nbuf = 0;
    st_filter_t f;

    MYSQL_SAFE(buf, 23 + strlen(owner), buflen);

    nbuf = sprintf(buf, "`collection-owner` = '%s'", owner);

    f = storage_filter(filter);
    if(f == NULL)
        return buf;

    MYSQL_SAFE(buf, buflen + 5, buflen);
    nbuf += sprintf(&buf[nbuf], " AND ");

    _st_mysql_convert_filter_recursive(drv, f, &buf, &buflen, &nbuf);

    pool_free(f->p);

    return buf;
}

static st_ret_t _st_mysql_add_type(st_driver_t drv, const char *type) {
    return st_SUCCESS;
}

static st_ret_t _st_mysql_put_guts(st_driver_t drv, const char *type, const char *owner, os_t os) {
    drvdata_t data = (drvdata_t) drv->private;
    char *left = NULL, *right = NULL;
    int lleft = 0, lright = 0, nleft, nright;
    os_object_t o;
    char *key, *cval = NULL;
    void *val;
    os_type_t ot;
    const char *xml;
    int xlen;
    char tbuf[128];

    if(os_count(os) == 0)
        return st_SUCCESS;

    if(data->prefix != NULL) {
        snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
        type = tbuf;
    }

    if(os_iter_first(os))
        do {
            MYSQL_SAFE(left, strlen(type) + 35, lleft);
            nleft = sprintf(left, "INSERT INTO `%s` ( `collection-owner`", type);
    
            MYSQL_SAFE(right, strlen(owner) + 14, lright);
            nright = sprintf(right, " ) VALUES ( '%s'", owner);
    
            o = os_iter_object(os);
            if(os_object_iter_first(o))
                do {
                    os_object_iter_get(o, &key, &val, &ot);
        
                    switch(ot) {
                        case os_type_BOOLEAN:
                            cval = val ? strdup("1") : strdup("0");
                            break;
        
                        case os_type_INTEGER:
                            cval = (char *) malloc(sizeof(char) * 20);
                            sprintf(cval, "%ld", (long int) val);
                            break;
        
                        case os_type_STRING:
                            cval = (char *) malloc(sizeof(char) * ((strlen((char *) val) * 2) + 1));
                            mysql_real_escape_string(data->conn, cval, (char *) val, strlen((char *) val));
                            break;
        
                        case os_type_NAD:
                            nad_print((nad_t) val, 0, &xml, &xlen);
                            cval = (char *) malloc(sizeof(char) * ((xlen * 2) + 4));
                            mysql_real_escape_string(data->conn, &cval[3], xml, xlen);
                            strncpy(cval, "NAD", 3);
                            break;

			case os_type_UNKNOWN:
                            break;
                    }
        
                    log_debug(ZONE, "key %s val %s", key, cval);
        
                    MYSQL_SAFE(left, lleft + strlen(key) + 4, lleft);
                    nleft += sprintf(&left[nleft], ", `%s`", key);
        
                    MYSQL_SAFE(right, lright + strlen(cval) + 4, lright);
                    nright += sprintf(&right[nright], ", '%s'", cval);
        
                    free(cval);
                } while(os_object_iter_next(o));
    
            MYSQL_SAFE(left, lleft + strlen(right) + 2, lleft);
            sprintf(&left[nleft], "%s )", right);
        
            log_debug(ZONE, "prepared sql: %s", left);
    
            if(mysql_query(data->conn, left) != 0) {
                log_write(drv->st->log, LOG_ERR, "mysql: sql insert failed: %s", mysql_error(data->conn));
                free(left);
                free(right);
                return st_FAILED;
            }
    
        } while(os_iter_next(os));

    free(left);
    free(right);

    return st_SUCCESS;
}

static st_ret_t _st_mysql_put(st_driver_t drv, const char *type, const char *owner, os_t os) {
    drvdata_t data = (drvdata_t) drv->private;

    if(os_count(os) == 0)
        return st_SUCCESS;

    if(mysql_ping(data->conn) != 0) {
        log_write(drv->st->log, LOG_ERR, "mysql: connection to database lost");
        return st_FAILED;
    }

    if(data->txn) {
        if(mysql_query(data->conn, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE") != 0) {
            log_write(drv->st->log, LOG_ERR, "mysql: sql transaction setup failed: %s", mysql_error(data->conn));
            return st_FAILED;
        }

        if(mysql_query(data->conn, "BEGIN") != 0) {
            log_write(drv->st->log, LOG_ERR, "mysql: sql transaction begin failed: %s", mysql_error(data->conn));
            return st_FAILED;
        }
    }

    if(_st_mysql_put_guts(drv, type, owner, os) != st_SUCCESS) {
        if(data->txn)
            mysql_query(data->conn, "ROLLBACK");
        return st_FAILED;
    }

    if(data->txn)
        if(mysql_query(data->conn, "COMMIT") != 0) {
            log_write(drv->st->log, LOG_ERR, "mysql: sql transaction commit failed: %s", mysql_error(data->conn));
            mysql_query(data->conn, "ROLLBACK");
            return st_FAILED;
        }

    return st_SUCCESS;
}

static st_ret_t _st_mysql_get(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t *os) {
    drvdata_t data = (drvdata_t) drv->private;
    char *cond, *buf = NULL;
    int buflen = 0;
    MYSQL_RES *res;
    int ntuples, nfields, i, j;
    MYSQL_FIELD *fields;
    MYSQL_ROW tuple;
    os_object_t o;
    char *val;
    os_type_t ot;
    int ival;
    char tbuf[128];

    if(mysql_ping(data->conn) != 0) {
        log_write(drv->st->log, LOG_ERR, "mysql: connection to database lost");
        return st_FAILED;
    }

    if(data->prefix != NULL) {
        snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
        type = tbuf;
    }

    cond = _st_mysql_convert_filter(drv, owner, filter);
    log_debug(ZONE, "generated filter: %s", cond);

    MYSQL_SAFE(buf, strlen(type) + strlen(cond) + 50, buflen);
    sprintf(buf, "SELECT * FROM `%s` WHERE %s ORDER BY `object-sequence`", type, cond);
    free(cond);

    log_debug(ZONE, "prepared sql: %s", buf);

    if(mysql_query(data->conn, buf) != 0) {
        log_write(drv->st->log, LOG_ERR, "mysql: sql select failed: %s", mysql_error(data->conn));
        free(buf);
        return st_FAILED;
    }
    free(buf);

    res = mysql_store_result(data->conn);
    if(res == NULL) {
        log_write(drv->st->log, LOG_ERR, "mysql: sql result retrieval failed: %s", mysql_error(data->conn));
        return st_FAILED;
    }

    ntuples = mysql_num_rows(res);
    if(ntuples == 0) {
        mysql_free_result(res);
        return st_NOTFOUND;
    }

    log_debug(ZONE, "%d tuples returned", ntuples);

    nfields = mysql_num_fields(res);

    if(nfields == 0) {
        log_debug(ZONE, "weird, tuples were returned but no fields *shrug*");
        mysql_free_result(res);
        return st_NOTFOUND;
    }

    fields = mysql_fetch_fields(res);

    *os = os_new();

    for(i = 0; i < ntuples; i++) {
        o = os_object_new(*os);

        if((tuple = mysql_fetch_row(res)) == NULL)
            break;

        for(j = 0; j < nfields; j++) {
            if(strcmp(fields[j].name, "collection-owner") == 0)
                continue;

            if(tuple[j] == NULL)
                continue;

            // mysql_fetch_lengths(res); // TODO check if mysql_fetch_lengths must be called.

            switch(fields[j].type) {
                case FIELD_TYPE_TINY:   /* tinyint */
                    ot = os_type_BOOLEAN;
                    break;

                case FIELD_TYPE_LONG:   /* integer */
                    ot = os_type_INTEGER;
                    break;

                case FIELD_TYPE_BLOB:   /* text */
                case FIELD_TYPE_VAR_STRING:   /* varchar */
                    ot = os_type_STRING;
                    break;

                default:
                    log_debug(ZONE, "unknown field type %d, ignoring it", fields[j].type);
                    continue;
            }

            val = tuple[j];

            switch(ot) {
                case os_type_BOOLEAN:
                    ival = (val[0] == '0') ? 0 : 1;
                    os_object_put(o, fields[j].name, &ival, ot);
                    break;

                case os_type_INTEGER:
                    ival = atoi(val);
                    os_object_put(o, fields[j].name, &ival, ot);
                    break;

                case os_type_STRING:
                    os_object_put(o, fields[j].name, val, os_type_STRING);
                    break;

		case os_type_NAD:
		case os_type_UNKNOWN:
                    break;
            }
        }
    }

    mysql_free_result(res);

    return st_SUCCESS;
}

static st_ret_t _st_mysql_count(st_driver_t drv, const char *type, const char *owner, const char *filter, int *count) {
    drvdata_t data = (drvdata_t) drv->private;
    char *cond, *buf = NULL;
    int buflen = 0;
    MYSQL_RES *res;
    int ntuples, nfields;
    MYSQL_ROW tuple;
    char tbuf[128];

    if(mysql_ping(data->conn) != 0) {
        log_write(drv->st->log, LOG_ERR, "mysql: connection to database lost");
        return st_FAILED;
    }

    if(data->prefix != NULL) {
        snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
        type = tbuf;
    }

    cond = _st_mysql_convert_filter(drv, owner, filter);
    log_debug(ZONE, "generated filter: %s", cond);

    MYSQL_SAFE(buf, strlen(type) + strlen(cond) + 31, buflen);
    sprintf(buf, "SELECT COUNT(*) FROM `%s` WHERE %s", type, cond);
    free(cond);

    log_debug(ZONE, "prepared sql: %s", buf);

    if(mysql_query(data->conn, buf) != 0) {
        log_write(drv->st->log, LOG_ERR, "mysql: sql select failed: %s", mysql_error(data->conn));
        free(buf);
        return st_FAILED;
    }
    free(buf);

    res = mysql_store_result(data->conn);
    if(res == NULL) {
        log_write(drv->st->log, LOG_ERR, "mysql: sql result retrieval failed: %s", mysql_error(data->conn));
        return st_FAILED;
    }

    ntuples = mysql_num_rows(res);
    if(ntuples == 0) {
        mysql_free_result(res);
        return st_NOTFOUND;
    }

    log_debug(ZONE, "%d tuples returned", ntuples);

    nfields = mysql_num_fields(res);

    if(nfields == 0) {
        log_debug(ZONE, "weird, tuples were returned but no fields *shrug*");
        mysql_free_result(res);
        return st_NOTFOUND;
    }

    if((tuple = mysql_fetch_row(res)) == NULL)
        return st_NOTFOUND;

    if (count!=NULL)
        *count = atoi(tuple[0]);

    mysql_free_result(res);

    return st_SUCCESS;
}

static st_ret_t _st_mysql_delete(st_driver_t drv, const char *type, const char *owner, const char *filter) {
    drvdata_t data = (drvdata_t) drv->private;
    char *cond, *buf = NULL;
    int buflen = 0;
    char tbuf[128];

    if(mysql_ping(data->conn) != 0) {
        log_write(drv->st->log, LOG_ERR, "mysql: connection to database lost");
        return st_FAILED;
    }

    if(data->prefix != NULL) {
        snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
        type = tbuf;
    }

    cond = _st_mysql_convert_filter(drv, owner, filter);
    log_debug(ZONE, "generated filter: %s", cond);

    MYSQL_SAFE(buf, strlen(type) + strlen(cond) + 21, buflen);
    sprintf(buf, "DELETE FROM `%s` WHERE %s", type, cond);
    free(cond);

    log_debug(ZONE, "prepared sql: %s", buf);

    if(mysql_query(data->conn, buf) != 0) {
        log_write(drv->st->log, LOG_ERR, "mysql: sql delete failed: %s", mysql_error(data->conn));
        free(buf);
        return st_FAILED;
    }
    free(buf);

    return st_SUCCESS;
}

static st_ret_t _st_mysql_replace(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t os) {
    drvdata_t data = (drvdata_t) drv->private;

    if(mysql_ping(data->conn) != 0) {
        log_write(drv->st->log, LOG_ERR, "mysql: connection to database lost");
        return st_FAILED;
    }

    if(data->txn) {
        if(mysql_query(data->conn, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE") != 0) {
            log_write(drv->st->log, LOG_ERR, "mysql: sql transaction setup failed: %s", mysql_error(data->conn));
            return st_FAILED;
        }

        if(mysql_query(data->conn, "BEGIN") != 0) {
            log_write(drv->st->log, LOG_ERR, "mysql: sql transaction begin failed: %s", mysql_error(data->conn));
            return st_FAILED;
        }
    }

    if(_st_mysql_delete(drv, type, owner, filter) == st_FAILED) {
        if(data->txn)
            mysql_query(data->conn, "ROLLBACK");
        return st_FAILED;
    }

    if(_st_mysql_put_guts(drv, type, owner, os) == st_FAILED) {
        if(data->txn)
            mysql_query(data->conn, "ROLLBACK");
        return st_FAILED;
    }

    if(data->txn)
        if(mysql_query(data->conn, "COMMIT") != 0) {
            log_write(drv->st->log, LOG_ERR, "mysql: sql transaction commit failed: %s", mysql_error(data->conn));
            mysql_query(data->conn, "ROLLBACK");
            return st_FAILED;
        }

    return st_SUCCESS;
}

static void _st_mysql_free(st_driver_t drv) {
    drvdata_t data = (drvdata_t) drv->private;

    mysql_close(data->conn);

    free(data);
}

DLLEXPORT st_ret_t st_init(st_driver_t drv) {
    const char *host, *port, *dbname, *user, *pass;
    MYSQL *conn;
    drvdata_t data;

    host = config_get_one(drv->st->config, "storage.mysql.host", 0);
    port = config_get_one(drv->st->config, "storage.mysql.port", 0);
    dbname = config_get_one(drv->st->config, "storage.mysql.dbname", 0);
    user = config_get_one(drv->st->config, "storage.mysql.user", 0);
    pass = config_get_one(drv->st->config, "storage.mysql.pass", 0);

    if(host == NULL || port == NULL || dbname == NULL || user == NULL || pass == NULL) {
        log_write(drv->st->log, LOG_ERR, "mysql: invalid driver config");
        return st_FAILED;
    }

    conn = mysql_init(NULL);
    if(conn == NULL) {
        log_write(drv->st->log, LOG_ERR, "mysql: unable to allocate database connection state");
        return st_FAILED;
    }

    mysql_options(conn, MYSQL_READ_DEFAULT_GROUP, "jabberd");
    mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8");

    /* connect with CLIENT_INTERACTIVE to get a (possibly) higher timeout value than default */
    if(mysql_real_connect(conn, host, user, pass, dbname, atoi(port), NULL, CLIENT_INTERACTIVE) == NULL) {
        log_write(drv->st->log, LOG_ERR, "mysql: connection to database failed: %s", mysql_error(conn));
        mysql_close(conn);
        return st_FAILED;
    }

    /* Set reconnect flag to 1 (set to 0 by default from mysql 5 on) */
    conn->reconnect = 1;

    data = (drvdata_t) calloc(1, sizeof(struct drvdata_st));

    data->conn = conn;

    if(config_get_one(drv->st->config, "storage.mysql.transactions", 0) != NULL)
        data->txn = 1;
    else
        log_write(drv->st->log, LOG_WARNING, "mysql: transactions disabled");

    data->prefix = config_get_one(drv->st->config, "storage.mysql.prefix", 0);

    drv->private = (void *) data;

    drv->add_type = _st_mysql_add_type;
    drv->put = _st_mysql_put;
    drv->count = _st_mysql_count;
    drv->get = _st_mysql_get;
    drv->delete = _st_mysql_delete;
    drv->replace = _st_mysql_replace;
    drv->free = _st_mysql_free;

    return st_SUCCESS;
}
