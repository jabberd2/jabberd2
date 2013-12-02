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

/** @file sm/storage_pgsql.c
  * @brief postgresql storage module
  * @author Robert Norris
  * $Date: 2005/06/02 04:48:25 $
  * $Revision: 1.25 $
  */

#include "storage.h"
#include <libpq-fe.h>

/** internal structure, holds our data */
typedef struct drvdata_st {
    PGconn *conn;

    const char *prefix;

    int txn;
} *drvdata_t;

#define FALLBACK_BLOCKSIZE (4096)

/** internal: do and return the math and ensure it gets realloc'd */
static size_t _st_pgsql_realloc(char **oblocks, size_t len) {
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
#define PGSQL_SAFE(blocks, size, len) if((size) >= len) len = _st_pgsql_realloc(&(blocks),(size + 1));

static void _st_pgsql_convert_filter_recursive(st_driver_t drv, st_filter_t f, char **buf, unsigned int *buflen, unsigned int *nbuf) {
    st_filter_t scan;
    int vlen;
    char *cval;

    switch(f->type) {
        case st_filter_type_PAIR:
            /* do sql escaping for apostrophes */
            cval = (char *) malloc(sizeof(char) * ((strlen(f->val) * 2) + 1));
            vlen = PQescapeString(cval, f->val, strlen(f->val));

            PGSQL_SAFE((*buf), *buflen + 12 + vlen - strlen(f->val), *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "( \"%s\" = \'%s\' ) ", f->key, f->val);
            free(cval);

            break;

        case st_filter_type_AND:
            PGSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "( ");

            for(scan = f->sub; scan != NULL; scan = scan->next) {
                _st_pgsql_convert_filter_recursive(drv, scan, buf, buflen, nbuf);

                if(scan->next != NULL) {
                    PGSQL_SAFE((*buf), *buflen + 4, *buflen);
                    *nbuf += sprintf(&((*buf)[*nbuf]), "AND ");
                }
            }

            PGSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), ") ");

            return;

        case st_filter_type_OR:
            PGSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "( ");

            for(scan = f->sub; scan != NULL; scan = scan->next) {
                _st_pgsql_convert_filter_recursive(drv, scan, buf, buflen, nbuf);

                if(scan->next != NULL) {
                    PGSQL_SAFE((*buf), *buflen + 3, *buflen);
                    *nbuf += sprintf(&((*buf)[*nbuf]), "OR ");
                }
            }

            PGSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), ") ");

            return;

        case st_filter_type_NOT:
            PGSQL_SAFE((*buf), *buflen + 6, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "( NOT ");

            _st_pgsql_convert_filter_recursive(drv, f->sub, buf, buflen, nbuf);

            PGSQL_SAFE((*buf), *buflen + 2, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), ") ");

            return;
    }
}

static char *_st_pgsql_convert_filter(st_driver_t drv, const char *owner, const char *filter) {
    /* drvdata_t data = (drvdata_t) drv->private;*/
    char *buf = NULL;
    unsigned int buflen = 0, nbuf = 0;
    st_filter_t f;

    PGSQL_SAFE(buf, 24 + strlen(owner), buflen);

    nbuf = sprintf(buf, "\"collection-owner\" = '%s'", owner);

    f = storage_filter(filter);
    if(f == NULL)
        return buf;

    PGSQL_SAFE(buf, buflen + 5, buflen);
    nbuf += sprintf(&buf[nbuf], " AND ");

    _st_pgsql_convert_filter_recursive(drv, f, &buf, &buflen, &nbuf);

    pool_free(f->p);

    return buf;
}

static st_ret_t _st_pgsql_add_type(st_driver_t drv, const char *type) {
    return st_SUCCESS;
}

static st_ret_t _st_pgsql_put_guts(st_driver_t drv, const char *type, const char *owner, os_t os) {
    drvdata_t data = (drvdata_t) drv->private;
    char *left = NULL, *right = NULL;
    int lleft = 0, lright = 0, nleft, nright;
    os_object_t o;
    char *key, *cval = NULL;
    void *val;
    os_type_t ot;
    const char *xml;
    int xlen;
    PGresult *res;
    char tbuf[128];

    if(os_count(os) == 0)
        return st_SUCCESS;

    if(data->prefix != NULL) {
        snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
        type = tbuf;
    }

    if(os_iter_first(os))
        do {
            PGSQL_SAFE(left, strlen(type) + 55, lleft);
            nleft = sprintf(left, "INSERT INTO \"%s\" ( \"collection-owner\", \"object-sequence\"", type);

            PGSQL_SAFE(right, strlen(owner) + 43, lright);
            nright = sprintf(right, " ) VALUES ( '%s', nextval('object-sequence')", owner);

            o = os_iter_object(os);
            if(os_object_iter_first(o))
                do {
                    os_object_iter_get(o, &key, &val, &ot);

                    switch(ot) {
                        case os_type_BOOLEAN:
                            cval = val ? strdup("t") : strdup("f");
                            break;

                        case os_type_INTEGER:
                            cval = (char *) malloc(sizeof(char) * 20);
                            sprintf(cval, "%ld", (int) (intptr_t) val);
                            break;

                        case os_type_STRING:
                            cval = (char *) malloc(sizeof(char) * ((strlen((char *) val) * 2) + 1));
                            PQescapeString(cval, (char *) val, strlen((char *) val));
                            break;

                        case os_type_NAD:
                            nad_print((nad_t) val, 0, &xml, &xlen);
                            cval = (char *) malloc(sizeof(char) * ((xlen * 2) + 4));
                            PQescapeString(&cval[3], xml, xlen);
                            strncpy(cval, "NAD", 3);
                            break;

                        case os_type_UNKNOWN:
                            break;
                    }

                    log_debug(ZONE, "key %s val %s", key, cval);

                    PGSQL_SAFE(left, lleft + strlen(key) + 4, lleft);
                    nleft += sprintf(&left[nleft], ", \"%s\"", key);

                    PGSQL_SAFE(right, lright + strlen(cval) + 4, lright);
                    nright += sprintf(&right[nright], ", '%s'", cval);

                    free(cval);
                } while(os_object_iter_next(o));

            PGSQL_SAFE(left, lleft + strlen(right) + 3, lleft);
            sprintf(&left[nleft], "%s );", right);
    
            log_debug(ZONE, "prepared sql: %s", left);

            res = PQexec(data->conn, left);

            if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(data->conn) != CONNECTION_OK) {
                log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
                PQclear(res);
                PQreset(data->conn);
                res = PQexec(data->conn, left);
            }
            if(PQresultStatus(res) != PGRES_COMMAND_OK) {
                log_write(drv->st->log, LOG_ERR, "pgsql: sql insert failed: %s", PQresultErrorMessage(res));
                free(left);
                free(right);
                PQclear(res);
                return st_FAILED;
            }

            PQclear(res);

        } while(os_iter_next(os));

    free(left);
    free(right);

    return st_SUCCESS;
}

static st_ret_t _st_pgsql_put(st_driver_t drv, const char *type, const char *owner, os_t os) {
    drvdata_t data = (drvdata_t) drv->private;
    PGresult *res;

    if(os_count(os) == 0)
        return st_SUCCESS;

    if(data->txn) {
        res = PQexec(data->conn, "BEGIN;");
        if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(data->conn) != CONNECTION_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
            PQclear(res);
            PQreset(data->conn);
            res = PQexec(data->conn, "BEGIN;");
        }
        if(PQresultStatus(res) != PGRES_COMMAND_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: sql transaction begin failed: %s", PQresultErrorMessage(res));
            PQclear(res);
            return st_FAILED;
        }
        PQclear(res);

        res = PQexec(data->conn, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
        if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(data->conn) != CONNECTION_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
            PQclear(res);
            PQreset(data->conn);
            res = PQexec(data->conn, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
        }
        if(PQresultStatus(res) != PGRES_COMMAND_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: sql transaction setup failed: %s", PQresultErrorMessage(res));
            PQclear(res);
            PQclear(PQexec(data->conn, "ROLLBACK;"));
            return st_FAILED;
        }
        PQclear(res);
    }

    if(_st_pgsql_put_guts(drv, type, owner, os) != st_SUCCESS) {
        if(data->txn)
            PQclear(PQexec(data->conn, "ROLLBACK;"));
        return st_FAILED;
    }

    if(data->txn) {
        res = PQexec(data->conn, "COMMIT;");
        if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(data->conn) != CONNECTION_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
            PQclear(res);
            PQreset(data->conn);
            res = PQexec(data->conn, "COMMIT;");
        }
        if(PQresultStatus(res) != PGRES_COMMAND_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: sql transaction commit failed: %s", PQresultErrorMessage(res));
            PQclear(res);
            PQclear(PQexec(data->conn, "ROLLBACK;"));
            return st_FAILED;
        }
        PQclear(res);
    }

    return st_SUCCESS;
}

static st_ret_t _st_pgsql_get(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t *os) {
    drvdata_t data = (drvdata_t) drv->private;
    char *cond, *buf = NULL;
    int buflen = 0;
    PGresult *res;
    int ntuples, nfields, i, j;
    os_object_t o;
    char *fname, *val;
    os_type_t ot;
    int ival;
    char tbuf[128];

    if(data->prefix != NULL) {
        snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
        type = tbuf;
    }

    cond = _st_pgsql_convert_filter(drv, owner, filter);
    log_debug(ZONE, "generated filter: %s", cond);

    PGSQL_SAFE(buf, strlen(type) + strlen(cond) + 51, buflen);
    sprintf(buf, "SELECT * FROM \"%s\" WHERE %s ORDER BY \"object-sequence\";", type, cond);
    free(cond);

    log_debug(ZONE, "prepared sql: %s", buf);

    res = PQexec(data->conn, buf);

    if(PQresultStatus(res) != PGRES_TUPLES_OK && PQstatus(data->conn) != CONNECTION_OK) {
        log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
        PQclear(res);
        PQreset(data->conn);
        res = PQexec(data->conn, buf);
    }

    free(buf);

    if(PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_write(drv->st->log, LOG_ERR, "pgsql: sql select failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return st_FAILED;
    }

    ntuples = PQntuples(res);
    if(ntuples == 0) {
        PQclear(res);
        return st_NOTFOUND;
    }

    log_debug(ZONE, "%d tuples returned", ntuples);

    nfields = PQnfields(res);

    if(nfields == 0) {
        log_debug(ZONE, "weird, tuples were returned but no fields *shrug*");
        PQclear(res);
        return st_NOTFOUND;
    }

    *os = os_new();

    for(i = 0; i < ntuples; i++) {
        o = os_object_new(*os);

        for(j = 0; j < nfields; j++) {
            fname = PQfname(res, j);
            if(strcmp(fname, "collection-owner") == 0)
                continue;

            switch(PQftype(res, j)) {
                case 16:    /* boolean */
                    ot = os_type_BOOLEAN;
                    break;

                case 23:    /* integer */
                    ot = os_type_INTEGER;
                    break;

                case 25:    /* text */
                    ot = os_type_STRING;
                    break;

                default:
                    log_debug(ZONE, "unknown oid %d, ignoring it", PQfname(res, j));
                    continue;
            }

            if(PQgetisnull(res, i, j))
                continue;

            val = PQgetvalue(res, i, j);

            switch(ot) {
                case os_type_BOOLEAN:
                    ival = (val[0] == 't') ? 1 : 0;
                    os_object_put(o, fname, &ival, ot);
                    break;

                case os_type_INTEGER:
                    ival = atoi(val);
                    os_object_put(o, fname, &ival, ot);
                    break;

                case os_type_STRING:
                    os_object_put(o, fname, val, os_type_STRING);
                    break;

                case os_type_NAD:
                case os_type_UNKNOWN:
                    break;
            }
        }
    }

    PQclear(res);

    return st_SUCCESS;
}

static st_ret_t _st_pgsql_count(st_driver_t drv, const char *type, const char *owner, const char *filter, int *count) {
    drvdata_t data = (drvdata_t) drv->private;
    char *cond, *buf = NULL;
    int buflen = 0;
    PGresult *res;
    int ntuples, nfields;
    char tbuf[128];

    if(data->prefix != NULL) {
        snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
        type = tbuf;
    }

    cond = _st_pgsql_convert_filter(drv, owner, filter);
    log_debug(ZONE, "generated filter: %s", cond);

    PGSQL_SAFE(buf, strlen(type) + strlen(cond) + 31, buflen);
    sprintf(buf, "SELECT COUNT(*) FROM \"%s\" WHERE %s", type, cond);
    free(cond);

    log_debug(ZONE, "prepared sql: %s", buf);

    res = PQexec(data->conn, buf);

    if(PQresultStatus(res) != PGRES_TUPLES_OK && PQstatus(data->conn) != CONNECTION_OK) {
        log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
        PQclear(res);
        PQreset(data->conn);
        res = PQexec(data->conn, buf);
    }

    free(buf);

    if(PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_write(drv->st->log, LOG_ERR, "pgsql: sql select failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return st_FAILED;
    }

    ntuples = PQntuples(res);
    if(ntuples == 0) {
        PQclear(res);
        return st_NOTFOUND;
    }

    log_debug(ZONE, "%d tuples returned", ntuples);

    nfields = PQnfields(res);

    if(nfields == 0) {
        log_debug(ZONE, "weird, tuples were returned but no fields *shrug*");
        PQclear(res);
        return st_NOTFOUND;
    }

    if(PQgetisnull(res, 0, 0) || PQftype(res, 0) != 20)
        return st_NOTFOUND;

    if (count!=NULL)
        *count = atoi(PQgetvalue(res, 0, 0));

    PQclear(res);

    return st_SUCCESS;
}

static st_ret_t _st_pgsql_delete(st_driver_t drv, const char *type, const char *owner, const char *filter) {
    drvdata_t data = (drvdata_t) drv->private;
    char *cond, *buf = NULL;
    int buflen = 0;
    PGresult *res;
    char tbuf[128];

    if(data->prefix != NULL) {
        snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
        type = tbuf;
    }

    cond = _st_pgsql_convert_filter(drv, owner, filter);
    log_debug(ZONE, "generated filter: %s", cond);

    PGSQL_SAFE(buf, strlen(type) + strlen(cond) + 23, buflen);
    sprintf(buf, "DELETE FROM \"%s\" WHERE %s;", type, cond);
    free(cond);

    log_debug(ZONE, "prepared sql: %s", buf);

    res = PQexec(data->conn, buf);

    if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(data->conn) != CONNECTION_OK) {
        log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
        PQclear(res);
        PQreset(data->conn);
        res = PQexec(data->conn, buf);
    }

    free(buf);

    if(PQresultStatus(res) != PGRES_COMMAND_OK) {
        log_write(drv->st->log, LOG_ERR, "pgsql: sql delete failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return st_FAILED;
    }

    PQclear(res);

    return st_SUCCESS;
}

static st_ret_t _st_pgsql_replace(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t os) {
    drvdata_t data = (drvdata_t) drv->private;
    PGresult *res;

    if(data->txn) {
        res = PQexec(data->conn, "BEGIN;");
        if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(data->conn) != CONNECTION_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
            PQclear(res);
            PQreset(data->conn);
            res = PQexec(data->conn, "BEGIN;");
        }
        if(PQresultStatus(res) != PGRES_COMMAND_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: sql transaction begin failed: %s", PQresultErrorMessage(res));
            PQclear(res);
            return st_FAILED;
        }
        PQclear(res);

        res = PQexec(data->conn, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
        if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(data->conn) != CONNECTION_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
            PQclear(res);
            PQreset(data->conn);
            res = PQexec(data->conn, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
        }
        if(PQresultStatus(res) != PGRES_COMMAND_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: sql transaction setup failed: %s", PQresultErrorMessage(res));
            PQclear(res);
            PQclear(PQexec(data->conn, "ROLLBACK;"));
            return st_FAILED;
        }
        PQclear(res);
    }

    if(_st_pgsql_delete(drv, type, owner, filter) == st_FAILED) {
        if(data->txn)
            PQclear(PQexec(data->conn, "ROLLBACK;"));
        return st_FAILED;
    }

    if(_st_pgsql_put_guts(drv, type, owner, os) == st_FAILED) {
        if(data->txn)
            PQclear(PQexec(data->conn, "ROLLBACK;"));
        return st_FAILED;
    }

    if(data->txn) {
        res = PQexec(data->conn, "COMMIT;");
        if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(data->conn) != CONNECTION_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
            PQclear(res);
            PQreset(data->conn);
            res = PQexec(data->conn, "COMMIT;");
        }
        if(PQresultStatus(res) != PGRES_COMMAND_OK) {
            log_write(drv->st->log, LOG_ERR, "pgsql: sql transaction commit failed: %s", PQresultErrorMessage(res));
            PQclear(res);
            PQclear(PQexec(data->conn, "ROLLBACK;"));
            return st_FAILED;
        }
        PQclear(res);
    }

    return st_SUCCESS;
}

static void _st_pgsql_free(st_driver_t drv) {
    drvdata_t data = (drvdata_t) drv->private;

    PQfinish(data->conn);

    free(data);
}

st_ret_t st_init(st_driver_t drv) {
    const char *host, *port, *dbname, *schema, *user, *pass, *conninfo;
    char sql[1024];
    PGconn *conn;
    drvdata_t data;

    host = config_get_one(drv->st->config, "storage.pgsql.host", 0);
    port = config_get_one(drv->st->config, "storage.pgsql.port", 0);
    dbname = config_get_one(drv->st->config, "storage.pgsql.dbname", 0);
    schema = config_get_one(drv->st->config, "storage.pgsql.schema", 0);
    user = config_get_one(drv->st->config, "storage.pgsql.user", 0);
    pass = config_get_one(drv->st->config, "storage.pgsql.pass", 0);
    conninfo = config_get_one(drv->st->config, "storage.pgsql.conninfo",0);

    if(conninfo) {
        conn = PQconnectdb(conninfo);
    } else {
        conn = PQsetdbLogin(host, port, NULL, NULL, dbname, user, pass);
    }

    if(conn == NULL) {
        log_write(drv->st->log, LOG_ERR, "pgsql: unable to allocate database connection state");
        return st_FAILED;
    }

    if(PQstatus(conn) != CONNECTION_OK)
        log_write(drv->st->log, LOG_ERR, "pgsql: connection to database failed: %s", PQerrorMessage(conn));

    if (schema) {
        snprintf(sql, sizeof(sql), "SET search_path TO \"%s\"", schema);
        PQexec(conn, sql);
    }

    data = (drvdata_t) calloc(1, sizeof(struct drvdata_st));

    data->conn = conn;

    if(config_get_one(drv->st->config, "storage.pgsql.transactions", 0) != NULL)
        data->txn = 1;
    else
        log_write(drv->st->log, LOG_WARNING, "pgsql: transactions disabled");

    data->prefix = config_get_one(drv->st->config, "storage.pgsql.prefix", 0);

    drv->private = (void *) data;

    drv->add_type = _st_pgsql_add_type;
    drv->put = _st_pgsql_put;
    drv->count = _st_pgsql_count;
    drv->get = _st_pgsql_get;
    drv->delete = _st_pgsql_delete;
    drv->replace = _st_pgsql_replace;
    drv->free = _st_pgsql_free;

    return st_SUCCESS;
}
