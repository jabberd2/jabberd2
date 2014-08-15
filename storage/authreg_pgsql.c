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

/* this module talks to a PostgreSQL server via libpq */

#define _XOPEN_SOURCE 500
#include "c2s.h"
#include <libpq-fe.h>

/* Windows does not have the crypt() function, let's take DES_crypt from OpenSSL instead */
#if defined(HAVE_OPENSSL_CRYPTO_H) && defined(_WIN32)
#include <openssl/des.h>
#define crypt DES_crypt
#define HAVE_CRYPT 1
#else
#ifdef HAVE_CRYPT
#include <unistd.h>
#endif
#endif

#ifdef HAVE_SSL
/* We use OpenSSL's MD5 routines for the a1hash password type */
#include <openssl/md5.h>
#endif

#define PGSQL_LU  1024   /* maximum length of username - should correspond to field length */
#define PGSQL_LR   256   /* maximum length of realm - should correspond to field length */
#define PGSQL_LP   256   /* maximum length of password - should correspond to field length */

enum pgsql_pws_crypt {
    MPC_PLAIN,
#ifdef HAVE_CRYPT
    MPC_CRYPT,
#endif
#ifdef HAVE_SSL
    MPC_A1HASH,
#endif
};

typedef struct pgsqlcontext_st {
  PGconn * conn;
  const char * sql_create;
  const char * sql_select;
  const char * sql_setpassword;
  const char * sql_delete;
  const char * sql_check_password;
  const char * field_password;
  enum pgsql_pws_crypt password_type;
  } *pgsqlcontext_t;

#ifdef HAVE_SSL
static void calc_a1hash(const char *username, const char *realm, const char *password, char *a1hash)
{
#define A1PPASS_LEN PGSQL_LU + 1 + PGSQL_LR + 1 + PGSQL_LP + 1 /* user:realm:password\0 */
    char buf[A1PPASS_LEN];
    unsigned char md5digest[MD5_DIGEST_LENGTH];
    int i;

    snprintf(buf, A1PPASS_LEN, "%.*s:%.*s:%.*s", PGSQL_LU, username, PGSQL_LR, realm, PGSQL_LP, password);

    MD5((unsigned char*)buf, strlen(buf), md5digest);

    for(i=0; i<16; i++) {
        sprintf(a1hash+i*2, "%02hhx", md5digest[i]);
    }
}
#endif

static PGresult *_ar_pgsql_get_user_tuple(authreg_t ar, const char *username, const char *realm) {
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    PGconn *conn = ctx->conn;

    char iuser[PGSQL_LU+1], irealm[PGSQL_LR+1];
    char euser[PGSQL_LU*2+1], erealm[PGSQL_LR*2+1], sql[1024+PGSQL_LU*2+PGSQL_LR*2+1];  /* query(1024) + euser + erealm + \0(1) */
    PGresult *res;

    snprintf(iuser, PGSQL_LU+1, "%s", username);
    snprintf(irealm, PGSQL_LR+1, "%s", realm);

    PQescapeString(euser, iuser, strlen(iuser));
    PQescapeString(erealm, irealm, strlen(irealm));

    sprintf(sql, ctx->sql_select, euser, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    res = PQexec(conn, sql);
    if(PQresultStatus(res) != PGRES_TUPLES_OK && PQstatus(conn) != CONNECTION_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
        PQclear(res);
        PQreset(conn);
        if(PQstatus(conn) != CONNECTION_OK) {
            log_write(ar->c2s->log, LOG_ERR, "pgsql: connection to database failed, will retry later: %s", PQerrorMessage(conn));
            return NULL;
        }

        res = PQexec(conn, sql);
    }
    if(PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: sql select failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return NULL;
    }

    if(PQntuples(res) != 1) {
        PQclear(res);
        return NULL;
    }

    return res;
}

static int _ar_pgsql_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm) {
    if (ar->get_password) {
        PGresult *res = _ar_pgsql_get_user_tuple(ar, username, realm);

        if(res != NULL) {
            PQclear(res);
            return 1;
        }

        return 0;
    } else {
        return 1; // Try to check password later.
    }
}

static int _ar_pgsql_get_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257]) {
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    PGresult *res = _ar_pgsql_get_user_tuple(ar, username, realm);
    int fpass;

    if(res == NULL)
        return 1;

    fpass = PQfnumber(res, ctx->field_password);
    if(fpass == -1) {
        log_debug(ZONE, "weird, password field wasn't returned");
        PQclear(res);
        return 1;
    }

    if(PQgetisnull(res, 0, fpass)) {
        PQclear(res);
        return 1;
    }

    strcpy(password, PQgetvalue(res, 0, fpass));

    PQclear(res);

    return 0;
}

static int _ar_pgsql_dbcheck_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    PGconn *conn = ctx->conn;

    char iuser[PGSQL_LU+1], irealm[PGSQL_LR+1], ipassword[PGSQL_LR+1];
    char euser[PGSQL_LU*2+1], erealm[PGSQL_LR*2+1], epassword[PGSQL_LR*2+1], sql[1024+PGSQL_LU*2+PGSQL_LR*2+1+PGSQL_LR*2+1];  /* query(1024) + euser + erealm + \0(1) */
    PGresult *res;

    snprintf(iuser, PGSQL_LU+1, "%s", username);
    snprintf(irealm, PGSQL_LR+1, "%s", realm);
    snprintf(ipassword, PGSQL_LR+1, "%s", password);

    PQescapeString(euser, iuser, strlen(iuser));
    PQescapeString(erealm, irealm, strlen(irealm));
    PQescapeString(epassword, ipassword, strlen(ipassword));

    sprintf(sql, ctx->sql_check_password, euser, epassword, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    res = PQexec(conn, sql);
    if(PQresultStatus(res) != PGRES_TUPLES_OK && PQstatus(conn) != CONNECTION_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
        PQclear(res);
        PQreset(conn);
        if(PQstatus(conn) != CONNECTION_OK) {
            log_write(ar->c2s->log, LOG_ERR, "pgsql: connection to database failed, will retry later: %s", PQerrorMessage(conn));
            return 1;
        }

        res = PQexec(conn, sql);
    }
    if(PQresultStatus(res) != PGRES_TUPLES_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: sql select failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return 1;
    }

    if(PQntuples(res) != 1) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: Empty result");
        PQclear(res);
        return 1;
    }

    int retval = 1;

    if(PQgetisnull(res, 0, 0)) {
        log_debug(ZONE, "pgsql: check_password returns NULL");
        PQclear(res);
        return 1;
    }

    const char *result = PQgetvalue(res, 0, 0);
    log_debug(ZONE, "pgsql:  check_password result: '%s'", result);

    if (strcmp("0", result) != 0) {
        // something except 0 -> authenticated
        retval = 0;
    } else {
        retval = 1;
    }

    PQclear(res);

    return retval;
};

static int _ar_pgsql_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    char db_pw_value[257];
#ifdef HAVE_CRYPT
    char *crypted_pw;
#endif
#ifdef HAVE_SSL
    char a1hash_pw[33];
#endif
    int ret;

    ret = _ar_pgsql_get_password(ar, sess, username, realm, db_pw_value);
    /* return if error */
    if (ret)
        return ret;

    switch (ctx->password_type) {
        case MPC_PLAIN:
                ret = (strcmp(password, db_pw_value) != 0);
                break;

#ifdef HAVE_CRYPT
        case MPC_CRYPT:
                crypted_pw = crypt(password,db_pw_value);
                ret = (strcmp(crypted_pw, db_pw_value) != 0);
                break;
#endif

#ifdef HAVE_SSL
        case MPC_A1HASH:
                if (strchr(username, ':')) {
                    ret = 1;
                    log_write(ar->c2s->log, LOG_ERR, "Username cannot contain : with a1hash encryption type.");
                    break;
                }
                if (strchr(realm, ':')) {
                    ret = 1;
                    log_write(ar->c2s->log, LOG_ERR, "Realm cannot contain : with a1hash encryption type.");
                    break;
                }
                calc_a1hash(username, realm, password, a1hash_pw);
                ret = (strncmp(a1hash_pw, db_pw_value, 32) != 0);
                break;
#endif

        default:
        /* should never happen */
                ret = 1;
                log_write(ar->c2s->log, LOG_ERR, "Unknown encryption type which passed through config check.");
                break;
    }

    return ret;
}

static int _ar_pgsql_set_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257]) {
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    PGconn *conn = ctx->conn;
    char iuser[PGSQL_LU+1], irealm[PGSQL_LR+1];
    char euser[PGSQL_LU*2+1], erealm[PGSQL_LR*2+1], epass[513], sql[1024+PGSQL_LU*2+PGSQL_LR*2+512+1];  /* query(1024) + euser + erealm + epass(512) + \0(1) */
    PGresult *res;

    snprintf(iuser, PGSQL_LU+1, "%s", username);
    snprintf(irealm, PGSQL_LR+1, "%s", realm);

    PQescapeString(euser, iuser, strlen(iuser));
    PQescapeString(erealm, irealm, strlen(irealm));
    PQescapeString(epass, password, strlen(password));

    sprintf(sql, ctx->sql_setpassword, epass, euser, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    res = PQexec(conn, sql);
    if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(conn) != CONNECTION_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
        PQclear(res);
        PQreset(conn);

        if(PQstatus(conn) != CONNECTION_OK) {
            log_write(ar->c2s->log, LOG_ERR, "pgsql: connection to database failed, will retry later: %s", PQerrorMessage(conn));
            return 1;
        }
        res = PQexec(conn, sql);
    }
    if(PQresultStatus(res) != PGRES_COMMAND_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: sql update failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return 1;
    }

    PQclear(res);

    return 0;
}

static int _ar_pgsql_create_user(authreg_t ar, sess_t sess, const char *username, const char *realm) {
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    PGconn *conn = ctx->conn;
    char iuser[PGSQL_LU+1], irealm[PGSQL_LR+1];
    char euser[PGSQL_LU*2+1], erealm[PGSQL_LR*2+1], sql[1024+PGSQL_LU*2+PGSQL_LR*2+1];  /* query(1024) + euser + erealm + \0(1) */
    PGresult *res;

    res = _ar_pgsql_get_user_tuple(ar, username, realm);
    if(res != NULL) {
        PQclear(res);
        return 1;
    }

    PQclear(res);

    snprintf(iuser, PGSQL_LU+1, "%s", username);
    snprintf(irealm, PGSQL_LR+1, "%s", realm);

    PQescapeString(euser, iuser, strlen(iuser));
    PQescapeString(erealm, irealm, strlen(irealm));

    sprintf(sql, ctx->sql_create, euser, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    res = PQexec(conn, sql);
    if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(conn) != CONNECTION_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
        PQclear(res);
        PQreset(conn);

        if(PQstatus(conn) != CONNECTION_OK) {
            log_write(ar->c2s->log, LOG_ERR, "pgsql: connection to database failed, will retry later: %s", PQerrorMessage(conn));
            return 1;
        }

        res = PQexec(conn, sql);
    }
    if(PQresultStatus(res) != PGRES_COMMAND_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: sql insert failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return 1;
    }

    PQclear(res);

    return 0;
}

static int _ar_pgsql_delete_user(authreg_t ar, sess_t sess, const char *username, const char *realm) {
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    PGconn *conn = ctx->conn;
    char iuser[PGSQL_LU+1], irealm[PGSQL_LR+1];
    char euser[PGSQL_LU*2+1], erealm[PGSQL_LR*2+1], sql[1024+PGSQL_LU*2+PGSQL_LR*2+1];    /* query(1024) + euser + erealm + \0(1) */
    PGresult *res;

    snprintf(iuser, PGSQL_LU+1, "%s", username);
    snprintf(irealm, PGSQL_LR+1, "%s", realm);

    PQescapeString(euser, iuser, strlen(iuser));
    PQescapeString(erealm, irealm, strlen(irealm));

    sprintf(sql, ctx->sql_delete, euser, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    res = PQexec(conn, sql);
    if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(conn) != CONNECTION_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
        PQclear(res);
        PQreset(conn);

        if(PQstatus(conn) != CONNECTION_OK) {
            log_write(ar->c2s->log, LOG_ERR, "pgsql: connection to database failed, will retry later: %s", PQerrorMessage(conn));
            return 1;
        }

        res = PQexec(conn, sql);
    }
    if(PQresultStatus(res) != PGRES_COMMAND_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: sql delete failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return 1;
    }

    PQclear(res);

    return 0;
}

static void _ar_pgsql_free(authreg_t ar) {
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    PGconn *conn = ctx->conn;

    if(conn != NULL)
       PQfinish(conn);

    free((void*)ctx->sql_create);
    free((void*)ctx->sql_select);
    free((void*)ctx->sql_setpassword);
    free((void*)ctx->sql_delete);
    if (ctx->sql_check_password) {
        free((void*)ctx->sql_check_password);
    }
    free(ctx);
}

/** Provide a configuration parameter or default value. */
static const char * _ar_pgsql_param( config_t c, const char * key, const char * def ) {
    const char * value = config_get_one( c, key, 0 );
    if( value == NULL )
      return def;
    else
      return value;
}

/* Ensure the sprintf template is less than 1K long and contains the */
/* required parameter placeholder types. The types string contains */
/* one each, in order, of the one character sprintf types that are */
/* expected to follow the escape characters '%' in the template. */
/* Returns 0 on success, or an error message on failures. */
static const char * _ar_pgsql_check_template( const char * template, const char * types ) {
    int pScan = 0;
    int pType = 0;
    char c;

    /* check that it's 1K or less */
    if( strlen( template ) > 1024 ) return "longer than 1024 characters";

    /* count the parameter placeholders */
    while( pScan < strlen( template ) )
    {
      if( template[ pScan++ ] != '%' ) continue;

      c = template[ pScan++ ];
      if( c == '%' ) continue; /* ignore escaped precentages */
      if( c == types[ pType ] )
      {
	/* we found the placeholder */
	pType++;  /* search for the next type */
        continue;
      }

      /* we found an unexpected placeholder type */
      return "contained unexpected placeholder type";
    }

    if( pType < strlen( types ) )
      return "contained too few placeholders";
    else
      return 0;
}

/* Ensure the SQL template is less than 1K long and contains the */
/* required parameter placeholders.  If there is an error, it is   */
/* written to the error log. */
/* Returns 0 on success, or 1 on errors. */
int _ar_pgsql_check_sql( authreg_t ar, const char * sql, const char * types ) {
  const char * error;

  error = _ar_pgsql_check_template( sql, types );
  if( error == 0 ) return 0;  /* alls right :) */

  /* signal error */
  log_write( ar->c2s->log, LOG_ERR, "pgsql: template error: %s - %s", error, sql );
  return 1;
}

#ifdef HAVE_SSL
extern int sx_openssl_initialized;
#endif

/** start me up */
int ar_init(authreg_t ar) {
    const char *host, *port, *dbname, *schema, *user, *pass, *conninfo;
    char *create, *select, *setpassword, *delete, *setsearchpath;
    const char *table, *username, *realm;
    char *template;
    int strlentur; /* string length of table, user, and realm strings */
    PGconn *conn;
    pgsqlcontext_t pgsqlcontext;

    /* configure the database context with field names and SQL statements */
    pgsqlcontext = (pgsqlcontext_t) calloc(1, sizeof( struct pgsqlcontext_st ) );
    ar->private = pgsqlcontext;
    ar->free = _ar_pgsql_free;

    /* determine our field names and table name */
    username = _ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.field.username"
	       , "username" );
    realm = _ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.field.realm"
	       , "realm" );
    pgsqlcontext->field_password = _ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.field.password"
	       , "password" );
    table = _ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.table"
	       , "authreg" );

    /* get encryption type used in DB */
    if (config_get_one(ar->c2s->config, "authreg.pgsql.password_type.plaintext", 0)) {
        pgsqlcontext->password_type = MPC_PLAIN;
#ifdef HAVE_CRYPT
    } else if (config_get_one(ar->c2s->config, "authreg.pgsql.password_type.crypt", 0)) {
        pgsqlcontext->password_type = MPC_CRYPT;
#endif
#ifdef HAVE_SSL
    } else if (config_get_one(ar->c2s->config, "authreg.pgsql.password_type.a1hash", 0)) {
        pgsqlcontext->password_type = MPC_A1HASH;
#endif
    } else {
        pgsqlcontext->password_type = MPC_PLAIN;
    }

    /* craft the default SQL statements */
    /* we leave unused statements allocated to simplify code - a small price to pay */
    /* bounds checking and parameter format verification will be perfomed if the statement is used (see next section) */
    /* For malloc(), there is no +1 for trailing 0 as parameter substitution will net us several extra characters */

    strlentur = strlen( table ) + strlen( username) + strlen( realm );  /* avoid repetition */

    template = "INSERT INTO \"%s\" ( \"%s\", \"%s\" ) VALUES ( '%%s', '%%s' )";
    create = malloc( strlen( template ) + strlentur );
    sprintf( create, template, table, username, realm );

    template = "SELECT \"%s\" FROM \"%s\" WHERE \"%s\" = '%%s' AND \"%s\" = '%%s'";
    select = malloc( strlen( template )
		     + strlen( pgsqlcontext->field_password )
		     + strlentur );
    sprintf( select, template
	     , pgsqlcontext->field_password
	     , table, username, realm );

    template = "UPDATE \"%s\" SET \"%s\" = '%%s' WHERE \"%s\" = '%%s' AND \"%s\" = '%%s'";
    setpassword = malloc( strlen( template ) + strlentur + strlen( pgsqlcontext->field_password ) );
    sprintf( setpassword, template, table, pgsqlcontext->field_password, username, realm );

    template = "DELETE FROM \"%s\" WHERE \"%s\" = '%%s' AND \"%s\" = '%%s'";
    delete = malloc( strlen( template ) + strlentur );
    sprintf( delete, template, table, username, realm );

    /* allow the default SQL statements to be overridden; also verify the statements format and length */
    pgsqlcontext->sql_create = strdup(_ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.sql.create"
           , create ));
    if( _ar_pgsql_check_sql( ar, pgsqlcontext->sql_create, "ss" ) != 0 ) return 1;

    pgsqlcontext->sql_select = strdup(_ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.sql.select"
           , select ));
    if( _ar_pgsql_check_sql( ar, pgsqlcontext->sql_select, "ss" ) != 0 ) return 1;

    pgsqlcontext->sql_setpassword = strdup(_ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.sql.setpassword"
           , setpassword ));
    if( _ar_pgsql_check_sql( ar, pgsqlcontext->sql_setpassword, "sss" ) != 0 ) return 1;

    pgsqlcontext->sql_delete = strdup(_ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.sql.delete"
           , delete ));
    if( _ar_pgsql_check_sql( ar, pgsqlcontext->sql_delete, "ss" ) != 0 ) return 1;

    // Check password is optional
    const char *sql_check_password = _ar_pgsql_param( ar->c2s->config, "authreg.pgsql.sql.checkpassword", 0);

    if (sql_check_password) {
        ar->check_password = _ar_pgsql_dbcheck_password;
        pgsqlcontext->sql_check_password = strdup(sql_check_password);
        if( _ar_pgsql_check_sql( ar, pgsqlcontext->sql_check_password, "sss" ) != 0 ) return 1;
    }
    else
        ar->check_password = _ar_pgsql_check_password;

    /* echo our configuration to debug */
    log_debug( ZONE, "SQL to create account: %s", pgsqlcontext->sql_create );
    log_debug( ZONE, "SQL to query user information: %s", pgsqlcontext->sql_select );
    log_debug( ZONE, "SQL to set password: %s", pgsqlcontext->sql_setpassword );
    log_debug( ZONE, "SQL to delete account: %s", pgsqlcontext->sql_delete );
    log_debug( ZONE, "SQL to check password: %s", pgsqlcontext->sql_check_password );

    free(create);
    free(select);
    free(setpassword);
    free(delete);

#ifdef HAVE_SSL
    if(sx_openssl_initialized)
	PQinitSSL(0);
#endif

    host = config_get_one(ar->c2s->config, "authreg.pgsql.host", 0);
    port = config_get_one(ar->c2s->config, "authreg.pgsql.port", 0);
    dbname = config_get_one(ar->c2s->config, "authreg.pgsql.dbname", 0);
    schema = config_get_one(ar->c2s->config, "authreg.pgsql.schema", 0);
    user = config_get_one(ar->c2s->config, "authreg.pgsql.user", 0);
    pass = config_get_one(ar->c2s->config, "authreg.pgsql.pass", 0);
    conninfo = config_get_one(ar->c2s->config,"authreg.pgsql.conninfo",0);

    if(conninfo) {
        /* don't log connection info for it can contain password */
        log_debug( ZONE, "pgsql connecting to the databse");
        conn = PQconnectdb(conninfo);
    } else {
        /* compatibility settings */
        log_debug( ZONE, "pgsql connecting as '%s' to database '%s' on %s:%s", user, dbname, host, port );
        conn = PQsetdbLogin(host, port, NULL, NULL, dbname, user, pass);
    }

    if(conn == NULL) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: unable to allocate database connection state");
        return 1;
    }

    if(PQstatus(conn) != CONNECTION_OK)
        log_write(ar->c2s->log, LOG_ERR, "pgsql: connection to database failed, will retry later: %s", PQerrorMessage(conn));

    if (schema) {
        template = "SET search_path TO \"%s\"";
        setsearchpath = malloc( strlen( template ) + strlen(schema) );
        sprintf( setsearchpath, template, schema );
        PQexec(conn, setsearchpath);
        free(setsearchpath);
    }

    pgsqlcontext->conn = conn;

    ar->user_exists = _ar_pgsql_user_exists;
    if (MPC_PLAIN == pgsqlcontext->password_type) {
        /* only possible with plaintext passwords */
        ar->get_password = _ar_pgsql_get_password;
    } else {
        ar->get_password = NULL;
    }

    ar->set_password = _ar_pgsql_set_password;
    ar->create_user = _ar_pgsql_create_user;
    ar->delete_user = _ar_pgsql_delete_user;

    return 0;
}
