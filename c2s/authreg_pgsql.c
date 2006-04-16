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

#include "c2s.h"

#ifdef STORAGE_PGSQL

#include <libpq-fe.h>

#define PGSQL_LU  1024   /* maximum length of username - should correspond to field length */
#define PGSQL_LR   256   /* maximum length of realm - should correspond to field length */
#define PGSQL_LP   256   /* maximum length of password - should correspond to field length */

typedef struct pgsqlcontext_st {
  PGconn * conn;
  char * sql_create;
  char * sql_select;
  char * sql_setpassword;
  char * sql_setzerok;
  char * sql_delete;
  char * field_password;
  char * field_hash;
  char * field_token;
  char * field_sequence;
  } *pgsqlcontext_t;

static PGresult *_ar_pgsql_get_user_tuple(authreg_t ar, char *username, char *realm) {
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

static int _ar_pgsql_user_exists(authreg_t ar, char *username, char *realm) {
    PGresult *res = _ar_pgsql_get_user_tuple(ar, username, realm);

    if(res != NULL) {
        PQclear(res);
        return 1;
    }

    return 0;
}

static int _ar_pgsql_get_password(authreg_t ar, char *username, char *realm, char password[257]) {
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

static int _ar_pgsql_set_password(authreg_t ar, char *username, char *realm, char password[257]) {
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

static int _ar_pgsql_get_zerok(authreg_t ar, char *username, char *realm, char hash[41], char token[11], int *sequence) {
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    PGresult *res = _ar_pgsql_get_user_tuple(ar, username, realm);
    int fhash, ftok, fseq;

    if(res == NULL)
        return 1;

    fhash = PQfnumber(res, ctx->field_hash);
    ftok = PQfnumber(res, ctx->field_token);
    fseq = PQfnumber(res, ctx->field_sequence);
    if(fhash == -1 || ftok == -1 || fseq == -1) {
        log_debug(ZONE, "weird, required field wasn't returned");
        PQclear(res);
        return 1;
    }

    if(PQgetisnull(res, 0, fhash) || PQgetisnull(res, 0, ftok) || PQgetisnull(res, 0, fseq)) {
        PQclear(res);
        return 1;
    }

    strcpy(hash, PQgetvalue(res, 0, fhash));
    strcpy(token, PQgetvalue(res, 0, ftok));
    *sequence = atoi(PQgetvalue(res, 0, fseq));

    PQclear(res);

    return 0;
}

static int _ar_pgsql_set_zerok(authreg_t ar, char *username, char *realm, char hash[41], char token[11], int sequence) {
    pgsqlcontext_t ctx = (pgsqlcontext_t) ar->private;
    PGconn *conn = ctx->conn;
    char iuser[PGSQL_LU+1], irealm[PGSQL_LR+1];
    char euser[PGSQL_LU*2+1], erealm[PGSQL_LR*2+1], ehash[81], etoken[21], sql[1024 + PGSQL_LU*2 + PGSQL_LR*2 + 80 + 20 + 12 + 1]; /* query(1024) + euser + erealm + ehash(80) + etoken(20) + sequence(12) + \0(1) */
    PGresult *res;

    snprintf(iuser, PGSQL_LU+1, "%s", username);
    snprintf(irealm, PGSQL_LR+1, "%s", realm);

    PQescapeString(euser, iuser, strlen(iuser));
    PQescapeString(erealm, irealm, strlen(irealm));
    PQescapeString(ehash, hash, strlen(hash));
    PQescapeString(etoken, token, strlen(token));

    sprintf(sql, ctx->sql_setzerok, ehash, etoken, sequence, euser, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    res = PQexec(conn, sql);
    if(PQresultStatus(res) != PGRES_COMMAND_OK && PQstatus(conn) != CONNECTION_OK) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: lost connection to database, attempting reconnect");
        PQclear(res);
        PQreset(conn);
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

static int _ar_pgsql_create_user(authreg_t ar, char *username, char *realm) {
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

static int _ar_pgsql_delete_user(authreg_t ar, char *username, char *realm) {
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

    free(ctx->sql_create);
    free(ctx->sql_select);
    free(ctx->sql_setpassword);
    free(ctx->sql_setzerok);
    free(ctx->sql_delete);
    free(ctx);
}

/** Provide a configuration parameter or default value. */
char * _ar_pgsql_param( config_t c, char * key, char * def ) {
    char * value = config_get_one( c, key, 0 );
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
char * _ar_pgsql_check_template( char * template, char * types ) {
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
int _ar_pgsql_check_sql( authreg_t ar, char * sql, char * types ) {
  char * error;

  error = _ar_pgsql_check_template( sql, types );
  if( error == 0 ) return 0;  /* alls right :) */

  /* signal error */
  log_write( ar->c2s->log, LOG_ERR, "pgsql: template error: %s - %s", error, sql );
  return 1;
}

/** start me up */
int ar_pgsql_init(authreg_t ar) {
    char *host, *port, *dbname, *user, *pass;
    char *create, *select, *setpassword, *setzerok, *delete;
    char *table, *username, *realm;
    char *template;
    int strlentur; /* string length of table, user, and realm strings */
    PGconn *conn;
    pgsqlcontext_t pgsqlcontext;

    /* configure the database context with field names and SQL statements */
    pgsqlcontext = (pgsqlcontext_t) malloc( sizeof( struct pgsqlcontext_st ) );
    memset(pgsqlcontext, 0, sizeof( struct pgsqlcontext_st ));
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
    pgsqlcontext->field_hash = _ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.field.hash"
	       , "hash" ); 
    pgsqlcontext->field_token = _ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.field.token"
	       , "token" ); 
    pgsqlcontext->field_sequence = _ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.field.sequence"
	       , "sequence" ); 
    table = _ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.table"
	       , "authreg" ); 

    /* craft the default SQL statements */
    /* we leave unused statements allocated to simplify code - a small price to pay */
    /* bounds checking and parameter format verification will be perfomed if the statement is used (see next section) */
    /* For malloc(), there is no +1 for trailing 0 as parameter substitution will net us several extra characters */

    strlentur = strlen( table ) + strlen( username) + strlen( realm );  /* avoid repetition */

    template = "INSERT INTO \"%s\" ( \"%s\", \"%s\" ) VALUES ( '%%s', '%%s' )";
    create = malloc( strlen( template ) + strlentur ); 
    sprintf( create, template, table, username, realm );

    template = "SELECT \"%s\",\"%s\",\"%s\",\"%s\" FROM \"%s\" WHERE \"%s\" = '%%s' AND \"%s\" = '%%s'";
    select = malloc( strlen( template )
		     + strlen( pgsqlcontext->field_password )
		     + strlen( pgsqlcontext->field_hash ) + strlen( pgsqlcontext->field_token )
		     + strlen( pgsqlcontext->field_sequence )
		     + strlentur ); 
    sprintf( select, template
	     , pgsqlcontext->field_password
	     , pgsqlcontext->field_hash, pgsqlcontext->field_token, pgsqlcontext->field_sequence
	     , table, username, realm );

    template = "UPDATE \"%s\" SET \"%s\" = '%%s' WHERE \"%s\" = '%%s' AND \"%s\" = '%%s'";
    setpassword = malloc( strlen( template ) + strlentur + strlen( pgsqlcontext->field_password ) ); 
    sprintf( setpassword, template, table, pgsqlcontext->field_password, username, realm );

    template = "UPDATE \"%s\" SET \"%s\" = '%%s', \"%s\" = '%%s', \"%s\" = '%%d'  WHERE \"%s\" = '%%s' AND \"%s\" = '%%s'";
    setzerok = malloc( strlen( template ) + strlentur
		     + strlen( pgsqlcontext->field_hash ) + strlen( pgsqlcontext->field_token )
		     + strlen( pgsqlcontext->field_sequence ) ); 
    sprintf( setzerok, template, table
	     , pgsqlcontext->field_hash, pgsqlcontext->field_token, pgsqlcontext->field_sequence
	     , username, realm );

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

    pgsqlcontext->sql_setzerok = strdup(_ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.sql.setzerok"
           , setzerok ));
    if( _ar_pgsql_check_sql( ar, pgsqlcontext->sql_setzerok, "ssdss" ) != 0 ) return 1;

    pgsqlcontext->sql_delete = strdup(_ar_pgsql_param( ar->c2s->config
	       , "authreg.pgsql.sql.delete"
           , delete ));
    if( _ar_pgsql_check_sql( ar, pgsqlcontext->sql_delete, "ss" ) != 0 ) return 1;

    /* echo our configuration to debug */
    log_debug( ZONE, "SQL to create account: %s", pgsqlcontext->sql_create );
    log_debug( ZONE, "SQL to query user information: %s", pgsqlcontext->sql_select );
    log_debug( ZONE, "SQL to set password: %s", pgsqlcontext->sql_setpassword );
    log_debug( ZONE, "SQL to set zero K: %s", pgsqlcontext->sql_setzerok );
    log_debug( ZONE, "SQL to delete account: %s", pgsqlcontext->sql_delete );

    free(create);
    free(select);
    free(setpassword);
    free(setzerok);
    free(delete);

    host = config_get_one(ar->c2s->config, "authreg.pgsql.host", 0);
    port = config_get_one(ar->c2s->config, "authreg.pgsql.port", 0);
    dbname = config_get_one(ar->c2s->config, "authreg.pgsql.dbname", 0);
    user = config_get_one(ar->c2s->config, "authreg.pgsql.user", 0);
    pass = config_get_one(ar->c2s->config, "authreg.pgsql.pass", 0);

    if(host == NULL || port == NULL || dbname == NULL || user == NULL || pass == NULL) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: invalid module config");
        return 1;
    }

    log_debug( ZONE, "pgsql connecting as '%s' to database '%s' on %s:%s", user, dbname, host, port );

    conn = PQsetdbLogin(host, port, NULL, NULL, dbname, user, pass);
    if(conn == NULL) {
        log_write(ar->c2s->log, LOG_ERR, "pgsql: unable to allocate database connection state");
        return 1;
    }

    if(PQstatus(conn) != CONNECTION_OK)
        log_write(ar->c2s->log, LOG_ERR, "pgsql: connection to database failed, will retry later: %s", PQerrorMessage(conn));

    pgsqlcontext->conn = conn;

    ar->user_exists = _ar_pgsql_user_exists;
    ar->get_password = _ar_pgsql_get_password;
    ar->set_password = _ar_pgsql_set_password;
    ar->get_zerok = _ar_pgsql_get_zerok;
    ar->set_zerok = _ar_pgsql_set_zerok;
    ar->create_user = _ar_pgsql_create_user;
    ar->delete_user = _ar_pgsql_delete_user;

    return 0;
}

#endif
