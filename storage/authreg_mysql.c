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

/* this module talks to a MySQL server via libmysqlclient */

#define _XOPEN_SOURCE 500
#include "c2s.h"
#include <mysql.h>

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
#include <util/crypt_blowfish.h>
#endif

#define MYSQL_LU  1024   /* maximum length of username - should correspond to field length */
#define MYSQL_LR   256   /* maximum length of realm - should correspond to field length */
#define MYSQL_LP   256   /* maximum length of password - should correspond to field length */

enum mysql_pws_crypt {
    MPC_PLAIN,
#ifdef HAVE_CRYPT
    MPC_CRYPT,
#endif
#ifdef HAVE_SSL
    MPC_A1HASH,
    MPC_BCRYPT
#endif
};

#ifdef HAVE_CRYPT
static char salter[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./";
#endif

typedef struct mysqlcontext_st {
  MYSQL * conn;
  const char * sql_create;
  const char * sql_select;
  const char * sql_setpassword;
  const char * sql_delete;
  const char * field_password;
  enum mysql_pws_crypt password_type;
#ifdef HAVE_SSL
  int bcrypt_cost;
#endif
} *mysqlcontext_t;

#ifdef HAVE_SSL
static void calc_a1hash(const char *username, const char *realm, const char *password, char *a1hash)
{
#define A1PPASS_LEN MYSQL_LU + 1 + MYSQL_LR + 1 + MYSQL_LP + 1 /* user:realm:password\0 */
    char buf[A1PPASS_LEN];
    unsigned char md5digest[MD5_DIGEST_LENGTH];
    int i;

    snprintf(buf, A1PPASS_LEN, "%.*s:%.*s:%.*s", MYSQL_LU, username, MYSQL_LR, realm, MYSQL_LP, password);

    MD5((unsigned char*)buf, strlen(buf), md5digest);

    for(i=0; i<16; i++) {
        sprintf(a1hash+i*2, "%02hhx", md5digest[i]);
    }
}

static void bcrypt_hash(const char *password, int cost, char* hash)
{
    char salt[16];
    if(!RAND_bytes(salt, 16))
        ; //we've got a problem

    char* gen = bcrypt_gensalt("$2y$", cost, salt, 16);
    strcpy(hash, bcrypt(password, gen));
}

static int bcrypt_verify(const char *password, const char* hash)
{
    char *ret;
    ret = bcrypt(password, hash);

    if(strlen(ret) != strlen(hash))
        return 1;

    int status = 0;
    int i = 0;
    for(i; i < strlen(ret); i++)
        status |= (ret[i] ^ hash[i]);
    return status != 0;
}

static int bcrypt_needs_rehash(int current_cost, const char* hash)
{
    int hash_cost;
    sscanf(hash, "$2y$%d$", &hash_cost);

    if(current_cost != hash_cost)
        return 1;

    return 0;
}
#endif

static MYSQL_RES *_ar_mysql_get_user_tuple(authreg_t ar, const char *username, const char *realm) {
    mysqlcontext_t ctx = (mysqlcontext_t) ar->private;
    MYSQL *conn = ctx->conn;
    char iuser[MYSQL_LU+1], irealm[MYSQL_LR+1];
    char euser[MYSQL_LU*2+1], erealm[MYSQL_LR*2+1], sql[1024 + MYSQL_LU*2 + MYSQL_LR*2 + 1];  /* query(1024) + euser + erealm + \0(1) */
    MYSQL_RES *res;
    
    if(mysql_ping(conn) != 0) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: connection to database lost");
        return NULL;
    }

    snprintf(iuser, MYSQL_LU+1, "%s", username);
    snprintf(irealm, MYSQL_LR+1, "%s", realm);

    mysql_real_escape_string(conn, euser, iuser, strlen(iuser));
    mysql_real_escape_string(conn, erealm, irealm, strlen(irealm));

    sprintf(sql, ctx->sql_select, euser, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    if(mysql_query(conn, sql) != 0) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: sql select failed: %s", mysql_error(conn));
        return NULL;
    }

    res = mysql_store_result(conn);
    if(res == NULL) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: sql result retrieval failed: %s", mysql_error(conn));
        return NULL;
    }

    if(mysql_num_rows(res) != 1) {
        mysql_free_result(res);
        return NULL;
    }

    return res;
}

static int _ar_mysql_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm) {
    MYSQL_RES *res = _ar_mysql_get_user_tuple(ar, username, realm);

    if(res != NULL) {
        mysql_free_result(res);
        return 1;
    }

    return 0;
}

static int _ar_mysql_get_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257]) {
    mysqlcontext_t ctx = (mysqlcontext_t) ar->private;
    MYSQL *conn = ctx->conn;
    MYSQL_RES *res = _ar_mysql_get_user_tuple(ar, username, realm);
    MYSQL_FIELD *field;
    MYSQL_ROW tuple;
    int i, fpass = 0;

    if(res == NULL)
        return 1;

    for(i = mysql_num_fields(res) - 1; i >= 0; i--) {
        field = mysql_fetch_field_direct(res, i);
        if(strcmp(field->name, ctx->field_password) == 0) {
            fpass = i;
            break;
        }
    }

    if((tuple = mysql_fetch_row(res)) == NULL) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: sql tuple retrieval failed: %s", mysql_error(conn));
        mysql_free_result(res);
        return 1;
    }

    if(tuple[fpass] == NULL) {
        mysql_free_result(res);
        return 1;
    }

    strcpy(password, tuple[fpass]);

    mysql_free_result(res);

    return 0;
}

static int _ar_mysql_set_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257]) {
    mysqlcontext_t ctx = (mysqlcontext_t) ar->private;
    MYSQL *conn = ctx->conn;
    char iuser[MYSQL_LU+1], irealm[MYSQL_LR+1];
    char euser[MYSQL_LU*2+1], erealm[MYSQL_LR*2+1], epass[513], sql[1024+MYSQL_LU*2+MYSQL_LR*2+512+1];  /* query(1024) + euser + erealm + epass(512) + \0(1) */

    if(mysql_ping(conn) != 0) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: connection to database lost");
        return 1;
    }

    snprintf(iuser, MYSQL_LU+1, "%s", username);
    snprintf(irealm, MYSQL_LR+1, "%s", realm);

#ifdef HAVE_CRYPT
    if (ctx->password_type == MPC_CRYPT) {
        char salt[39] = "$6$rounds=50000$";
        int i;

        srand(time(0));
        for(i=0; i<22; i++)
            salt[16+i] = salter[rand()%64];
        salt[38] = '\0';
        strcpy(password, crypt(password, salt));
    }
#endif

#ifdef HAVE_SSL
    if (ctx->password_type == MPC_A1HASH) {
        calc_a1hash(username, realm, password, password);
    } else if (ctx->password_type == MPC_BCRYPT) {
        bcrypt_hash(password, ctx->bcrypt_cost, password);
    }
#endif
    
    password[256]= '\0';

    mysql_real_escape_string(conn, euser, iuser, strlen(iuser));
    mysql_real_escape_string(conn, erealm, irealm, strlen(irealm));
    mysql_real_escape_string(conn, epass, password, strlen(password));

    sprintf(sql, ctx->sql_setpassword, epass, euser, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    if(mysql_query(conn, sql) != 0) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: sql update failed: %s", mysql_error(conn));
        return 1;
    }

    return 0;
}

static int _ar_mysql_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257]) {
    mysqlcontext_t ctx = (mysqlcontext_t) ar->private;
    char db_pw_value[257];
#ifdef HAVE_CRYPT
    char *crypted_pw;
#endif
#ifdef HAVE_SSL
    char a1hash_pw[33];
#endif
    int ret;

    ret = _ar_mysql_get_password(ar, sess, username, realm, db_pw_value);
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
    case MPC_BCRYPT:
        ret = bcrypt_verify(password, db_pw_value);
        if(ret == 0) {
            if(bcrypt_needs_rehash(ctx->bcrypt_cost, db_pw_value)) {
                char tmp[257];
                strcpy(tmp, password);
                _ar_mysql_set_password(ar, sess, username, realm, tmp);
            }
        }
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

static int _ar_mysql_create_user(authreg_t ar, sess_t sess, const char *username, const char *realm) {
    mysqlcontext_t ctx = (mysqlcontext_t) ar->private;
    MYSQL *conn = ctx->conn;
    char iuser[MYSQL_LU+1], irealm[MYSQL_LR+1];
    char euser[MYSQL_LU*2+1], erealm[MYSQL_LR*2+1], sql[1024+MYSQL_LU*2+MYSQL_LR*2+1];    /* query(1024) + euser + erealm + \0(1) */
    MYSQL_RES *res = _ar_mysql_get_user_tuple(ar, username, realm);

    if(res != NULL) {
        mysql_free_result(res);
        return 1;
    }

    mysql_free_result(res);

    if(mysql_ping(conn) != 0) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: connection to database lost");
        return 1;
    }

    snprintf(iuser, MYSQL_LU+1, "%s", username);
    snprintf(irealm, MYSQL_LR+1, "%s", realm);

    mysql_real_escape_string(conn, euser, iuser, strlen(iuser));
    mysql_real_escape_string(conn, erealm, irealm, strlen(irealm));

    sprintf(sql, ctx->sql_create, euser, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    if(mysql_query(conn, sql) != 0) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: sql insert failed: %s", mysql_error(conn));
        return 1;
    }

    return 0;
}

static int _ar_mysql_delete_user(authreg_t ar, sess_t sess, const char *username, const char *realm) {
    mysqlcontext_t ctx = (mysqlcontext_t) ar->private;
    MYSQL *conn = ctx->conn;
    char iuser[MYSQL_LU+1], irealm[MYSQL_LR+1];
    char euser[MYSQL_LU*2+1], erealm[MYSQL_LR*2+1], sql[1024+MYSQL_LU*2+MYSQL_LR*2+1];    /* query(1024) + euser + erealm + \0(1) */

    if(mysql_ping(conn) != 0) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: connection to database lost");
        return 1;
    }

    snprintf(iuser, MYSQL_LU+1, "%s", username);
    snprintf(irealm, MYSQL_LR+1, "%s", realm);

    mysql_real_escape_string(conn, euser, iuser, strlen(iuser));
    mysql_real_escape_string(conn, erealm, irealm, strlen(irealm));

    sprintf(sql, ctx->sql_delete, euser, erealm);

    log_debug(ZONE, "prepared sql: %s", sql);

    if(mysql_query(conn, sql) != 0) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: sql insert failed: %s", mysql_error(conn));
        return 1;
    }

    return 0;
}

static void _ar_mysql_free(authreg_t ar) {
    mysqlcontext_t ctx = (mysqlcontext_t) ar->private;
    MYSQL *conn = ctx->conn;

    if(conn != NULL)
       mysql_close(conn);

    free((void*)ctx->sql_create);
    free((void*)ctx->sql_select);
    free((void*)ctx->sql_setpassword);
    free((void*)ctx->sql_delete);
    free(ctx);
}

/** Provide a configuration parameter or default value. */
static const char * _ar_mysql_param( config_t c, const char * key, const char * def ) {
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
static char * _ar_mysql_check_template( const char * template, const char * types ) {
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
static int _ar_mysql_check_sql( authreg_t ar, const char * sql, const char * types ) {
  const char * error;

  error = _ar_mysql_check_template( sql, types );
  if( error == 0 ) return 0;  /* alls right :) */

  /* signal error */
  log_write( ar->c2s->log, LOG_ERR, "mysql: template error: %s - %s", error, sql );
  return 1;
}

/** start me up */
DLLEXPORT int ar_init(authreg_t ar) {
    const char *host, *port, *dbname, *user, *pass;
    char *create, *select, *setpassword, *delete;
    const char *table, *username, *realm;
    char *template;
    int strlentur; /* string length of table, user, and realm strings */
    MYSQL *conn;
    mysqlcontext_t mysqlcontext;

    /* configure the database context with field names and SQL statements */
    mysqlcontext = (mysqlcontext_t) malloc( sizeof( struct mysqlcontext_st ) );
    ar->private = mysqlcontext;
    ar->free = _ar_mysql_free;

    /* determine our field names and table name */
    username = _ar_mysql_param( ar->c2s->config
               , "authreg.mysql.field.username"
               , "username" ); 
    realm = _ar_mysql_param( ar->c2s->config
               , "authreg.mysql.field.realm"
               , "realm" ); 
    mysqlcontext->field_password = _ar_mysql_param( ar->c2s->config
               , "authreg.mysql.field.password"
               , "password" ); 
    table = _ar_mysql_param( ar->c2s->config
               , "authreg.mysql.table"
               , "authreg" ); 

    /* get encryption type used in DB */
    if (config_get_one(ar->c2s->config, "authreg.mysql.password_type.plaintext", 0)) {
        mysqlcontext->password_type = MPC_PLAIN;
#ifdef HAVE_CRYPT
    } else if (config_get_one(ar->c2s->config, "authreg.mysql.password_type.crypt", 0)) {
        mysqlcontext->password_type = MPC_CRYPT;
#endif
#ifdef HAVE_SSL
    } else if (config_get_one(ar->c2s->config, "authreg.mysql.password_type.a1hash", 0)) {
        mysqlcontext->password_type = MPC_A1HASH;
    } else if (config_get_one(ar->c2s->config, "authreg.mysql.password_type.bcrypt", 0)) {
        mysqlcontext->password_type = MPC_BCRYPT;
    int cost;
    if(cost = j_atoi(config_get_attr(ar->c2s->config, "authreg.mysql.password_type.bcrypt", 0, "cost"), 0))
    {
        if(cost < 4 || cost > 31) {
            log_write(ar->c2s->log, LOG_ERR, "bcrypt cost has to be higher than 3 and lower than 32.");
            mysqlcontext->bcrypt_cost = 10; // use default
        } else {
            mysqlcontext->bcrypt_cost = cost;
        }
    }
#endif
    } else {
        mysqlcontext->password_type = MPC_PLAIN;
    }

    /* craft the default SQL statements */
    /* we leave unused statements allocated to simplify code - a small price to pay */
    /* bounds checking and parameter format verification will be perfomed if the statement is used (see next section) */
    /* For malloc(), there is no +1 for trailing 0 as parameter substitution will net us several extra characters */

    strlentur = strlen( table ) + strlen( username) + strlen( realm );  /* avoid repetition */

    template = "INSERT INTO `%s` ( `%s`, `%s` ) VALUES ( '%%s', '%%s' )";
    create = malloc( strlen( template ) + strlentur ); 
    sprintf( create, template, table, username, realm );

    template = "SELECT `%s` FROM `%s` WHERE `%s` = '%%s' AND `%s` = '%%s'";
    select = malloc( strlen( template )
                     + strlen( mysqlcontext->field_password )
                     + strlentur ); 
    sprintf( select, template
             , mysqlcontext->field_password
             , table, username, realm );

    template = "UPDATE `%s` SET `%s` = '%%s' WHERE `%s` = '%%s' AND `%s` = '%%s'";
    setpassword = malloc( strlen( template ) + strlentur + strlen( mysqlcontext->field_password ) ); 
    sprintf( setpassword, template, table, mysqlcontext->field_password, username, realm );

    template = "DELETE FROM `%s` WHERE `%s` = '%%s' AND `%s` = '%%s'";
    delete = malloc( strlen( template ) + strlentur ); 
    sprintf( delete, template, table, username, realm );

    /* allow the default SQL statements to be overridden; also verify the statements format and length */
    mysqlcontext->sql_create = strdup(_ar_mysql_param( ar->c2s->config
               , "authreg.mysql.sql.create"
               , create ));
    if( _ar_mysql_check_sql( ar, mysqlcontext->sql_create, "ss" ) != 0 ) return 1;

    mysqlcontext->sql_select = strdup(_ar_mysql_param( ar->c2s->config
               , "authreg.mysql.sql.select"
               , select ));
    if( _ar_mysql_check_sql( ar, mysqlcontext->sql_select, "ss" ) != 0 ) return 1;

    mysqlcontext->sql_setpassword = strdup(_ar_mysql_param( ar->c2s->config
               , "authreg.mysql.sql.setpassword"
               , setpassword ));
    if( _ar_mysql_check_sql( ar, mysqlcontext->sql_setpassword, "sss" ) != 0 ) return 1;

    mysqlcontext->sql_delete = strdup(_ar_mysql_param( ar->c2s->config
               , "authreg.mysql.sql.delete"
               , delete ));
    if( _ar_mysql_check_sql( ar, mysqlcontext->sql_delete, "ss" ) != 0 ) return 1;

    /* echo our configuration to debug */
    log_debug( ZONE, "SQL to create account: %s", mysqlcontext->sql_create );
    log_debug( ZONE, "SQL to query user information: %s", mysqlcontext->sql_select );
    log_debug( ZONE, "SQL to set password: %s", mysqlcontext->sql_setpassword );
    log_debug( ZONE, "SQL to delete account: %s", mysqlcontext->sql_delete );

    free(create);
    free(select);
    free(setpassword);
    free(delete);

    host = config_get_one(ar->c2s->config, "authreg.mysql.host", 0);
    port = config_get_one(ar->c2s->config, "authreg.mysql.port", 0);
    dbname = config_get_one(ar->c2s->config, "authreg.mysql.dbname", 0);
    user = config_get_one(ar->c2s->config, "authreg.mysql.user", 0);
    pass = config_get_one(ar->c2s->config, "authreg.mysql.pass", 0);

    if(host == NULL || port == NULL || dbname == NULL || user == NULL || pass == NULL) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: invalid module config");
        return 1;
    }

    log_debug( ZONE, "mysql connecting as '%s' to database '%s' on %s:%s", user, dbname, host, port );

    conn = mysql_init(NULL);
    mysqlcontext->conn = conn;

    if(conn == NULL) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: unable to allocate database connection state");
        return 1;
    }

    mysql_options(conn, MYSQL_READ_DEFAULT_GROUP, "jabberd");
    mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8");

    /* connect with CLIENT_INTERACTIVE to get a (possibly) higher timeout value than default */
    if(mysql_real_connect(conn, host, user, pass, dbname, atoi(port), NULL, CLIENT_INTERACTIVE) == NULL) {
        log_write(ar->c2s->log, LOG_ERR, "mysql: connection to database failed: %s", mysql_error(conn));
        return 1;
    }

    mysql_query(conn, "SET NAMES 'utf8'");

    /* Set reconnect flag to 1 (set to 0 by default from mysql 5 on) */
    conn->reconnect = 1;

    ar->user_exists = _ar_mysql_user_exists;
    if (MPC_PLAIN == mysqlcontext->password_type) {
        /* only possible with plaintext passwords */
        ar->get_password = _ar_mysql_get_password;
    } else {
        ar->get_password = NULL;
    }
    ar->check_password = _ar_mysql_check_password;
    ar->set_password = _ar_mysql_set_password;
    ar->create_user = _ar_mysql_create_user;
    ar->delete_user = _ar_mysql_delete_user;

    return 0;
}
