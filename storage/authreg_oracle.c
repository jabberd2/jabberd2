/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2007 Ubiquecom Inc.
 * Copyright (c) 2007 liulw
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

/* this module talks to a Oracle server via libmysqlclient */

#include "c2s.h"
#include <string.h>
#include <oci.h>

//#define ORACLE_LU    1024   /* maximum length of username - should correspond to field length */
//#define MYSQL_LR   256   /* maximum length of realm - should correspond to field length */
//#define MYSQL_LP   256   /* maximum length of password - should correspond to field length */

#define BLOCKSIZE (1024)
#define PWSIZE (257) 

typedef struct Oracle_context_st
{
    OCIEnv*        ociEnvironment;
    OCIError*    ociError;
    OCISvcCtx*    ociService;
    OCIStmt*    ociStatement;
    OCIDefine*    ociDefine;
//    OCIBind*    ociBind;
//    xht             filters;
//    char *prefix;
//    char *svUser;
//    char *svPass;
    char*    sql_create;
    char*    sql_select;
    char*    sql_delete;
    char*    sql_setpassword;
} *Oracle_context_t;

/** internal: do and return the math and ensure it gets realloc'd */
static int _st_oracle_realloc(void **oblocks, int len)
{
    void *nblocks;
    int nlen;

    /* round up to standard block sizes */
    nlen = (((len-1)/BLOCKSIZE)+1)*BLOCKSIZE;

    /* keep trying till we get it */
    while((nblocks = realloc(*oblocks, nlen)) == NULL) sleep(1);
    *oblocks = nblocks;
    return nlen;
}

#define ORACLE_SAFE(blocks, size, len) if((size) > len){ len = _st_oracle_realloc((void**)&(blocks),(size)); }

int checkOCIError( authreg_t ar, const char *szDoing, OCIError *m_ociError, sword nStatus )
{
    text txtErrorBuffer[512];
    ub4 nErrorCode;

    switch (nStatus)
    {
        case OCI_SUCCESS:
                break;
        case OCI_SUCCESS_WITH_INFO:
                log_write(ar->c2s->log, LOG_ERR, "(%s) Error - OCI_SUCCESS_WITH_INFO\n", szDoing);
                break;
        case OCI_NEED_DATA:
                log_write(ar->c2s->log, LOG_ERR, "(%s) Error - OCI_NEED_DATA\n", szDoing);
                break;
        case OCI_NO_DATA:
                log_write(ar->c2s->log, LOG_ERR, "(%s) Error - OCI_NODATA\n", szDoing);
                break;
        case OCI_ERROR:
                OCIErrorGet(m_ociError, (ub4) 1, (text *) NULL, &nErrorCode, txtErrorBuffer, (ub4) sizeof(txtErrorBuffer), OCI_HTYPE_ERROR);
                log_write(ar->c2s->log, LOG_ERR, "(%s) Error - %s\n", szDoing, txtErrorBuffer);
                break;
        case OCI_INVALID_HANDLE:
                log_write(ar->c2s->log, LOG_ERR, "(%s) Error - OCI_INVALID_HANDLE\n", szDoing);
                break;
        case OCI_STILL_EXECUTING:
                log_write(ar->c2s->log, LOG_ERR, "(%s) Error - OCI_STILL_EXECUTE\n", szDoing);
                break;
        default:
                break;
    }

    return nStatus;
}


static int _sql_length( char* sql )
{
    const char* _pt = sql;
    int _num = 0;
    
    while( *_pt != '\0' )
    {
        if( *_pt == '"' )++_num;
        ++_pt;
    }

    return (strlen(sql) - _num);
}

static int _ar_oracle_get_user_tuple( authreg_t ar, char* username, char* realm )
{
    Oracle_context_t _ctx = (Oracle_context_t)ar->private;
    char* _sqlbuf = NULL;
    int _nNumberOfFields = 0;
    int _nResultCode = 0;
    int _len = 0;
    char _password[64] = { '\0' };

     ORACLE_SAFE( _sqlbuf, strlen(username) + strlen(realm) + _sql_length(_ctx->sql_select), _len );
    sprintf( _sqlbuf, _ctx->sql_select, username, realm );
//    fprintf( stdout, "_sqlbuf = %s\n", _sqlbuf );
    _nResultCode = checkOCIError( ar, "_ar_oracle_get_user_tuple: prepare statement", _ctx->ociError, OCIStmtPrepare( _ctx->ociStatement, \
                                                                _ctx->ociError, _sqlbuf, strlen(_sqlbuf), OCI_NTV_SYNTAX, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        fprintf( stdout, "OCIStmtPrepare\n" );
        free( _sqlbuf );
        return 1;
    }

    _nResultCode = checkOCIError(ar, "_ar_oracle_get_user_tuple:define pos", _ctx->ociError, OCIDefineByPos( _ctx->ociStatement, \
                            &_ctx->ociDefine, _ctx->ociError, 1, &_password, 65, SQLT_STR, 0, 0, 0, OCI_DEFAULT ) );

    if( _nResultCode != 0 )
    {
        fprintf( stdout, "OCIDefineByPos\n" );
        free( _sqlbuf );
        return 1;
    }
    
    _nResultCode = checkOCIError( ar, "_ar_oracle_get_user_tuple:execse", _ctx->ociError, OCIStmtExecute( _ctx->ociService, \
                                                            _ctx->ociStatement, _ctx->ociError, 0, 0, 0, 0, OCI_STMT_SCROLLABLE_READONLY ) );
    if( _nResultCode != 0 )
    {
        fprintf( stdout, "OCIStmtExecute\n" );
        free( _sqlbuf );
        return 1;
    }

    OCIStmtFetch2( _ctx->ociStatement, _ctx->ociError, 1, OCI_FETCH_FIRST, 0, OCI_DEFAULT);
    free( _sqlbuf );

    if( strlen(_password) != 0 )return 1;
    else return 0;
}

static int _ar_oracle_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    if( _ar_oracle_get_user_tuple(ar, username, realm ) > 0 )
    {
        return 1;
    }

    return 0;
}

static int _ar_oracle_create_user( authreg_t ar, sess_t sess, const char *username, const char *realm )
{
    Oracle_context_t _ctx = (Oracle_context_t)ar->private;
    char* _sqlbuf = NULL;
    int _len = 0;
    int _nResultCode = 0;
    int errcode;
    char errbuf[512];

    ORACLE_SAFE( _sqlbuf, strlen(username) + strlen(realm) + _sql_length(_ctx->sql_create), _len );
    sprintf( _sqlbuf, _ctx->sql_create, username, realm );
    _nResultCode = checkOCIError( ar, "_ar_oracle_create_user:prepare", _ctx->ociError, OCIStmtPrepare( _ctx->ociStatement, _ctx->ociError,\
                            _sqlbuf, (ub4)strlen(_sqlbuf), OCI_NTV_SYNTAX, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        return -1;
    }

    _nResultCode = checkOCIError( ar, "_ar_oracle_create_user:execute", _ctx->ociError, OCIStmtExecute( _ctx->ociService, _ctx->ociStatement, _ctx->ociError, 1, 0, 0, 0, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
          OCIErrorGet((dvoid *)_ctx->ociError, (ub4)1, (text *)NULL, &errcode, 
                          errbuf, (ub4)sizeof(errbuf), OCI_HTYPE_ERROR);
          fprintf(stdout, "%.*s\n", 512, errbuf);
        fprintf( stdout, "eaarror..\n" );
        return -1;
    }

    return 0;
}

int _ar_oracle_get_authreg_user( authreg_t ar )
{
    Oracle_context_t _ctx = (Oracle_context_t)ar->private;
    char _sql[] = { "select count(*) from \"authreg\"" };
    int _nNumberOfFields = 0;
    int _nResultCode = 0;

    /*start action via oracle*/
    _nResultCode = checkOCIError( ar, "_st_oracle_get: prepare statement", _ctx->ociError, OCIStmtPrepare( _ctx->ociStatement, _ctx->ociError,\
                            _sql, (ub4)strlen(_sql), OCI_NTV_SYNTAX, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        return -1;
    }

    _nResultCode = checkOCIError( ar, "_st_oracle_get: Define pos", _ctx->ociError, OCIDefineByPos( _ctx->ociStatement, &_ctx->ociDefine, \
                            _ctx->ociError,    1, (dvoid*)&_nNumberOfFields, sizeof(_nNumberOfFields), SQLT_INT, 0, 0, 0, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        return -1;
    }

    _nResultCode = checkOCIError( ar, "_st_oracle_get: Statement descript", _ctx->ociError, OCIStmtExecute( _ctx->ociService, \
                            _ctx->ociStatement, _ctx->ociError, 0, 0, 0, 0, OCI_STMT_SCROLLABLE_READONLY ) );
    if( _nResultCode != 0 )
    {
        return -1;
    }

    _nResultCode = checkOCIError( ar, "", _ctx->ociError, OCIStmtFetch2( _ctx->ociStatement, _ctx->ociError, 1, OCI_FETCH_FIRST, 0, \
                                                                                                                    OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        return -1;
    }

    return _nNumberOfFields;
}


static int _ar_oracle_get_password( authreg_t ar, sess_t sess, const char *username, const char *realm, char password[PWSIZE] )
{
    Oracle_context_t _ctx = (Oracle_context_t)ar->private;
    char* _sqlbuf = NULL;
    int _nNumberOfFields = 0;
    int _nResultCode = 0;
    int _len = 0;
    char _password[PWSIZE];
    memset( _password, '\0', sizeof(_password) );
     ORACLE_SAFE( _sqlbuf, strlen(username) + strlen(realm) + _sql_length(_ctx->sql_select), _len );
    sprintf( _sqlbuf, _ctx->sql_select, username, realm );

    _nResultCode = checkOCIError( ar, "_ar_oracle_get_user_tuple: prepare statement", _ctx->ociError, OCIStmtPrepare( _ctx->ociStatement, \
                                                                _ctx->ociError, _sqlbuf, strlen(_sqlbuf), OCI_NTV_SYNTAX, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        free( _sqlbuf );
        return -1;
    }

    _nResultCode = checkOCIError(ar, "_ar_oracle_get_user_tuple:define pos", _ctx->ociError, OCIDefineByPos( _ctx->ociStatement, \
                                    &_ctx->ociDefine, _ctx->ociError, 1, &_password, PWSIZE, SQLT_STR, 0, 0, 0, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        free( _sqlbuf );
        return -1;
    }
    
    _nResultCode = checkOCIError( ar, "_ar_oracle_get_user_tuple:execse", _ctx->ociError, OCIStmtExecute( _ctx->ociService, \
                                                            _ctx->ociStatement, _ctx->ociError, 0, 0, 0, 0, OCI_STMT_SCROLLABLE_READONLY ) );
    if( _nResultCode != 0 )
    {
        free( _sqlbuf );
        return -1;
    }

    OCIStmtFetch2( _ctx->ociStatement, _ctx->ociError, 1, OCI_FETCH_FIRST, 0, OCI_DEFAULT ); 
    free( _sqlbuf );
    
    strncpy( password, _password, PWSIZE - 1 );
    password[PWSIZE - 1] = '\0';

    return 0;
}

static int _ar_oracle_set_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[PWSIZE])
{
    Oracle_context_t _ctx = (Oracle_context_t)ar->private;
    char* _sqlbuf = NULL;
    int _len = 0;
    int _nResultCode = 0;

    ORACLE_SAFE( _sqlbuf, strlen(username) + strlen(realm) + strlen(password) + _sql_length(_ctx->sql_setpassword), _len );
    sprintf( _sqlbuf, _ctx->sql_setpassword, password, username, realm );

    _nResultCode = checkOCIError( ar, "_ar_oracle_set_password:prepare", _ctx->ociError, OCIStmtPrepare( _ctx->ociStatement, _ctx->ociError,\
                            _sqlbuf, (ub4)strlen(_sqlbuf), OCI_NTV_SYNTAX, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        return -1;
    }

    _nResultCode = checkOCIError( ar, "_ar_oracle_set_password:execute", _ctx->ociError, OCIStmtExecute( _ctx->ociService, \
                            _ctx->ociStatement, _ctx->ociError, 1, 0, 0, 0, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        fprintf( stdout, "error \n" );
        return -1;
    }

    return 0;
}

static int _ar_oracle_delete_user(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    if( _ar_oracle_get_user_tuple(ar, username, realm ) == 0 )return 0;

    Oracle_context_t _ctx = (Oracle_context_t)ar->private;
    char* _sqlbuf = NULL;
    int _len = 0;
    int _nResultCode = 0;

    ORACLE_SAFE( _sqlbuf, strlen(username) + strlen(realm) + _sql_length(_ctx->sql_delete), _len );
    sprintf( _sqlbuf, _ctx->sql_delete, username, realm );

    _nResultCode = checkOCIError( ar, "_ar_oracle_delete_user:prepare", _ctx->ociError, OCIStmtPrepare( _ctx->ociStatement, _ctx->ociError,\
                                                                        _sqlbuf, (ub4)strlen(_sqlbuf), OCI_NTV_SYNTAX, OCI_DEFAULT ) );
    if( _nResultCode != 0 )
    {
        return -1;
    }

    _nResultCode = checkOCIError( ar, "_ar_oracle_delete_user:execute", _ctx->ociError, OCIStmtExecute( _ctx->ociService, \
                                                            _ctx->ociStatement, _ctx->ociError, 1, 0, 0, 0, OCI_COMMIT_ON_SUCCESS ) );
    if( _nResultCode != 0 )
    {
        return -1;
    }

    return 0;
}

static void _ar_oracle_free( authreg_t ar )
{
    Oracle_context_t ctx = (Oracle_context_t)ar->private;

    OCILogoff(     ctx->ociService, ctx->ociError );
    OCIHandleFree( (dvoid *)ctx->ociStatement, OCI_HTYPE_STMT );
    OCIHandleFree( (dvoid *)ctx->ociService, OCI_HTYPE_SVCCTX );
    OCIHandleFree( (dvoid *)ctx->ociError, OCI_HTYPE_ERROR );
    OCIHandleFree( (dvoid *)ctx->ociEnvironment, OCI_HTYPE_ENV );

    free(ctx);
}

/** Provide a configuration parameter or default value. */
static char * _ar_oracle_param( config_t c, const char * key, const char * def ) {
    char * value = config_get_one( c, key, 0 );
    if( value == NULL )
      return def;
    else
      return value;
}

/** start me up */
int ar_init(authreg_t ar) {
    char *host, *port, *dbname, *user, *pass, *oracle_server_host = NULL;
    char *create, *select, *setpassword, *delete;
    char table[] = { "\"authreg\"" };
    char username[] = { "\"username\"" };
    char realm[] = { "\"realm\"" };
    char password[] = { "\"password\"" };
    int nResultCode = 0, _len = 0;
    static char* oracle_server_parameters = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=\"%s\")(PORT=\"%s\"))(CONNECT_DATA=(SID=\"%s\")))";
    Oracle_context_t oraclecontext;

    OCIEnv     *ociEnvironment;
    OCIError   *ociError;
    OCISvcCtx  *ociService;
    OCIStmt    *ociStatement;

    /* configure the database context with field names and SQL statements */
    oraclecontext = (Oracle_context_t)malloc( sizeof( struct Oracle_context_st ) );
    ar->private = oraclecontext;
    ar->free = _ar_oracle_free;

    /* craft the default SQL statements */
    /* we leave unused statements allocated to simplify code - a small price to pay */
    /* bounds checking and parameter format verification will be perfomed if the statement is used (see next section) */
    /* For malloc(), there is no +1 for trailing 0 as parameter substitution will net us several extra characters */

    create = strdup( "INSERT INTO \"authreg\" ( \"username\", \"realm\" ) VALUES ( '%s', '%s' )" );

    select = strdup( "SELECT \"password\" FROM \"authreg\" WHERE \"username\" = '%s' AND \"realm\" = '%s'" );

    setpassword = strdup( "UPDATE \"authreg\" SET \"password\" = '%s' WHERE \"username\" = '%s' AND \"realm\" = '%s'" );

    delete = strdup( "DELETE FROM \"authreg\" WHERE \"username\" = '%s' AND \"realm\" = '%s'" );

    /* allow the default SQL statements to be overridden; also verify the statements format and length */
    oraclecontext->sql_create = strdup(_ar_oracle_param( ar->c2s->config
                            , "authreg.oracle.sql.create"
                            , create ));

    oraclecontext->sql_select = strdup(_ar_oracle_param( ar->c2s->config
                            , "authreg.oracle.sql.select"
                            , select ));

    oraclecontext->sql_setpassword = strdup(_ar_oracle_param( ar->c2s->config
                            , "authreg.oracle.sql.setpassword"
                            , setpassword ));

    oraclecontext->sql_delete = strdup(_ar_oracle_param( ar->c2s->config
                            , "authreg.oracle.sql.delete"
                            , delete ));

    /* echo our configuration to debug */
    log_debug( ZONE, "SQL to create account: %s", oraclecontext->sql_create );
    log_debug( ZONE, "SQL to query user information: %s", oraclecontext->sql_select );
    log_debug( ZONE, "SQL to set password: %s", oraclecontext->sql_setpassword );
    log_debug( ZONE, "SQL to delete account: %s", oraclecontext->sql_delete );

    free(create);
    free(select);
    free(setpassword);
    free(delete);

    host = config_get_one(ar->c2s->config, "authreg.oracle.host", 0);
    port = config_get_one(ar->c2s->config, "authreg.oracle.port", 0);
    dbname = config_get_one(ar->c2s->config, "authreg.oracle.dbname", 0);
    user = config_get_one(ar->c2s->config, "authreg.oracle.user", 0);
    pass = config_get_one(ar->c2s->config, "authreg.oracle.pass", 0);

    if(host == NULL || port == NULL || dbname == NULL || user == NULL || pass == NULL) {
            log_write(ar->c2s->log, LOG_ERR, "oracle: invalid module config");
            return 1;
    }

    ORACLE_SAFE( oracle_server_host, strlen(host) + strlen(port) + strlen(dbname) + _sql_length(oracle_server_parameters), _len );
    sprintf( oracle_server_host, oracle_server_parameters, host, port, dbname );

    log_debug( ZONE, "OCI connecting as '%s' to database '%s' on %s:%s", user, dbname, host, port );

    nResultCode = OCIEnvCreate( (OCIEnv**)&ociEnvironment, OCI_DEFAULT, (dvoid*)0, 0, 0, 0, (size_t)0, (dvoid **)0 );

    if (nResultCode != 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "(st_oracle_init: ) Could not Initialize OCI Environment (%d)", nResultCode);
        return 1;
    }

    /* Initialize handles */
    nResultCode = OCIHandleAlloc( (dvoid *)ociEnvironment, (dvoid **) &ociError, OCI_HTYPE_ERROR, (size_t)0, (dvoid **)0 );

    if (nResultCode != 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "(st_oracle_init: ) Could not create OCI Error object (%d)" , nResultCode);
        nResultCode = OCIHandleFree((dvoid *) ociEnvironment, OCI_HTYPE_ENV);
        return 1;
    }

    nResultCode = checkOCIError(ar, "st_oracle_init: Allocate Service", ociError, OCIHandleAlloc((dvoid *)ociEnvironment,
                            (dvoid **)&ociService, OCI_HTYPE_SVCCTX,
                            (size_t)NULL, (dvoid **)NULL) );
    if (nResultCode != 0)
    {
        nResultCode = OCIHandleFree((dvoid *) ociError, OCI_HTYPE_ERROR);
        nResultCode = OCIHandleFree((dvoid *) ociEnvironment, OCI_HTYPE_ENV);
        return 1;
    }

/* Connect to database server */
    nResultCode = checkOCIError(ar, "st_oracle_init: Connect to Server", ociError, OCILogon(ociEnvironment, ociError, &ociService,
                            user, strlen(user), pass, strlen(pass),
                            oracle_server_host, strlen(oracle_server_host)));

    if (nResultCode != 0)
    {
        nResultCode = OCIHandleFree((dvoid *) ociService, OCI_HTYPE_SVCCTX);
        nResultCode = OCIHandleFree((dvoid *) ociError, OCI_HTYPE_ERROR);
        nResultCode = OCIHandleFree((dvoid *) ociEnvironment, OCI_HTYPE_ENV);
        return 1;
    }

    /* Allocate and prepare SQL statement */
    nResultCode = checkOCIError(ar, "st_oracle_init: Allocate Statement", ociError, OCIHandleAlloc((dvoid *)ociEnvironment,
                            (dvoid **)&ociStatement, OCI_HTYPE_STMT,
                            (size_t)NULL, (dvoid **)NULL));

    if (nResultCode != 0)
    {
        nResultCode = OCILogoff(ociService, ociError);
        nResultCode = OCIHandleFree((dvoid *) ociService, OCI_HTYPE_SVCCTX);
        nResultCode = OCIHandleFree((dvoid *) ociError, OCI_HTYPE_ERROR);
        nResultCode = OCIHandleFree((dvoid *) ociEnvironment, OCI_HTYPE_ENV);
        return 1;
    }

    free(oracle_server_host);

    oraclecontext->ociEnvironment = ociEnvironment;
    oraclecontext->ociError = ociError;
    oraclecontext->ociService = ociService;
    oraclecontext->ociStatement = ociStatement;

    ar->user_exists = _ar_oracle_user_exists;
    ar->get_password = _ar_oracle_get_password;
    ar->set_password = _ar_oracle_set_password;
    ar->create_user = _ar_oracle_create_user;
    ar->delete_user = _ar_oracle_delete_user;

    return 0;
}
