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

#include "storage.h"
#include <string.h>
#include <oci.h>

/** internal structure, holds our data */
typedef struct OracleDriver
{
  OCIEnv *ociEnvironment;
  OCIError *ociError;
  OCISvcCtx *ociService;
  OCIStmt *ociStatement;
  OCIDefine *ociDefine;
  OCIBind *ociBind;
  xht filters;
  char *prefix;
} *OracleDriverPointer;

#define BLOCKSIZE (1024)

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

/** this is the safety check used to make sure there's always enough mem */
#define ORACLE_SAFE(blocks, size, len) if((size) > len) len = _st_oracle_realloc((void**)&(blocks),(size));

int checkOCIError(st_driver_t drv, const char *szDoing, OCIError *m_ociError, sword nStatus)
{
  text txtErrorBuffer[512];
  ub4 nErrorCode;

  switch (nStatus)
  {
    case OCI_SUCCESS:
      break;
    case OCI_SUCCESS_WITH_INFO:
      log_write(drv->st->log, LOG_ERR, "(%s) Error - OCI_SUCCESS_WITH_INFO\n", szDoing);
      break;
    case OCI_NEED_DATA:
      log_write(drv->st->log, LOG_ERR, "(%s) Error - OCI_NEED_DATA\n", szDoing);
      break;
    case OCI_NO_DATA:
      log_write(drv->st->log, LOG_ERR, "(%s) Error - OCI_NODATA\n", szDoing);
      break;
    case OCI_ERROR:
      OCIErrorGet(m_ociError, (ub4) 1, (text *) NULL, &nErrorCode, txtErrorBuffer, (ub4) sizeof(txtErrorBuffer), OCI_HTYPE_ERROR);
      log_write(drv->st->log, LOG_ERR, "(%s) Error - %s\n", szDoing, txtErrorBuffer);
      break;
    case OCI_INVALID_HANDLE:
      log_write(drv->st->log, LOG_ERR, "(%s) Error - OCI_INVALID_HANDLE\n", szDoing);
      break;
    case OCI_STILL_EXECUTING:
      log_write(drv->st->log, LOG_ERR, "(%s) Error - OCI_STILL_EXECUTE\n", szDoing);
      break;
    default:
      break;
  }

  return nStatus;
}


/* Return the number of occurrences of key in src */
int count_chars(char *src, char key)
{
  int count = 0;

  while ( *src != '\0' )
  {
    if ( *src == key )
      count++; 
    src++;
  }
  
  return count;
}



int oracle_escape_string(char *dest, int dest_length, const char *src, int src_length)
{
  int  result = 0;
  /* src is not null ended */
  char *src_end  = src + src_length;
  char *dest_end = dest + dest_length - 1;

  while (src < src_end)
  {
    if (dest < dest_end)
    {
      static const char ESCAPED_STR[] = "&";
      static const char QUOTE_STR[] = "'";

      if (strchr(ESCAPED_STR, *src) != NULL)
      {
        if (dest + 9 < dest_end)
        {
          /*  '||'&'||' */
          *dest++ = '\'';
          *dest++ = '|';
          *dest++ = '|';
          *dest++ = '\'';
          *dest++ = '&';
          *dest++ = '\'';
          *dest++ = '|';
          *dest++ = '|';
          *dest++ = '\'';
          src++;
        }
        else
        {
          result = -1;
          break;
        }
      }
      else if (strchr(QUOTE_STR, *src) != NULL)
      {
        if (dest + 2 < dest_end)
        {
          *dest++ = '\'';
          *dest++ = *src;
          src++;
        }
        else
        {
          result = -1;
          break;
        }
      }
      else
      {
        *dest++ = *src++;
      }
    }
    else
    {
      result = -1;
      break;
    }
  }
  *dest = '\0';

  return result;
}



static int oracle_ping(st_driver_t drv)
{
  OracleDriverPointer odpOracleDriver = (OracleDriverPointer)drv->private;

  // Prepare the check statement
  int nResultCode = OCIStmtPrepare(odpOracleDriver->ociStatement, odpOracleDriver->ociError,
                                   "select sysdate from dual", (ub4) 24, OCI_NTV_SYNTAX,
                                   OCI_DEFAULT);

  // This is the real check
  nResultCode = OCIStmtExecute(odpOracleDriver->ociService, odpOracleDriver->ociStatement, odpOracleDriver->ociError,
                                   (ub4) 0, (ub4) 0,
                                   (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL,
                                   OCI_DESCRIBE_ONLY );


  // If there was an error...
  if (nResultCode != 0)
  {
    char szErrorBuffer[250];
    char *svHost, *svUser, *svPass;
    char *svPort, *svSid, *oracle_server_host = NULL;
    static char* oracle_server_parameters = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=\"%s\")(PORT=\"%s\"))(CONNECT_DATA=(SID=\"%s\")))";
    int _len = 0;

    OCIErrorGet((dvoid *)odpOracleDriver->ociError, (ub4) 1, (text *) NULL, &nResultCode, szErrorBuffer, (ub4) sizeof(szErrorBuffer), OCI_HTYPE_ERROR);
    log_write(drv->st->log, LOG_ERR, "storage_oracle.c (oracle_ping): %s", szErrorBuffer);

    // Obtain user configuration
    svHost = config_get_one(drv->st->config, "storage.oracle.host", 0);
    svUser = config_get_one(drv->st->config, "storage.oracle.user", 0);
    svPass = config_get_one(drv->st->config, "storage.oracle.pass", 0);
    svPort = config_get_one(drv->st->config, "storage.oracle.port", 0);
    svSid  = config_get_one(drv->st->config, "storage.oracle.dbname", 0);

    ORACLE_SAFE( oracle_server_host, strlen(svHost) + strlen(svPort) + strlen(svSid) + strlen(oracle_server_parameters), _len );
    sprintf( oracle_server_host, oracle_server_parameters, svHost, svPort, svSid );

    // Logon to the database
    nResultCode = OCILogon((dvoid *)odpOracleDriver->ociEnvironment, (dvoid *)odpOracleDriver->ociError, &(odpOracleDriver->ociService), svUser, strlen(svUser), svPass, strlen(svPass), oracle_server_host, strlen(oracle_server_host));

    
    if (nResultCode != 0)
    {
      OCIErrorGet((dvoid *)odpOracleDriver->ociError, (ub4) 1, (text *) NULL, &nResultCode, szErrorBuffer, (ub4) sizeof(szErrorBuffer), OCI_HTYPE_ERROR);
      log_write(drv->st->log, LOG_ERR, "storage_oracle.c (oracle_ping): %s", szErrorBuffer);
    }

    free(oracle_server_host);
  }

  return nResultCode;
}



static void _st_oracle_convert_filter_recursive(st_filter_t f, const char **buf, int *buflen, int *nbuf)
{
  st_filter_t scan;

  switch(f->type)
  {
    case st_filter_type_PAIR:
      ORACLE_SAFE((*buf), *buflen + 12, *buflen);
      *nbuf += sprintf(&((*buf)[*nbuf]), "( \"%s\" = \'%s\' ) ", f->key, f->val);

      break;

      case st_filter_type_AND:
        ORACLE_SAFE((*buf), *buflen + 2, *buflen);
        *nbuf += sprintf(&((*buf)[*nbuf]), "( ");

        for(scan = f->sub; scan != NULL; scan = scan->next)
        {
          _st_oracle_convert_filter_recursive(scan, buf, buflen, nbuf);

          if(scan->next != NULL)
          {
            ORACLE_SAFE((*buf), *buflen + 4, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "AND ");
          }
        }

        ORACLE_SAFE((*buf), *buflen + 2, *buflen);
        *nbuf += sprintf(&((*buf)[*nbuf]), ") ");

        return;

      case st_filter_type_OR:
        ORACLE_SAFE((*buf), *buflen + 2, *buflen);
        *nbuf += sprintf(&((*buf)[*nbuf]), "( ");

        for(scan = f->sub; scan != NULL; scan = scan->next)
        {
          _st_oracle_convert_filter_recursive(scan, buf, buflen, nbuf);

          if(scan->next != NULL)
          {
            ORACLE_SAFE((*buf), *buflen + 3, *buflen);
            *nbuf += sprintf(&((*buf)[*nbuf]), "OR ");
          }
        }

        ORACLE_SAFE((*buf), *buflen + 2, *buflen);
        *nbuf += sprintf(&((*buf)[*nbuf]), ") ");

        return;

      case st_filter_type_NOT:
        ORACLE_SAFE((*buf), *buflen + 6, *buflen);
        *nbuf += sprintf(&((*buf)[*nbuf]), "( NOT ");

        _st_oracle_convert_filter_recursive(f->sub, buf, buflen, nbuf);

        ORACLE_SAFE((*buf), *buflen + 2, *buflen);
        *nbuf += sprintf(&((*buf)[*nbuf]), ") ");

        return;
  }
}

static char *_st_oracle_convert_filter(st_driver_t drv, const char *owner, const char *filter)
{
  OracleDriverPointer data = (OracleDriverPointer) drv->private;
  char *buf = NULL, *sbuf = NULL, *cfilter;
  int buflen = 0, nbuf = 0, fbuf;
  st_filter_t f;

  ORACLE_SAFE(buf, 24 + strlen(owner), buflen);

  nbuf = sprintf(buf, "\"collection-owner\" = '%s'", owner);

  sbuf = xhash_get(data->filters, filter);
  if(sbuf != NULL)
  {
    ORACLE_SAFE(buf, buflen + strlen(sbuf) + 7, buflen);
    nbuf += sprintf(&buf[nbuf], " AND %s", sbuf);
    return buf;
  }

  cfilter = pstrdup(xhash_pool(data->filters), filter);

  f = storage_filter(filter);
  if(f == NULL)
  {
    return buf;
  }

  ORACLE_SAFE(buf, buflen + 5, buflen);
  nbuf += sprintf(&buf[nbuf], " AND ");

  fbuf = nbuf;

  _st_oracle_convert_filter_recursive(f, &buf, &buflen, &nbuf);

  xhash_put(data->filters, cfilter, pstrdup(xhash_pool(data->filters), &buf[fbuf]));

  pool_free(f->p);

  return buf;
}

static st_ret_t _st_oracle_add_type(st_driver_t drv, const char *type)
{
  return st_SUCCESS;
}


static st_ret_t _st_oracle_put_guts(st_driver_t drv, const char *type, const char *owner, os_t os)
{
  static const char NAD_PREFIX[] = "NAD";
  
  OracleDriverPointer data = (OracleDriverPointer) drv->private;
  char *left = NULL, *right = NULL;
  int lleft = 0, lright = 0, nleft, nright;
  os_object_t o;
  char *key = NULL, *cval = NULL;
  int vlen;
  dvoid *val = NULL;
  os_type_t ot;
  char *xml = NULL;
  int xlen;
  char tbuf[128];
  int nResultCode = 0;

  if(os_count(os) == 0)
  {
    return st_SUCCESS;
  }

  if(data->prefix != NULL)
  {
    snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
    type = tbuf;
  }

  if(os_iter_first(os))
  {
    do
    {
      ORACLE_SAFE(left, strlen(type) + 36, lleft);
      nleft = sprintf(left, "INSERT INTO \"%s\" ( \"collection-owner\"", type);

      ORACLE_SAFE(right, strlen(owner) + 15, lright);
      nright = sprintf(right, " ) VALUES ( '%s'", owner);

      o = os_iter_object(os);

      if(os_object_iter_first(o))
      {
        do 
        {
          os_object_iter_get(o, &key, &val, &ot);

          switch(ot) 
          {
            case os_type_BOOLEAN:
              cval = val ? strdup("1") : strdup("0");
              vlen = 1;
              break;

            case os_type_INTEGER:
              cval = (char *) malloc(sizeof(char) * 20);
              sprintf(cval, "%d", (int) val);
              vlen = strlen(cval);
              break;

            case os_type_STRING:
          /* Ensure that we have enough space for an escaped string. */
              cval = (char *) malloc(sizeof(char) * ((strlen((char *) val) * 2 + count_chars((char *) val,'&') * 8) + 1));
              vlen = oracle_escape_string(cval , (strlen((char *) val) * 2) + count_chars((char *) val,'&') * 8 + 1, (char *) val, strlen((char *) val));
              break;

            /* !!! might not be a good idea to mark nads this way */
            case os_type_NAD:
              nad_print((nad_t) val, 0, &xml, &xlen);
          /* Ensure that we have enough space for an escaped string. */
              cval = (char *) malloc(sizeof(char) * ((xlen * 2 + count_chars((char *) val,'&') * 8) + 4));
              vlen = oracle_escape_string(&cval[3],(xlen * 2 + count_chars((char *) val,'&') * 8) + 4, (char *) xml, xlen) + 3;
              strncpy(cval, "NAD", 3);
              break;
          }
      
          log_debug(ZONE, "key %s val %s", key, cval);
      
          ORACLE_SAFE(left, lleft + strlen(key) + 4, lleft);
          nleft += sprintf(&left[nleft], ", \"%s\"", key);
    
          ORACLE_SAFE(right, lright + strlen(cval) + 4, lright);
          nright += sprintf(&right[nright], ", '%s'", cval);
    
          free(cval);
        } while(os_object_iter_next(o));
  
        ORACLE_SAFE(left, lleft + strlen(right) + 2, lleft);
        sprintf(&left[nleft], "%s )", right);
    
        log_debug(ZONE, "_st_oracle_put_guts: Generated SQL: %s", left);

        nResultCode = checkOCIError(drv, "oracle_put_guts: Prepare", data->ociError, OCIStmtPrepare(data->ociStatement, data->ociError, left, 
                                                                                     (ub4) strlen(left), OCI_NTV_SYNTAX, OCI_DEFAULT));
  
        if (nResultCode != 0)
        {
          free(left);
          free(right);
          return st_FAILED;
        }

        nResultCode = checkOCIError(drv, "oracle_put_guts: Execute", data->ociError, OCIStmtExecute(data->ociService, data->ociStatement, 
                                                                                     data->ociError, (ub4) 1, (ub4) 0, 
                                                                                     (CONST OCISnapshot *) NULL, (OCISnapshot *) NULL, 
                                                                                     OCI_DEFAULT | OCI_COMMIT_ON_SUCCESS));

        if (nResultCode != 0)
        {
          free(left);
          free(right);
          return st_FAILED;
        }
      }
    } while(os_iter_next(os));
  }

  free(left);
  free(right);

  return st_SUCCESS;
}

static st_ret_t _st_oracle_put(st_driver_t drv, const char *type, const char *owner, os_t os)
{

  if( !owner ) {
    log_debug(ZONE,"_st_oracle_put: owner is null");
    return st_FAILED;
  }
  
  if(os_count(os) == 0)
  {
    return st_SUCCESS;
  }

  if(oracle_ping(drv) != 0)
  {
    log_write(drv->st->log, LOG_ERR, "oracle: connection to database lost");
    return st_FAILED;
  }

  if(_st_oracle_put_guts(drv, type, owner, os) != st_SUCCESS)
  {
    return st_FAILED;
  }

  return st_SUCCESS;
}

static st_ret_t _st_oracle_get(st_driver_t drv, const char *a_szType, const char *owner, const char *filter, os_t *os)
{
  OracleDriverPointer data = (OracleDriverPointer) drv->private;
  os_object_t o;
  os_type_t ot;
  char szBuffer[128];
  char *szWhereClause = NULL;
  char *szQuery = NULL;
  int nQueryLength = 0;
  int nResultCode = 0;
  int nNumberOfFields = 0;
  int nIndex = 0;

  if( !owner ) {
    log_debug(ZONE,"_st_oracle_get: owner is null");
    return st_FAILED;
  }
  
  if(oracle_ping(drv) != 0)
  {
    log_write(drv->st->log, LOG_ERR, "_st_oracle_get: Connection to database lost!");
    return st_FAILED;
  }

  if(data->prefix != NULL)
  {
    snprintf(szBuffer, sizeof(szBuffer), "%s%s", data->prefix, a_szType);
    a_szType = szBuffer;
  }

  szWhereClause = _st_oracle_convert_filter(drv, owner, filter);
  log_debug(ZONE, "_st_oracle_get: Generated Filter: %s", szWhereClause);

  ORACLE_SAFE(szQuery, strlen(a_szType) + strlen(szWhereClause) + 50, nQueryLength);
  sprintf(szQuery, "SELECT * FROM \"%s\" WHERE %s ORDER BY \"object-sequence\"", a_szType, szWhereClause);
  free(szWhereClause);

  log_debug(ZONE, "_st_oracle_get: Prepared SQL: %s", szQuery);

  nResultCode = checkOCIError(drv, "_st_oracle_get: Prepare Statement", data->ociError, OCIStmtPrepare(data->ociStatement, data->ociError,
                                                                                        szQuery, (ub4)strlen(szQuery), OCI_NTV_SYNTAX,
                                                                                        OCI_DEFAULT));

  if (nResultCode != 0)
  {
    free(szQuery);
    return st_FAILED;
  }

  nResultCode = checkOCIError(drv, "_st_oracle_get: Statement Describe", data->ociError, OCIStmtExecute(data->ociService,
                                                                                         data->ociStatement, data->ociError, (ub4)0,
                                                                                         (ub4)0, (CONST OCISnapshot *)NULL,
                                                                                         (OCISnapshot *)NULL, OCI_DESCRIBE_ONLY));

  if (nResultCode != 0)
  {
    free(szQuery);
    return st_FAILED;
  }

  free(szQuery);

  nResultCode = OCI_SUCCESS;

  checkOCIError(drv, "_st_oracle_get: Get Field Count", data->ociError, OCIAttrGet(data->ociStatement, OCI_HTYPE_STMT,
                                                                        (dvoid *)&nNumberOfFields, (ub4 *)NULL, OCI_ATTR_PARAM_COUNT,
                                                                        data->ociError));
  if (nNumberOfFields == 0)
  {
    return st_NOTFOUND;
  }


    /*
     * TODO: Handle memory better. 
     * The DDL for the "vcard" table has 21 fields. The following implementation allocates 82K for 21 fields.
     */
    OCIDefine *arrFields[nNumberOfFields];
    char arrszFieldData[nNumberOfFields][4001]; /* Size each field for the maximum VARCHAR2 size + terminating null */
    char arrszFieldName[nNumberOfFields][255];
    ub2 arrnFieldType[nNumberOfFields];
    sb2 arrnFieldIndicator[nNumberOfFields];
    ub2 arrnFieldSize[nNumberOfFields];
    char *svFieldName;
    int nNameSize;
    int nIntValue;
    nad_t nad;
    ub2 dummy[1];


    for (nIndex = 0; nIndex < nNumberOfFields; nIndex++)
    {
      arrFields[nIndex] = NULL;

      checkOCIError(drv, "_st_oracle_get: Get Parameter", data->ociError, OCIParamGet(data->ociStatement, OCI_HTYPE_STMT, data->ociError,
                                                                          (dvoid **) &arrFields[nIndex], (ub4) (nIndex + 1)));

      checkOCIError(drv, "_st_oracle_get: Get Field Name", data->ociError, OCIAttrGet(arrFields[nIndex], OCI_DTYPE_PARAM,
                                                                           (dvoid *) &svFieldName, &nNameSize,
                                                                           OCI_ATTR_NAME, data->ociError));
      strncpy(arrszFieldName[nIndex], svFieldName, nNameSize);
      arrszFieldName[nIndex][nNameSize] = '\0';
      
      arrnFieldType[nIndex] = 0;
      checkOCIError(drv, "_st_oracle_get: Get Field Type", data->ociError, OCIAttrGet(arrFields[nIndex], OCI_DTYPE_PARAM,
                                                                           (dvoid *) &arrnFieldType[nIndex], (ub4 *) NULL,
                                                                           (ub4) OCI_ATTR_DATA_TYPE, data->ociError));

      checkOCIError(drv, "_st_oracle_get: Get Field Size", data->ociError, OCIAttrGet(arrFields[nIndex], OCI_DTYPE_PARAM,
                                                                           (dvoid *) &dummy, (ub4 *) NULL,
                                                                           (ub4) OCI_ATTR_DATA_SIZE, data->ociError));

      arrnFieldSize[nIndex] = dummy[0];
      log_debug(ZONE, "Field %s of Size %d", arrszFieldName[nIndex], arrnFieldSize[nIndex]);

      if (arrnFieldSize[nIndex] > 4000 || arrnFieldSize[nIndex] < 1)
      {
          arrnFieldSize[nIndex] = 4000;
      }

      checkOCIError(drv, "_st_oracle_get: Define String", data->ociError, OCIDefineByPos(data->ociStatement, &arrFields[nIndex],
                                                                          data->ociError, (nIndex + 1), (dvoid *)&arrszFieldData[nIndex],
                                                                          4000, SQLT_STR, &arrnFieldIndicator[nIndex], 
                                                                          (ub2 *) 0, (ub2 *) 0, OCI_DEFAULT));
    }


    nResultCode = OCIStmtExecute(data->ociService, data->ociStatement, data->ociError, (ub4) 1, (ub4) 0, (CONST OCISnapshot *) NULL,
                  (OCISnapshot *) NULL, OCI_DEFAULT);

    if (nResultCode == OCI_SUCCESS || nResultCode == OCI_SUCCESS_WITH_INFO)
    {
      for (nIndex = 0; nIndex < nNumberOfFields; nIndex++)
      {
        if (arrnFieldIndicator[nIndex] == -1)
        {
          arrszFieldData[nIndex][0] = '\0';
        }
      }
    }
    else if (nResultCode != OCI_NO_DATA)
    {
      checkOCIError(drv, "_st_oracle_get: Execute Statement", data->ociError, nResultCode);
      return st_FAILED;
    }

    if (nResultCode == OCI_NO_DATA)
    {
      return st_NOTFOUND;
    }

    *os = os_new();

    while (nResultCode != OCI_NO_DATA)
    {
      o = os_object_new(*os);

      for (nIndex = 0; nIndex < nNumberOfFields; nIndex++)
      {
        if(strcmp(arrszFieldName[nIndex], "collection-owner") == 0)
        {
          continue;
        }
        
        if (arrszFieldData[nIndex][0] == '\0')
        {
          continue;
        }
        
        switch(arrnFieldType[nIndex])
        {
          case SQLT_CHR:   /* VARCHAR2, VARCHAR, CHAR_VARYING, CHARACTER_VARYING, NVARCHAR2, 
                            * NCHAR_VARYING, NATIONAL_CHAR_VARYING, or NATIONAL_CHARACTER_VARYING field. */
            if (arrnFieldSize[nIndex] > 2)
            {
              log_debug(ZONE, "Field %s is Field Type SQLT_CHR of Size %d, setting os_type_STRING", arrszFieldName[nIndex], arrnFieldSize[nIndex]);
              ot = os_type_STRING;
            }
            else
            {
              log_debug(ZONE, "Field %s is Field Type SQLT_CHR of Size %d, setting os_type_BOOLEAN", arrszFieldName[nIndex], arrnFieldSize[nIndex]);
              ot = os_type_BOOLEAN;
            }
            break;

          case SQLT_AFC:   /* CHAR, CHARACTER, NATIONAL_CHAR, NATIONAL_CHARACTER, or NCHAR field. */
            if (arrnFieldSize[nIndex] > 2)
            {
              log_debug(ZONE, "Field %s is Field Type SQLT_AFC of Size %d, setting os_type_STRING", arrszFieldName[nIndex], arrnFieldSize[nIndex]);
              ot = os_type_STRING;
            }
            else
            {
              log_debug(ZONE, "Field %s is Field Type SQLT_AFC of Size %d, setting os_type_BOOLEAN", arrszFieldName[nIndex], arrnFieldSize[nIndex]);
              ot = os_type_BOOLEAN;
            }
            break;

          case SQLT_NUM:   /* INT, REAL, NUMERIC, DOUBLE_PRECISION, SMALLINT, FLOAT, DECIMAL, NUMBER, or INTEGER field. */
            log_debug(ZONE, "Field %s is Field Type SQLT_NUM of Size %d", arrszFieldName[nIndex], arrnFieldSize[nIndex]);
            ot = os_type_INTEGER;
            break;

          case SQLT_CLOB: /* CLOB for binary photo */
            log_debug(ZONE, "Field %s is Field Type SQLT_CLOB of Size %d", arrszFieldName[nIndex], arrnFieldSize[nIndex]);
            ot = os_type_STRING;
            break;

          default:
            log_debug(ZONE, "Unknown field type %d, for column %s ignoring it", arrnFieldType[nIndex], arrszFieldName[nIndex]);
            continue;
        }
        
        switch(ot)
        {
          case os_type_BOOLEAN:
            nIntValue = (arrszFieldData[nIndex][0] == '0') ? 0 : 1;
            os_object_put(o, arrszFieldName[nIndex], &nIntValue, ot);
            break;

          case os_type_INTEGER:
            nIntValue = atoi(arrszFieldData[nIndex]);
            os_object_put(o, arrszFieldName[nIndex], &nIntValue, ot);
            break;

          case os_type_STRING:
              os_object_put(o, arrszFieldName[nIndex], arrszFieldData[nIndex], os_type_STRING);
              break;

            case os_type_NAD:
            case os_type_UNKNOWN:
              break;
          }
        }

      log_debug(ZONE, "Get Next Row.");
      nResultCode = OCIStmtFetch2(data->ociStatement, data->ociError, 1, OCI_DEFAULT, 0, OCI_DEFAULT);

      if (nResultCode == OCI_SUCCESS || nResultCode == OCI_SUCCESS_WITH_INFO)
      {
        for (nIndex = 0; nIndex < nNumberOfFields; nIndex++)
        {
          if (arrnFieldIndicator[nIndex] == -1)
          {
            arrszFieldData[nIndex][0] = '\0';
          }
        }
      }
      else if (nResultCode != OCI_NO_DATA)
      {
        checkOCIError(drv, "_st_oracle_get: Fetch Next Row", data->ociError, nResultCode);
        // If we get a database error exit the while loop. This probably should return st_FAILED here.
        break;
      }
    }


  return st_SUCCESS;
}

static int _st_oracle_count( st_driver_t drv, const char *a_szType, const char *owner, const char *filter, int *count )
{
    OracleDriverPointer data = (OracleDriverPointer) drv->private;
    const char *szStmtTemplate = "SELECT COUNT(*) FROM \"%s\" WHERE %s";
    char *szQuery = NULL;
    char szBuffer[128];
    char *szWhereClause = NULL;
    int  nResultCode = 0;
    int  nQueryLength = 0;

    if( !owner ) {
        log_debug(ZONE,"_st_oracle_count: owner is null");
        return st_FAILED;
    }

    if(oracle_ping(drv) != 0)
    {
        log_write(drv->st->log, LOG_ERR, "_st_oracle_count: Connection to database lost!");
        return st_FAILED;
    }

    if(data->prefix != NULL)
    {
        snprintf(szBuffer, sizeof(szBuffer), "%s%s", data->prefix, a_szType);
        a_szType = szBuffer;
    }


    szWhereClause = _st_oracle_convert_filter(drv, owner, filter);
    log_debug(ZONE, "_st_oracle_count: Generated Filter: %s", szWhereClause);

    ORACLE_SAFE(szQuery, strlen(a_szType) + strlen(szWhereClause) + strlen(szStmtTemplate), nQueryLength);
    sprintf(szQuery, szStmtTemplate, a_szType, szWhereClause);
    free(szWhereClause);

    nResultCode = checkOCIError(drv, "_st_oracle_count: Prepare Statement", data->ociError, OCIStmtPrepare(data->ociStatement, data->ociError,
                                                                                        szQuery, (ub4)strlen(szQuery), OCI_NTV_SYNTAX,
                                                                                        OCI_DEFAULT));

    if (nResultCode != 0)
    {
        free(szQuery);
        return st_FAILED;
    }

    nResultCode = checkOCIError(drv, "_st_oracle_count: Define Pos", data->ociError, OCIDefineByPos( data->ociStatement, &data->ociDefine, data->ociError,
                                                                                        1, count, sizeof(int), SQLT_INT, 0, 0, 0, OCI_DEFAULT ) );

    if (nResultCode != 0)
    {
        free(szQuery);
        return st_FAILED;
    }

    nResultCode = checkOCIError(drv, "_st_oracle_count: Statement Execute", data->ociError, OCIStmtExecute(data->ociService,
                                                                                         data->ociStatement, data->ociError, (ub4)0,
                                                                                         (ub4)0, (CONST OCISnapshot *)NULL,
                                                                                         (OCISnapshot *)NULL, OCI_STMT_SCROLLABLE_READONLY));

    if (nResultCode != 0)
    {
        free(szQuery);
        return st_FAILED;
    }

    OCIStmtFetch2( data->ociStatement, data->ociError, 1, OCI_FETCH_FIRST, 0, OCI_DEFAULT);
    free(szQuery);

    return st_SUCCESS;
}

static st_ret_t _st_oracle_delete(st_driver_t drv, const char *type, const char *owner, const char *filter)
{
  OracleDriverPointer data = (OracleDriverPointer) drv->private;
  char *cond, *buf = NULL;
  int buflen = 0;
  int nResultCode = 0;
  char tbuf[128];

  if(oracle_ping(drv) != 0) 
  {
    log_write(drv->st->log, LOG_ERR, "oracle: Connection to database lost");
    return st_FAILED;
  }

  if(data->prefix != NULL)
  {
    snprintf(tbuf, sizeof(tbuf), "%s%s", data->prefix, type);
    type = tbuf;
  }

  cond = _st_oracle_convert_filter(drv, owner, filter);
  log_debug(ZONE, "oracle: Generated filter: %s", cond);

  ORACLE_SAFE(buf, strlen(type) + strlen(cond) + 19, buflen);
  sprintf(buf, "DELETE FROM \"%s\" WHERE %s", type, cond);
  free(cond);

  log_debug(ZONE, "_st_oracle_delete: Prepared SQL: %s", buf);

  nResultCode = checkOCIError(drv, "_st_oracle_delete: Prepare", data->ociError, OCIStmtPrepare(data->ociStatement, data->ociError, buf, 
                                                                                 (ub4) strlen(buf), OCI_NTV_SYNTAX, OCI_DEFAULT));
  
  if (nResultCode != 0)
  {
      free(buf);
    return st_FAILED;
  }
  
  log_debug(ZONE, "_st_oracle_delete: Executing Delete.");

  nResultCode = checkOCIError(drv, "_st_oracle_delete: Execute", data->ociError, OCIStmtExecute(data->ociService, data->ociStatement, 
                                                                                 data->ociError, (ub4) 1, (ub4) 0, (CONST OCISnapshot *) NULL, 
                                                                                 (OCISnapshot *) NULL, OCI_DEFAULT | OCI_COMMIT_ON_SUCCESS));
  free(buf);

  log_debug(ZONE, "Result query: %d",nResultCode);
  
  if(nResultCode != 0) 
  {
    return st_FAILED;
  }
  
  return st_SUCCESS;
}

static st_ret_t _st_oracle_replace(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t os)
{
  if(oracle_ping(drv) != 0)
  {
    log_write(drv->st->log, LOG_ERR, "oracle: connection to database lost");
    return st_FAILED;
  }

  if(_st_oracle_delete(drv, type, owner, filter) == st_FAILED)
  {
    return st_FAILED;
  }

  if(_st_oracle_put_guts(drv, type, owner, os) == st_FAILED)
  {
    return st_FAILED;
  }

  return st_SUCCESS;
}

static void _st_oracle_free(st_driver_t drv) {
    OracleDriverPointer data = (OracleDriverPointer) drv->private;

    OCILogoff(data->ociService, data->ociError);
    OCIHandleFree((dvoid *) data->ociStatement, OCI_HTYPE_STMT);
    OCIHandleFree((dvoid *) data->ociService, OCI_HTYPE_SVCCTX);
    OCIHandleFree((dvoid *) data->ociError, OCI_HTYPE_ERROR);
    OCIHandleFree((dvoid *) data->ociEnvironment, OCI_HTYPE_ENV);

    xhash_free(data->filters);

    free(data->prefix);

    free(data);
}

st_ret_t st_init(st_driver_t drv) {
    int nResultCode;
    char *svHost, *svUser, *svPass;
    char *svPort, *svSid, *oracle_server_host = NULL;
    OCIEnv     *ociEnvironment;
    OCIError   *ociError;
    OCISvcCtx  *ociService;
    OCIStmt    *ociStatement;
    static char* oracle_server_parameters = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=\"%s\")(PORT=\"%s\"))(CONNECT_DATA=(SID=\"%s\")))";
    int _len = 0;

    OracleDriverPointer data;

    svHost = config_get_one(drv->st->config, "storage.oracle.host", 0);
    svUser = config_get_one(drv->st->config, "storage.oracle.user", 0);
    svPass = config_get_one(drv->st->config, "storage.oracle.pass", 0);
    svPort = config_get_one(drv->st->config, "storage.oracle.port", 0);
    svSid  = config_get_one(drv->st->config, "storage.oracle.dbname", 0);

    if(svHost == NULL || svUser == NULL || svPass == NULL || svPort == NULL || svSid == NULL)
    {
      log_write(drv->st->log, LOG_ERR, "(st_oracle_init: ) Invalid driver config from XML file.");
      return st_FAILED;
    }

    ORACLE_SAFE( oracle_server_host, strlen(svHost) + strlen(svPort) + strlen(svSid) + strlen(oracle_server_parameters), _len );
    sprintf( oracle_server_host, oracle_server_parameters, svHost, svPort, svSid );

    nResultCode = OCIEnvCreate( (OCIEnv**)&ociEnvironment, OCI_DEFAULT, (dvoid*)0, 0, 0, 0, (size_t)0, (dvoid **)0 );

    if (nResultCode != 0)
    {
      log_write(drv->st->log, LOG_ERR, "(st_oracle_init: ) Could not Initialize OCI Environment (%d)", nResultCode);
      return st_FAILED;
    }

    /* Initialize handles */
    nResultCode = OCIHandleAlloc((dvoid *) ociEnvironment, (dvoid **) &ociError, OCI_HTYPE_ERROR, (size_t) 0, (dvoid **) 0);

    if (nResultCode != 0)
    {
      log_write(drv->st->log, LOG_ERR, "(st_oracle_init: ) Could not create OCI Error object (%d)" , nResultCode);
      nResultCode = OCIHandleFree((dvoid *) ociEnvironment, OCI_HTYPE_ENV);
      return st_FAILED;
    }

    nResultCode = checkOCIError(drv, "st_oracle_init: Allocate Service", ociError, OCIHandleAlloc((dvoid *) ociEnvironment,
                                                                                   (dvoid **)&ociService, OCI_HTYPE_SVCCTX,
                                                                                   (size_t)NULL, (dvoid **)NULL));
    if (nResultCode != 0)
    {
      nResultCode = OCIHandleFree((dvoid *) ociError, OCI_HTYPE_ERROR);
      nResultCode = OCIHandleFree((dvoid *) ociEnvironment, OCI_HTYPE_ENV);
      return st_FAILED;
    }

    /* Connect to database server */
    nResultCode = checkOCIError(drv, "st_oracle_init: Connect to Server", ociError, OCILogon(ociEnvironment, ociError, &ociService,
                                                                                    svUser, strlen(svUser), svPass, strlen(svPass),
                                                                                    oracle_server_host, strlen(oracle_server_host)));

    if (nResultCode != 0)
    {
      nResultCode = OCIHandleFree((dvoid *) ociService, OCI_HTYPE_SVCCTX);
      nResultCode = OCIHandleFree((dvoid *) ociError, OCI_HTYPE_ERROR);
      nResultCode = OCIHandleFree((dvoid *) ociEnvironment, OCI_HTYPE_ENV);
      return st_FAILED;
    }

    /* Allocate and prepare SQL statement */
    nResultCode = checkOCIError(drv, "st_oracle_init: Allocate Statement", ociError, OCIHandleAlloc((dvoid *)ociEnvironment,
                                                                                     (dvoid **)&ociStatement, OCI_HTYPE_STMT,
                                                                                     (size_t)NULL, (dvoid **)NULL));

    if (nResultCode != 0)
    {
      nResultCode = OCILogoff(ociService, ociError);
      nResultCode = OCIHandleFree((dvoid *) ociService, OCI_HTYPE_SVCCTX);
      nResultCode = OCIHandleFree((dvoid *) ociError, OCI_HTYPE_ERROR);
      nResultCode = OCIHandleFree((dvoid *) ociEnvironment, OCI_HTYPE_ENV);
      return st_FAILED;
    }

    free(oracle_server_host);

    data = (OracleDriverPointer) calloc(1, sizeof(struct OracleDriver));

    data->ociEnvironment = ociEnvironment;
    data->ociError = ociError;
    data->ociService = ociService;
    data->ociStatement = ociStatement;
    data->ociDefine = NULL;
    data->ociBind = NULL;

    data->filters = xhash_new(17);

    data->prefix = config_get_one(drv->st->config, "storage.oracle.prefix", 0);

    drv->private = (void *) data;

    drv->add_type = _st_oracle_add_type;
    drv->put = _st_oracle_put;
    drv->count = _st_oracle_count;
    drv->get = _st_oracle_get;
    drv->delete = _st_oracle_delete;
    drv->replace = _st_oracle_replace;
    drv->free = _st_oracle_free;

    return st_SUCCESS;
}
