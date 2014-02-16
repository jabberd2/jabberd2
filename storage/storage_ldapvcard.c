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

/*
 * Written by Nikita Smirnov in 2004
 * on basis of authreg_ldap.c and storage_fs.c
 */

#include "storage.h"

#ifdef STORAGE_LDAP

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <time.h>
#include <regex.h>

#define LDAPVCARD_SRVTYPE_LDAP 1
#define LDAPVCARD_SRVTYPE_AD 2

#define LDAPVCARD_SEARCH_MAX_RETRIES 1

extern int _ldap_get_lderrno(LDAP *ld);

/** internal structure, holds our data */
typedef struct drvdata_st {
    LDAP *ld;
    const char *uri;

    const char *realm; // server id to be appended to uid

    const char *binddn;
    const char *bindpw;
    const char *basedn;

    const char *objectclass; // objectclass of jabber users
    const char *uidattr; // search attribute for users
    const char *validattr; // search attribute for valid
    const char *pwattr; // attribute which holds password
    const char *groupattr; // attribute with group name for published-roster in jabberuser entry
    const char *groupattr_regex; // regex to create a new group attribute based on groupattr
    const char *publishedattr; // can we publish it?

    const char *groupsdn; // base dn for group names search
    const char *groupsoc; // objectclass for group names search
    const char *groupsidattr; // search attribute for group names
    const char *groupnameattr; // attribute with text group name

    int srvtype;
    int mappedgroups;

#ifndef NO_SM_CACHE
    os_t cache;
    time_t cache_time;
    time_t cache_ttl;
#endif
} *drvdata_t;

typedef struct {
    char *ldapentry, *vcardentry;
    os_type_t ot;
} ldapvcard_entry_st;

ldapvcard_entry_st ldapvcard_entry[] =
{
    {"displayName","fn",os_type_STRING},
    {"cn","nickname",os_type_STRING},
    {"labeledURI","url",os_type_STRING},
    {"telephoneNumber","tel",os_type_STRING},
    {"mail","email",os_type_STRING},
    {"title","title",os_type_STRING},
    {"role","role",os_type_STRING},
    {"dateOfBirth","bday",os_type_UNKNOWN}, /* fake type. TODO: os_type_DATE? */
//    {"birthDate","bday",os_type_UNKNOWN}, /* http://tools.ietf.org/html/draft-gryphon-ldap-schema-vcard4-00 */
    {"description","desc",os_type_STRING},
    {"givenName","n-given",os_type_STRING},
    {"jpegPhoto","photo-binval",os_type_STRING},
    {"sn","n-family",os_type_STRING},
    {"initials","n-middle",os_type_STRING},
    {"st","adr-street",os_type_STRING},
    {"zip","adr-extadd",os_type_STRING},
    {"l","adr-locality",os_type_STRING},
//    {"","adr-region",os_type_STRING},
    {"postalCode","adr-pcode",os_type_STRING},
    {"c","adr-country",os_type_STRING},
    {"o","org-orgname",os_type_STRING},
    {"ou","org-orgunit",os_type_STRING},
    {NULL,NULL,0}
};

static int processregex(char *src, const char *regex, int patterngroups, int wantedgroup, char *dest, size_t dest_size, st_driver_t drv) {
  regex_t preg;
  regmatch_t pmatch[patterngroups];
  //log_debug(ZONE,"processregex: src='%s' regex='%s'", src, regex);
  if (regcomp(&preg, regex, REG_ICASE|REG_EXTENDED) !=0) {
        log_write(drv->st->log, LOG_ERR, "ldapvcard: regex compile failed on '%s'", regex);
	return -1;
  }
  if (regexec(&preg, src, patterngroups, pmatch, 0) !=0) {
        log_write(drv->st->log, LOG_ERR, "ldapvcard: regexec failed");
	return -2;
  }
  regfree(&preg);
  int len = pmatch[wantedgroup].rm_eo-pmatch[wantedgroup].rm_so>dest_size?dest_size:pmatch[wantedgroup].rm_eo-pmatch[wantedgroup].rm_so;
  memcpy(dest, src+pmatch[wantedgroup].rm_so, len);
  dest[len<dest_size?len:dest_size]='\0';
  //log_debug(ZONE,"processregex: dest='%s'", dest);
  return 0;
}

#ifndef NO_SM_CACHE
void os_copy(os_t src, os_t dst) {
    os_object_t o,dsto;
    char *key;
    void *val, *cval;
    os_type_t ot;

    if(os_iter_first(src)) {
        do {
            //log_write(log, LOG_ERR, "reading object");
            o = os_iter_object(src);
            dsto = os_object_new(dst);
            if( os_object_iter_first(o)) {
                do {
                    os_object_iter_get(o,&key,&val,&ot);
                    switch(ot) {
                        case os_type_BOOLEAN:
                        case os_type_INTEGER:
                            cval = &val;
                            break;
                        default:
                            cval = val;
                    }
                    os_object_put(dsto,key,cval,ot);
                    //log_write(log, LOG_ERR, "wrote.");
                } while(os_object_iter_next(o));
            }
        } while(os_iter_next(src));
    } else { // ! os_iter_first(src)
        log_debug(ZONE,"os_copy: cannot read source object");
    }
}
#endif

/** utility function to get ld_errno */
static int _st_ldapvcard_get_lderrno(LDAP *ld)
{
  int ld_errno;
  ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
  return ld_errno;
}

/** entry-point function for following referrals, required in some cases by Active Directory */
static int rebindProc(LDAP *ld, LDAP_CONST char *url, ber_tag_t request, ber_int_t msgid, void *mdata)
{
    drvdata_t data = mdata;
    data->ld = ld;
    if(ldap_simple_bind_s(data->ld, data->binddn, data->bindpw)) {
        log_debug(ZONE, "ldapvcard: bind failed (to %s): %s", url, ldap_err2string(_ldap_get_lderrno(data->ld)));
        ldap_unbind_s(data->ld);
        data->ld = NULL;
        return LDAP_INAPPROPRIATE_AUTH;
    }

    return LDAP_SUCCESS;
}

/** connect to the ldap host */
static int _st_ldapvcard_connect(st_driver_t drv)
{
  drvdata_t data = (drvdata_t) drv->private;
  int ldapversion = LDAP_VERSION3;
  int rc;

  if(data->ld != NULL)
    ldap_unbind_s(data->ld);

  rc = ldap_initialize( &(data->ld), data->uri);
  if( rc != LDAP_SUCCESS )
  {
    log_write(drv->st->log, LOG_ERR, "ldapvcard: ldap_initialize failed (uri=%s): %s", data->uri, ldap_err2string(rc));
    return 1;
  }

  if (ldap_set_option(data->ld, LDAP_OPT_PROTOCOL_VERSION, &ldapversion) != LDAP_SUCCESS)
  {
    log_write(drv->st->log, LOG_ERR, "ldapvcard: couldn't set v3 protocol");
    return 1;
  }
  if (ldap_set_option(data->ld, LDAP_OPT_REFERRALS, LDAP_OPT_ON) != LDAP_SUCCESS)
  {
    log_write(drv->st->log, LOG_ERR, "ldapvcard: couldn't set LDAP_OPT_REFERRALS");
  }

  return 0;
}

/** unbind and clear variables */
static int _st_ldapvcard_unbind(st_driver_t drv) {
  drvdata_t data = (drvdata_t) drv->private;
  ldap_unbind_s(data->ld);
  data->ld = NULL;
  return 0;
}

/** connect to ldap and bind as data->binddn */
static int _st_ldapvcard_connect_bind(st_driver_t drv) {
  drvdata_t data = (drvdata_t) drv->private;

  if(data->ld != NULL ) {
    return 0;
  }

  if( _st_ldapvcard_connect(drv) ) {
    return 1;
  }
  if(ldap_simple_bind_s(data->ld, data->binddn, data->bindpw))
  {
    log_write(drv->st->log, LOG_ERR, "ldapvcard: bind as %s failed: %s", data->binddn, ldap_err2string(_st_ldapvcard_get_lderrno(data->ld)));
    _st_ldapvcard_unbind(drv);
    return 1;
  }
  return 0;
}

static st_ret_t _st_ldapvcard_add_type(st_driver_t drv, const char *type) {
    drvdata_t data = (drvdata_t) drv->private;

    if( strncmp(type,"vcard",6) &&
        strncmp(type,"published-roster",17) &&
        strncmp(type,"published-roster-groups",24)
        ) {
        log_write(drv->st->log, LOG_ERR, "ldapvcard: only vcard,published-roster,published-roster-groups types supperted for now");
        return st_FAILED;
    } else {
        if( !strncmp(type,"published-roster-groups",24) ) {
            if( !data->mappedgroups ) {
                log_write(drv->st->log, LOG_ERR, "ldapvcard: published-roster-groups is not enabled by map-groups config option in ldapvcard section");
                return st_FAILED;
            }
        }
        return st_SUCCESS;
    }

    return st_SUCCESS;
}

static st_ret_t _st_ldapvcard_get(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t *os) {
    drvdata_t data = (drvdata_t) drv->private;
    os_object_t o;
    char validfilter[256], ldapfilter[1024], **vals;
    char *attrs_vcard[sizeof(ldapvcard_entry)/sizeof(ldapvcard_entry_st)];
    const char *attrs_pr[] = { data->uidattr, data->groupattr, "sn", "displayName", "initials", NULL };
    const char *attrs_prg[] = { data->groupnameattr, NULL };
    LDAPMessage *result, *entry;
    ldapvcard_entry_st le;
    int i,ival;
    int tried = 0;
    char jid[2048], group[1024], name[2048]; // name is sn[1024] + ' ' + initials[1024]

    if( _st_ldapvcard_connect_bind(drv) ) {
        return st_FAILED;
    }

    if( strncmp(type,"vcard",6) == 0 ) {
        // prepare need attributes
        i = 0;
        do {
            le = ldapvcard_entry[i];
            attrs_vcard[i++] = le.ldapentry;
        } while ( le.ldapentry != NULL );

        snprintf(ldapfilter, 1024, "(&(objectClass=%s)(%s=%s))", data->objectclass, data->uidattr, owner);
        log_debug(ZONE, "search filter: %s", ldapfilter);

        if(ldap_set_rebind_proc(data->ld, &rebindProc, data))
        {
            log_write(drv->st->log, LOG_ERR, "ldap: set_rebind_proc failed: %s", ldap_err2string(_st_ldapvcard_get_lderrno(data->ld)));
            ldap_unbind_s(data->ld);
            data->ld = NULL;
            return st_FAILED;
        }

        if(ldap_search_s(data->ld, data->basedn, LDAP_SCOPE_SUBTREE, ldapfilter, attrs_vcard, 0, &result))
        {
            log_write(drv->st->log, LOG_ERR, "ldapvcard: search %s failed: %s", ldapfilter, ldap_err2string(_st_ldapvcard_get_lderrno(data->ld)));
            _st_ldapvcard_unbind(drv);
            return st_FAILED;
        }

        entry = ldap_first_entry(data->ld, result);
        if(entry == NULL)
        {
            ldap_msgfree(result);
            return st_FAILED;
        }

        *os = os_new();

        o = os_object_new(*os);

        i = 0;
        le = ldapvcard_entry[i];
        while( le.ldapentry != NULL ) {
            if ( (strlen(le.ldapentry) == 9) && (!strncmp("jpegPhoto",le.ldapentry,9)))
            {
                struct berval **valphoto=(struct berval **)ldap_get_values_len(data->ld,entry,le.ldapentry);
                if ( ldap_count_values_len(valphoto) > 0 )
                {
                    char *VALJPG = b64_encode(valphoto[0]->bv_val, valphoto[0]->bv_len);
                    os_object_put(o, "photo-binval", VALJPG, os_type_STRING);
                    if( !strncmp(VALJPG, "/9j/4", 5) ) {
                        os_object_put(o, "photo-type", "image/jpeg", os_type_STRING);
                    } else if( !strncmp(VALJPG, "iVBOR", 5) ) {
                        os_object_put(o, "photo-type", "image/png", os_type_STRING);
                    } else if( !strncmp(VALJPG, "R0lGO", 5) ) {
                        os_object_put(o, "photo-type", "image/gif", os_type_STRING);
                    } else {
                        log_write(drv->st->log, LOG_ERR, "ldap: unknown photo fprmat photo %s", VALJPG);
                        os_object_put(o, "photo-type", "image/jpeg", os_type_STRING);
                    }
                    free(VALJPG);
                }
                ldap_value_free_len(valphoto);
            } else {
                vals=(char **)ldap_get_values(data->ld,entry,le.ldapentry);
                if( ldap_count_values(vals) > 0  ) {
                    switch(le.ot) {
                        case os_type_BOOLEAN:
                        case os_type_INTEGER:
                            ival=atoi(vals[0]);
                            os_object_put(o, le.vcardentry, &ival, le.ot);
                            break;
                        case os_type_STRING:
                            os_object_put(o, le.vcardentry, vals[0], le.ot);
                            break;
                        case os_type_UNKNOWN: /* TODO: os_type_DATE? */
                            if( strlen(vals[0])==15 && vals[0][14]=='Z' ) { /* YYYYMMDDHHmmssZ */
                                /* convert generalizedTime to ISO-8601 date */
                                vals[0][10]='\0';
                                vals[0][9]=vals[0][7];
                                vals[0][8]=vals[0][6];
                                vals[0][7]='-';
                                vals[0][6]=vals[0][5];
                                vals[0][5]=vals[0][4];
                                vals[0][4]='-';
                                os_object_put(o, le.vcardentry, vals[0], os_type_STRING);
                            }
                            break;
                        case os_type_NAD:
                            log_write(drv->st->log, LOG_ERR, "ldapvcard: got unsupported os_type_NAD");
                            break;
                    }
                }
                ldap_value_free(vals);
            }
            le = ldapvcard_entry[++i];
        }
        ldap_msgfree(result);
    } else if( strncmp(type,"published-roster",17) == 0 ) {
#ifndef NO_SM_CACHE
        if( data->cache_ttl && data->cache && (time(NULL) - data->cache_time < data->cache_ttl) ) {
            *os = os_new();
            os_copy(data->cache, *os);
        } else {
#endif
            validfilter[0] = '\0';
            if( data->srvtype == LDAPVCARD_SRVTYPE_AD ) {
                if( data->validattr ) {
                    snprintf(validfilter, 256, "(%s=TRUE)(%s=TRUE)", data->publishedattr, data->validattr);
                } else {
                    snprintf(validfilter, 256, "(%s=TRUE)", data->publishedattr);
                }
            } else {
                if( data->validattr ) {
                    snprintf(validfilter, 256, "(&(%s=*)(!(%s=0)))(%s=1)", data->publishedattr, data->publishedattr, data->validattr);
                } else {
                    snprintf(validfilter, 256, "(&(%s=*)(!(%s=0)))", data->publishedattr, data->publishedattr);
                }
            }

            snprintf(ldapfilter, 1024, "(&%s(objectClass=%s)(%s=*))", validfilter, data->objectclass, data->uidattr);

            log_debug(ZONE, "search filter: %s", ldapfilter);

retry_pubrost:
            if(ldap_search_s(data->ld, data->basedn, LDAP_SCOPE_SUBTREE, ldapfilter, (char**)attrs_pr, 0, &result))
            {
                if( tried++ < LDAPVCARD_SEARCH_MAX_RETRIES ) {
                    log_debug(ZONE, "ldapvcard: search fail, will retry; %s: %s", ldapfilter, ldap_err2string(_st_ldapvcard_get_lderrno(data->ld)));
                    _st_ldapvcard_unbind(drv);
                    if( _st_ldapvcard_connect_bind(drv) == 0 ) {
                        goto retry_pubrost;
                    } else {
                        return st_FAILED;
                    }
                }
                log_write(drv->st->log, LOG_ERR, "ldapvcard: search %s failed: %s", ldapfilter, ldap_err2string(_st_ldapvcard_get_lderrno(data->ld)));
                _st_ldapvcard_unbind(drv);
                return st_FAILED;
            }

            entry = ldap_first_entry(data->ld, result);
            if(entry == NULL)
            {
                ldap_msgfree(result);
                return st_FAILED;
            }

            *os = os_new();

            do {
                vals = (char **)ldap_get_values(data->ld,entry,data->groupattr);
                if( ldap_count_values(vals) <= 0 ) {
                    ldap_value_free(vals);
                    continue;
                }
                if (data->groupattr_regex == NULL || processregex(vals[0],data->groupattr_regex,2,1,group,sizeof(group),drv) !=0) {
                    // if there is no regex defined or processing the regex failed - take value as is
                    strncpy(group,vals[0],sizeof(group)-1);
                }
                group[sizeof(group)-1]='\0';
                ldap_value_free(vals);

                vals = (char **)ldap_get_values(data->ld,entry,data->uidattr);
                if( ldap_count_values(vals) <= 0 ) {
                    ldap_value_free(vals);
                    continue;
                }
                if( data->realm == NULL ) {
                    strncpy(jid,vals[0],sizeof(jid)-1); jid[sizeof(jid)-1]='\0';
                } else {
                    snprintf(jid, 2048, "%s@%s", vals[0], data->realm);
                }

                ldap_value_free(vals);

                vals = (char **)ldap_get_values(data->ld,entry,"displayName");
                if( ldap_count_values(vals) <= 0 ) {
                    ldap_value_free(vals);
                    vals = (char **)ldap_get_values(data->ld,entry,"cn");
                    if( ldap_count_values(vals) <= 0 ) {
                        strncpy(name,jid,sizeof(name)-1); name[sizeof(name)-1]='\0';
                    } else {
                        strncpy(name,vals[0],sizeof(name)-1); name[sizeof(name)-1]='\0';
                    }
                } else {
                    strncpy(name,vals[0],1023); name[1023]='\0';
                }
                ldap_value_free(vals);

                o = os_object_new(*os);
                os_object_put(o,"jid",jid,os_type_STRING);
                os_object_put(o,"group",group,os_type_STRING);
                os_object_put(o,"name",name,os_type_STRING);
                ival=1;
                os_object_put(o,"to",&ival,os_type_BOOLEAN);
                os_object_put(o,"from",&ival,os_type_BOOLEAN);
                ival=0;
                os_object_put(o,"ask",&ival,os_type_INTEGER);
            } while( (entry = ldap_next_entry(data->ld, entry)) );
            ldap_msgfree(result);
#ifndef NO_SM_CACHE
            if( data->cache_ttl ) {
                if( data->cache ) {
                    os_free(data->cache);
                }
                data->cache = os_new();
                os_copy(*os, data->cache);
                data->cache_time = time(NULL);
            }
#endif
#ifndef NO_SM_CACHE
        } // if !cached
#endif
    } else if( strncmp(type,"published-roster-groups",24) == 0 ) {
        snprintf(ldapfilter, 1024, "(&(objectClass=%s)(%s=%s))", data->groupsoc, data->groupsidattr, owner);
        log_debug(ZONE, "search filter: %s", ldapfilter);
retry_pubrostgr:
        if(ldap_search_s(data->ld, data->basedn, LDAP_SCOPE_SUBTREE, ldapfilter, (char**)attrs_prg, 0, &result))
        {
            if( tried++ < LDAPVCARD_SEARCH_MAX_RETRIES ) {
                log_debug(ZONE, "ldapvcard: search fail, will retry; %s: %s", ldapfilter, ldap_err2string(_st_ldapvcard_get_lderrno(data->ld)));
                _st_ldapvcard_unbind(drv);
                if( _st_ldapvcard_connect_bind(drv) == 0 ) {
                    goto retry_pubrostgr;
                } else {
                    return st_FAILED;
                }
            }
            log_write(drv->st->log, LOG_ERR, "ldapvcard: search %s failed: %s", ldapfilter, ldap_err2string(_st_ldapvcard_get_lderrno(data->ld)));
            _st_ldapvcard_unbind(drv);
            return st_FAILED;
        }

        entry = ldap_first_entry(data->ld, result);
        if(entry == NULL)
        {
            ldap_msgfree(result);
            return st_FAILED;
        }

        *os = os_new();

        // use only the first found entry and the first found attribute value
        vals = (char **)ldap_get_values(data->ld,entry,data->groupnameattr);
        if( ldap_count_values(vals) <= 0 ) {
            ldap_value_free(vals);
            ldap_msgfree(result);
            return st_FAILED;
        }
        strncpy(group,vals[0],sizeof(group)-1); group[sizeof(group)-1]='\0';
        ldap_value_free(vals);
        ldap_msgfree(result);

        o = os_object_new(*os);
        os_object_put(o,"groupname",group,os_type_STRING);
    } else {
        log_write(drv->st->log, LOG_ERR, "ldapvcard: unknown storage type: '%s'", type);
        return st_FAILED;
    }

    return st_SUCCESS;
}

static st_ret_t _st_ldapvcard_put(st_driver_t drv, const char *type, const char *owner, os_t os) {
    return st_FAILED;
}
static st_ret_t _st_ldapvcard_delete(st_driver_t drv, const char *type, const char *owner, const char *filter) {
    return st_SUCCESS;
}
static st_ret_t _st_ldapvcard_replace(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t os) {
    return st_FAILED;
}

static void _st_ldapvcard_free(st_driver_t drv) {
    drvdata_t data = (drvdata_t) drv->private;
    if( data->ld ) {
        _st_ldapvcard_unbind(drv);
    }
    free(data);
}

DLLEXPORT st_ret_t st_init(st_driver_t drv)
{
    drvdata_t data;
    const char *uri, *realm, *basedn, *srvtype_s;
    int srvtype_i;

    log_write(drv->st->log, LOG_NOTICE, "ldapvcard: initializing");

    uri = config_get_one(drv->st->config, "storage.ldapvcard.uri", 0);
    if(uri == NULL) {
        log_write(drv->st->log, LOG_ERR, "ldapvcard: no uri specified in config file");
        return st_FAILED;
    }

    realm = config_get_one(drv->st->config, "storage.ldapvcard.realm", 0);
    if(realm != NULL) {
        log_write(drv->st->log, LOG_NOTICE, "ldapvcard: defined realm %s", realm);
    }

    basedn = config_get_one(drv->st->config, "storage.ldapvcard.basedn", 0);
    if(basedn == NULL) {
        log_write(drv->st->log, LOG_ERR, "ldapvcard: no basedn specified in config file");
        return st_FAILED;
    }

    srvtype_s = config_get_one(drv->st->config, "storage.ldapvcard.type", 0);
    if( srvtype_s == NULL ) {
        srvtype_i = LDAPVCARD_SRVTYPE_LDAP;
    } else if( !strcmp(srvtype_s, "ldap") ) {
        srvtype_i = LDAPVCARD_SRVTYPE_LDAP;
    } else if( !strcmp(srvtype_s, "ad") ) {
        srvtype_i = LDAPVCARD_SRVTYPE_AD;
    } else {
        log_write(drv->st->log, LOG_ERR, "ldapvcard: unknown server type: %s", srvtype_s);
        return 1;
    }

    data = (drvdata_t) calloc(1, sizeof(struct drvdata_st));

    drv->private = (void *) data;

    data->uri = uri;
    data->realm = realm;
    data->basedn = basedn;
    data->srvtype = srvtype_i;

    data->binddn = config_get_one(drv->st->config, "storage.ldapvcard.binddn", 0);
    if(data->binddn != NULL)
        data->bindpw = config_get_one(drv->st->config, "storage.ldapvcard.bindpw", 0);

    data->uidattr = config_get_one(drv->st->config, "storage.ldapvcard.uidattr", 0);
    if(data->uidattr == NULL)
        data->uidattr = "uid";

    data->validattr = config_get_one(drv->st->config, "storage.ldapvcard.validattr", 0);

    data->groupattr = config_get_one(drv->st->config, "storage.ldapvcard.groupattr", 0);
    if(data->groupattr == NULL)
        data->groupattr = "jabberPublishedGroup";

    data->groupattr_regex = config_get_one(drv->st->config, "storage.ldapvcard.groupattr_regex", 0);

    data->publishedattr = config_get_one(drv->st->config, "storage.ldapvcard.publishedattr", 0);
    if(data->publishedattr == NULL)
        data->publishedattr = "jabberPublishedItem";

#ifndef NO_SM_CACHE
    data->cache_ttl = j_atoi(config_get_one(drv->st->config, "storage.ldapvcard.publishedcachettl", 0), 0);
    data->cache = NULL;
    data->cache_time = 0;
#endif

    data->objectclass = config_get_one(drv->st->config, "storage.ldapvcard.objectclass", 0);
    if(data->objectclass == NULL)
        data->objectclass = "jabberUser";

    data->mappedgroups = j_atoi(config_get_one(drv->st->config, "storage.ldapvcard.mapped-groups.map-groups", 0), 0);
    if( data->mappedgroups ) {
        data->groupsdn = config_get_one(drv->st->config, "storage.ldapvcard.mapped-groups.basedn", 0);
        if(data->groupsdn == NULL) {
            log_write(drv->st->log, LOG_ERR, "ldapvcard: no basedn for mapped-groups specified in config file");
            return st_FAILED;
        }

        data->groupsoc = config_get_one(drv->st->config, "storage.ldapvcard.mapped-groups.objectclass", 0);
        if(data->groupsoc == NULL)
            data->groupsoc = "jabberGroup";

        data->groupsidattr = config_get_one(drv->st->config, "storage.ldapvcard.mapped-groups.idattr", 0);
        if(data->groupsidattr == NULL)
            data->groupsidattr = "cn";

        data->groupnameattr = config_get_one(drv->st->config, "storage.ldapvcard.mapped-groups.nameattr", 0);
        if(data->groupnameattr == NULL)
            data->groupnameattr = "description";
    }

    drv->add_type = _st_ldapvcard_add_type;
    drv->put = _st_ldapvcard_put;
    drv->get = _st_ldapvcard_get;
    drv->delete = _st_ldapvcard_delete;
    drv->replace = _st_ldapvcard_replace;
    drv->free = _st_ldapvcard_free;

    return st_SUCCESS;
}

#endif
