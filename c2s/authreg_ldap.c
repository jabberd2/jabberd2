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

/* this plugin authenticates against an LDAP directory by attempting to bind
 * as the user. It won't store or retrieve any actual data, so only the
 * plaintext mechanism is available.
 *
 * !!! this doesn't do any caching. It really should.
 *
 * !!! this blocks for every auth. We're stuck with this until authreg can
 *     return a pending state. The timeout helps, but its still icky.
 */

#include "c2s.h"

#ifdef STORAGE_LDAP

#include <lber.h>
#include <ldap.h>

#define AR_LDAP_FLAGS_NONE      (0x0)
#define AR_LDAP_FLAGS_STARTTLS  (0x1)
#define AR_LDAP_FLAGS_SSL       (0x2)
#define AR_LDAP_FLAGS_V3        (0x4)

/** internal structure, holds our data */
typedef struct moddata_st
{
    authreg_t ar;

    LDAP *ld;

    char *host;
    long port;

    int flags;

    char *binddn;
    char *bindpw;

    char *uidattr;

    xht basedn;
    char *default_basedn;
} *moddata_t;

/** utility function to get ld_errno */
static int _ldap_get_lderrno(LDAP *ld)
{
    int ld_errno;

    ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);

    return ld_errno;
}

/** connect to the ldap host */
static int _ldap_connect(moddata_t data)
{
    char url[1024];
    int version = (data->flags & AR_LDAP_FLAGS_V3) ? 3 : 2;
    
    /* ssl "wrappermode" */
    if(data->flags & AR_LDAP_FLAGS_SSL) {
      snprintf(url, sizeof(url), "ldaps://%s:%d", data->host, data->port);
      ldap_initialize(&data->ld, url);
    }
    /* non-SSL connect method */
    else 
      data->ld = ldap_init(data->host, data->port);
    
    if(data->ld != NULL) {
      /* explicitly set ldap version for all connections */
      if(ldap_set_option(data->ld, LDAP_OPT_PROTOCOL_VERSION, &version)) {
	log_write(data->ar->c2s->log, LOG_ERR, "ldap: couldn't use version %d: %s", version, ldap_err2string(_ldap_get_lderrno(data->ld)));
	ldap_unbind_s(data->ld);
	data->ld = NULL;
	return 1;
      }
      
      /* starttls */
      if(data->flags & AR_LDAP_FLAGS_STARTTLS) { 
	if(ldap_start_tls_s(data->ld, NULL, NULL)) {
	  log_write(data->ar->c2s->log, LOG_ERR, "ldap: couldn't start TLS: %s", ldap_err2string(_ldap_get_lderrno(data->ld)));
	  ldap_unbind_s(data->ld);
	  data->ld = NULL;
	  return 1;
	}
      }
    } else {
      log_write(data->ar->c2s->log, LOG_ERR, "ldap: connect to server at %s:%d failed", data->host, data->port);
      return 1;
    }

    return 0;
}

/** do a search, return the dn */
static char *_ldap_search(moddata_t data, char *realm, char *username)
{
    char filter[1024], *dn, *no_attrs[] = { NULL }, *basedn;
    LDAPMessage *result, *entry;

    basedn = xhash_get(data->basedn, realm);
    if(basedn == NULL)
        basedn = data->default_basedn;

    if(basedn == NULL) {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: no basedn specified for realm '%s'", realm);
        ldap_unbind_s(data->ld);
        data->ld = NULL;
        return NULL;
    }

    if(ldap_simple_bind_s(data->ld, data->binddn, data->bindpw)
        && (_ldap_connect(data) || ldap_simple_bind_s(data->ld, data->binddn, data->bindpw))) 
    {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: bind failed: %s", ldap_err2string(_ldap_get_lderrno(data->ld)));
        ldap_unbind_s(data->ld);
        data->ld = NULL;
        return NULL;
    }

    snprintf(filter, 1024, "(%s=%s)", data->uidattr, username);

    if(ldap_search_s(data->ld, basedn, LDAP_SCOPE_SUBTREE, filter, no_attrs, 0, &result))
    {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: search %s failed: %s", filter, ldap_err2string(_ldap_get_lderrno(data->ld)));
        ldap_unbind_s(data->ld);
        data->ld = NULL;
        return NULL;
    }

    entry = ldap_first_entry(data->ld, result);
    if(entry == NULL)
    {
        ldap_msgfree(result);

        return NULL;
    }

    dn = ldap_get_dn(data->ld, entry);

    ldap_msgfree(result);

    log_debug(ZONE, "got dn '%s' from realm '%s', user '%s'", dn, realm, username);

    return dn;
}

/** do we have this user? */
static int _ldap_user_exists(authreg_t ar, char *username, char *realm)
{
    char *dn;
    int result;
    
    moddata_t data = (moddata_t) ar->private;

    if(data->ld == NULL && _ldap_connect(data))
        return 0;
    
    dn = _ldap_search(data, realm, username);
    result = (int) dn;
    ldap_memfree(dn);

    return result;
}

/** check the password */
static int _ldap_check_password(authreg_t ar, char *username, char *realm, char password[257])
{
    moddata_t data = (moddata_t) ar->private;
    char *dn;

    if(password[0] == '\0')
        return 1;

    if(data->ld == NULL && _ldap_connect(data))
        return 1;

    dn = _ldap_search(data, realm, username);
    if(dn == NULL)
        return 1;

    if(ldap_simple_bind_s(data->ld, dn, password))
    {
        if(_ldap_get_lderrno(data->ld) != LDAP_INVALID_CREDENTIALS)
        {
            log_write(data->ar->c2s->log, LOG_ERR, "ldap: bind as '%s' failed: %s", dn, ldap_err2string(_ldap_get_lderrno(data->ld)));
            ldap_unbind_s(data->ld);
            data->ld = NULL;
        }

        ldap_memfree(dn);
        return 1;
    }

    ldap_memfree(dn);
    return 0;
}

/** shut me down */
static void _ldap_free(authreg_t ar)
{
    moddata_t data = (moddata_t) ar->private;

    if(data->ld != NULL)
        ldap_unbind_s(data->ld);

    xhash_free(data->basedn);
    free(data);

    return;
}

/** start me up */
int ar_ldap_init(authreg_t ar)
{
    moddata_t data;
    char *host, *realm;
    config_elem_t basedn;
    int i;

    host = config_get_one(ar->c2s->config, "authreg.ldap.host", 0);
    if(host == NULL)
    {
        log_write(ar->c2s->log, LOG_ERR, "ldap: no host specified in config file");
        return 1;
    }

    basedn = config_get(ar->c2s->config, "authreg.ldap.basedn");
    if(basedn == NULL)
    {
        log_write(ar->c2s->log, LOG_ERR, "ldap: no basedns specified in config file");
        return 1;
    }

    data = (moddata_t) malloc(sizeof(struct moddata_st));
    memset(data, 0, sizeof(struct moddata_st));

    data->basedn = xhash_new(101);

    for(i = 0; i < basedn->nvalues; i++)
    {
        realm = (basedn->attrs[i] != NULL) ? j_attr((const char **) basedn->attrs[i], "realm") : NULL;
        if(realm == NULL)
            data->default_basedn = basedn->values[i];
        else
            xhash_put(data->basedn, realm, basedn->values[i]);

        log_debug(ZONE, "realm '%s' has base dn '%s'", realm, basedn->values[i]);
    }

    log_write(ar->c2s->log, LOG_NOTICE, "ldap: configured %d realms", i);

    data->host = host;

    data->port = j_atoi(config_get_one(ar->c2s->config, "authreg.ldap.port", 0), 389);

    data->flags = AR_LDAP_FLAGS_NONE;

    if(config_get(ar->c2s->config, "authreg.ldap.v3") != NULL)
      data->flags |= AR_LDAP_FLAGS_V3;
    if(config_get(ar->c2s->config, "authreg.ldap.starttls") != NULL)
      data->flags |= AR_LDAP_FLAGS_STARTTLS;
    if(config_get(ar->c2s->config, "authreg.ldap.ssl") != NULL)
      data->flags |= AR_LDAP_FLAGS_SSL;

    if((data->flags & AR_LDAP_FLAGS_STARTTLS) && (data->flags & AR_LDAP_FLAGS_SSL)) {
	log_write(ar->c2s->log, LOG_ERR, "ldap: not possible to use both SSL and starttls");
	return 1;
    }

    data->binddn = config_get_one(ar->c2s->config, "authreg.ldap.binddn", 0);
    if(data->binddn != NULL)
        data->bindpw = config_get_one(ar->c2s->config, "authreg.ldap.bindpw", 0);

    data->uidattr = config_get_one(ar->c2s->config, "authreg.ldap.uidattr", 0);
    if(data->uidattr == NULL)
        data->uidattr = "uid";

    data->ar = ar;
    
    if(_ldap_connect(data))
    {
        xhash_free(data->basedn);
        free(data);
        return 1;
    }

    ar->private = data;

    ar->user_exists = _ldap_user_exists;
    ar->check_password = _ldap_check_password;
    ar->free = _ldap_free;

    return 0;
}

#endif
