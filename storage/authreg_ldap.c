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
#include <stddef.h>
#include <lber.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>

#define AR_LDAP_FLAGS_NONE      (0x0)
#define AR_LDAP_FLAGS_STARTTLS  (0x1)
#define AR_LDAP_FLAGS_SSL       (0x2)
#define AR_LDAP_FLAGS_V3        (0x4)
#define AR_LDAP_FLAGS_RECONNECT (0x8)
#define AR_LDAP_FLAGS_DISABLE_REFERRALS (0x10)
#define AR_LDAP_FLAGS_APPEND_REALM (0x20)

typedef enum uidattr_order_e {
    AR_LDAP_UAO_UNUSED,
    AR_LDAP_UAO_USERNAME_DOMAIN,
    AR_LDAP_UAO_DOMAIN_USERNAME,
    AR_LDAP_UAO_USERNAME
} uidattr_order_t;

/** internal structure, holds our data */
typedef struct moddata_st
{
    authreg_t ar;

    LDAP *ld;

    const char *host;
    long port;

    int flags;
    int timeout;

    const char *binddn;
    const char *bindpw;

    const char *uidattr;
    const char *query;
    uidattr_order_t uidattr_order;
    
    xht basedn;
    const char *default_basedn;
} *moddata_t;

/** utility function to get ld_errno */
static int _ldap_get_lderrno(LDAP *ld)
{
    int ld_errno;

    ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);

    return ld_errno;
}

/** utility function to generate a printf format string from a "%u@%r" configuration string
 * accepted user parameters are %u for username and %r for realm/domain.
 *
 * \params uidattr_fmt a string containing %u for username and possibly %r for realm. This string will be modified to replace %u and %r with %s
 * \params order a returned value saying whether the username appears alone, before domain, or after domain
 * 
 * \return 1 for error
 *
 * \warning  We do not clean up the supplied string. As this is a configuration parameter 
 * and not a user-supplied string the risk is considered limited, but still exists */
static int _create_user_filter(moddata_t data) {
    char *pos_u;
    char *pos_d;
    ptrdiff_t u_d_diff;
    
    if (data->query == NULL) {
        data->uidattr_order = AR_LDAP_UAO_UNUSED;
        return 1;
    }
    
    pos_u = strstr(data->query, "%u");
    
    if (pos_u == NULL) {
        data->uidattr_order = AR_LDAP_UAO_UNUSED;
        return 1;
    }
    pos_u[1] = 's';
    
    pos_d = strstr(data->query, "%r");
    if (pos_d != NULL) pos_d[1] = 's';
    
    u_d_diff = pos_u - pos_d;
    
    if (u_d_diff == (ptrdiff_t)pos_u) {
        data->uidattr_order = AR_LDAP_UAO_USERNAME;
        return 0;
    } else {
        if (u_d_diff > 0) {
            data->uidattr_order = AR_LDAP_UAO_DOMAIN_USERNAME;
            return 0;
        } else {
            data->uidattr_order = AR_LDAP_UAO_USERNAME_DOMAIN;
            return 0;
        }
    }
    
    /* shouldn't arrive here */
    data->uidattr_order = AR_LDAP_UAO_UNUSED;
    return 1;
}

/** entry-point function for following referrals, required in some cases by Active Directory */
static int rebindProc(LDAP *ld, LDAP_CONST char *url, ber_tag_t request, ber_int_t msgid, void *mdata)
{
    moddata_t data = mdata;
    data->ld = ld;
    if(ldap_simple_bind_s(data->ld, data->binddn, data->bindpw)) {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: bind failed (to %s): %s", url, ldap_err2string(_ldap_get_lderrno(data->ld)));
        ldap_unbind_s(data->ld);
        data->ld = NULL;
        // return NULL;  // TODO FIXME Wrong: It is the same as LDAP_SUCCESS
        return LDAP_OPERATIONS_ERROR;// TODO check if it is correct
    }

    return LDAP_SUCCESS;
}

/** connect to the ldap host */
static int _ldap_connect(moddata_t data)
{
    char url[1024];
    int version = (data->flags & AR_LDAP_FLAGS_V3) ? 3 : 2;
    struct timeval timeout = {data->timeout,0};
    
    /* ssl "wrappermode" */
    if(data->flags & AR_LDAP_FLAGS_SSL) {
      snprintf(url, sizeof(url), "ldaps://%s:%ld", data->host, data->port); // TODO FIXME data->port shall be at most 'unsigned int'
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

      /* referrals */
      if(data->flags & AR_LDAP_FLAGS_DISABLE_REFERRALS) {
        if( ldap_set_option( data->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF ) != LDAP_OPT_SUCCESS )
        {
          log_write(data->ar->c2s->log, LOG_ERR, "ldap: couldn't set Referrals Off: %s", ldap_err2string(_ldap_get_lderrno(data->ld)));
          ldap_unbind_s(data->ld);
          data->ld = NULL;
          return 1;
        }
      }

      /* timeout */
      if( ldap_set_option( data->ld, LDAP_OPT_NETWORK_TIMEOUT, &timeout ) != LDAP_OPT_SUCCESS || ldap_set_option( data->ld, LDAP_OPT_TIMEOUT, &timeout ) != LDAP_OPT_SUCCESS )
      {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: couldn't set Timeout: %s", ldap_err2string(_ldap_get_lderrno(data->ld)));
        ldap_unbind_s(data->ld);
        data->ld = NULL;
        return 1;
      }

    } else {
      log_write(data->ar->c2s->log, LOG_ERR, "ldap: connect to server at %s:%d failed", data->host, data->port);
      return 1;
    }

    return 0;
}

/** Reconnect */
static int _ldap_reconnect(moddata_t data)
{

    if (data->ld != NULL) {
        ldap_unbind_s(data->ld);
        data->ld = NULL;
    }

    return (_ldap_connect(data));
}


/** do a search, return the dn */
static char *_ldap_search(moddata_t data, const char *realm, const char *username)
{
    char filter[1024], *dn, *no_attrs[] = { NULL };
    const char *basedn;
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

    if (data->flags & AR_LDAP_FLAGS_RECONNECT) {
        if (_ldap_reconnect(data)) {
            log_write(data->ar->c2s->log, LOG_ERR, "ldap: reconnect failed: %s realm: %s basedn: %s binddn: %s pass: %s", ldap_err2string(_ldap_get_lderrno(data->ld)), realm, basedn, data->binddn, data->bindpw ); 
            return NULL;
        }
    }

    if(ldap_simple_bind_s(data->ld, data->binddn, data->bindpw)
        && (_ldap_connect(data) || ldap_simple_bind_s(data->ld, data->binddn, data->bindpw))) 
    {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: bind failed: %s realm: %s basedn: %s binddn: %s pass: %s", ldap_err2string(_ldap_get_lderrno(data->ld)), realm, basedn, data->binddn, data->bindpw );
        ldap_unbind_s(data->ld);
        data->ld = NULL;
        return NULL;
    }

    if (data->query) { /* custom uid format search fun */
        switch(data->uidattr_order) {
            case AR_LDAP_UAO_USERNAME_DOMAIN:
                snprintf(filter, 1024, data->query, username, realm);
                break;
            case AR_LDAP_UAO_DOMAIN_USERNAME:
                snprintf(filter, 1024, data->query, realm, username);
                break;
            case AR_LDAP_UAO_USERNAME:
                snprintf(filter, 1024, data->query,  username);
                break;
            default:
                log_write(data->ar->c2s->log, LOG_ERR, "ldap: creating filter failed: expected valid custom query, check your <query> config parameter");
                       log_debug(ZONE, "got unhandled %d for uidattr_order", data->uidattr_order);
                return NULL;
        }
    } else if (data->flags & AR_LDAP_FLAGS_APPEND_REALM) {
        snprintf(filter, 1024, "(%s=%s@%s)", data->uidattr, username, realm);
    } else {
        snprintf(filter, 1024, "(%s=%s)", data->uidattr, username);
    }

    log_debug(ZONE, "LDAP: will query with filter: %s\n", filter);
    
    if(ldap_set_rebind_proc(data->ld, &rebindProc, data)) {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: set_rebind_proc failed: %s", ldap_err2string(_ldap_get_lderrno(data->ld)));
        ldap_unbind_s(data->ld);
        data->ld = NULL;
        return NULL;
    }

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
static int _ldap_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{

    char *dn;
    moddata_t data;

    if(xhash_iter_first((xht) ar->private))
    do {
        xhash_iter_get((xht) ar->private, NULL, NULL, (void *) &data);
        if( ! (data->ld == NULL && _ldap_connect(data)) ) {
            dn = _ldap_search(data, realm, username);
            if (dn != NULL) {
                ldap_memfree(dn);
                return 1;
            }
        }
    } while(xhash_iter_next((xht) ar->private));

    return 0;

}

/** check the password */
static int _ldap_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{

    moddata_t data;
    char *dn;

    if(password[0] == '\0')
        return 1;

    if(xhash_iter_first((xht) ar->private))
    do {
        xhash_iter_get((xht) ar->private, NULL, NULL, (void *) &data);

        if( ! (data->ld == NULL && _ldap_connect(data)) ) {

            dn = _ldap_search(data, realm, username);
            if (dn != NULL) {

                if(ldap_simple_bind_s(data->ld, dn, password) ) {
                    if(_ldap_get_lderrno(data->ld) != LDAP_INVALID_CREDENTIALS)
                    {
                        log_write(data->ar->c2s->log, LOG_ERR, "ldap: bind as '%s' on host '%s' failed: %s", dn,data->host, ldap_err2string(_ldap_get_lderrno(data->ld)));
                        ldap_unbind_s(data->ld);
                        data->ld = NULL;
                    }
                    ldap_memfree(dn);
                } else {
                    ldap_memfree(dn);
                    return 0;
                }
            }
        }
    } while(xhash_iter_next((xht) ar->private));


    return 1;

}

/** shut me down */
static void _ldap_free(authreg_t ar)
{
    moddata_t data;

    if(xhash_iter_first((xht) ar->private))
    do {
        xhash_iter_get((xht) ar->private, NULL, NULL, (void *) &data);
        if(data->ld != NULL)
            ldap_unbind_s(data->ld);
        xhash_free(data->basedn);
        free(data);
    } while(xhash_iter_next((xht) ar->private));


    xhash_free((xht) ar->private);

    return;
}


/** start me up */
int ar_init(authreg_t ar)
{
    moddata_t data;
    char ldap_entry[128];
    const char *host, *realm;
    config_elem_t basedn;
    int i,l=0;
    xht domains;

    domains = xhash_new(17);
    ldap_entry[15]='\0';

    /* while we have more ldap entries*/
    do {

    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.host", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.host");
    host = config_get_one(ar->c2s->config, ldap_entry, 0);
    if(host == NULL)
    {
        log_write(ar->c2s->log, LOG_ERR, "ldap: no host specified in config file");
        return 1;
    }

    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.basedn", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.basedn");
    basedn = config_get(ar->c2s->config, ldap_entry);
    if(basedn == NULL)
    {
        log_write(ar->c2s->log, LOG_ERR, "ldap: no basedn specified in config file");
        return 1;
    }

    data = (moddata_t) calloc(1, sizeof(struct moddata_st));

    data->basedn = xhash_new(101);

    for(i = 0; i < basedn->nvalues; i++)
    {
        realm = (basedn->attrs[i] != NULL) ? j_attr((const char **) basedn->attrs[i], "realm") : NULL;
        if(realm == NULL)
            data->default_basedn = basedn->values[i];
        else
            xhash_put(data->basedn, realm, (void*)basedn->values[i]);

        log_debug(ZONE, "realm '%s' has base dn '%s'", realm, basedn->values[i]);
    }

    log_write(ar->c2s->log, LOG_NOTICE, "ldap: configured %d realms", i);

    data->host = host;

    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.port", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.port");
    data->port = j_atoi(config_get_one(ar->c2s->config, ldap_entry, 0), 389);

    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.timeout", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.timeout");
    data->timeout = j_atoi(config_get_one(ar->c2s->config, ldap_entry, 0), 5);

    data->flags = AR_LDAP_FLAGS_NONE;

    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.reconnect", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.reconnect");
    if(config_get(ar->c2s->config, ldap_entry) != NULL)
        data->flags |= AR_LDAP_FLAGS_RECONNECT;
    
    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.v3", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.v3");
    if(config_get(ar->c2s->config, ldap_entry) != NULL)
        data->flags |= AR_LDAP_FLAGS_V3;

    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.starttls", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.starttls");
    if(config_get(ar->c2s->config, ldap_entry) != NULL)
        data->flags |= AR_LDAP_FLAGS_STARTTLS;

    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.ssl", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.ssl");
    if(config_get(ar->c2s->config, ldap_entry) != NULL)
        data->flags |= AR_LDAP_FLAGS_SSL;

    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.disablereferrals", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.disablereferrals");
    if(config_get(ar->c2s->config, ldap_entry) != NULL)
        data->flags |= AR_LDAP_FLAGS_DISABLE_REFERRALS;

    /* Append realm is deprecated, use <query> option instead! */
    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.append-realm", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.append-realm");
    if(config_get(ar->c2s->config, ldap_entry) != NULL)
        data->flags |= AR_LDAP_FLAGS_APPEND_REALM;

    if((data->flags & AR_LDAP_FLAGS_STARTTLS) && (data->flags & AR_LDAP_FLAGS_SSL)) {
        log_write(ar->c2s->log, LOG_ERR, "ldap: not possible to use both SSL and starttls");
        return 1;
    }

    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.binddn", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.binddn");
    data->binddn = config_get_one(ar->c2s->config, ldap_entry, 0);
    if(data->binddn != NULL) {
        if (l>0)
            snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.bindpw", l );
        else
            snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.bindpw");
        data->bindpw = config_get_one(ar->c2s->config, ldap_entry, 0);
    }
    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.uidattr", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.uidattr");
    data->uidattr = config_get_one(ar->c2s->config, ldap_entry, 0);
    if(data->uidattr == NULL)
        data->uidattr = "uid";
    
    if (l>0)
        snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d.query", l );
    else
        snprintf(ldap_entry, sizeof(ldap_entry), "authreg.ldap.query");
    data->query = config_get_one(ar->c2s->config, ldap_entry, 0);
    if(_create_user_filter(data))
        data->query = NULL;

    data->ar = ar;
    
    if(_ldap_connect(data))
    {
        xhash_free(data->basedn);
        free(data);
        return 1;
    }

    xhash_put(domains, data->host, data);

    l++;
    snprintf(ldap_entry,sizeof(ldap_entry), "authreg.ldap%d", l );

    } while ( config_count(ar->c2s->config, ldap_entry) > 0 );
    

    ar->private = domains;

    ar->user_exists = _ldap_user_exists;
    ar->check_password = _ldap_check_password;
    ar->free = _ldap_free;

    return 0;
}
