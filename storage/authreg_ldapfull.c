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
 * on basis of authreg_ldap.c
 */

/*
 * !!! this doesn't do any caching. It really should.
 *
 * !!! this blocks for every auth.
 */

#define _XOPEN_SOURCE 500	// need this to get crypt()
#include "c2s.h"

#ifdef STORAGE_LDAP
#ifdef HAVE_CRYPT
#include <unistd.h>
#endif

#ifdef HAVE_SSL
#include <openssl/rand.h>
#endif

#include <lber.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>

#define LDAPFULL_PASSBUF_MAX 257
#define LDAPFULL_DN_MAX 4096

#define LDAPFULL_SRVTYPE_LDAP 1
#define LDAPFULL_SRVTYPE_AD 2

#define LDAPFULL_SEARCH_MAX_RETRIES 1

/** internal structure, holds our data */
typedef struct moddata_st
{
    authreg_t ar;

    LDAP *ld;

    const char *uri;

    const char *binddn;
    const char *bindpw;

    const char *objectclass;
    const char *uidattr;
    const char *validattr;
    const char *group_dn;
    const char *pwattr;
    const char *pwscheme;

    int fulluid; // use "uid@realm" in ldap searches (1) or just use "uid" (0)
    int binded; // if we are binded with binddn and bindpw, then 1, otherwise 0

    int srvtype;

    xht basedn;
    const char *default_basedn;
} *moddata_t;

//////////////////////////////////////////////////////////////////////////////
//
// Here is stuff for hashing passwords
// ideas and some part of code are taken from cyrus-sasl/saslauthd
//
//////////////////////////////////////////////////////////////////////////////

#ifdef HAVE_SSL
#include <openssl/evp.h>
#include <openssl/des.h>
#endif

typedef struct _ldapfull_pw_scheme {
    char *name;
    char *scheme;
    char *prefix;
    int saltlen;
    int (*check) (moddata_t data, const char *scheme, int salted, const char *hash, const char *passwd);
    int (*set) (moddata_t data, const char *scheme, const char *prefix, int saltlen, const char *passwd, char *buf, int buflen);
} ldapfull_pw_scheme;

int _ldapfull_hash_init(); // call it before use of other stuff
#ifdef HAVE_SSL
static int _ldapfull_chk_hashed(moddata_t data, const char *scheme, int salted, const char *hash, const char *passwd);
static int _ldapfull_set_hashed(moddata_t data, const char *scheme, const char *prefix, int saltlen, const char *passwd, char *buf, int buflen);
#endif
#ifdef HAVE_CRYPT
static int _ldapfull_chk_crypt(moddata_t data, const char *scheme, int salted, const char *hash, const char *passwd);
static int _ldapfull_set_crypt(moddata_t data, const char *scheme, const char *prefix, int saltlen, const char *passwd, char *buf, int buflen);
#endif
static int _ldapfull_chk_clear(moddata_t data, const char *scheme, int salted, const char *hash, const char *passwd);
static int _ldapfull_set_clear(moddata_t data, const char* scheme, const char* prefix, int saltlen, const char* passwd, char* buf, int buflen);

static int _ldapfull_check_passhash(moddata_t data, const char *hash, const char *passwd);
static int _ldapfull_set_passhash(moddata_t data, const char* scheme_name, const char* passwd, char* buf, int buflen);
static int _ldapfull_check_password_bind(authreg_t ar, const char *username, const char *realm, char password[LDAPFULL_PASSBUF_MAX]);

ldapfull_pw_scheme _ldapfull_pw_schemas[] = {
#ifdef HAVE_SSL
    { "sha", "sha1", "{SHA}", 0, _ldapfull_chk_hashed, _ldapfull_set_hashed },
    { "ssha", "sha1", "{SSHA}", 4, _ldapfull_chk_hashed, _ldapfull_set_hashed },
#endif
#ifdef HAVE_CRYPT
    { "crypt", "crypt", "", 2, _ldapfull_chk_crypt, _ldapfull_set_crypt },
#endif
    { "clear", "", "", 0, _ldapfull_chk_clear, _ldapfull_set_clear },
    { "bind", "", "", 0, NULL, NULL },
    { NULL, NULL, NULL, 0, NULL, NULL }
};


// general check_password
// returns 1 if password is checked, 0 otherwise
int _ldapfull_check_passhash(moddata_t data, const char *hash, const char *passwd) {
    int n;
    int plen;
    int hlen;

    if( ! hash ) {
        log_write(data->ar->c2s->log,LOG_ERR,"_ldapfull_check_passhash: hash is NULL");
        return 0;
    }
    if( ! passwd ) {
        log_write(data->ar->c2s->log,LOG_ERR,"_ldapfull_check_passhash: passwd is NULL");
        return 0;
    }

    hlen = strlen(hash);

    for( n=0 ; _ldapfull_pw_schemas[n].name != NULL ; n++ ) {
        plen = strlen(_ldapfull_pw_schemas[n].prefix);
        if( (plen <= hlen) && !strncmp(hash,_ldapfull_pw_schemas[n].prefix,plen) ) {
            // if scheme found is cleartext and hash begins with '{', than maybe it is
            // unknown scheme, so don't pass it
            if( ! strlen(_ldapfull_pw_schemas[n].scheme) && hlen ) {
                if( hash[0] == '{' ) {
                    continue;
                }
            }
            if( _ldapfull_pw_schemas[n].check ) {
              return _ldapfull_pw_schemas[n].check(
                  data,
                  _ldapfull_pw_schemas[n].scheme,
                  _ldapfull_pw_schemas[n].saltlen,
                  hash + plen,passwd);
            } else {
                log_write(data->ar->c2s->log,LOG_ERR,"_ldapfull_check_passhash: no check function for schema %s",
                        _ldapfull_pw_schemas[n].name);
                return 0;
            }
        }
    }
    return 0;
}

// general set_password
// returns 1 if password in buf is set, 0 otherwise
// must provide with buffer of sufficient length, or it will fail
int _ldapfull_set_passhash(moddata_t data, const char *scheme_name, const char *passwd, char *buf, int buflen) {
    int n;

    if( ! passwd ) {
        log_write(data->ar->c2s->log,LOG_ERR,"_ldapfull_set_passhash: passwd is NULL");
        return 0;
    }
    if( ! buf ) {
        log_write(data->ar->c2s->log,LOG_ERR,"_ldapfull_set_passhash: buf is NULL");
        return 0;
    }

    for( n=0 ; _ldapfull_pw_schemas[n].name != NULL ; n++ ) {
        if( !strcmp(scheme_name,_ldapfull_pw_schemas[n].name) ) {
            if( _ldapfull_pw_schemas[n].set ) {
              return _ldapfull_pw_schemas[n].set(
                  data,
                  _ldapfull_pw_schemas[n].scheme,
                  _ldapfull_pw_schemas[n].prefix,
                  _ldapfull_pw_schemas[n].saltlen,
                  passwd, buf, buflen);
            } else {
                log_write(data->ar->c2s->log,LOG_ERR,"_ldapfull_set_passhash: no set function for schema %s",
                        _ldapfull_pw_schemas[n].name);
                return 0;
            }
        }
    }
    return 0;
}

int _ldapfull_chk_clear(moddata_t data, const char *scheme, int salted, const char *hash, const char *passwd) {
    return !strcmp(hash,passwd);
}

int _ldapfull_set_clear(moddata_t data, const char *scheme, const char *prefix, int saltlen, const char *passwd, char *buf, int buflen) {
    if( buflen <= strlen(passwd) ) {
        log_write(data->ar->c2s->log,LOG_ERR,"_ldapfull_set_clear: buffer is too short (%i bytes)",buflen);
        return 0;
    }
    strcpy(buf, passwd);
    return 1;
}

#ifdef HAVE_SSL
int _ldapfull_base64_decode( const char *src, const unsigned char **ret, int *rlen ) {
    unsigned int rc, tlen = 0;
    int i;
    unsigned char *text;
    EVP_ENCODE_CTX EVP_ctx;

    text = (unsigned char *)malloc(((strlen(src)+3)/4 * 3) + 1);
    if (text == NULL) {
        return 0;
    }

    EVP_DecodeInit(&EVP_ctx);
    rc = EVP_DecodeUpdate(&EVP_ctx, text, &i, (const unsigned char *)src, strlen(src));
    if (rc < 0) {
        free(text);
        return 0;
    }
    tlen+=i;
    EVP_DecodeFinal(&EVP_ctx, (unsigned char*)text, &i); 

    *ret = text;
    if (rlen != NULL) {
        *rlen = tlen;
    }

    return 1;
}

static int _ldapfull_base64_encode( const unsigned char *src, int srclen, char **ret, int *rlen ) {
    int tlen = 0;
    unsigned char *text;
    EVP_ENCODE_CTX EVP_ctx;

    text = (unsigned char *)malloc((srclen*4/3) + 1 );
    if (text == NULL) {
        return 0;
    }

    EVP_EncodeInit(&EVP_ctx);
    EVP_EncodeUpdate(&EVP_ctx, text, &tlen, src, srclen);
    EVP_EncodeFinal(&EVP_ctx, text, &tlen); 

    *ret = (char*)text; 
    if (rlen != NULL) {
        *rlen = tlen;
    }

    return 1;
}

int _ldapfull_chk_hashed(moddata_t data, const char *scheme, int salted, const char *hash, const char *passwd) {
    const unsigned char *bhash; // binary hash, will get it from base64
    EVP_MD_CTX mdctx;
    const EVP_MD *md;
    unsigned char digest[EVP_MAX_MD_SIZE];
    int bhlen, rc;

    md = EVP_get_digestbyname(scheme);
    if (!md) {
        return 0;
    }
    if( ! _ldapfull_base64_decode(hash, &bhash, &bhlen) ) {
        return 0;
    }

    EVP_DigestInit(&mdctx, md);
    EVP_DigestUpdate(&mdctx, passwd, strlen(passwd));
    if (salted) {
        EVP_DigestUpdate(&mdctx, &bhash[EVP_MD_size(md)],
                bhlen - EVP_MD_size(md));
    }
    EVP_DigestFinal(&mdctx, digest, NULL);

    rc = memcmp((char *)bhash, (char *)digest, EVP_MD_size(md));
    free((void*)bhash);
    return !rc;
}

int _ldapfull_set_hashed(moddata_t data, const char *scheme, const char *prefix, int saltlen, const char *passwd, char *buf, int buflen) {
    char *hash = 0; // base64 hash
    EVP_MD_CTX mdctx;
    const EVP_MD *md;
    unsigned char *digest;
    unsigned char *salt;
    int hlen=0;
    int plen, rc;
    unsigned int dlen;

    md = EVP_get_digestbyname(scheme);
    if (!md) {
        return 0;
    }
    EVP_DigestInit(&mdctx, md);
    EVP_DigestUpdate(&mdctx, passwd, strlen(passwd));
    if (saltlen) {
        salt = (unsigned char *)malloc(saltlen);
        if( !salt ) {
            EVP_MD_CTX_cleanup(&mdctx);
            return 0;
        }
        if( !RAND_bytes(salt,saltlen) ) {
            EVP_MD_CTX_cleanup(&mdctx);
            free(salt);
        }
        EVP_DigestUpdate(&mdctx, salt, saltlen);
    }
    digest = (unsigned char *)malloc(EVP_MD_size(md) + saltlen);
    if( !digest ) {
        if (saltlen) {
            free(salt);
        }
        EVP_MD_CTX_cleanup(&mdctx);
        return 0;
    }
    EVP_DigestFinal(&mdctx, digest, &dlen);

    memcpy(digest+dlen,salt,saltlen);
    if (saltlen) {
        free(salt);
    }
    rc = _ldapfull_base64_encode(digest, dlen+saltlen, &hash, &hlen);
    if( hash[hlen-1] == '\n' ) {
        hash[--hlen] = '\0';
    }
    free(digest);
    if( !rc ) {
        free(hash);
        return 0;
    }

    plen = strlen(prefix);
    if( hlen + plen >= buflen ) {
        log_write(data->ar->c2s->log,LOG_ERR,"_ldapfull_set_hashed: buffer is too short (%i bytes)",buflen);
        free(hash);
        return 0;
    }
    memcpy(buf,prefix,plen);
    memcpy(buf+plen,hash,hlen);
    buf[hlen+plen]='\0';
    free(hash);

    return 1;
}
#endif // HAVE_SSL

#ifdef HAVE_CRYPT
/** Check UNIX style crypt hashed password */
int _ldapfull_chk_crypt(moddata_t data, const char *scheme, int salted, const char *hash, const char *passwd) {
    const char *encrypted;
    char salt[3];
    if (strlen(hash) != 13) {
        log_write(data->ar->c2s->log, LOG_ERR, "Invalid crypt hash length %d", strlen(hash));
        return 0;
    }
    salt[0] = hash[0];
    salt[1] = hash[1];
    salt[2] = 0;
    encrypted = crypt(passwd, salt);
    return !strcmp(encrypted, hash);
}

int _ldapfull_set_crypt(moddata_t data, const char *scheme, const char *prefix, int saltlen, const char *passwd, char *buf, int buflen) {
    const char *encrypted;
    char salt[3];
    static const char saltchars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    if ((saltlen != 2) || (buflen < 14)) {
        log_write(data->ar->c2s->log, LOG_ERR, "Invalid crypt hash params");
        return 0;
    }
#ifdef HAVE_SSL
    if( !RAND_bytes((unsigned char*)salt, saltlen) )
        return 0;
    salt[0] = saltchars[salt[0] % 64];
    salt[1] = saltchars[salt[1] % 64];
    salt[2] = 0;
#else
    /* Note: This is not a cryptographically secure random number generator */
    salt[0] = saltchars[random() % 64];
    salt[1] = saltchars[random() % 64];
    salt[2] = 0;
#endif
    encrypted = crypt(passwd, salt);
    strncpy(buf, encrypted, buflen);
    buf[buflen-1] = 0;
    return 1;
}
#endif // HAVE_CRYPT


/** Makes a copy of enough LDAP data in order to establish a second connection */
static void copy_ldap_config(moddata_t from, moddata_t to)
{
    memset(to, 0, sizeof(struct moddata_st));
    to->uri = from->uri;
    to->ar = from->ar;
}

int _ldapfull_hash_init() {
#ifdef HAVE_SSL
    OpenSSL_add_all_digests();
#else
    srandom(time(NULL) ^ getpid());
#endif
    return 1;
}
//////////////////////////////////////////////////////////////////////////////
//
// end of stuff for hashing passwords
//
//////////////////////////////////////////////////////////////////////////////


/** utility function to get ld_errno */
static int _ldapfull_get_lderrno(LDAP *ld)
{
    int ld_errno;

    ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);

    return ld_errno;
}

/** connect to the ldap host */
static int _ldapfull_connect(moddata_t data)
{
    int ldapversion = LDAP_VERSION3;
    int rc;

    if(data->ld != NULL)
        ldap_unbind_s(data->ld);

    data->binded=0;

    rc = ldap_initialize(&(data->ld), data->uri);
    if( rc != LDAP_SUCCESS )
    {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: ldap_initialize failed, uri=%s (%d): %s", data->uri, rc, ldap_err2string(rc));
        return 1;
    }

    if (ldap_set_option(data->ld, LDAP_OPT_PROTOCOL_VERSION, &ldapversion) != LDAP_SUCCESS)
    {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: couldn't set v3 protocol");
        return 1;
    }

    if (ldap_set_option(data->ld, LDAP_OPT_REFERRALS, LDAP_OPT_ON) != LDAP_SUCCESS) {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: couldn't set LDAP_OPT_REFERRALS");
    }

    log_debug(ZONE, "connected to ldap server");

    return 0;
}

/** unbind and clear variables */
static int _ldapfull_unbind(moddata_t data) {
    ldap_unbind_s(data->ld);
    data->ld = NULL;
    data->binded = 0;
    log_debug(ZONE, "unbinded from ldap server");
    return 0;
}

/** connect to ldap and bind as data->binddn */
static int _ldapfull_connect_bind(moddata_t data)
{
    if(data->ld != NULL && data->binded ) {
        return 0;
    }

    if( _ldapfull_connect(data) ) {
        return 1;
    }

    if(ldap_simple_bind_s(data->ld, data->binddn, data->bindpw))
    {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: bind as '%s' failed: %s", data->binddn, ldap_err2string(_ldapfull_get_lderrno(data->ld)));
        _ldapfull_unbind(data);
        return 1;
    }

    log_debug(ZONE, "binded to ldap server");
    data->binded = 1;
    return 0;
}

/** do a search, return the dn */
static char *_ldapfull_search(moddata_t data, const char *realm, const char *username)
{
    char validfilter[256], filter[1024], *dn, *no_attrs[] = { NULL };
    const char *basedn;
    LDAPMessage *result, *entry;
    int tried = 0;

    log_debug(ZONE, "searching for %s", username);

    basedn = xhash_get(data->basedn, realm);
    if(basedn == NULL)
        basedn = data->default_basedn;

    if(basedn == NULL) {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: no basedn specified for realm '%s'", realm);
        _ldapfull_unbind(data);
        return NULL;
    }

    // for AD validattr should be =TRUE, for [open]ldap =1
    if( data->validattr ) {
        validfilter[0] = '\0';
        if( data->srvtype == LDAPFULL_SRVTYPE_AD ) {
            snprintf(validfilter, 256, "(%s=TRUE)", data->validattr);
        } else {
            snprintf(validfilter, 256, "(%s=1)", data->validattr);
        }
        if( data->fulluid ) {
            snprintf(filter, 1024, "(&(objectClass=%s)%s(%s=%s@%s))", data->objectclass, validfilter, data->uidattr, username, realm);
        } else {
            snprintf(filter, 1024, "(&(objectClass=%s)%s(%s=%s))", data->objectclass, validfilter, data->uidattr, username);
        }
    } else {
        if( data->fulluid ) {
            snprintf(filter, 1024, "(&(objectClass=%s)(%s=%s@%s))", data->objectclass, data->uidattr, username, realm);
        } else {
            snprintf(filter, 1024, "(&(objectClass=%s)(%s=%s))", data->objectclass, data->uidattr, username);
        }
    }

    log_debug(ZONE, "search filter: %s", filter);

retry:
    if(ldap_search_s(data->ld, basedn, LDAP_SCOPE_SUBTREE, filter, no_attrs, 0, &result))
    {
        if( tried++ < LDAPFULL_SEARCH_MAX_RETRIES ) {
            log_debug(ZONE, "ldap: search fail, will retry; %s: %s", filter, ldap_err2string(_ldapfull_get_lderrno(data->ld)));
            _ldapfull_unbind(data);
            if( _ldapfull_connect_bind(data) == 0 ) {
                goto retry;
            } else {
                return NULL;
            }
        }
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: search %s failed: %s", filter, ldap_err2string(_ldapfull_get_lderrno(data->ld)));
        _ldapfull_unbind(data);
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

    log_debug(ZONE, "found user %s: dn=%s", username, dn);

    return dn;
}

/** Is this user part of the given LDAP group? */
static int _ldapfull_user_in_group(moddata_t data, const char *user_dn, const char *group_dn)
{
    LDAPMessage *result, *entry;
    int tried = 0;
    char filter[1024];

    log_debug(ZONE, "checking whether user with dn %s is in group %s", user_dn, group_dn);

    memset(filter, 0, 1024);
    snprintf(filter, 1024, "(member=%s)", user_dn); // TODO Check if snprintf result was truncated

    retry:
    if(ldap_search_s(data->ld, group_dn, LDAP_SCOPE_BASE, filter, NULL, 0, &result))
    {
        if( tried++ < LDAPFULL_SEARCH_MAX_RETRIES ) {
            log_debug(ZONE, "ldap: group search fail, will retry; %s: %s", filter, ldap_err2string(_ldapfull_get_lderrno(data->ld)));
            _ldapfull_unbind(data);
            if( _ldapfull_connect_bind(data) == 0 ) {
                goto retry;
            } else {
                return 0;
            }
        }
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: group search %s failed: %s", filter, ldap_err2string(_ldapfull_get_lderrno(data->ld)));
        _ldapfull_unbind(data);
        return 0;
    }

    entry = ldap_first_entry(data->ld, result);
    if(entry == NULL)
    {
        ldap_msgfree(result);

        return 0;
    }
    else
    {
        ldap_msgfree(result);

        return 1;
    }
}

/** Get distinguished name for this user if we have it */
static int _ldapfull_find_user_dn(moddata_t data, const char *username, const char *realm, const char **dn)
{
    *dn = NULL;
    if(_ldapfull_connect_bind(data))
        return 0; // error

    log_debug(ZONE, "checking existance of %s", username);

    *dn = _ldapfull_search(data, realm, username);
    return *dn != NULL;
}

/** do we have this user? */
static int _ldapfull_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    const char *dn;
    if (_ldapfull_find_user_dn((moddata_t) ar->private, username, realm, &dn)) {
        if(((moddata_t) ar->private)->group_dn != NULL
            && !_ldapfull_user_in_group((moddata_t) ar->private, dn, ((moddata_t) ar->private)->group_dn)) {
            ldap_memfree((void*)dn);
            return 0;
            }
        ldap_memfree((void*)dn);
        return 1;
    }
    return 0;
}

/** This method determines the DN of the user and does a new simple bind of the LDAP
server. If the server allows it, the user has been authenticated.
*/
static int _ldapfull_check_password_bind(authreg_t ar, const char *username, const char *realm, char password[LDAPFULL_PASSBUF_MAX])
{
    moddata_t data = (moddata_t) ar->private;
    struct moddata_st bind_data;
    int invalid;
    const char *dn;

    if (!_ldapfull_find_user_dn(data, username, realm, &dn)) {
        log_debug(ZONE, "User %s not found", username);
        return 1;
    }

    /* Try logging in to the LDAP server as this user's DN */
    copy_ldap_config(data, &bind_data);
    bind_data.binddn = dn;
    bind_data.bindpw = password;
    invalid = _ldapfull_connect_bind(&bind_data);
    if (!invalid)
        _ldapfull_unbind(&bind_data);
    ldap_memfree((void*)dn);
    return invalid;
}

// get password from jabberPassword attribute
static int _ldapfull_get_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[LDAPFULL_PASSBUF_MAX]) {
    moddata_t data = (moddata_t) ar->private;
    LDAPMessage *result, *entry;
    const char *dn, *no_attrs[] = { data->pwattr, NULL };
    char **vals;

    log_debug(ZONE, "getting password for %s", username);

    if( _ldapfull_connect_bind(data) ) {
        return 1;
    }

    dn = _ldapfull_search(data, realm, username);
    if(dn == NULL)
        return 1;

    if(ldap_search_s(data->ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)", (char**)no_attrs, 0, &result))
    {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: search %s failed: %s", dn, ldap_err2string(_ldapfull_get_lderrno(data->ld)));
        ldap_memfree((void*)dn);
        _ldapfull_unbind(data);
        return 1;
    }

    ldap_memfree((void*)dn);

    entry = ldap_first_entry(data->ld, result);
    if(entry == NULL)
    {
        ldap_msgfree(result);
        return 1;
    }

    vals=ldap_get_values(data->ld,entry,data->pwattr);
    if( ldap_count_values(vals) <= 0 ) {
        ldap_value_free(vals);
        ldap_msgfree(result);
        return 1;
    }
    strncpy(password,vals[0],LDAPFULL_PASSBUF_MAX-1);
    password[LDAPFULL_PASSBUF_MAX-1] = '\0';
    ldap_value_free(vals);

    ldap_msgfree(result);

    log_debug(ZONE, "found password for %s", username);

    return 0;
}

// set password from jabberPassword attribute
static int _ldapfull_set_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[LDAPFULL_PASSBUF_MAX]) {
    moddata_t data = (moddata_t) ar->private;
    LDAPMessage *result, *entry;
    LDAPMod *mods[2], attr_pw;
    char buf[LDAPFULL_PASSBUF_MAX];
    char *pdn, *attrs[] = { NULL }, *pw_mod_vals[] = { buf, NULL };
    char dn[LDAPFULL_DN_MAX];

    log_debug(ZONE, "setting password for %s", username);

    if( ! _ldapfull_set_passhash(data,data->pwscheme,password,buf,LDAPFULL_PASSBUF_MAX) ) {
        log_debug(ZONE, "password scheme is not defined");
        return 1;
    }

    if( _ldapfull_connect_bind(data) ) {
        return 1;
    }

    pdn = _ldapfull_search(data, realm, username);
    if(pdn == NULL)
        return 1;

    strncpy(dn, pdn, LDAPFULL_DN_MAX-1); dn[LDAPFULL_DN_MAX-1] = '\0';
    ldap_memfree(pdn);

    if(ldap_search_s(data->ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &result))
    {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: search %s failed: %s", dn, ldap_err2string(_ldapfull_get_lderrno(data->ld)));
        _ldapfull_unbind(data);
        return 1;
    }

    entry = ldap_first_entry(data->ld, result);
    if(entry == NULL)
    {
        ldap_msgfree(result);
        return 1;
    }
    ldap_msgfree(result);

    attr_pw.mod_op = LDAP_MOD_REPLACE;
    attr_pw.mod_type = (char*)data->pwattr;
    attr_pw.mod_values = pw_mod_vals;

    mods[0] = &attr_pw;
    mods[1] = NULL;

    if( ldap_modify_s(data->ld, dn, mods) != LDAP_SUCCESS ) {
        log_write(data->ar->c2s->log, LOG_ERR, "ldap: error modifying %s: %s", dn, ldap_err2string(_ldapfull_get_lderrno(data->ld)));
        _ldapfull_unbind(data);
        return 1;
    }

    log_debug(ZONE, "password was set for %s", username);

    return 0;
}

/** check the password */
static int _ldapfull_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[LDAPFULL_PASSBUF_MAX])
{
    moddata_t data = (moddata_t) ar->private;
    char buf[LDAPFULL_PASSBUF_MAX];
    const char *dn = NULL;

    log_debug(ZONE, "checking password for %s", username);

    if(password[0] == '\0')
        return 1;

    if(data->group_dn != NULL) {
        if (!_ldapfull_find_user_dn(data, username, realm, &dn))
            return 1;
    }
    /* The bind scheme doesn't need the password read first, so short circuit
       the whole passhash scheme */
    if (!strcmp(data->pwscheme, "bind")) {
        if(_ldapfull_check_password_bind(ar, username, realm, password) == 0) {
            if(data->group_dn != NULL && !_ldapfull_user_in_group(data, dn, data->group_dn)) {
                ldap_memfree((void*)dn);
                return 1;
            }
            else {
                ldap_memfree((void*)dn);
                return 0;
            }
        }
    }

    if( _ldapfull_get_password(ar,sess,username,realm,buf) != 0  ) {
        if(dn != NULL)
            ldap_memfree((void*)dn);
        return 1;
    }

    if(_ldapfull_check_passhash(data,buf,password)){
        if(data->group_dn != NULL && !_ldapfull_user_in_group(data, dn, data->group_dn)) {
            ldap_memfree((void*)dn);
            return 1;
        }
        else {
            if(dn != NULL)
                ldap_memfree((void*)dn);
            return 0;
        }
    }
    else {
        if(dn != NULL)
            ldap_memfree((void*)dn);
        return 1;
    }
}

static int _ldapfull_create_user(authreg_t ar, sess_t sess, const char *username, const char *realm) {
    if( _ldapfull_user_exists(ar,sess,username,realm) ) {
        return 0;
    } else {
        return 1;
    }
}

static int _ldapfull_delete_user(authreg_t ar, sess_t sess, const char *username, const char *realm) {
    return 0;
}

/** shut me down */
static void _ldapfull_free(authreg_t ar)
{
    moddata_t data = (moddata_t) ar->private;

    _ldapfull_unbind(data);

    xhash_free(data->basedn);
    free(data);

    return;
}

/** start me up */
DLLEXPORT int ar_init(authreg_t ar)
{
    moddata_t data;
    const char *uri, *realm, *srvtype_s;
    config_elem_t basedn;
    int i,hascheck,srvtype_i;

    uri = config_get_one(ar->c2s->config, "authreg.ldapfull.uri", 0);
    if(uri == NULL)
    {
        log_write(ar->c2s->log, LOG_ERR, "ldap: no uri specified in config file");
        return 1;
    }

    basedn = config_get(ar->c2s->config, "authreg.ldapfull.basedn");
    if(basedn == NULL)
    {
        log_write(ar->c2s->log, LOG_ERR, "ldap: no basedn specified in config file");
        return 1;
    }

    srvtype_s = config_get_one(ar->c2s->config, "authreg.ldapfull.type", 0);
    if( srvtype_s == NULL ) {
        srvtype_i = LDAPFULL_SRVTYPE_LDAP;
    } else if( !strcmp(srvtype_s, "ldap") ) {
        srvtype_i = LDAPFULL_SRVTYPE_LDAP;
    } else if( !strcmp(srvtype_s, "ad") ) {
        srvtype_i = LDAPFULL_SRVTYPE_AD;
    } else {
        log_write(ar->c2s->log, LOG_ERR, "ldap: unknown server type: %s", srvtype_s);
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

    data->uri = uri;

    data->srvtype = srvtype_i;

    data->binddn = config_get_one(ar->c2s->config, "authreg.ldapfull.binddn", 0);
    if(data->binddn != NULL)
        data->bindpw = config_get_one(ar->c2s->config, "authreg.ldapfull.bindpw", 0);

    data->uidattr = config_get_one(ar->c2s->config, "authreg.ldapfull.uidattr", 0);
    if(data->uidattr == NULL)
        data->uidattr = "uid";

    data->validattr = config_get_one(ar->c2s->config, "authreg.ldapfull.validattr", 0);

    data->group_dn = config_get_one(ar->c2s->config, "authreg.ldapfull.group_dn", 0);

    data->pwattr = config_get_one(ar->c2s->config, "authreg.ldapfull.pwattr", 0);
    if(data->pwattr == NULL)
        data->pwattr = "jabberPassword";

    data->pwscheme = config_get_one(ar->c2s->config, "authreg.ldapfull.pwscheme", 0);
    if(data->pwscheme == NULL) {
        data->pwscheme = "clear";
        hascheck=0;
    } else {
        hascheck=1;
    }

    data->objectclass = config_get_one(ar->c2s->config, "authreg.ldapfull.objectclass", 0);
    if(data->objectclass == NULL)
        data->objectclass = "jabberUser";

    if( (char *)config_get_one(ar->c2s->config, "authreg.ldapfull.fulluid", 0) != NULL ) {
      data->fulluid = 1;
    }

    data->ar = ar;

    if(_ldapfull_connect_bind(data))
    {
        xhash_free(data->basedn);
        free(data);
        return 1;
    }

    _ldapfull_hash_init();

    ar->private = data;

    ar->user_exists = _ldapfull_user_exists;
    ar->create_user = _ldapfull_create_user;
    ar->delete_user = _ldapfull_delete_user;
    ar->set_password = _ldapfull_set_password;
    if( hascheck ) {
        ar->check_password = _ldapfull_check_password;
    } else {
        ar->get_password = _ldapfull_get_password;
    }

    ar->free = _ldapfull_free;

    return 0;
}

#endif // STORAGE_LDAP
