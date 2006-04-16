/*
 * scod - a minimal sasl implementation for jabberd2
 * Copyright (c) 2003 Robert Norris
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

/* DIGEST-MD5 mechanism */

#include "scod.h"

#include <ctype.h>

#define HT  (9)
#define CR  (13)
#define LF  (10)
#define SP  (32)
#define DEL (127)

/* unions to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  xht *xht_val;
};

union scod_u
{
  void **val;
  char **char_val;
};

static char *_opt_quote(char *in) {
    int nesc;
    char *r, *out, *w;

    r = in;
    nesc = 0;
    while(*r != '\0') {
        if(*r == '"' || *r == '\\')
            nesc++;
        r++;
    }

    out = (char *) malloc(sizeof(char) * (strlen(in) + nesc + 3));

    r = in;
    w = out;

    *w = '"';
    w++;
    while(*r != '\0') {
        if(*r == '"' || *r == '\\') {
            *w = '\\';
            w++;
        }
        *w = *r;
        w++;
        r++;
    }

    *w = '"';
    w++;
    *w = '\0';

    log_debug(ZONE, "escaped '%s' into '%s'", in, out);

    return out;
}

/** the list parser is based on code from cyrus-sasl. I love open source ;) */
static char *_opt_skip_lws(char *c) {
    if(c == NULL)
        return NULL;

    while(*c == ' ' || *c == HT || *c == CR || *c == LF) {
        if(*c == '\0')
            break;
        c++;
    }  
    
    return c;
}

static char *_opt_skip_token(char *c, int ci) {
    if(c == NULL)
        return NULL;
    
    while(*c > SP) {
        if(*c == DEL || *c == '(' || *c == ')' || *c == '<' || *c == '>' ||
           *c == '@' || *c == ',' || *c == ';' || *c == ':' || *c == '\\' ||
           *c == '\'' || *c == '/' || *c == '[' || *c == ']' || *c == '?' ||
           *c == '=' || *c == '{' || *c == '}') {
            if(ci) {
                if(!isupper((unsigned char) *c))
                break;
            } else
                break;
        }
        c++;
    }  

    return c;
}

static char *_opt_unquote(char *in) {
    char *out, *end;
    int esc = 0;

    /* if its not quoted, there's nothing to do */
    if(*in != '"')
        return _opt_skip_token(in, 0);
    
    in++;
    out = in;
    
    for(end = in; *end != '\0'; end++, out++) {
        if(esc) {
            *out = *end;
            esc = 0;
        }
        else if(*end == '\\') {
            esc = 1;
            out--;
        }
        else if(*end == '"')
            break;
        else
            *out = *end;      
    }
    
    if(*end != '"')
        return NULL;
    
    while(out <= end) {
        *out = '\0';
        out++;
    }

    end++;
    
    return end;  
} 

static void _opt_get_pair(char **in, char **key, char **val) {
    char *end, *cur = *in;

    *key = NULL;
    *val = NULL;
    
    if(*cur == '\0')
        return;
    
    cur = _opt_skip_lws(cur);
    
    *key = cur;
    
    cur = _opt_skip_token(cur, 1);
    
    if(*cur != '=' && *cur != '\0') {
        *cur = '\0';
        cur++;
    }
    
    cur = _opt_skip_lws(cur);
    
    if(*cur != '=') {
        *key = NULL;
        return;
    }
    
    *cur = '\0';
    cur++;
    
    cur = _opt_skip_lws(cur);  
    
    *val = (*cur == '"') ? cur + 1 : cur;
    
    end = _opt_unquote(cur);
    if(end == NULL) {
        *key = NULL;
        return;
    }
    
    if(*end != ',' && *end != '\0') {
        *end = '\0';
        end++;
    }
    
    end = _opt_skip_lws(end);
    
    if(*end == ',') {
        *end = '\0';
        end++;
    }
    else if(*end != '\0') { 
        *key = NULL;
        return;
    }
    
    *in = end;
}

static xht _digest_md5_parse_options(const char *buf, int buflen) {
    xht hash, sub;
    char *nbuf, *in, *key, *val;

    nbuf = (char *) malloc(sizeof(char) * (buflen + 1));
    strncpy(nbuf, buf, buflen);
    nbuf[buflen] = '\0';

    hash = xhash_new(101);

    in = nbuf;
    while(1) {
        _opt_get_pair(&in, &key, &val);
        if(key == NULL)
            break;

        sub = xhash_get(hash, key);
        if(sub == NULL) {
            sub = xhash_new(11);
            xhash_put(hash, pstrdup(xhash_pool(hash), key), sub);
            pool_cleanup(xhash_pool(hash), (void (*)(void *)) xhash_free, sub);
        }

        xhash_put(sub, pstrdup(xhash_pool(hash), val), (void *) 1);

        log_debug(ZONE, "got key '%s' val '%s'", key, val);
    }

    free(nbuf);

    return hash;
}

static char *_digest_md5_gen_nonce(void) {
    int i, r;
    char nonce[65], hnonce[41];

    for(i = 0; i < 64; i++) {
        r = (int) (36.0 * rand() / RAND_MAX);
        nonce[i] = (r >= 0 && r <= 9) ? (r + 48) : (r + 87);
    }
    nonce[64] = '\0';

    shahash_r(nonce, hnonce);

    log_debug(ZONE, "generated nonce: %s", hnonce);

    return strdup(hnonce);
}

typedef struct _digest_md5_st {
    pool        p;

    char        *nonce;
    char        *cnonce;
    char        *nc;

    int         step;
} *digest_md5_t;

static int _digest_md5_client_start(scod_mech_t mech, scod_t sd, char **resp, int *resplen) {
    log_debug(ZONE, "DIGEST-MD5 client start");

    return sd_CONTINUE;
}

static int _digest_md5_client_step(scod_mech_t mech, scod_t sd, const char *chal, int challen, char **resp, int *resplen) {
    xht attrs, sub;
    char *key, *realm, *nonce, *qop, *charset, *algorithm, *cnonce, *c;
    md5_state_t md5;
    md5_byte_t hash[16];
    char ha1[33], ha2[33], hrsp[33];
    pool p;
    spool s;
    union xhashv xhv;
    union scod_u su;

    log_debug(ZONE, "DIGEST-MD5 client step; challenge: %.*s", challen, chal);

    if(sd->mech_data != NULL) {
        /* !!! check rspauth */
        sd->mech_data = NULL;
        return sd_SUCCESS;
    }

    realm = nonce = qop = charset = algorithm = NULL;

    attrs = _digest_md5_parse_options(chal, challen);
    if(xhash_iter_first(attrs))
        do {
            xhv.xht_val = &sub;
            xhash_iter_get(attrs, (const char **) &key, xhv.val);
            log_debug(ZONE, "extracting '%s'", key);

            if(xhash_iter_first(sub)) {
                if(strcmp(key, "realm") == 0) {
                    su.char_val = &realm;
                    (mech->ctx->cb)(sd, sd_cb_DIGEST_MD5_CHOOSE_REALM, (void *) sub, su.val, mech->ctx->cbarg);
                }
                else if(strcmp(key, "nonce") == 0)
                    xhash_iter_get(sub, (const char **) &nonce, NULL);
                else if(strcmp(key, "qop") == 0)
                    xhash_iter_get(sub, (const char **) &qop, NULL);
                else if(strcmp(key, "charset") == 0)
                    xhash_iter_get(sub, (const char **) &charset, NULL);
                else if(strcmp(key, "algorithm") == 0)
                    xhash_iter_get(sub, (const char **) &algorithm, NULL);
            }
        } while(xhash_iter_next(attrs));

    if(nonce == NULL || qop == NULL || charset == NULL || algorithm == NULL) {
        log_debug(ZONE, "missing attribute");
        xhash_free(attrs);
        return sd_auth_MALFORMED_DATA;
    }

    cnonce = _digest_md5_gen_nonce();

    md5_init(&md5);
    md5_append(&md5, sd->authnid, strlen(sd->authnid));
    md5_append(&md5, ":", 1);
    if(realm != NULL) md5_append(&md5, realm, strlen(realm));
    md5_append(&md5, ":", 1);
    md5_append(&md5, sd->pass, strlen(sd->pass));
    md5_finish(&md5, hash);

    md5_init(&md5);
    md5_append(&md5, hash, 16);
    md5_append(&md5, ":", 1);
    md5_append(&md5, nonce, strlen(nonce));
    md5_append(&md5, ":", 1);
    md5_append(&md5, cnonce, 40);
    if(sd->authzid != NULL) {
        md5_append(&md5, ":", 1);
        md5_append(&md5, sd->authzid, strlen(sd->authzid));
    }
    md5_finish(&md5, hash);                         /* A1 */

    hex_from_raw(hash, 16, ha1);

    log_debug(ZONE, "HEX(H(A1)) = %s", ha1);

    md5_init(&md5);
    md5_append(&md5, "AUTHENTICATE:", 13);
    md5_append(&md5, "xmpp/", 5);                   /* !!! make this configurable */
    md5_finish(&md5, hash);                         /* A2 */

    hex_from_raw(hash, 16, ha2);

    log_debug(ZONE, "HEX(H(A2)) = %s", ha2);

    md5_init(&md5);
    md5_append(&md5, ha1, 32);
    md5_append(&md5, ":", 1);
    md5_append(&md5, nonce, strlen(nonce));
    md5_append(&md5, ":", 1);
    md5_append(&md5, "00000001", 8);
    md5_append(&md5, ":", 1);
    md5_append(&md5, cnonce, 40);
    md5_append(&md5, ":auth:", 6);
    md5_append(&md5, ha2, 32);
    md5_finish(&md5, hash);                         /* KD(HA1, foo, HA2) */

    hex_from_raw(hash, 16, hrsp);

    log_debug(ZONE, "response is %s", hrsp);

    /* !!! generate rspauth and save it for later so we can validate */

    p = pool_new();
    s = spool_new(p);

    c = _opt_quote(sd->authnid);
    spooler(s, "username=", c, ",", s);
    free(c);

    c = _opt_quote(nonce);
    spooler(s, "nonce=", c, ",", s);
    free(c);

    c = _opt_quote(cnonce);
    spooler(s, "cnonce=", c, ",", s);
    free(c);

    if(sd->authzid != NULL) {
        c = _opt_quote(sd->authzid);
        spooler(s, "authzid=", c, ",", s);
        free(c);
    }

    if(realm != NULL) {
        c = _opt_quote(realm);
        spooler(s, "realm=", c, ",", s);
        free(c);
    }

    spooler(s, "nc=00000001,qop=auth,digest-uri=\"xmpp/\",charset=utf-8,response=", hrsp, s);

    *resp = strdup(spool_print(s));
    *resplen = strlen(*resp);

    pool_free(p);
    xhash_free(attrs);

    free(cnonce);

    log_debug(ZONE, "generated initial response: %.*s", *resplen, *resp);

    sd->mech_data = (void *) 1;
    
    return sd_CONTINUE;
}

static int _digest_md5_server_start(scod_mech_t mech, scod_t sd, const char *resp, int resplen, char **chal, int *challen) {
    digest_md5_t md;
    pool p;
    spool s;
    char *c, *nonce;

    log_debug(ZONE, "DIGEST-MD5 server start");

    p = pool_new();
    md = (digest_md5_t) pmalloco(p, sizeof(struct _digest_md5_st));
    md->p = p;
    sd->mech_data = md;

    p = pool_new();
    s = spool_new(p);

    if(sd->realm != NULL) {
        c = _opt_quote(sd->realm);
        spooler(s, "realm=", c, ",", s);
        free(c);
    }

    nonce = _digest_md5_gen_nonce();
    md->nonce = pstrdup(md->p, nonce);
    free(nonce);

    c = _opt_quote(md->nonce);
    spooler(s, "nonce=", c, ",qop=\"auth\",charset=utf-8,algorithm=md5-sess", s);
    free(c);

    *chal = strdup(spool_print(s));
    *challen = strlen(*chal);

    pool_free(p);

    log_debug(ZONE, "generated initial challenge: %.*s", *challen, *chal);

    return sd_CONTINUE;
}

static int _digest_md5_server_step(scod_mech_t mech, scod_t sd, const char *resp, int resplen, char **chal, int *challen) {
    digest_md5_t md = (digest_md5_t) sd->mech_data;
    xht attrs, sub;
    char *key, *username, *realm, *nonce, *cnonce, *nc, *qop, *digest_uri, *response, *charset, *pass, buf[257], *c, authzid[3072];
    int err;
    md5_state_t md5;
    md5_byte_t hash[16];
    char ha1[33], ha2[33], hrsp[33];
    struct _scod_cb_creds_st creds;
    union xhashv xhv;
    union scod_u su;

    log_debug(ZONE, "DIGEST-MD5 server step; response: %.*s", resplen, resp);

    if(md->step == 1) {
        /* we're done */
        pool_free(md->p);
        sd->mech_data = NULL;
        return sd_SUCCESS;
    }

    username = realm = nonce = cnonce = nc = qop = digest_uri = response = charset = NULL;
    authzid[0] = '\0';

    attrs = _digest_md5_parse_options(resp, resplen);
    if(xhash_iter_first(attrs))
        do {
            xhv.xht_val = &sub;
            xhash_iter_get(attrs, (const char **) &key, xhv.val);
            log_debug(ZONE, "extracting '%s'", key);

            if(xhash_iter_first(sub)) {
                if(strcmp(key, "username") == 0)
                    xhash_iter_get(sub, (const char **) &username, NULL);
                else if(strcmp(key, "realm") == 0)
                    xhash_iter_get(sub, (const char **) &realm, NULL);
                else if(strcmp(key, "nonce") == 0)
                    xhash_iter_get(sub, (const char **) &nonce, NULL);
                else if(strcmp(key, "cnonce") == 0)
                    xhash_iter_get(sub, (const char **) &cnonce, NULL);
                else if(strcmp(key, "nc") == 0)
                    xhash_iter_get(sub, (const char **) &nc, NULL);
                else if(strcmp(key, "qop") == 0)
                    xhash_iter_get(sub, (const char **) &qop, NULL);
                else if(strcmp(key, "digest-uri") == 0)
                    xhash_iter_get(sub, (const char **) &digest_uri, NULL);
                else if(strcmp(key, "response") == 0)
                    xhash_iter_get(sub, (const char **) &response, NULL);
                else if(strcmp(key, "charset") == 0)
                    xhash_iter_get(sub, (const char **) &charset, NULL);
                else if(strcmp(key, "authzid") == 0) {
                    xhash_iter_get(sub, (const char **) &c, NULL);
                    strncpy(authzid, c, sizeof(authzid));
                }
            }
        } while(xhash_iter_next(attrs));

    err = sd_SUCCESS;
    if(username == NULL || nonce == NULL || cnonce == NULL || nc == NULL || qop == NULL || digest_uri == NULL || response == NULL)
        err = sd_auth_MALFORMED_DATA;
    else if(strcmp(nonce, md->nonce) != 0)
        err = sd_auth_MISMATCH;
    else if(strcmp(qop, "auth") != 0)
        err = sd_auth_NOT_OFFERED;

    if(err != sd_SUCCESS) {
        log_debug(ZONE, "returning error %d", err);

        xhash_free(attrs);
        pool_free(md->p);
        sd->mech_data = NULL;

        return err;
    }

    /* !!! verify realm? */

    creds.authnid = username;
    creds.realm = realm;
    creds.pass = NULL;
    pass = buf;
    su.char_val = &pass;
    if((mech->ctx->cb)(sd, sd_cb_GET_PASS, &creds, su.val, mech->ctx->cbarg) != 0) {
        log_debug(ZONE, "user not found (or some other error getting password), failing");

        xhash_free(attrs);
        pool_free(md->p);
        sd->mech_data = NULL;

        return sd_auth_USER_UNKNOWN;
    }

    md->cnonce = pstrdup(md->p, cnonce);
    md->nc = pstrdup(md->p, nc);

    md5_init(&md5);
    md5_append(&md5, username, strlen(username));
    md5_append(&md5, ":", 1);
    if(realm != NULL) md5_append(&md5, realm, strlen(realm));
    md5_append(&md5, ":", 1);
    if(pass != NULL) md5_append(&md5, pass, strlen(pass));
    md5_finish(&md5, hash);

    md5_init(&md5);
    md5_append(&md5, hash, 16);
    md5_append(&md5, ":", 1);
    md5_append(&md5, md->nonce, strlen(md->nonce));
    md5_append(&md5, ":", 1);
    md5_append(&md5, md->cnonce, strlen(md->cnonce));
    if(authzid[0] != '\0') {
        md5_append(&md5, ":", 1);
        md5_append(&md5, authzid, strlen(authzid));
    }
    md5_finish(&md5, hash);                         /* A1 */

    hex_from_raw(hash, 16, ha1);

    log_debug(ZONE, "HEX(H(A1)) = %s", ha1);

    md5_init(&md5);
    md5_append(&md5, "AUTHENTICATE:", 13);
    md5_append(&md5, digest_uri, strlen(digest_uri));
    md5_finish(&md5, hash);                         /* A2 */

    hex_from_raw(hash, 16, ha2);

    log_debug(ZONE, "HEX(H(A2)) = %s", ha2);

    md5_init(&md5);
    md5_append(&md5, ha1, 32);
    md5_append(&md5, ":", 1);
    md5_append(&md5, nonce, strlen(nonce));
    md5_append(&md5, ":", 1);
    md5_append(&md5, nc, strlen(nc));
    md5_append(&md5, ":", 1);
    md5_append(&md5, cnonce, strlen(cnonce));
    md5_append(&md5, ":auth:", 6);
    md5_append(&md5, ha2, 32);
    md5_finish(&md5, hash);                         /* KD(HA1, foo, HA2) */

    hex_from_raw(hash, 16, hrsp);

    log_debug(ZONE, "our response is %s, theirs is %s", hrsp, response);

    if(strcmp(hrsp, response) != 0) {
        log_debug(ZONE, "not matched, denied");

        xhash_free(attrs);
        pool_free(md->p);
        sd->mech_data = NULL;

        return sd_auth_AUTH_FAILED;
    }

    log_debug(ZONE, "matched, they're authenticated");

    creds.authnid = username;
    creds.realm = realm;
    creds.pass = NULL;

    creds.authzid = authzid;

    if((mech->ctx->cb)(sd, sd_cb_CHECK_AUTHZID, &creds, NULL, mech->ctx->cbarg) != 0) {
        log_debug(ZONE, "authzid is invalid (app policy said so)");

        xhash_free(attrs);
        pool_free(md->p);
        sd->mech_data = NULL;

        return sd_auth_AUTHZID_POLICY;
    }

    sd->authzid = strdup(creds.authzid);

    md5_init(&md5);
    md5_append(&md5, ":", 1);
    md5_append(&md5, digest_uri, strlen(digest_uri));
    md5_finish(&md5, hash);                         /* rspauth A2 */

    hex_from_raw(hash, 16, ha2);

    log_debug(ZONE, "HEX(H(rspauth A2)) = %s", ha2);

    md5_init(&md5);
    md5_append(&md5, ha1, 32);
    md5_append(&md5, ":", 1);
    md5_append(&md5, nonce, strlen(nonce));
    md5_append(&md5, ":", 1);
    md5_append(&md5, nc, strlen(nc));
    md5_append(&md5, ":", 1);
    md5_append(&md5, cnonce, strlen(cnonce));
    md5_append(&md5, ":auth:", 6);
    md5_append(&md5, ha2, 32);
    md5_finish(&md5, hash);                         /* KD(HA1, foo, HA2) */

    hex_from_raw(hash, 16, hrsp);

    log_debug(ZONE, "rspauth: %s", hrsp);

    *chal = (char *) malloc(sizeof(char) * 41);
    snprintf(*chal, 41, "rspauth=%s", hrsp);
    *challen = 40;

    log_debug(ZONE, "generated final challenge: %.*s", *challen, *chal);

    md->step = 1;
    
    xhash_free(attrs);

    return sd_CONTINUE;
}

static void _digest_md5_free(scod_mech_t mech) {
    xhash_free((xht) mech->private);
}

int scod_mech_digest_md5_init(scod_mech_t mech) {
    log_debug(ZONE, "initialising DIGEST-MD5 mechanism");

    mech->name = "DIGEST-MD5";

    mech->flags = sd_flag_GET_PASS;

    mech->client_start = _digest_md5_client_start;
    mech->client_step = _digest_md5_client_step;
    mech->server_start = _digest_md5_server_start;
    mech->server_step = _digest_md5_server_step;
    mech->free = _digest_md5_free;

    return 0;
}
