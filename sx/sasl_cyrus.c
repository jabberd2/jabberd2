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

/* SASL authentication handler */

#error Cyrus SASL implementation is not supported! It is included here only for the brave ones, that do know what they are doing. You need to remove this line to compile it.

#include "sx.h"
#include "sasl.h"

/* Gack - need this otherwise SASL's MD5 definitions conflict with OpenSSLs */
#ifdef HEADER_MD5_H
#  define MD5_H
#endif
#ifdef _WIN32
# include <sasl.h>
# include <saslutil.h>
# include <saslplug.h>
#else /* _WIN32 */
# include <sasl/sasl.h>
# include <sasl/saslutil.h>
# include <sasl/saslplug.h>
#endif /* _WIN32 */

/** our context */
typedef struct _sx_sasl_st {
    char                        *appname;
    sasl_security_properties_t  sec_props;

    sx_sasl_callback_t          cb;
    void                        *cbarg;

    sasl_callback_t		*saslcallbacks;
} *_sx_sasl_t;

/* data for per-conncetion sasl handshakes */
typedef struct _sx_sasl_data_st {
    char                        *user;
    sasl_secret_t               *psecret;

    sasl_callback_t             *callbacks;

    _sx_sasl_t	                ctx;
    sasl_conn_t                 *sasl;
    sx_t                        stream;
} *_sx_sasl_data_t;


/* Forward definitions */
static void _sx_sasl_free(sx_t, sx_plugin_t);

static int _sx_sasl_getopt(void * glob_context,
			   const char *plugin_name,
			   const char *option,
			   const char **result,
			   unsigned *len)
{
    if (strcmp(option,"auxprop_plugin") == 0) {
        *result = "jabberdsx";
        if (len)
            *len = strlen("jabberdsx");
        return SASL_OK;
    }
    return SASL_FAIL;
}

#ifdef _WIN32
/* This handles returning library path on Windows to current directory.
 */
#include <windows.h>
static int _sx_sasl_getpath(void *glob_context, const char **path_dest) {
    static char win32_path[MAX_PATH] = "\0";

    if(!path_dest) {
        return SASL_BADPARAM;
    }

    if(!*win32_path) {
        char *r;
        GetModuleFileName(NULL, win32_path, MAX_PATH - 5);
        if(!*win32_path || !(r = strrchr(win32_path, '\\')))
            return SASL_NOMEM;
        strcpy(r + 1, "sasl");
    }

    *path_dest = win32_path;
    return SASL_OK;
}
#endif /* _WIN32 */

/* Support auxprop so that we can use the standard Jabber authreg plugins
 * with SASL mechanisms requiring passwords 
 */
static void _sx_auxprop_lookup(void *glob_context,
			      sasl_server_params_t *sparams,
			      unsigned flags,
			      const char *user,
			      unsigned ulen) {
    const char *realm  = NULL;
    char *c;
    const struct propval *to_fetch, *current;
    char *user_buf = NULL;
    char *value;
    _sx_sasl_t ctx = (_sx_sasl_t) glob_context;
    struct sx_sasl_creds_st creds = {NULL, NULL, NULL, NULL};

    if (!sparams || !user) 
        return;

    /* It would appear that there's no guarantee that 'user' is NULL 
     * terminated, so we'd better terminate it ... 
     */

    user_buf = sparams->utils->malloc(ulen + 1);
    if (!user_buf)
        goto done;

    memcpy(user_buf, user, ulen);
    user_buf[ulen] = '\0';

    c = strchr(user_buf, '@');
    if (!c) {
        if (sparams->user_realm && sparams->user_realm[0])
            realm = sparams->user_realm;
        else
            realm = sparams->serverFQDN;
    } else {
        *c = '\0';
        realm = c+1;
    }

    /* At present, we only handle fetching the user's password */
    to_fetch = sparams->utils->prop_get(sparams->propctx);
    if (!to_fetch)
        goto done;
    for (current = to_fetch; current->name; current++) {
        if (strncmp(current->name, SASL_AUX_PASSWORD, sizeof(SASL_AUX_PASSWORD)) == 0) {
            /* If we've already got a value, see if we can override it */
            if (current->values) {
                if (flags & SASL_AUXPROP_OVERRIDE) 
                    sparams->utils->prop_erase(sparams->propctx, current->name);
		else
		    continue;
            }

            creds.authnid = user_buf;
            creds.realm = realm;
            if ((ctx->cb)(sx_sasl_cb_GET_PASS, &creds, (void **)&value, 
                          NULL, ctx->cbarg) == sx_sasl_ret_OK) {
                sparams->utils->prop_set(sparams->propctx, current->name,
                                         value, strlen(value));
            }
        }
    }
 done:
    if (user_buf) sparams->utils->free(user_buf);
}

static sasl_auxprop_plug_t _sx_auxprop_plugin = 
    {0, 0, NULL, NULL, _sx_auxprop_lookup, "jabberdsx", NULL};

static int 
sx_auxprop_init(const sasl_utils_t *utils, int max_version, int *out_version,
                sasl_auxprop_plug_t **plug, const char *plugname) {

    if (!out_version || !plug) 
        return SASL_BADPARAM;
    if (max_version < SASL_AUXPROP_PLUG_VERSION ) 
        return SASL_BADVERS;

    *out_version = SASL_AUXPROP_PLUG_VERSION;
    *plug = &_sx_auxprop_plugin;

    return SASL_OK;
}

/* This handles those authreg plugins which won't provide plaintext access
 * to the user's password. Note that there are very few mechanisms which
 * call the verify function, rather than asking for the password
 */
static int _sx_sasl_checkpass(sasl_conn_t *conn, void *ctx, const char *user, const char *pass, unsigned passlen, struct propctx *propctx) {
    _sx_sasl_data_t sd = (_sx_sasl_data_t)ctx;
    struct sx_sasl_creds_st creds = {NULL, NULL, NULL, NULL};
    char *c;
    char *buf;

    /* SASL doesn't seem to pass us the username and realm as seperate items,
     * instead it combines them into the 'user' variable. In order to preserve
     * the existing behaviour, we need to split them up again ...
     */

    buf = strdup(user);
    c = strchr(buf,'@');
    if (c) {
        *c = '\0';
        creds.realm = c+1;
    }
    creds.authnid = buf;
    creds.pass = pass;

    if (sd->ctx->cb(sx_sasl_cb_CHECK_PASS, &creds, NULL, sd->stream, sd->ctx->cbarg)==sx_sasl_ret_OK) {
        free(buf);
        return SASL_OK;
    } else {
        free(buf);
        return SASL_BADAUTH;
    }
}

/* Canonicalize the username. Normally this does nothing, but if we're
 * calling from an anonymous plugin, then we need to generate a JID for
 * the user
 */

static int _sx_sasl_canon_user(sasl_conn_t *conn, void *ctx, const char *user, unsigned ulen, unsigned flags, const char *user_realm, char *out_user, unsigned out_umax, unsigned *out_ulen) {
    char *buf;
    _sx_sasl_data_t sd = (_sx_sasl_data_t)ctx;
    sasl_getprop(conn, SASL_MECHNAME, (const void **) &buf);
    if (strncmp(buf, "ANONYMOUS", 10) == 0) {
        sd->ctx->cb(sx_sasl_cb_GEN_AUTHZID, NULL, (void **)&buf, sd->stream, sd->ctx->cbarg);
        strncpy(out_user, buf, out_umax);
        out_user[out_umax]='\0';
        *out_ulen=strlen(out_user);
    } else {
        memcpy(out_user,user,ulen);
        *out_ulen = ulen;
    }
    return SASL_OK;
}

/* Need to make sure that
 *  *) The authnid is permitted to become the given authzid
 *  *) The authnid is included in the given authreg systems DB
 */
static int _sx_sasl_proxy_policy(sasl_conn_t *conn, void *ctx, const char *requested_user, int rlen, const char *auth_identity, int alen, const char *realm, int urlen, struct propctx *propctx) {
    _sx_sasl_data_t sd = (_sx_sasl_data_t) ctx;
    struct sx_sasl_creds_st creds = {NULL, NULL, NULL, NULL};
    char *buf, *c;
    size_t len;
    int ret;

    sasl_getprop(conn, SASL_MECHNAME, (const void **) &buf);
    if (strncmp(buf, "ANONYMOUS", 10) == 0) {
        /* If they're anonymous, their ID comes from us, so it must be OK! */
        return SASL_OK;
    } else {
        /* This will break with clients that give requested user as a JID,
         * where requested_user != auth_identity */
        if (!requested_user || !auth_identity || rlen == 0 || alen==0) {
          sasl_seterror(conn, 0,
                        "Bad identities provided");
          return SASL_BADAUTH;
      }

      /* No guarantee that realm is NULL terminated - so make a terminated
         * version before we do anything */

      /* XXX - Do we also need to check if realm contains NULL values, 
       *       and complain if it does?
         */

      buf = malloc(urlen + 1);
      strncpy(buf, realm?realm:"", urlen);
      buf[urlen] = '\0';
      creds.realm = buf;

      /* By this point, SASL's default canon_user plugin has appended the
         * realm to both the auth_identity, and the requested_user. This
         * isn't what we want.
         *   auth_identity should be a bare username
         *   requested_user should be a JID
         *
         * We can't just remove everything after the '@' as some mechanisms
         * (such as GSSAPI) use the @ to denote users in foreign realms.
         */

      buf = malloc(alen + 1);
      strncpy(buf, auth_identity, alen);
      buf[alen] = '\0';
      c = strrchr(buf, '@');
      if (c && strcmp(c+1, creds.realm) == 0)
            *c = '\0';
      creds.authnid = buf;

      /* Now, we need to turn requested_user into a JID 
         * (if it isn't already)
       *
       * XXX - This will break with s2s SASL, where the authzid is a domain
       */
      len = rlen;
      if (sd->stream->req_to)
          len+=strlen(sd->stream->req_to) + 2;
      buf = malloc(len + 1);
      strncpy(buf, requested_user, rlen);
      buf[rlen] = '\0';
      c = strrchr(buf, '@');
      if (c && strcmp(c + 1, creds.realm) == 0)
          *c = '\0';
      if (sd->stream->req_to && strchr(buf, '@') == 0) {
          strcat(buf, "@");
          strcat(buf, sd->stream->req_to);
      }
      creds.authzid = buf;

          /* If we start being fancy and allow auth_identity to be different from
           * requested_user, then this will need to be changed to permit it!
           */
        ret = (sd->ctx->cb)(sx_sasl_cb_CHECK_AUTHZID, &creds, NULL, sd->stream, sd->ctx->cbarg);

      free((void *)creds.authnid);
      free((void *)creds.authzid);
      free((void *)creds.realm);

      if (ret == sx_sasl_ret_OK) {
          return SASL_OK;
      } else {
          sasl_seterror(conn, 0, "Requested identity not permitted for authorization identity");
          return SASL_BADAUTH;
      }
    }
}

static int _sx_sasl_wio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    sasl_conn_t *sasl;
    int *x, len, pos, reslen, maxbuf;
    char *out, *result;

    sasl = ((_sx_sasl_data_t) s->plugin_data[p->index])->sasl;

    /* if there's no security layer, don't bother */
    sasl_getprop(sasl, SASL_SSF, (const void **) &x);
    if(*x == 0)
        return 1;

    _sx_debug(ZONE, "doing sasl encode");

    /* can only encode x bytes at a time */
    sasl_getprop(sasl, SASL_MAXOUTBUF, (const void **) &x);
    maxbuf = *x;

    /* encode the output */
    pos = 0;
    result = NULL; reslen = 0;
    while(pos < buf->len) {
        if((buf->len - pos) < maxbuf)
            maxbuf = buf->len - pos;

        sasl_encode(sasl, &buf->data[pos], maxbuf, (const char **) &out, &len);
        
        result = (char *) realloc(result, sizeof(char) * (reslen + len));
        memcpy(&result[reslen], out, len);
        reslen += len;

        pos += maxbuf;
    }
    
    /* replace the buffer */
    _sx_buffer_set(buf, result, reslen, result);

    _sx_debug(ZONE, "%d bytes encoded for sasl channel", buf->len);
    
    return 1;
}

static int _sx_sasl_rio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    sasl_conn_t *sasl;
    sx_error_t sxe;
    int *x, len;
    char *out;

    sasl = ((_sx_sasl_data_t) s->plugin_data[p->index])->sasl;

    /* if there's no security layer, don't bother */
    sasl_getprop(sasl, SASL_SSF, (const void **) &x);
    if(*x == 0)
        return 1;

    _sx_debug(ZONE, "doing sasl decode");

    /* decode the input */
    if (sasl_decode(sasl, buf->data, buf->len, (const char **) &out, &len)
      != SASL_OK) {
      /* Fatal error */
      _sx_gen_error(sxe, SX_ERR_AUTH, "SASL Stream decoding failed", NULL);
      _sx_event(s, event_ERROR, (void *) &sxe);
      return -1;
    }
    
    /* replace the buffer */
    _sx_buffer_set(buf, out, len, NULL);

    _sx_debug(ZONE, "%d bytes decoded from sasl channel", len);
    
    return 1;
}

/** move the stream to the auth state */
void _sx_sasl_open(sx_t s, sasl_conn_t *sasl) {
    char *method;
    char *buf, *c;
    char *authzid;
    size_t len;
    int *ssf;
    
    /* get the method */
    sasl_getprop(sasl, SASL_MECHNAME, (const void **) &buf);

    method = (char *) malloc(sizeof(char) * (strlen(buf) + 17));
    sprintf(method, "SASL/%s", buf);

    /* get the ssf */
    if(s->ssf == 0) {
        sasl_getprop(sasl, SASL_SSF, (const void **) &ssf);
        s->ssf = *ssf;
    }

    /* and the authenticated id */
    sasl_getprop(sasl, SASL_USERNAME, (const void **) &buf);

    if (s->type == type_SERVER) {
        /* Now, we need to turn the id into a JID 
         * (if it isn't already)
         *
         * XXX - This will break with s2s SASL, where the authzid is a domain
         */

      len = strlen(buf);
      if (s->req_to)
          len+=strlen(s->req_to) + 2;
        authzid = malloc(len + 1);
        strcpy(authzid, buf);

        sasl_getprop(sasl, SASL_DEFUSERREALM, (const void **) &buf);

        c = strrchr(authzid, '@');
        if (c && buf && strcmp(c+1, buf) == 0)
            *c = '\0';
        if (s->req_to && strchr(authzid, '@') == 0) {
            strcat(authzid, "@");
            strcat(authzid, s->req_to);
        }

        /* schwing! */
        sx_auth(s, method, authzid);
        free(authzid);
    } else {
        sx_auth(s, method, buf);
    }

    free(method);
}

/** make the stream authenticated second time round */
static void _sx_sasl_stream(sx_t s, sx_plugin_t p) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    sasl_conn_t *sasl;
    _sx_sasl_data_t sd;
    int ret, i;
    char *realm = NULL, *ext_id, *mech;
    sasl_security_properties_t sec_props;

    /* First time around, we need to set up our SASL connection, otherwise
     * features will fall flat on its face */
    if (s->plugin_data[p->index] == NULL) {
        if(s->type == type_SERVER) {

            if(!(s->flags & SX_SASL_OFFER)) {
                _sx_debug(ZONE, "application did not request sasl offer, not offering for this conn");
                return;
            }

            _sx_debug(ZONE, "setting up sasl for this server conn");

            /* Initialise our data object */
            sd = (_sx_sasl_data_t) calloc(1, sizeof(struct _sx_sasl_data_st));

            /* get the realm */
            if(ctx->cb != NULL)
                (ctx->cb)(sx_sasl_cb_GET_REALM, NULL, (void **) &realm, s, ctx->cbarg);

            /* Initialize our callbacks */
            sd->callbacks = calloc(sizeof(sasl_callback_t),4);

            sd->callbacks[0].id = SASL_CB_PROXY_POLICY;
            sd->callbacks[0].proc = &_sx_sasl_proxy_policy;
            sd->callbacks[0].context = sd;

            sd->callbacks[1].id = SASL_CB_CANON_USER;
            sd->callbacks[1].proc = &_sx_sasl_canon_user;
            sd->callbacks[1].context = sd;

            sd->callbacks[2].id = SASL_CB_SERVER_USERDB_CHECKPASS;
            sd->callbacks[2].proc = &_sx_sasl_checkpass;
            sd->callbacks[2].context = sd;

            sd->callbacks[3].id = SASL_CB_LIST_END;

            /* startup */
            ret = sasl_server_new(ctx->appname, NULL,
                                  realm ? (realm[0] == '\0' ? NULL : realm) : NULL,
                                  NULL, NULL, sd->callbacks,
                                  ctx->sec_props.security_flags, &sasl);
            if(ret != SASL_OK) {
                _sx_debug(ZONE, "sasl_server_new failed (%s), not offering sasl for this conn", sasl_errstring(ret, NULL, NULL));
                free(sd->callbacks);
                free(sd);
                return;
            }

            /* get external data from the ssl plugin */
            ext_id = NULL;
#ifdef HAVE_SSL
            for(i = 0; i < s->env->nplugins; i++)
                if(s->env->plugins[i]->magic == SX_SSL_MAGIC && s->plugin_data[s->env->plugins[i]->index] != NULL)
                    ext_id = ((_sx_ssl_conn_t) s->plugin_data[s->env->plugins[i]->index])->external_id;

            /* if we've got some, setup for external auth */
            if(ext_id != NULL) {
                ret = sasl_setprop(sasl, SASL_AUTH_EXTERNAL, ext_id);
                if(ret == SASL_OK) 
                    ret = sasl_setprop(sasl, SASL_SSF_EXTERNAL, &s->ssf);
            }
#endif /* HAVE_SSL */

            /* security properties */
            sec_props = ctx->sec_props;
            if(s->ssf > 0)
                /* if we're already encrypted, then no security layers */
                sec_props.max_ssf = 0;

            if(ret == SASL_OK) 
                ret = sasl_setprop(sasl, SASL_SEC_PROPS, &sec_props);

            if(ret != SASL_OK) {
                _sx_debug(ZONE, "sasl_setprop failed (%s), not offering sasl for this conn", sasl_errstring(ret, NULL, NULL));
                free(sd->callbacks);
                free(sd);
                return;
            }

            sd->sasl = sasl;
            sd->stream = s;
            sd->ctx = ctx;

            _sx_debug(ZONE, "sasl context initialised for %d", s->tag);

            s->plugin_data[p->index] = (void *) sd;

        }

        return;
    }

    sasl = ((_sx_sasl_data_t) s->plugin_data[p->index])->sasl;

    /* are we auth'd? */
    if (sasl_getprop(sasl, SASL_MECHNAME, (void *) &mech) == SASL_NOTDONE) {
        _sx_debug(ZONE, "not auth'd, not advancing to auth'd state yet");
        return;
    }

    /* otherwise, its auth time */
    _sx_sasl_open(s, sasl);
}

static void _sx_sasl_features(sx_t s, sx_plugin_t p, nad_t nad) {
    _sx_sasl_data_t sd = (_sx_sasl_data_t) s->plugin_data[p->index];
    int ret, nmechs, ns;
    char *mechs, *mech, *c;

    if(s->type != type_SERVER || sd == NULL || sd->sasl == NULL)
        return;

    if((ret = sasl_getprop(sd->sasl, SASL_MECHNAME, (void *) &mech)) != SASL_NOTDONE) {
        _sx_debug(ZONE, "already auth'd, not offering sasl mechanisms");
        return;
    }

    if(!(s->flags & SX_SASL_OFFER)) {
        _sx_debug(ZONE, "application didn't ask us to offer sasl, so we won't");
        return;
    }

#ifdef HAVE_SSL
    if((s->flags & SX_SSL_STARTTLS_REQUIRE) && s->ssf == 0) {
        _sx_debug(ZONE, "ssl not established yet but the app requires it, not offering mechanisms");
        return;
    }
#endif
    
    _sx_debug(ZONE, "offering sasl mechanisms");

    ret = sasl_listmech(sd->sasl, NULL, "", "|", "", (const char **) &mechs, NULL, &nmechs);
    if(ret != SASL_OK) {
        _sx_debug(ZONE, "sasl_listmech failed (%s), not offering sasl for this conn", sasl_errstring(ret, NULL, NULL));
        _sx_sasl_free(s,p);
        return;
    }
    
    if(nmechs <= 0) {
        _sx_debug(ZONE, "sasl_listmech returned no mechanisms, not offering sasl for this conn");
        _sx_sasl_free(s,p);
        return;
    }

    mech = mechs;
    nmechs = 0;
    while(mech != NULL) {
        c = strchr(mech, '|');
        if(c != NULL)
            *c = '\0';

        if ((sd->ctx->cb)(sx_sasl_cb_CHECK_MECH, mech, NULL, sd->stream, sd->ctx->cbarg)==sx_sasl_ret_OK) {
            if (nmechs == 0) {
                ns = nad_add_namespace(nad, uri_SASL, NULL);
                nad_append_elem(nad, ns, "mechanisms", 1);
            }
            _sx_debug(ZONE, "offering mechanism: %s", mech);

            nad_append_elem(nad, ns, "mechanism", 2);
            nad_append_cdata(nad, mech, strlen(mech), 3);
            nmechs++;
        }

        if(c == NULL)
            mech = NULL;
        else
            mech = ++c;
    }
}

/** utility: generate a success nad */
static nad_t _sx_sasl_success(sx_t s) {
    nad_t nad;
    int ns;

    nad = nad_new();
    ns = nad_add_namespace(nad, uri_SASL, NULL);

    nad_append_elem(nad, ns, "success", 0);

    return nad;
}

/** utility: generate a failure nad */
static nad_t _sx_sasl_failure(sx_t s, const char *err) {
    nad_t nad;
    int ns;

    nad = nad_new();
    ns = nad_add_namespace(nad, uri_SASL, NULL);

    nad_append_elem(nad, ns, "failure", 0);
    if(err != NULL)
        nad_append_elem(nad, ns, err, 1);

    return nad;
}

/** utility: generate a challenge nad */
static nad_t _sx_sasl_challenge(sx_t s, char *data, int dlen) {
    nad_t nad;
    int ns;

    nad = nad_new();
    ns = nad_add_namespace(nad, uri_SASL, NULL);

    nad_append_elem(nad, ns, "challenge", 0);
    if(data != NULL)
        nad_append_cdata(nad, data, dlen, 1);

    return nad;
}

/** utility: generate a response nad */
static nad_t _sx_sasl_response(sx_t s, char *data, int dlen) {
    nad_t nad;
    int ns;

    nad = nad_new();
    ns = nad_add_namespace(nad, uri_SASL, NULL);

    nad_append_elem(nad, ns, "response", 0);
    if(data != NULL)
        nad_append_cdata(nad, data, dlen, 1);

    return nad;
}

/** utility: generate an abort nad */
static nad_t _sx_sasl_abort(sx_t s) {
    nad_t nad;
    int ns;

    nad = nad_new();
    ns = nad_add_namespace(nad, uri_SASL, NULL);

    nad_append_elem(nad, ns, "abort", 0);

    return nad;
}

/** utility: decode incoming handshake data */
static void _sx_sasl_decode(char *in, int inlen, char **out, int *outlen) {
    *out = (char *) malloc(sizeof(char) * (2 * inlen));
    sasl_decode64(in,inlen,out,2*inlen,outlen);
}

/** utility: encode outgoing handshake data */
static void _sx_sasl_encode(char *in, int inlen, char **out, int *outlen) {
    *out = (char *) malloc(sizeof(char) * (2 * inlen));
    sasl_encode64(in,inlen,out,2*inlen,outlen);
}

/** auth done, restart the stream */
static void _sx_sasl_notify_success(sx_t s, void *arg) {
    sx_plugin_t p = (sx_plugin_t) arg;

    _sx_chain_io_plugin(s, p);
    _sx_debug(ZONE, "auth completed, resetting");

    _sx_reset(s);

    sx_server_init(s, s->flags);
}

/** process handshake packets from the client */
static void _sx_sasl_client_process(sx_t s, sx_plugin_t p, char *mech, char *in, int inlen) {
    _sx_sasl_data_t sd = (_sx_sasl_data_t) s->plugin_data[p->index];
    char *buf = NULL, *out = NULL;
    int buflen, outlen, ret;

    /* decode the response */
    _sx_sasl_decode(in, inlen, &buf, &buflen);

    if(mech != NULL) {
        _sx_debug(ZONE, "auth request from client (mechanism=%s)", mech);
    } else {
        _sx_debug(ZONE, "response from client (response: %.*s)", buflen, buf);
    }

    /* process the data */
    if(mech != NULL)
        ret = sasl_server_start(sd->sasl, mech, buf, buflen, (const char **) &out, &outlen);
    else {
        if(!sd->sasl) {
            _sx_debug(ZONE, "response send before auth request enabling mechanism (decoded: %.*s)", buflen, buf);
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_MECH_TOO_WEAK), 0);
            if(buf != NULL) free(buf);
            return;
        }
        ret = sasl_server_step(sd->sasl, buf, buflen, (const char **) &out, &outlen);
    }

    if(buf != NULL) free(buf);

    /* auth completed */
    if(ret == SASL_OK) {
        _sx_debug(ZONE, "sasl handshake completed");

        /* send success */
        _sx_nad_write(s, _sx_sasl_success(s), 0);

        /* set a notify on the success nad buffer */
        ((sx_buf_t) s->wbufq->front->data)->notify = _sx_sasl_notify_success;
        ((sx_buf_t) s->wbufq->front->data)->notify_arg = (void *) p;

	return;
    }

    /* in progress */
    if(ret == SASL_CONTINUE) {
        _sx_debug(ZONE, "sasl handshake in progress (challenge: %.*s)", outlen, out);

        /* encode the challenge */
        _sx_sasl_encode(out, outlen, &buf, &buflen);

        _sx_nad_write(s, _sx_sasl_challenge(s, buf, buflen), 0);

        free(buf);

        return;
    }

    /* its over */
    buf = (char *) sasl_errdetail(sd->sasl);
    if(buf == NULL)
        buf = "[no error message available]";

    _sx_debug(ZONE, "sasl handshake failed: %s", buf);

    _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_MALFORMED_REQUEST), 0);
}

/** process handshake packets from the server */
static void _sx_sasl_server_process(sx_t s, sx_plugin_t p, char *in, int inlen) {
    _sx_sasl_data_t sd = (_sx_sasl_data_t)s->plugin_data[p->index];
    char *buf, *out;
    int buflen, outlen, ret;
    const char *err_buf;

    _sx_debug(ZONE, "challenge from client");

    /* decode the response */
    _sx_sasl_decode(in, inlen, &buf, &buflen);

    /* process the data */
    ret = sasl_client_step(sd->sasl, buf, buflen, NULL, (const char **) &out, &outlen);
    if(buf != NULL) free(buf);

    /* in progress */
    if(ret == SASL_OK || ret == SASL_CONTINUE) {
        _sx_debug(ZONE, "sasl handshake in progress (response: %.*s)", outlen, out);

        /* encode the response */
        _sx_sasl_encode(out, outlen, &buf, &buflen);

        _sx_nad_write(s, _sx_sasl_response(s, buf, buflen), 0);

        if(buf != NULL) free(buf);

        return;
    }

    /* its over */
    err_buf = sasl_errdetail(sd->sasl);
    if (err_buf == NULL)
        err_buf = "[no error message available]";
    
    _sx_debug(ZONE, "sasl handshake aborted: %s", err_buf);

    _sx_nad_write(s, _sx_sasl_abort(s), 0);
}

/** main nad processor */
static int _sx_sasl_process(sx_t s, sx_plugin_t p, nad_t nad) {
    _sx_sasl_data_t sd = (_sx_sasl_data_t)s->plugin_data[p->index];
    int attr;
    char mech[128];
    sx_error_t sxe;
    int flags;
    char *ns = NULL, *to = NULL, *from = NULL, *version = NULL;

    /* only want sasl packets */
    if(NAD_ENS(nad, 0) < 0 || NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_SASL) || strncmp(NAD_NURI(nad, NAD_ENS(nad, 0)), uri_SASL, strlen(uri_SASL)) != 0)
        return 1;

    /* quietly drop it if sasl is disabled, or if not ready */
    if(s->state != state_STREAM || sd == NULL) {
        _sx_debug(ZONE, "not correct state for sasl, ignoring");
        nad_free(nad);
        return 0;
    }

    /* packets from the client */
    if(s->type == type_SERVER) {
        if(!(s->flags & SX_SASL_OFFER)) {
            _sx_debug(ZONE, "they tried to do sasl, but we never offered it, ignoring");
            nad_free(nad);
            return 0;
        }

#ifdef HAVE_SSL
        if((s->flags & SX_SSL_STARTTLS_REQUIRE) && s->ssf == 0) {
            _sx_debug(ZONE, "they tried to do sasl, but they have to do starttls first, ignoring");
            nad_free(nad);
            return 0;
        }
#endif

        /* auth */
        if(NAD_ENAME_L(nad, 0) == 4 && strncmp("auth", NAD_ENAME(nad, 0), NAD_ENAME_L(nad, 0)) == 0) {
            /* require mechanism */
            if((attr = nad_find_attr(nad, 0, -1, "mechanism", NULL)) < 0) {
                _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_INVALID_MECHANISM), 0);
                nad_free(nad);
                return 0;
            }

            /* extract */
            snprintf(mech, 127, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

            /* go */
            _sx_sasl_client_process(s, p, mech, NAD_CDATA(nad, 0), NAD_CDATA_L(nad, 0));

            nad_free(nad);
            return 0;
        }

        /* response */
        else if(NAD_ENAME_L(nad, 0) == 8 && strncmp("response", NAD_ENAME(nad, 0), NAD_ENAME_L(nad, 0)) == 0) {
            /* process it */
            _sx_sasl_client_process(s, p, NULL, NAD_CDATA(nad, 0), NAD_CDATA_L(nad, 0));

            nad_free(nad);
            return 0;
        }

        /* abort */
        else if(NAD_ENAME_L(nad, 0) == 5 && strncmp("abort", NAD_ENAME(nad, 0), NAD_ENAME_L(nad, 0)) == 0) {
            _sx_debug(ZONE, "sasl handshake aborted");

            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_ABORTED), 0);

            nad_free(nad);
            return 0;
        }
    }
    
    /* packets from the server */
    else if(s->type == type_CLIENT) {
        if(sd == NULL) {
            _sx_debug(ZONE, "got sasl client packets, but they never started sasl, ignoring");
            nad_free(nad);
            return 0;
        }

        /* challenge */
        if(NAD_ENAME_L(nad, 0) == 9 && strncmp("challenge", NAD_ENAME(nad, 0), NAD_ENAME_L(nad, 0)) == 0) {
            /* process it */
            _sx_sasl_server_process(s, p, NAD_CDATA(nad, 0), NAD_CDATA_L(nad, 0));

            nad_free(nad);
            return 0;
        }

        /* success */
        else if(NAD_ENAME_L(nad, 0) == 7 && strncmp("success", NAD_ENAME(nad, 0), NAD_ENAME_L(nad, 0)) == 0) {
            _sx_debug(ZONE, "sasl handshake completed, resetting");
            nad_free(nad);

            /* save interesting bits */
            flags = s->flags;

            if(s->ns != NULL) ns = strdup(s->ns);

            if(s->req_to != NULL) to = strdup(s->req_to);
            if(s->req_from != NULL) from = strdup(s->req_from);
            if(s->req_version != NULL) version = strdup(s->req_version);

            /* setup the encoder */
            _sx_chain_io_plugin(s, p);

            /* reset state */
            _sx_reset(s);

            _sx_debug(ZONE, "restarting stream with sasl layer established");

            /* second time round */
            sx_client_init(s, flags, ns, to, from, version);

            /* free bits */
            if(ns != NULL) free(ns);
            if(to != NULL) free(to);
            if(from != NULL) free(from);
            if(version != NULL) free(version);

            return 0;
        }

        /* failure */
        else if(NAD_ENAME_L(nad, 0) == 7 && strncmp("failure", NAD_ENAME(nad, 0), NAD_ENAME_L(nad, 0)) == 0) {
            /* fire the error */
            _sx_gen_error(sxe, SX_ERR_AUTH, "Authentication failed", NULL);
            _sx_event(s, event_ERROR, (void *) &sxe);

            /* cleanup */
            _sx_sasl_free(s,p);

            nad_free(nad);
            return 0;
        }
    }

    /* invalid sasl command, quietly drop it */
    _sx_debug(ZONE, "unknown sasl command '%.*s', ignoring", NAD_ENAME_L(nad, 0), NAD_ENAME(nad, 0));

    nad_free(nad);
    return 0;
}

/** cleanup */
static void _sx_sasl_free(sx_t s, sx_plugin_t p) {
    _sx_sasl_data_t sd = (_sx_sasl_data_t) s->plugin_data[p->index];

    if(sd == NULL)
        return;

    _sx_debug(ZONE, "cleaning up conn state");

    if(sd->sasl != NULL) sasl_dispose(&sd->sasl);
    if(sd->user != NULL) free(sd->user);
    if(sd->psecret != NULL) free(sd->psecret);
    if(sd->callbacks != NULL) free(sd->callbacks);

    free(sd);

    s->plugin_data[p->index] = NULL;
}

static void _sx_sasl_unload(sx_plugin_t p) {
    _sx_sasl_t ctx;

    ctx = (_sx_sasl_t) p->private;

    if (ctx->appname != NULL) free(ctx->appname);
    if (ctx->saslcallbacks != NULL) free(ctx->saslcallbacks);

    if (p->private != NULL) free(p->private);
}

/** args: appname, callback, cb arg */
int sx_sasl_init(sx_env_t env, sx_plugin_t p, va_list args) {
    char *appname;
    sx_sasl_callback_t cb;
    void *cbarg;
    int ret;
    _sx_sasl_t ctx;

    _sx_debug(ZONE, "initialising sasl plugin");

    appname = va_arg(args, char *);
    if(appname == NULL) {
        _sx_debug(ZONE, "appname was NULL, failing");
        return 1;
    }

    cb = va_arg(args, sx_sasl_callback_t);
    cbarg = va_arg(args, void *);

    /* Set up the auxiliary property plugin, which we use to gave SASL
     * mechanism plugins access to our passwords
     */
    sasl_auxprop_add_plugin("jabbersx", sx_auxprop_init);

    ctx = (_sx_sasl_t) calloc(1, sizeof(struct _sx_sasl_st));

    ctx->sec_props.min_ssf = 0;
    ctx->sec_props.max_ssf = -1;    /* sasl_ssf_t is typedef'd to unsigned, so -1 gets us the max possible ssf */
    ctx->sec_props.maxbufsize = 1024;
    ctx->sec_props.security_flags = 0;

    ctx->appname = strdup(appname);
    ctx->cb = cb;
    ctx->cbarg = cbarg;
  
    /* Push the location of our callbacks into the auxprop structure */
    
    _sx_auxprop_plugin.glob_context = (void *) ctx;

#ifdef _WIN32
    ctx->saslcallbacks = calloc(sizeof(sasl_callback_t), 3);
#else
    ctx->saslcallbacks = calloc(sizeof(sasl_callback_t), 2);
#endif
    ctx->saslcallbacks[0].id = SASL_CB_GETOPT;
    ctx->saslcallbacks[0].proc = &_sx_sasl_getopt;
    ctx->saslcallbacks[0].context = NULL;
#ifdef _WIN32
	ctx->saslcallbacks[1].id = SASL_CB_GETPATH;
    ctx->saslcallbacks[1].proc = &_sx_sasl_getpath;
    ctx->saslcallbacks[1].context = NULL;

    ctx->saslcallbacks[2].id = SASL_CB_LIST_END;
#else
    ctx->saslcallbacks[1].id = SASL_CB_LIST_END;
#endif

    ret = sasl_server_init(ctx->saslcallbacks, appname);
    if(ret != SASL_OK) {
        _sx_debug(ZONE, "sasl_server_init() failed (%s), disabling", sasl_errstring(ret, NULL, NULL));
        free(ctx->saslcallbacks);
        free(ctx);
        return 1;
    }

    _sx_debug(ZONE, "sasl context initialised; appname=%s", appname);

    p->private = (void *) ctx;

    p->unload = _sx_sasl_unload;
    p->wio = _sx_sasl_wio;
    p->rio = _sx_sasl_rio;

    p->stream = _sx_sasl_stream;
    p->features = _sx_sasl_features;
    p->process = _sx_sasl_process;

    p->free = _sx_sasl_free;

    return 0;
}

/* callback functions for client auth */
static int _sx_sasl_cb_get_simple(void *ctx, int id, const char **result, unsigned *len)
{
    _sx_sasl_data_t sd = (_sx_sasl_data_t) ctx;

    _sx_debug(ZONE, "in _sx_sasl_cb_get_simple (id 0x%x)", id);

    *result = sd->user;
    if(len != NULL)
        *len = strlen(*result);

    return SASL_OK;
}

static int _sx_sasl_cb_get_secret(sasl_conn_t *conn, void *ctx, int id, sasl_secret_t **psecret)
{
    _sx_sasl_data_t sd = (_sx_sasl_data_t) ctx;

    _sx_debug(ZONE, "in _sx_sasl_cb_get_secret (id 0x%x)", id);
    
    /* sanity check */
    if(conn == NULL || psecret == NULL || id != SASL_CB_PASS)
        return SASL_BADPARAM;

    *psecret = sd->psecret;

    return SASL_OK;
}

/** kick off the auth handshake */
int sx_sasl_auth(sx_plugin_t p, sx_t s, char *appname, char *mech, char *user, char *pass) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    _sx_sasl_data_t sd;
    char *buf, *out, *ext_id;
    int i, ret, buflen, outlen, ns;
    sasl_security_properties_t sec_props;
    nad_t nad;
#ifdef _WIN32
    static sasl_callback_t win32_callbacks[2] = {
        {SASL_CB_GETPATH, &_sx_sasl_getpath, NULL},
        {SASL_CB_LIST_END, NULL, NULL}};
#endif

    assert((int) (p != NULL));
    assert((int) (s != NULL));
    assert((int) (appname != NULL));
    assert((int) (mech != NULL));

    if(s->type != type_CLIENT || s->state != state_STREAM) {
        _sx_debug(ZONE, "need client in stream state for sasl auth");
        return 1;
     }
    
    /* startup */
#ifdef _WIN32
    ret = sasl_client_init(win32_callbacks);
#else
    ret = sasl_client_init(NULL);
#endif
    if(ret != SASL_OK) {
        _sx_debug(ZONE, "sasl_client_init() failed (%s), not authing", sasl_errstring(ret, NULL, NULL));
        return 1;
    }

    sd = (_sx_sasl_data_t) calloc(1, sizeof(struct _sx_sasl_data_st));

    if(user != NULL)
        sd->user = strdup(user);

    if(pass != NULL) {
        sd->psecret = (sasl_secret_t *) malloc(sizeof(sasl_secret_t) + strlen(pass) + 1);
        strcpy(sd->psecret->data, pass);
        sd->psecret->len = strlen(pass);
    }

    sd->callbacks=calloc(sizeof(sasl_callback_t),4);

    /* authentication name callback */
    sd->callbacks[0].id = SASL_CB_AUTHNAME;
    sd->callbacks[0].proc = &_sx_sasl_cb_get_simple;
    sd->callbacks[0].context = (void *) sd;

    /* password callback */
    sd->callbacks[1].id = SASL_CB_PASS;
    sd->callbacks[1].proc = &_sx_sasl_cb_get_secret;
    sd->callbacks[1].context = (void *) sd;

    /* user identity callback */
    sd->callbacks[2].id = SASL_CB_USER;
    sd->callbacks[2].proc = &_sx_sasl_cb_get_simple;
    sd->callbacks[2].context = (void *) sd;

    /* end of callbacks */
    sd->callbacks[3].id = SASL_CB_LIST_END;
    sd->callbacks[3].proc = NULL;
    sd->callbacks[3].context = NULL;

    /* handshake start */
    ret = sasl_client_new(appname, (s->req_to != NULL) ? s->req_to : "", NULL, NULL, sd->callbacks, 0, &sd->sasl);
    if(ret != SASL_OK) {
        _sx_debug(ZONE, "sasl_client_new failed, (%s), not authing", sasl_errstring(ret, NULL, NULL));

        if (sd->user != NULL) free(sd->user);
        if (sd->psecret != NULL) free(sd->psecret);
        free(sd->callbacks);
        free(sd);

        return 1;
    }

    /* get external data from the ssl plugin */
    ext_id = NULL;
#ifdef HAVE_SSL
    for(i = 0; i < s->env->nplugins; i++)
        if(s->env->plugins[i]->magic == SX_SSL_MAGIC && s->plugin_data[s->env->plugins[i]->index] != NULL)
            ext_id = ((_sx_ssl_conn_t) s->plugin_data[s->env->plugins[i]->index])->external_id;

    /* !!! XXX certs */
    /*
    if(ext != NULL) {
        ext->external_id = strdup("foo");
        ext->external_ssf = 20;
    }
    */

    /* if we've got some, setup for external auth */
    if(ext_id != NULL) {
        ret = sasl_setprop(sd->sasl, SASL_AUTH_EXTERNAL, ext_id);
        if(ret == SASL_OK) ret = sasl_setprop(sd->sasl, SASL_SSF_EXTERNAL, &s->ssf);
    }
#endif /* HAVE_SSL */

    /* setup security properties */
    sec_props = ctx->sec_props;
    if(s->ssf > 0)
        /* if we're already encrypted, then no security layers */
        sec_props.max_ssf = 0;

    ret = sasl_setprop(sd->sasl, SASL_SEC_PROPS, &sec_props);
    if(ret != SASL_OK) {
        _sx_debug(ZONE, "sasl_setprop failed (%s), not authing", sasl_errstring(ret, NULL, NULL));

        sasl_dispose(&sd->sasl);

        if (sd->user != NULL) free(sd->user);
        if (sd->psecret != NULL) free(sd->psecret);
        free(sd->callbacks);
        free(sd);

        return 1;
    }

    /* handshake start */
    ret = sasl_client_start(sd->sasl, mech, NULL, (const char **) &out, &outlen, NULL);
    if(ret != SASL_OK && ret != SASL_CONTINUE) {
        _sx_debug(ZONE, "sasl_client_start failed (%s), not authing", sasl_errstring(ret, NULL, NULL));

        sasl_dispose(&sd->sasl);

        if (sd->user != NULL) free(sd->user);
        if (sd->psecret != NULL) free(sd->psecret);
        free(sd->callbacks);
        free(sd);

        return 1;
    }

    /* save userdata */
    s->plugin_data[p->index] = (void *) sd;

    /* in progress */
    _sx_debug(ZONE, "sending auth request to server, mech '%s': %.*s", mech, outlen, out);

    /* encode the challenge */
    _sx_sasl_encode(out, outlen, &buf, &buflen);

    /* build the nad */
    nad = nad_new();
    ns = nad_add_namespace(nad, uri_SASL, NULL);

    nad_append_elem(nad, ns, "auth", 0);
    nad_append_attr(nad, -1, "mechanism", mech);
    if(buf != NULL) {
        nad_append_cdata(nad, buf, buflen, 1);
        free(buf);
    }

    /* its away */
    sx_nad_write(s, nad);

    return 0;
}
