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

#include "sx.h"
#include "sasl.h"
#include <gsasl.h>
#include <gsasl-mech.h>
#include <string.h>

/** our sasl application context */
typedef struct _sx_sasl_st {
    char                        *appname;
    Gsasl                       *gsasl_ctx;

    sx_sasl_callback_t          cb;
    void                        *cbarg;

    char                        *ext_id[SX_CONN_EXTERNAL_ID_MAX_COUNT];
} *_sx_sasl_t;

/** our sasl per session context */
typedef struct _sx_sasl_sess_st {
    sx_t            s;
    _sx_sasl_t      ctx;
} *_sx_sasl_sess_t;

/** utility: generate a success nad */
static nad_t _sx_sasl_success(sx_t s, const char *data, int dlen) {
    nad_t nad;
    int ns;

    nad = nad_new();
    ns = nad_add_namespace(nad, uri_SASL, NULL);

    nad_append_elem(nad, ns, "success", 0);
    if(data != NULL)
        nad_append_cdata(nad, data, dlen, 1);

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
static nad_t _sx_sasl_challenge(sx_t s, const char *data, int dlen) {
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
static nad_t _sx_sasl_response(sx_t s, const char *data, int dlen) {
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

static int _sx_sasl_wio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    sx_error_t sxe;
    size_t len;
    int ret;
    char *out;
    Gsasl_session *sd = (Gsasl_session *) s->plugin_data[p->index];

    _sx_debug(ZONE, "doing sasl encode");

    /* encode the output */
    ret = gsasl_encode(sd, buf->data, buf->len, &out, &len);
    if (ret != GSASL_OK) {
        _sx_debug(ZONE, "gsasl_encode failed (%d): %s", ret, gsasl_strerror (ret));
        /* Fatal error */
        _sx_gen_error(sxe, SX_ERR_AUTH, "SASL Stream encoding failed", (char*) gsasl_strerror (ret));
        _sx_event(s, event_ERROR, (void *) &sxe);
        return -1;
    }
    
    /* replace the buffer */
    _sx_buffer_set(buf, out, len, NULL);
    free(out);

    _sx_debug(ZONE, "%d bytes encoded for sasl channel", buf->len);
    
    return 1;
}

static int _sx_sasl_rio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    sx_error_t sxe;
    size_t len;
    int ret;
    char *out;
    Gsasl_session *sd = (Gsasl_session *) s->plugin_data[p->index];

    _sx_debug(ZONE, "doing sasl decode");

    /* decode the input */
    ret = gsasl_decode(sd, buf->data, buf->len, &out, &len);
    if (ret != GSASL_OK) {
        _sx_debug(ZONE, "gsasl_decode failed (%d): %s", ret, gsasl_strerror (ret));
        /* Fatal error */
        _sx_gen_error(sxe, SX_ERR_AUTH, "SASL Stream decoding failed", (char*) gsasl_strerror (ret));
        _sx_event(s, event_ERROR, (void *) &sxe);
        return -1;
    }
    
    /* replace the buffer */
    _sx_buffer_set(buf, out, len, NULL);
    free(out);

    _sx_debug(ZONE, "%d bytes decoded from sasl channel", len);
    
    return 1;
}

/** move the stream to the auth state */
void _sx_sasl_open(sx_t s, Gsasl_session *sd) {
    char *method, *authzid;
    const char *realm = NULL;
    struct sx_sasl_creds_st creds = {NULL, NULL, NULL, NULL};
    _sx_sasl_sess_t sctx = gsasl_session_hook_get(sd);
    _sx_sasl_t ctx = sctx->ctx;
    const char *mechname = gsasl_mechanism_name (sd);

    /* get the method */
    method = (char *) malloc(sizeof(char) * (strlen(mechname) + 6));
    sprintf(method, "SASL/%s", mechname);

    /* and the authorization identifier */
    creds.authzid = gsasl_property_fast(sd, GSASL_AUTHZID);
    creds.authnid = gsasl_property_fast(sd, GSASL_AUTHID);
    creds.realm   = gsasl_property_fast(sd, GSASL_REALM);

    if(0 && ctx && ctx->cb) { /* not supported yet */
        if((ctx->cb)(sx_sasl_cb_CHECK_AUTHZID, &creds, NULL, s, ctx->cbarg)!=sx_sasl_ret_OK) {
            _sx_debug(ZONE, "stream authzid: %s verification failed, not advancing to auth state", creds.authzid);
            free(method);
            return;
        }
    } else if (NULL != gsasl_property_fast(sd, GSASL_GSSAPI_DISPLAY_NAME)) {
        creds.authzid = strdup(gsasl_property_fast(sd, GSASL_GSSAPI_DISPLAY_NAME));
        authzid = NULL;
    } else {
        /* override unchecked arbitrary authzid */
        if(creds.realm && creds.realm[0] != '\0') {
            realm = creds.realm;
        } else {
            realm = s->req_to;
        }
        authzid = (char *) malloc(sizeof(char) * (strlen(creds.authnid) + strlen(realm) + 2));
        sprintf(authzid, "%s@%s", creds.authnid, realm);
        creds.authzid = authzid;
    }

    /* proceed stream to authenticated state */
    sx_auth(s, method, creds.authzid);

    free(method);
    if(authzid) free(authzid);
}

/** make the stream authenticated second time round */
static void _sx_sasl_stream(sx_t s, sx_plugin_t p) {
    Gsasl_session *sd = (Gsasl_session *) s->plugin_data[p->index];

    /* do nothing the first time */
    if(sd == NULL)
        return;

    /* are we auth'd? */
    if(NULL == gsasl_property_fast(sd, GSASL_AUTHID)) {
        _sx_debug(ZONE, "not auth'd, not advancing to auth'd state yet");
        return;
    }

    /* otherwise, its auth time */
    _sx_sasl_open(s, sd);
}

static void _sx_sasl_features(sx_t s, sx_plugin_t p, nad_t nad) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    Gsasl_session *sd = (Gsasl_session *) s->plugin_data[p->index];
    int nmechs, ret;
    char *mechs, *mech, *c;

    if(s->type != type_SERVER)
        return;

    if(sd != NULL) {
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
    
    ret = gsasl_server_mechlist(ctx->gsasl_ctx, &mechs);
    if(ret != GSASL_OK) {
        _sx_debug(ZONE, "gsasl_server_mechlist failed (%d): %s, not offering sasl for this conn", ret, gsasl_strerror (ret));
        return;
    }

    mech = mechs;
    nmechs = 0;
    while(mech != NULL) {
        c = strchr(mech, ' ');
        if(c != NULL)
            *c = '\0';

        if ((ctx->cb)(sx_sasl_cb_CHECK_MECH, mech, NULL, s, ctx->cbarg)==sx_sasl_ret_OK) {
            if (nmechs == 0) {
                int ns = nad_add_namespace(nad, uri_SASL, NULL);
                nad_append_elem(nad, ns, "mechanisms", 1);
            }
            _sx_debug(ZONE, "offering mechanism: %s", mech);

            nad_append_elem(nad, -1 /*ns*/, "mechanism", 2);
            nad_append_cdata(nad, mech, strlen(mech), 3);
            nmechs++;
        }

        if(c == NULL)
            mech = NULL;
        else
            mech = ++c;
    }
    
    free(mechs);
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
static void _sx_sasl_client_process(sx_t s, sx_plugin_t p, Gsasl_session *sd, const char *mech, const char *in, int inlen) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    _sx_sasl_sess_t sctx = NULL;
    char *buf = NULL, *out = NULL, *realm = NULL, **ext_id;
    char hostname[256];
    int ret;
#ifdef HAVE_SSL
    int i;
#endif
    size_t buflen, outlen;

    if(mech != NULL) {
        _sx_debug(ZONE, "auth request from client (mechanism=%s)", mech);

        if(!gsasl_server_support_p(ctx->gsasl_ctx, mech)) {
             _sx_debug(ZONE, "client requested mechanism (%s) that we didn't offer", mech);
             _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_INVALID_MECHANISM), 0);
             return;
        }

        /* startup */
        ret = gsasl_server_start(ctx->gsasl_ctx, mech, &sd);
        if(ret != GSASL_OK) {
            _sx_debug(ZONE, "gsasl_server_start failed, no sasl for this conn; (%d): %s", ret, gsasl_strerror(ret));
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_TEMPORARY_FAILURE), 0);
            return;
        }

        /* get the realm */
        if(ctx->cb != NULL)
            (ctx->cb)(sx_sasl_cb_GET_REALM, NULL, (void **) &realm, s, ctx->cbarg);

        /* cleanup any existing session context */ 
        sctx = gsasl_session_hook_get(sd);
        if (sctx != NULL) free(sctx);

        /* allocate and initialize our per session context */
        sctx = (_sx_sasl_sess_t) calloc(1, sizeof(struct _sx_sasl_sess_st));
        sctx->s = s;
        sctx->ctx = ctx;
        gsasl_session_hook_set(sd, (void *) sctx);
        gsasl_property_set(sd, GSASL_SERVICE, ctx->appname);
        gsasl_property_set(sd, GSASL_REALM, realm);

        /* get hostname */
        hostname[0] = '\0';
        gethostname(hostname, 256);
        hostname[255] = '\0';
        gsasl_property_set(sd, GSASL_HOSTNAME, hostname);

        /* get EXTERNAL data from the ssl plugin */
        ext_id = NULL;
#ifdef HAVE_SSL
        for(i = 0; i < s->env->nplugins; i++)
            if(s->env->plugins[i]->magic == SX_SSL_MAGIC && s->plugin_data[s->env->plugins[i]->index] != NULL)
                ext_id = ((_sx_ssl_conn_t) s->plugin_data[s->env->plugins[i]->index])->external_id;
        if (ext_id != NULL) {
            //_sx_debug(ZONE, "sasl context ext id '%s'", ext_id);
            /* if there is, store it for later */
            for (i = 0; i < SX_CONN_EXTERNAL_ID_MAX_COUNT; i++)
                if (ext_id[i] != NULL) {
                    ctx->ext_id[i] = strdup(ext_id[i]);
                } else {
                    ctx->ext_id[i] = NULL;
                    break;
                }
        }
#endif

        _sx_debug(ZONE, "sasl context initialised for %d", s->tag);

        s->plugin_data[p->index] = (void *) sd;

        if(strcmp(mech, "ANONYMOUS") == 0) {
            /*
             * special case for SASL ANONYMOUS: ignore the initial
             * response provided by the client and generate a random
             * authid to use as the jid node for the user, as
             * specified in XEP-0175
             */
            (ctx->cb)(sx_sasl_cb_GEN_AUTHZID, NULL, (void **)&out, s, ctx->cbarg);
            buf = strdup(out);
            buflen = strlen(buf);
        } else if (strstr(in, "<") != NULL && strncmp(in, "=", strstr(in, "<") - in ) == 0) {
            /* XXX The above check is hackish, but `in` is just weird */
            /* This is a special case for SASL External c2s. See XEP-0178 */
            _sx_debug(ZONE, "gsasl auth string is empty");
            buf = strdup("");
            buflen = strlen(buf);
        } else {
            /* decode and process */
            ret = gsasl_base64_from(in, inlen, &buf, &buflen);
            if (ret != GSASL_OK) {
                _sx_debug(ZONE, "gsasl_base64_from failed, no sasl for this conn; (%d): %s", ret, gsasl_strerror(ret));
                _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_INCORRECT_ENCODING), 0);
                if(buf != NULL) free(buf);
                return;
            }
        }

        ret = gsasl_step(sd, buf, buflen, &out, &outlen);
        if(ret != GSASL_OK && ret != GSASL_NEEDS_MORE) {
            _sx_debug(ZONE, "gsasl_step failed, no sasl for this conn; (%d): %s", ret, gsasl_strerror(ret));
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_MALFORMED_REQUEST), 0);
            if(out != NULL) free(out);
            if(buf != NULL) free(buf);
            return;
        }
    }

    else {
        /* decode and process */
        ret = gsasl_base64_from(in, inlen, &buf, &buflen);
        if (ret != GSASL_OK) {
            _sx_debug(ZONE, "gsasl_base64_from failed, no sasl for this conn; (%d): %s", ret, gsasl_strerror(ret));
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_INCORRECT_ENCODING), 0);
            return;
        }

        if(!sd) {
            _sx_debug(ZONE, "response send before auth request enabling mechanism (decoded: %.*s)", buflen, buf);
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_MECH_TOO_WEAK), 0);
            if(buf != NULL) free(buf);
            return;
        }
        _sx_debug(ZONE, "response from client (decoded: %.*s)", buflen, buf);
        ret = gsasl_step(sd, buf, buflen, &out, &outlen);
    }

    if(buf != NULL) free(buf);

    /* auth completed */
    if(ret == GSASL_OK) {
        _sx_debug(ZONE, "sasl handshake completed");

        /* encode the leftover response */
        ret = gsasl_base64_to(out, outlen, &buf, &buflen);
        if (ret == GSASL_OK) {
            /* send success */
            _sx_nad_write(s, _sx_sasl_success(s, buf, buflen), 0);
            free(buf);

            /* set a notify on the success nad buffer */
            ((sx_buf_t) s->wbufq->front->data)->notify = _sx_sasl_notify_success;
            ((sx_buf_t) s->wbufq->front->data)->notify_arg = (void *) p;
        }
        else {
            _sx_debug(ZONE, "gsasl_base64_to failed, no sasl for this conn; (%d): %s", ret, gsasl_strerror(ret));
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_INCORRECT_ENCODING), 0);
            if(buf != NULL) free(buf);
        }

        if(out != NULL) free(out);

        return;
    }

    /* in progress */
    if(ret == GSASL_NEEDS_MORE) {
        _sx_debug(ZONE, "sasl handshake in progress (challenge: %.*s)", outlen, out);

        /* encode the challenge */
        ret = gsasl_base64_to(out, outlen, &buf, &buflen);
        if (ret == GSASL_OK) {
            _sx_nad_write(s, _sx_sasl_challenge(s, buf, buflen), 0);
            free(buf);
        }
        else {
            _sx_debug(ZONE, "gsasl_base64_to failed, no sasl for this conn; (%d): %s", ret, gsasl_strerror(ret));
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_INCORRECT_ENCODING), 0);
            if(buf != NULL) free(buf);
        }

        if(out != NULL) free(out);

        return;
    }

    if(out != NULL) free(out);

    /* its over */
    _sx_debug(ZONE, "sasl handshake failed; (%d): %s", ret, gsasl_strerror(ret));

    /* !!! TODO XXX check ret and flag error appropriately */
    _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_MALFORMED_REQUEST), 0);
}

/** process handshake packets from the server */
static void _sx_sasl_server_process(sx_t s, sx_plugin_t p, Gsasl_session *sd, const char *in, int inlen) {
    char *buf = NULL, *out = NULL;
    size_t buflen, outlen;
    int ret;

    _sx_debug(ZONE, "data from client");

    /* decode the response */
    ret = gsasl_base64_from(in, inlen, &buf, &buflen);

    if (ret == GSASL_OK) {
        _sx_debug(ZONE, "decoded data: %.*s", buflen, buf);
    
        /* process the data */
        ret = gsasl_step(sd, buf, buflen, &out, &outlen);
        if(buf != NULL) free(buf); buf = NULL;
    
        /* in progress */
        if(ret == GSASL_OK || ret == GSASL_NEEDS_MORE) {
            _sx_debug(ZONE, "sasl handshake in progress (response: %.*s)", outlen, out);
    
            /* encode the response */
            ret = gsasl_base64_to(out, outlen, &buf, &buflen);

            if (ret == GSASL_OK) {
                _sx_nad_write(s, _sx_sasl_response(s, buf, buflen), 0);
            }

            if(out != NULL) free(out);
            if(buf != NULL) free(buf);
    
            return;
        }
    }
    if(out != NULL) free(out);
    if(buf != NULL) free(buf);

    /* its over */
    _sx_debug(ZONE, "sasl handshake aborted; (%d): %s", ret, gsasl_strerror(ret));

    _sx_nad_write(s, _sx_sasl_abort(s), 0);
}

/** main nad processor */
static int _sx_sasl_process(sx_t s, sx_plugin_t p, nad_t nad) {
    Gsasl_session *sd = (Gsasl_session *) s->plugin_data[p->index];
    int attr;
    char mech[128];
    sx_error_t sxe;
    int flags;
    char *ns = NULL, *to = NULL, *from = NULL, *version = NULL;

    /* only want sasl packets */
    if(NAD_ENS(nad, 0) < 0 || NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_SASL) || strncmp(NAD_NURI(nad, NAD_ENS(nad, 0)), uri_SASL, strlen(uri_SASL)) != 0)
        return 1;

    /* quietly drop it if sasl is disabled, or if not ready */
    if(s->state != state_STREAM) {
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
            _sx_sasl_client_process(s, p, sd, mech, NAD_CDATA(nad, 0), NAD_CDATA_L(nad, 0));

            nad_free(nad);
            return 0;
        }

        /* response */
        else if(NAD_ENAME_L(nad, 0) == 8 && strncmp("response", NAD_ENAME(nad, 0), NAD_ENAME_L(nad, 0)) == 0) {
            /* process it */
            _sx_sasl_client_process(s, p, sd, NULL, NAD_CDATA(nad, 0), NAD_CDATA_L(nad, 0));

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
            _sx_sasl_server_process(s, p, sd, NAD_CDATA(nad, 0), NAD_CDATA_L(nad, 0));

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
            gsasl_finish(sd);

            s->plugin_data[p->index] = NULL;

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
    Gsasl_session *sd = (Gsasl_session *) s->plugin_data[p->index];
    _sx_sasl_sess_t sctx;

    if(sd == NULL)
        return;

    _sx_debug(ZONE, "cleaning up conn state");

    /* we need to clean up our per session context but keep sasl ctx */
    sctx = gsasl_session_hook_get(sd);
    if (sctx != NULL){
        free(sctx);
        gsasl_session_hook_set(sd, (void *) NULL);
    }

    gsasl_finish(sd);
    s->plugin_data[p->index] = NULL;
}

static int _sx_sasl_gsasl_callback(Gsasl *gsasl_ctx, Gsasl_session *sd, Gsasl_property prop) {
    _sx_sasl_sess_t sctx = gsasl_session_hook_get(sd);
    _sx_sasl_t ctx = NULL;
    struct sx_sasl_creds_st creds = {NULL, NULL, NULL, NULL};
    char *value, *node, *host;
    int len, i;

    /*
     * session hook data is not always available while its being set up,
     * also not needed in many of the cases below.
     */
     if(sctx != NULL) {
         ctx = sctx->ctx;
     }

    _sx_debug(ZONE, "in _sx_sasl_gsasl_callback, property: %d", prop);

    switch(prop) {
        case GSASL_PASSWORD:
            /* GSASL_AUTHID, GSASL_AUTHZID, GSASL_REALM */
            assert((ctx->cb != NULL));
            creds.authnid = gsasl_property_fast(sd, GSASL_AUTHID);
            creds.realm   = gsasl_property_fast(sd, GSASL_REALM);
            if(!creds.authnid) return GSASL_NO_AUTHID;
            if(!creds.realm) return GSASL_NO_AUTHZID;
            if((ctx->cb)(sx_sasl_cb_GET_PASS, &creds, (void **)&value, sctx->s, ctx->cbarg) == sx_sasl_ret_OK) {
                gsasl_property_set(sd, GSASL_PASSWORD, value);
            }
            return GSASL_NEEDS_MORE;

        case GSASL_SERVICE:
            gsasl_property_set(sd, GSASL_SERVICE, "xmpp");
            return GSASL_OK;

        case GSASL_HOSTNAME:
            { 
                char hostname[256];
                /* get hostname */
                hostname[0] = '\0';
                gethostname(hostname, 256);
                hostname[255] = '\0';

                gsasl_property_set(sd, GSASL_HOSTNAME, hostname);
           }
           return GSASL_OK;

        case GSASL_VALIDATE_SIMPLE:
            /* GSASL_AUTHID, GSASL_AUTHZID, GSASL_PASSWORD */
            assert((ctx->cb != NULL));
            creds.authnid = gsasl_property_fast(sd, GSASL_AUTHID);
            creds.realm   = gsasl_property_fast(sd, GSASL_REALM);
            creds.pass    = gsasl_property_fast(sd, GSASL_PASSWORD);
            if(!creds.authnid) return GSASL_NO_AUTHID;
            if(!creds.realm) return GSASL_NO_AUTHZID;
            if(!creds.pass) return GSASL_NO_PASSWORD;
            if((ctx->cb)(sx_sasl_cb_CHECK_PASS, &creds, NULL, sctx->s, ctx->cbarg) == sx_sasl_ret_OK)
                return GSASL_OK;
            else
                return GSASL_AUTHENTICATION_ERROR;

        case GSASL_VALIDATE_GSSAPI:
            /* GSASL_AUTHZID, GSASL_GSSAPI_DISPLAY_NAME */
            creds.authnid = gsasl_property_fast(sd, GSASL_GSSAPI_DISPLAY_NAME);
            if(!creds.authnid) return GSASL_NO_AUTHID;
            creds.authzid = gsasl_property_fast(sd, GSASL_AUTHZID);
            if(!creds.authzid) return GSASL_NO_AUTHZID;
            gsasl_property_set(sd, GSASL_AUTHID, creds.authnid);
            return GSASL_OK;

        case GSASL_VALIDATE_ANONYMOUS:
            /* GSASL_ANONYMOUS_TOKEN */
            creds.authnid = gsasl_property_fast(sd, GSASL_ANONYMOUS_TOKEN);
            if(!creds.authnid) return GSASL_NO_ANONYMOUS_TOKEN;
            /* set token as authid for later use */
            gsasl_property_set(sd, GSASL_AUTHID, creds.authnid);
            return GSASL_OK;

        case GSASL_VALIDATE_EXTERNAL:
            /* GSASL_AUTHID */
            creds.authzid = gsasl_property_fast(sd, GSASL_AUTHZID);
            _sx_debug(ZONE, "sasl external");
            _sx_debug(ZONE, "sasl creds.authzid is '%s'", creds.authzid);

            for (i = 0; i < SX_CONN_EXTERNAL_ID_MAX_COUNT; i++) {
                if (ctx->ext_id[i] == NULL)
                    break;
                _sx_debug(ZONE, "sasl ext_id(%d) is '%s'", i, ctx->ext_id[i]);
                /* XXX hackish.. detect c2s by existance of @ */
                value = strstr(ctx->ext_id[i], "@");

                if(value == NULL && creds.authzid != NULL && strcmp(ctx->ext_id[i], creds.authzid) == 0) {
                    // s2s connection and it's valid
                    /* TODO Handle wildcards and other thigs from XEP-0178 */
                    _sx_debug(ZONE, "sasl ctx->ext_id doesn't have '@' in it. Assuming s2s");
                    return GSASL_OK;
                }
                if(value != NULL &&
                    ((creds.authzid != NULL && strcmp(ctx->ext_id[i], creds.authzid) == 0) ||
                     (creds.authzid == NULL)) ) {
                    // c2s connection
                    // creds.authzid == NULL condition is from XEP-0178 '=' auth reply

                    // This should be freed by gsasl_finish() but I'm not sure
                    // node  = authnid
                    len = value - ctx->ext_id[i];
                    node = (char *) malloc(sizeof(char) * (len + 1)); // + null termination
                    strncpy(node, ctx->ext_id[i], len);
                    node[len] = '\0'; // null terminate the string
                    // host = realm
                    len = strlen(value) - 1 + 1; // - the @ + null termination
                    host = (char *) malloc(sizeof(char) * (len));
                    strcpy(host, value + 1); // skip the @
                    gsasl_property_set(sd, GSASL_AUTHID, node);
                    gsasl_property_set(sd, GSASL_REALM, host);
                    return GSASL_OK;
                }

            }
            return GSASL_AUTHENTICATION_ERROR;

        default:
            break;
    }

    return GSASL_NO_CALLBACK;
}

static void _sx_sasl_unload(sx_plugin_t p) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    int i;

    if (ctx->gsasl_ctx != NULL) gsasl_done (ctx->gsasl_ctx);
    if (ctx->appname != NULL) free(ctx->appname);
    for (i = 0; i < SX_CONN_EXTERNAL_ID_MAX_COUNT; i++)
        if(ctx->ext_id[i] != NULL)
            free(ctx->ext_id[i]);
        else
            break;

    if (ctx != NULL) free(ctx);
}

/** args: appname, callback, cb arg */
int sx_sasl_init(sx_env_t env, sx_plugin_t p, va_list args) {
    const char *appname;
    sx_sasl_callback_t cb;
    void *cbarg;
    _sx_sasl_t ctx;
    int ret, i;

    _sx_debug(ZONE, "initialising sasl plugin");

    appname = va_arg(args, const char *);
    if(appname == NULL) {
        _sx_debug(ZONE, "appname was NULL, failing");
        return 1;
    }

    cb = va_arg(args, sx_sasl_callback_t);
    cbarg = va_arg(args, void *);

    ctx = (_sx_sasl_t) calloc(1, sizeof(struct _sx_sasl_st));

    ctx->appname = strdup(appname);
    ctx->cb = cb;
    ctx->cbarg = cbarg;
    for (i = 0; i < SX_CONN_EXTERNAL_ID_MAX_COUNT; i++)
        ctx->ext_id[i] = NULL;

    ret = gsasl_init(&ctx->gsasl_ctx);
    if(ret != GSASL_OK) {
        _sx_debug(ZONE, "couldn't initialize libgsasl (%d): %s", ret, gsasl_strerror (ret));
        free(ctx);
        return 1;
    }

    gsasl_callback_set (ctx->gsasl_ctx, &_sx_sasl_gsasl_callback);

    _sx_debug(ZONE, "sasl context initialised");

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

/** kick off the auth handshake */
int sx_sasl_auth(sx_plugin_t p, sx_t s, const char *appname, const char *mech, const char *user, const char *pass) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    _sx_sasl_sess_t sctx = NULL;
    Gsasl_session *sd;
    char *buf = NULL, *out = NULL;
    char hostname[256];
    int ret, ns;
    size_t buflen, outlen;
    nad_t nad;

    assert((p != NULL));
    assert((s != NULL));
    assert((appname != NULL));
    assert((mech != NULL));
    assert((user != NULL));
    assert((pass != NULL));

    if(s->type != type_CLIENT || s->state != state_STREAM) {
        _sx_debug(ZONE, "need client in stream state for sasl auth");
        return 1;
     }
    
    /* handshake start */
    ret = gsasl_client_start(ctx->gsasl_ctx, mech, &sd);
    if(ret != GSASL_OK) {
        _sx_debug(ZONE, "gsasl_client_start failed, not authing; (%d): %s", ret, gsasl_strerror(ret));

        return 1;
    }

    /* get hostname */
    hostname[0] = '\0';
    gethostname(hostname, 256);
    hostname[255] = '\0';

    /* cleanup any existing session context */ 
    sctx = gsasl_session_hook_get(sd);
    if (sctx != NULL) free(sctx);

    /* allocate and initialize our per session context */
    sctx = (_sx_sasl_sess_t) calloc(1, sizeof(struct _sx_sasl_sess_st));
    sctx->s = s;
    sctx->ctx = ctx;

    /* set user data in session handle */
    gsasl_session_hook_set(sd, (void *) sctx);
    gsasl_property_set(sd, GSASL_AUTHID, user);
    gsasl_property_set(sd, GSASL_PASSWORD, pass);
    gsasl_property_set(sd, GSASL_SERVICE, appname);
    gsasl_property_set(sd, GSASL_HOSTNAME, hostname);

    /* handshake step */
    ret = gsasl_step(sd, NULL, 0, &out, &outlen);
    if(ret != GSASL_OK && ret != GSASL_NEEDS_MORE) {
        _sx_debug(ZONE, "gsasl_step failed, not authing; (%d): %s", ret, gsasl_strerror(ret));

        gsasl_finish(sd);

        return 1;
    }

    /* save userdata */
    s->plugin_data[p->index] = (void *) sd;

    /* in progress */
    _sx_debug(ZONE, "sending auth request to server, mech '%s': %.*s", mech, outlen, out);

    /* encode the challenge */
    ret = gsasl_base64_to(out, outlen, &buf, &buflen);
    if(ret != GSASL_OK) {
        _sx_debug(ZONE, "gsasl_base64_to failed, not authing; (%d): %s", ret, gsasl_strerror(ret));

        gsasl_finish(sd);

        if (out != NULL) free(out);
        return 1;
    }
    free(out);

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
