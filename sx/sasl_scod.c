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

#error SCOD implementation is currently broken. If you have the guts, please fix it and share your changes.

#include "sx.h"
#include "sasl.h"
#include "sx/scod/scod.h"

/** our context */
typedef struct _sx_sasl_st {
    scod_ctx_t                  scod_ctx;

    sx_sasl_callback_t          cb;
    void                        *cbarg;

    int                         flags;
} *_sx_sasl_t;

/* mechanisms to offer */
#define SX_SASL_MECH_ANONYMOUS  (1<<4)
#define SX_SASL_MECH_PLAIN      (1<<5)
#define SX_SASL_MECH_DIGESTMD5  (1<<6)

/** move the stream to the auth state */
void _sx_sasl_open(sx_t s, scod_t sd) {
    char *method;
    
    /* get the method */
    method = (char *) malloc(sizeof(char) * (strlen(sd->mech->name) + 6));
    sprintf(method, "SASL/%s", sd->mech->name);

    /* schwing! */
    sx_auth(s, method, sd->authzid);

    free(method);
}

/** make the stream suthenticated second time round */
static void _sx_sasl_stream(sx_t s, sx_plugin_t p) {
    scod_t sd = (scod_t) s->plugin_data[p->index];

    /* do nothing the first time */
    if(sd == NULL)
        return;

    /* are we auth'd? */
    if(!sd->authd) {
        _sx_debug(ZONE, "not auth'd, not advancing to auth'd state yet");
        return;
    }

    /* otherwise, its auth time */
    _sx_sasl_open(s, sd);
}

static void _sx_sasl_features(sx_t s, sx_plugin_t p, nad_t nad) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    scod_t sd = (scod_t) s->plugin_data[p->index];
    int i, ns;

    if(s->type != type_SERVER)
        return;

    if(sd != NULL && sd->authd) {
        _sx_debug(ZONE, "already auth'd, not offering sasl mechanisms");
        return;
    }

    if(!(s->flags & SX_SASL_OFFER)) {
        _sx_debug(ZONE, "application didn't ask us to offer sasl, so we won't");
        return;
    }

    if(!(s->flags & SX_SASL_MECH_ANONYMOUS || s->flags & SX_SASL_MECH_PLAIN || s->flags & SX_SASL_MECH_DIGESTMD5)) {
        _sx_debug(ZONE, "application didn't provide any mechanisms we can offer");
        return;
    }

#ifdef HAVE_SSL
    if((s->flags & SX_SSL_STARTTLS_REQUIRE) && s->ssf == 0) {
        _sx_debug(ZONE, "ssl not established yet but the app requires it, not offering mechanisms");
        return;
    }
#endif
    
    _sx_debug(ZONE, "offering sasl mechanisms");
    
    ns = nad_add_namespace(nad, uri_SASL, NULL);
    nad_append_elem(nad, ns, "mechanisms", 1);

    for(i = 0; i < ctx->scod_ctx->nmechs; i++)
        if(ctx->scod_ctx->mechs[i]->flags == 0 || ctx->flags & ctx->scod_ctx->mechs[i]->flags) {
            if((s->flags & SX_SASL_MECH_ANONYMOUS && strcmp("ANONYMOUS", ctx->scod_ctx->names[i]) == 0) ||
               (s->flags & SX_SASL_MECH_PLAIN && strcmp("PLAIN", ctx->scod_ctx->names[i]) == 0) ||
               (s->flags & SX_SASL_MECH_DIGESTMD5 && strcmp("DIGEST-MD5", ctx->scod_ctx->names[i]) == 0)) {
                _sx_debug(ZONE, "offering mechanism: %s", ctx->scod_ctx->names[i]);

                nad_append_elem(nad, ns, "mechanism", 2);
                nad_append_cdata(nad, ctx->scod_ctx->names[i], strlen(ctx->scod_ctx->names[i]), 3);
            }
        }
}

/** utility: generate a success nad */
static nad_t _sx_sasl_success(sx_t s) {
    nad_t nad;
    int ns;

    nad = nad_new(s->nad_cache);
    ns = nad_add_namespace(nad, uri_SASL, NULL);

    nad_append_elem(nad, ns, "success", 0);

    return nad;
}

/** utility: generate a failure nad */
static nad_t _sx_sasl_failure(sx_t s, const char *err) {
    nad_t nad;
    int ns;

    nad = nad_new(s->nad_cache);
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

    nad = nad_new(s->nad_cache);
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

    nad = nad_new(s->nad_cache);
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

    nad = nad_new(s->nad_cache);
    ns = nad_add_namespace(nad, uri_SASL, NULL);

    nad_append_elem(nad, ns, "abort", 0);

    return nad;
}

/** utility: decode incoming handshake data */
static void _sx_sasl_decode(char *in, int inlen, char **out, int *outlen) {
    *outlen = apr_base64_decode_len(in, inlen);
    *out = (char *) malloc(sizeof(char) * (*outlen + 1));
    apr_base64_decode(*out, in, inlen);
}

/** utility: encode outgoing handshake data */
static void _sx_sasl_encode(char *in, int inlen, char **out, int *outlen) {
    *outlen = apr_base64_encode_len(inlen);
    *out = (char *) malloc(sizeof(char) * *outlen);
    apr_base64_encode(*out, in, inlen);
    (*outlen)--;
}

/** auth done, restart the stream */
static void _sx_sasl_notify_success(sx_t s, void *arg) {
    _sx_debug(ZONE, "auth completed, resetting");

    _sx_reset(s);

    sx_server_init(s, s->flags);
}

/** process handshake packets from the client */
static void _sx_sasl_client_process(sx_t s, sx_plugin_t p, scod_t sd, char *mech, char *in, int inlen) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    char realm[256];
    char *buf = NULL, *out = NULL;
    int buflen, outlen, ret;

    if(mech != NULL) {
        _sx_debug(ZONE, "auth request from client (mechanism=%s)", mech);

        if(!((s->flags & SX_SASL_MECH_ANONYMOUS && strcmp("ANONYMOUS", mech) == 0) ||
             (s->flags & SX_SASL_MECH_PLAIN && strcmp("PLAIN", mech) == 0) ||
             (s->flags & SX_SASL_MECH_DIGESTMD5 && strcmp("DIGEST-MD5", mech) == 0))) {
             _sx_debug(ZONE, "client requested mechanism that we didn't offer");
             _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_INVALID_MECHANISM), 0);
             return;
        }

        /* startup */
        sd = scod_new(ctx->scod_ctx, sd_type_SERVER);
        if(sd == NULL) {
            _sx_debug(ZONE, "scod_new failed, no sasl for this conn");
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_TEMPORARY_FAILURE), 0);
            return;
        }

        _sx_debug(ZONE, "sasl context initialised for %d", s->tag);

        s->plugin_data[p->index] = (void *) sd;

        sd->app_private = (void *) s;

        /* get the realm */
        realm[0] = '\0';
        assert((ctx->cb != NULL));
        (ctx->cb)(sx_sasl_cb_GET_REALM, (void *) s, (void **) realm, s, ctx->cbarg);

        /* decode and process */
        _sx_sasl_decode(in, inlen, &buf, &buflen);
        ret = scod_server_start(sd, mech, realm, buf, buflen, &out, &outlen);
    }

    else {
        /* decode and process */
        _sx_sasl_decode(in, inlen, &buf, &buflen);
        if(!sd) {
            _sx_debug(ZONE, "response send before auth request enabling mechanism (decoded: %.*s)", buflen, buf);
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_MECH_TOO_WEAK), 0);
            if(buf != NULL) free(buf);
            return;
        }
        _sx_debug(ZONE, "response from client (decoded: %.*s)", buflen, buf);
        ret = scod_server_step(sd, buf, buflen, &out, &outlen);
    }

    if(buf != NULL) free(buf);

    /* auth completed */
    if(ret == sd_SUCCESS) {
        _sx_debug(ZONE, "sasl handshake completed");

        if(out != NULL) free(out);

        /* send success */
        _sx_nad_write(s, _sx_sasl_success(s), 0);

        /* set a notify on the success nad buffer */
        ((sx_buf_t) s->wbufq->front->data)->notify = _sx_sasl_notify_success;
        ((sx_buf_t) s->wbufq->front->data)->notify_arg = (void *) p;

        return;
    }

    /* in progress */
    if(ret == sd_CONTINUE) {
        _sx_debug(ZONE, "sasl handshake in progress (challenge: %.*s)", outlen, out);

        /* encode the challenge */
        _sx_sasl_encode(out, outlen, &buf, &buflen);
        
        if(out != NULL) free(out);

        _sx_nad_write(s, _sx_sasl_challenge(s, buf, buflen), 0);

        free(buf);

        return;
    }

    if(out != NULL) free(out);

    /* its over */
    _sx_debug(ZONE, "sasl handshake failed: (%d)", ret);

    /* !!! check ret and flag error appropriately */
    _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_MALFORMED_REQUEST), 0);
}

/** process handshake packets from the server */
static void _sx_sasl_server_process(sx_t s, sx_plugin_t p, scod_t sd, char *in, int inlen) {
    char *buf, *out;
    int buflen, outlen, ret;

    _sx_debug(ZONE, "challenge from client");

    /* decode the response */
    _sx_sasl_decode(in, inlen, &buf, &buflen);

    /* process the data */
    ret = scod_client_step(sd, buf, buflen, &out, &outlen);
    if(buf != NULL) free(buf);

    /* in progress */
    if(ret == sd_SUCCESS || ret == sd_CONTINUE) {
        _sx_debug(ZONE, "sasl handshake in progress (response: %.*s)", outlen, out);

        /* encode the response */
        _sx_sasl_encode(out, outlen, &buf, &buflen);

        if(out != NULL) free(out);

        _sx_nad_write(s, _sx_sasl_response(s, buf, buflen), 0);

        if(buf != NULL) free(buf);

        return;
    }

    if(out != NULL) free(out);

    /* its over */
    _sx_debug(ZONE, "sasl handshake aborted: (%d)", ret);

    _sx_nad_write(s, _sx_sasl_abort(s), 0);
}

/** main nad processor */
static int _sx_sasl_process(sx_t s, sx_plugin_t p, nad_t nad) {
    scod_t sd = (scod_t) s->plugin_data[p->index];
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
            scod_free(sd);

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
    scod_t sd = (scod_t) s->plugin_data[p->index];

    if(sd == NULL)
        return;

    _sx_debug(ZONE, "cleaning up conn state");

    scod_free(sd);
    s->plugin_data[p->index] = NULL;
}

static int _sx_sasl_scod_callback(scod_t sd, int cb, void *arg, void **res, void *cbarg) {
    _sx_sasl_t ctx = (_sx_sasl_t) cbarg;
    xht realms;

    switch(cb) {
        case sd_cb_DIGEST_MD5_CHOOSE_REALM:
            realms = (xht) arg;
            if(xhash_iter_first(realms))
                xhash_iter_get(realms, (const char **) res, NULL);
            else
                *res = NULL;
            break;

        case sd_cb_GET_PASS:
            assert((ctx->cb != NULL));
            return (ctx->cb)(sx_sasl_cb_GET_PASS, arg, res, NULL, ctx->cbarg);

        case sd_cb_CHECK_PASS:
            assert((ctx->cb != NULL));
            return (ctx->cb)(sx_sasl_cb_CHECK_PASS, arg, res, NULL, ctx->cbarg);

        case sd_cb_CHECK_AUTHZID:
            assert((ctx->cb != NULL));
            return (ctx->cb)(sx_sasl_cb_CHECK_AUTHZID, arg, res, NULL, ctx->cbarg);

        case sd_cb_ANONYMOUS_GEN_AUTHZID:
            assert((ctx->cb != NULL));
            return (ctx->cb)(sx_sasl_cb_GEN_AUTHZID, arg, res, NULL, ctx->cbarg);

        default:
            break;
    }

    return 0;
}

static void _sx_sasl_unload(sx_plugin_t p) {
    scod_ctx_free( ((_sx_sasl_t) p->private)->scod_ctx);
    free(p->private);
}

/** args: realm callback, cb arg, scod flags */
int sx_sasl_init(sx_env_t env, sx_plugin_t p, va_list args) {
    sx_sasl_callback_t cb;
    void *cbarg;
    int flags;
    _sx_sasl_t ctx;

    _sx_debug(ZONE, "initialising sasl plugin");

    cb = va_arg(args, sx_sasl_callback_t);
    cbarg = va_arg(args, void *);
    flags = va_arg(args, int);

    ctx = (_sx_sasl_t) calloc(1, sizeof(struct _sx_sasl_st));

    ctx->cb = cb;
    ctx->cbarg = cbarg;
    ctx->flags = flags;

    ctx->scod_ctx = scod_ctx_new(_sx_sasl_scod_callback, ctx);
    if(ctx->scod_ctx == NULL) {
        _sx_debug(ZONE, "couldn't create scod context, disabling");
        free(ctx);
        return 1;
    }

    _sx_debug(ZONE, "sasl context initialised");

    p->private = (void *) ctx;

    p->unload = _sx_sasl_unload;

    p->stream = _sx_sasl_stream;
    p->features = _sx_sasl_features;
    p->process = _sx_sasl_process;

    p->free = _sx_sasl_free;

    return 0;
}

/** kick off the auth handshake */
int sx_sasl_auth(sx_plugin_t p, sx_t s, char *appname, char *mech, char *user, char *pass) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    scod_t sd;
    char *buf, *out;
    int ret, buflen, outlen, ns;
    nad_t nad;

    assert((p != NULL));
    assert((s != NULL));
    assert((mech != NULL));
    assert((user != NULL));
    assert((pass != NULL));

    if(s->type != type_CLIENT || s->state != state_STREAM) {
        _sx_debug(ZONE, "need client in stream state for sasl auth");
        return 1;
     }
    
    /* startup */
    sd = scod_new(ctx->scod_ctx, sd_type_CLIENT);
    if(sd == NULL) {
        _sx_debug(ZONE, "couldn't create scod instance, not authing");
        return 1;
    }

    /* handshake start */
    ret = scod_client_start(sd, mech, user, user, pass, &out, &outlen);
    if(ret != sd_SUCCESS && ret != sd_CONTINUE) {
        _sx_debug(ZONE, "scod_client_start failed (%d), not authing", ret);

        if(out != NULL) free(out);
        
        scod_free(sd);

        return 1;
    }

    /* save userdata */
    s->plugin_data[p->index] = (void *) sd;

    /* in progress */
    _sx_debug(ZONE, "sending auth request to server, mech '%s': %.*s", mech, outlen, out);

    /* encode the challenge */
    _sx_sasl_encode(out, outlen, &buf, &buflen);
    free(out);

    /* build the nad */
    nad = nad_new(s->nad_cache);
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
