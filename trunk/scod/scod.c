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

#include "scod.h"

extern int scod_mech_anonymous_init(scod_mech_t);
extern int scod_mech_digest_md5_init(scod_mech_t);
extern int scod_mech_plain_init(scod_mech_t);

scod_mech_init_fn mech_inits[] = {
    scod_mech_anonymous_init,
    scod_mech_digest_md5_init,
    scod_mech_plain_init,
    NULL
};

scod_ctx_t scod_ctx_new(scod_callback_t cb, void *cbarg) {
    int i = 0;
    scod_ctx_t ctx;
    scod_mech_t mech;

    assert((int) cb);

    log_debug(ZONE, "creating new scod context");

    ctx = (scod_ctx_t) malloc(sizeof(struct _scod_ctx_st));
    memset(ctx, 0, sizeof(struct _scod_ctx_st));

    ctx->cb = cb;
    ctx->cbarg = cbarg;

    while(mech_inits[i] != NULL) {
        mech = (scod_mech_t) malloc(sizeof(struct _scod_mech_st));
        memset(mech, 0, sizeof(struct _scod_mech_st));

        mech->ctx = ctx;

        if((mech_inits[i])(mech) != sd_SUCCESS) {
            log_debug(ZONE, "mech failed to init");
            free(mech);
        }

        else {
            ctx->mechs = (scod_mech_t *) realloc(ctx->mechs, sizeof(scod_mech_t) * (ctx->nmechs + 1));
            ctx->mechs[ctx->nmechs] = mech;

            ctx->names = (char **) realloc(ctx->names, sizeof(char *) * (ctx->nmechs + 1));
            ctx->names[ctx->nmechs] = strdup(mech->name);

            ctx->nmechs++;

            log_debug(ZONE, "mech '%s' initialised", mech->name);
        }

        i++;
    }

    if(ctx->nmechs == 0) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

void scod_ctx_free(scod_ctx_t ctx) {
    int i;

    assert((int) ctx);

    log_debug(ZONE, "freeing scod context");

    for(i = 0; i < ctx->nmechs; i++) {
        log_debug(ZONE, "freeing '%s' mech", ctx->mechs[i]->name);

        if(ctx->mechs[i]->free != NULL)
            (ctx->mechs[i]->free)(ctx->mechs[i]);

        free(ctx->mechs[i]);
        free(ctx->names[i]);
    }

    free(ctx->mechs);
    free(ctx->names);
    free(ctx);
}

int scod_mech_flags(scod_ctx_t ctx, char *name) {
    int i;

    assert((int) ctx);
    assert((int) name);

    for(i = 0; i < ctx->nmechs; i++)
        if(strcmp(ctx->mechs[i]->name, name) == 0)
            return ctx->mechs[i]->flags;

    return 0;
}

scod_t scod_new(scod_ctx_t ctx, scod_type_t type) {
    scod_t sd;

    assert((int) ctx);
    assert((int) (type == sd_type_CLIENT || type == sd_type_SERVER));

    log_debug(ZONE, "creating new scod");

    sd = (scod_t) malloc(sizeof(struct _scod_st));
    memset(sd, 0, sizeof(struct _scod_st));

    sd->ctx = ctx;

    sd->type = type;

    return sd;
}

void scod_free(scod_t sd) {
    assert((int) sd);

    log_debug(ZONE, "freeing scod");

    if(sd->authzid != NULL) free(sd->authzid);
    if(sd->authnid != NULL) free(sd->authnid);
    if(sd->pass != NULL) free(sd->pass);
    if(sd->realm != NULL) free(sd->realm);

    free(sd);
}

static scod_mech_t _scod_get_mech(scod_ctx_t ctx, char *name) {
    int i;

    log_debug(ZONE, "looking for mech '%s'", name);

    for(i = 0; i < ctx->nmechs; i++)
        if(strcmp(ctx->mechs[i]->name, name) == 0)
            return ctx->mechs[i];

    return NULL;
}

int scod_client_start(scod_t sd, char *name, char *authzid, char *authnid, char *pass, char **resp, int *resplen) {
    int ret;

    assert((int) sd);
    assert((int) name);
    assert((int) authnid);
    assert((int) pass);
    assert((int) resp);
    assert((int) resplen);

    *resp = NULL;
    *resplen = 0;

    if(sd->type != sd_type_CLIENT)
        return sd_err_WRONG_TYPE;

    if(sd->authd || sd->failed)
        return sd_err_COMPLETED;

    log_debug(ZONE, "client start; authzid=%s, authnid=%s, pass=%s", authzid, authnid, pass);

    if(sd->mech != NULL)
        return sd_err_IN_PROGRESS;

    if((sd->mech = _scod_get_mech(sd->ctx, name)) == NULL)
        return sd_err_UNKNOWN_MECH;

    if(authzid != NULL) sd->authzid = strdup(authzid);
    sd->authnid = strdup(authnid);
    sd->pass = strdup(pass);

    if(sd->mech->client_start != NULL)
        ret = (sd->mech->client_start)(sd->mech, sd, resp, resplen);
    else
        ret = sd_err_NOT_IMPLEMENTED;

    if(ret == sd_SUCCESS)
        sd->authd = 1;
    else if((ret & sd_auth_MASK) == sd_auth_MASK)
        sd->failed = 1;

    return ret;
}

int scod_client_step(scod_t sd, const char *chal, int challen, char **resp, int *resplen) {
    int ret;

    assert((int) sd);
    assert((int) chal);
    assert((int) challen);
    assert((int) resp);
    assert((int) resplen);

    *resp = NULL;
    *resplen = 0;

    if(sd->type != sd_type_CLIENT)
        return sd_err_WRONG_TYPE;

    if(sd->authd || sd->failed)
        return sd_err_COMPLETED;

    log_debug(ZONE, "client step");

    if(sd->mech->client_step != NULL)
        ret = (sd->mech->client_step)(sd->mech, sd, chal, challen, resp, resplen);
    else
        ret = sd_err_NOT_IMPLEMENTED;

    if(ret == sd_SUCCESS)
        sd->authd = 1;
    else if((ret & sd_auth_MASK) == sd_auth_MASK)
        sd->failed = 1;

    return ret;
}

int scod_server_start(scod_t sd, char *name, char *realm, const char *resp, int resplen, char **chal, int *challen) {
    int ret;

    assert((int) sd);
    assert((int) name);
    assert((int) resp);
    assert((int) chal);
    assert((int) challen);

    *chal = NULL;
    *challen = 0;

    if(sd->type != sd_type_SERVER)
        return sd_err_WRONG_TYPE;

    if(sd->authd || sd->failed)
        return sd_err_COMPLETED;

    log_debug(ZONE, "server start");

    if(sd->mech != NULL)
        return sd_err_IN_PROGRESS;

    if((sd->mech = _scod_get_mech(sd->ctx, name)) == NULL)
        return sd_err_UNKNOWN_MECH;

    if(realm != NULL)
        sd->realm = strdup(realm);

    if(sd->mech->server_start != NULL)
        ret = (sd->mech->server_start)(sd->mech, sd, resp, resplen, chal, challen);
    else
        ret = sd_err_NOT_IMPLEMENTED;

    if(ret == sd_SUCCESS)
        sd->authd = 1;
    else if((ret & sd_auth_MASK) == sd_auth_MASK)
        sd->failed = 1;

    return ret;
}

int scod_server_step(scod_t sd, const char *resp, int resplen, char **chal, int *challen) {
    int ret;

    assert((int) sd);
    assert((int) resp);
    assert((int) chal);
    assert((int) challen);

    *chal = NULL;
    *challen = 0;

    if(sd->type != sd_type_SERVER)
        return sd_err_WRONG_TYPE;

    if(sd->authd || sd->failed)
        return sd_err_COMPLETED;

    log_debug(ZONE, "server step");

    if(sd->mech->client_start != NULL)
        ret = (sd->mech->server_step)(sd->mech, sd, resp, resplen, chal, challen);
    else
        ret = sd_err_NOT_IMPLEMENTED;

    if(ret == sd_SUCCESS)
        sd->authd = 1;
    else if((ret & sd_auth_MASK) == sd_auth_MASK)
        sd->failed = 1;

    return ret;
}

int scod_sasl_encode(scod_t sd, const char *in, int inlen, char **out, char *outlen) {
    assert((int) sd);
    assert((int) in);
    assert((int) out);
    assert((int) outlen);

    log_debug(ZONE, "encode");

    if(sd->mech->encode != NULL)
        return (sd->mech->encode)(sd->mech, sd, in, inlen, out, outlen);

    *out = (char *) malloc(sizeof(char) * inlen);
    memcpy(*out, in, inlen);
    *outlen = inlen;

    return sd_SUCCESS;
}

int scod_sasl_decode(scod_t sd, const char *in, int inlen, char **out, char *outlen) {
    assert((int) sd);
    assert((int) in);
    assert((int) out);
    assert((int) outlen);

    log_debug(ZONE, "decode");

    if(sd->mech->decode != NULL)
        return (sd->mech->decode)(sd->mech, sd, in, inlen, out, outlen);

    *out = (char *) malloc(sizeof(char) * inlen);
    memcpy(*out, in, inlen);
    *outlen = inlen;

    return sd_SUCCESS;
}
