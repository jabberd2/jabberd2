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

#ifndef INCL_SCOD_H
#define INCL_SCOD_H

#include "util/util.h"

typedef struct _scod_ctx_st     *scod_ctx_t;
typedef struct _scod_st         *scod_t;
typedef struct _scod_mech_st    *scod_mech_t;

#define sd_cb_GET_PASS                  (0x00)
#define sd_cb_CHECK_PASS                (0x01)
#define sd_cb_CHECK_AUTHZID             (0x02)
#define sd_cb_DIGEST_MD5_CHOOSE_REALM   (0x03)
#define sd_cb_ANONYMOUS_GEN_AUTHZID     (0x04)

typedef int (*scod_callback_t)(scod_t sd, int cb, void *arg, void **res, void *cbarg);

typedef struct _scod_cb_creds_st {
    char        *authnid;
    char        *realm;
    char        *pass;
    char        *authzid;
} *scod_cb_creds_t;

struct _scod_ctx_st {
    scod_callback_t cb;
    void            *cbarg;

    scod_mech_t     *mechs;
    int             nmechs;

    char            **names;
};

typedef enum {
    sd_type_NONE = 0,
    sd_type_CLIENT = 1,
    sd_type_SERVER = 2
} scod_type_t;

struct _scod_st {
    scod_ctx_t      ctx;

    scod_type_t     type;

    scod_mech_t     mech;

    void            *mech_data;

    char            *authzid;
    char            *authnid;
    char            *pass;

    char            *realm;

    int             authd;
    int             failed;

    void            *app_private;
};

#define sd_flag_CHECK_PASS      (0x01)
#define sd_flag_GET_PASS        (0x02)

struct _scod_mech_st {
    scod_ctx_t      ctx;

    void            *private;

    char            *name;

    int             flags;

    int             (*client_start)(scod_mech_t mech, scod_t sd, char **resp, int *resplen);
    int             (*client_step)(scod_mech_t mech, scod_t sd, const char *chal, int challen, char **resp, int *resplen);

    int             (*server_start)(scod_mech_t mech, scod_t sd, const char *resp, int resplen, char **chal, int *challen);
    int             (*server_step)(scod_mech_t mech, scod_t sd, const char *resp, int resplen, char **chal, int *challen);

    int             (*encode)(scod_mech_t mech, scod_t sd, const char *in, int inlen, char **out, char *outlen);
    int             (*decode)(scod_mech_t mech, scod_t sd, const char *in, int inlen, char **out, char *outlen);

    void            (*free)(scod_mech_t mech);
};

typedef int (*scod_mech_init_fn)(scod_mech_t);

scod_ctx_t  scod_ctx_new(scod_callback_t cb, void *cbarg);
void        scod_ctx_free(scod_ctx_t ctx);

int         scod_mech_flags(scod_ctx_t ctx, char *name);

scod_t      scod_new(scod_ctx_t ctx, scod_type_t type);
void        scod_free(scod_t sd);

int         scod_client_start(scod_t sd, char *name, char *authzid, char *authnid, char *pass, char **resp, int *resplen);
int         scod_client_step(scod_t sd, const char *chal, int challen, char **resp, int *resplen);

int         scod_server_start(scod_t sd, char *name, char *realm, const char *resp, int resplen, char **chal, int *challen);
int         scod_server_step(scod_t sd, const char *resp, int resplen, char **chal, int *challen);

int         scod_sasl_encode(scod_t sd, const char *in, int inlen, char **out, char *outlen);
int         scod_sasl_decode(scod_t sd, const char *in, int inlen, char **out, char *outlen);

#define sd_SUCCESS                  (0x00)
#define sd_CONTINUE                 (0x01)

#define sd_err_NOT_IMPLEMENTED      (0x10)
#define sd_err_IN_PROGRESS          (0x11)
#define sd_err_WRONG_TYPE           (0x12)
#define sd_err_UNKNOWN_MECH         (0x13)
#define sd_err_COMPLETED            (0x14)
#define sd_err_OPTS_REQUIRED        (0x15)
#define sd_err_MASK                 (0x10)

#define sd_auth_USER_UNKNOWN        (0x20)
#define sd_auth_AUTH_FAILED         (0x21)
#define sd_auth_MALFORMED_DATA      (0x22)
#define sd_auth_AUTHZID_REQUIRED    (0x23)
#define sd_auth_MISMATCH            (0x24)
#define sd_auth_NOT_OFFERED         (0x25)
#define sd_auth_AUTHZID_POLICY      (0x26)
#define sd_auth_MASK                (0x20)

#endif
