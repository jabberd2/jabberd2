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

#ifndef INCL_SX_SASL_H
#define INCL_SX_SASL_H

#include "sx.h"

/* RFC 3290 defines a number of failure messages */
#define _sasl_err_ABORTED               "aborted"
#define _sasl_err_INCORRECT_ENCODING    "incorrect-encoding"
#define _sasl_err_INVALID_AUTHZID       "invalid-authzid"
#define _sasl_err_INVALID_MECHANISM     "invalid-mechanism"
#define _sasl_err_MALFORMED_REQUEST     "malformed-request"
#define _sasl_err_MECH_TOO_WEAK         "mechanism-too-weak"
#define _sasl_err_NOT_AUTHORIZED        "not-authorized"
#define _sasl_err_TEMPORARY_FAILURE     "temporary-auth-failure"

#ifdef __cplusplus
extern "C" {
#endif

/** init function */
JABBERD2_API int                         sx_sasl_init(sx_env_t env, sx_plugin_t p, va_list args);

/** server init flag, don't offer sasl without this */
#define SX_SASL_OFFER       (1<<3)

/** the callback function */
typedef int                 (*sx_sasl_callback_t)(int cb, void *arg, void **res, sx_t s, void *cbarg);

/* callbacks */
#define sx_sasl_cb_GET_REALM        (0x00)
#define sx_sasl_cb_GET_PASS         (0x01)
#define sx_sasl_cb_CHECK_PASS       (0x02)
#define sx_sasl_cb_CHECK_AUTHZID    (0x03)
#define sx_sasl_cb_GEN_AUTHZID      (0x04)
#define sx_sasl_cb_CHECK_MECH       (0x05)

/* error codes */
#define sx_sasl_ret_OK		    0
#define sx_sasl_ret_FAIL	    1

/** trigger for client auth */
JABBERD2_API int                         sx_sasl_auth(sx_plugin_t p, sx_t s, char *appname, char *mech, char *user, char *pass);

/* for passing auth data to callback */
typedef struct sx_sasl_creds_st {
    const char                  *authnid;
    const char                  *realm;
    const char                  *authzid;
    const char                  *pass;
} *sx_sasl_creds_t;

/** magic number of the ssl plugin, must match SX_SSL_MAGIC in sx/ssl.h */
#define SX_SASL_SSL_MAGIC       (0x01)

#ifdef __cplusplus
}
#endif

#endif
