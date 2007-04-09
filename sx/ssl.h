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

#ifndef INCL_SX_SSL_H
#define INCL_SX_SSL_H

#include "sx.h"

#ifdef HAVE_SSL

#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/** our magic, so plugins can find us */
#define SX_SSL_MAGIC        (0x01)

/** init function */
int                         sx_ssl_init(sx_env_t env, sx_plugin_t p, va_list args);

/* flags for client/server init */
#define SX_SSL_WRAPPER          (1<<0)
#define SX_SSL_STARTTLS_OFFER   (1<<1)
#define SX_SSL_STARTTLS_REQUIRE (1<<2)

/** trigger for client starttls */
int                         sx_ssl_client_starttls(sx_plugin_t p, sx_t s, char *pemfile);

/** error code */
#define SX_ERR_SSL              (0x010)
#define SX_ERR_STARTTLS_FAILURE (0x011)

/* previous states */
#define SX_SSL_STATE_NONE       (0)
#define SX_SSL_STATE_WANT_READ  (1)
#define SX_SSL_STATE_WANT_WRITE (2)
#define SX_SSL_STATE_ERROR      (3)

/** a single conn */
typedef struct _sx_ssl_conn_st {
    /* id and ssf for sasl external auth */
    char        *external_id;

    SSL         *ssl;

    BIO         *wbio, *rbio;

    jqueue_t    wq;

    int         last_state;

    char        *pemfile;
} *_sx_ssl_conn_t;

#ifdef __cplusplus
}
#endif

#endif /* HAVE_SSL */

#endif
