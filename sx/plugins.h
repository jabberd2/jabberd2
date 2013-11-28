/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2007 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris, Tomasz Sterna
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

#ifndef INCL_SX_PLUGINS_H
#define INCL_SX_PLUGINS_H

/** sx stream flags */
#define SX_SSL_WRAPPER          (1<<0)    /** SSL wrapper on legacy 5223 port */
#define SX_SSL_STARTTLS_OFFER   (1<<1)    /** don't offer starttls without this */
#define SX_SSL_STARTTLS_REQUIRE (1<<2)    /** starttls is required on the stream */

#define SX_SASL_OFFER           (1<<3)    /** don't offer sasl without this */

#define SX_COMPRESS_WRAPPER     (1<<4)
#define SX_COMPRESS_OFFER       (1<<5)


/** magic numbers, so plugins can find each other */
#define SX_SSL_MAGIC        (0x01)


/** error codes */
/* prefix 0x0. is taken by sx core errors in sx.h */
#define SX_ERR_SSL              (0x010)
#define SX_ERR_STARTTLS_FAILURE (0x011)

#define SX_ERR_COMPRESS         (0x020)
#define SX_ERR_COMPRESS_FAILURE (0x021)


#define SX_CONN_EXTERNAL_ID_MAX_COUNT 8

#ifdef __cplusplus
extern "C" {
#endif


/* SSL plugin */
#ifdef HAVE_SSL

#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>


/** init function */
JABBERD2_API int                         sx_ssl_init(sx_env_t env, sx_plugin_t p, va_list args);

/** add cert function */
JABBERD2_API int                         sx_ssl_server_addcert(sx_plugin_t p, const char *name, const char *pemfile, const char *cachain, int mode, const char *private_key_password);

/** trigger for client starttls */
JABBERD2_API int                         sx_ssl_client_starttls(sx_plugin_t p, sx_t s, const char *pemfile, const char *private_key_password);

/* previous states */
#define SX_SSL_STATE_NONE       (0)
#define SX_SSL_STATE_WANT_READ  (1)
#define SX_SSL_STATE_WANT_WRITE (2)
#define SX_SSL_STATE_ERROR      (3)

/** a single conn */
typedef struct _sx_ssl_conn_st {
    /* id and ssf for sasl external auth */
    char        *external_id[SX_CONN_EXTERNAL_ID_MAX_COUNT];

    SSL         *ssl;

    BIO         *wbio, *rbio;

    jqueue_t    wq;

    int         last_state;

    char        *pemfile;

    char        *private_key_password;
} *_sx_ssl_conn_t;

#endif /* HAVE_SSL */


/* SASL plugin */

/** init function */
JABBERD2_API int                         sx_sasl_init(sx_env_t env, sx_plugin_t p, va_list args);

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
#define sx_sasl_ret_OK		    (0)
#define sx_sasl_ret_FAIL	    (1)

/** trigger for client auth */
JABBERD2_API int                         sx_sasl_auth(sx_plugin_t p, sx_t s, const char *appname, const char *mech, const char *user, const char *pass);

/* for passing auth data to callback */
typedef struct sx_sasl_creds_st {
    const char                  *authnid;
    const char                  *realm;
    const char                  *authzid;
    const char                  *pass;
} *sx_sasl_creds_t;


/* Stream Compression plugin */
#ifdef HAVE_LIBZ

#include <zlib.h>

/** init function */
JABBERD2_API int                         sx_compress_init(sx_env_t env, sx_plugin_t p, va_list args);

/* allocation chunk for decompression */
#define SX_COMPRESS_CHUNK       16384

/** a single conn */
typedef struct _sx_compress_conn_st {
    /* zlib streams for deflate() and inflate() */
    z_stream    wstrm, rstrm;

    /* buffers for compressed and decompressed data */
    sx_buf_t    wbuf, rbuf;

} *_sx_compress_conn_t;

#endif /* HAVE_LIBZ */


/* Stanza Acknowledgements plugin */
/** init function */
JABBERD2_API int                         sx_ack_init(sx_env_t env, sx_plugin_t p, va_list args);


#ifdef __cplusplus
}
#endif


#endif /* INCL_SX_PLUGINS_H */
