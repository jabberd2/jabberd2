/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2007 Tomasz Sterna
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
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

#ifndef INCL_SX_COMPRESS_H
#define INCL_SX_COMPRESS_H

#include "sx.h"

#ifdef HAVE_LIBZ

#include <zlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** init function */
JABBERD2_API int                         sx_compress_init(sx_env_t env, sx_plugin_t p, va_list args);

/* flags for client/server init */
#define SX_COMPRESS_WRAPPER  (1<<4)
#define SX_COMPRESS_OFFER    (1<<5)

/** trigger for client starttls */
JABBERD2_API int                         sx_compress_client_starttls(sx_plugin_t p, sx_t s, char *pemfile);

/** error code */
#define SX_ERR_COMPRESS         (0x020)
#define SX_ERR_COMPRESS_FAILURE (0x021)

/* allocation chunk for decompression */
#define SX_COMPRESS_CHUNK       16384

/* previous states */
//#define SX_COMPRESS_STATE_NONE       (0)
//#define SX_COMPRESS_STATE_WANT_READ  (1)
//#define SX_COMPRESS_STATE_WANT_WRITE (2)
//#define SX_COMPRESS_STATE_ERROR      (3)

/** a single conn */
typedef struct _sx_compress_conn_st {
    /* zlib streams for deflate() and inflate() */
    z_stream    wstrm, rstrm;

    /* buffers for compressed and decompressed data */
    sx_buf_t    wbuf, rbuf;

//    int         last_state;
} *_sx_compress_conn_t;

#ifdef __cplusplus
}
#endif

#endif /* HAVE_LIBZ */

#endif
