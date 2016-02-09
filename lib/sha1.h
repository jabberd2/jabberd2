/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
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

/* sha1 functions */

#ifndef INCL_SHA1_H
#define INCL_SHA1_H

/* jabberd2 Windows DLL */
#ifndef JABBERD2_API
# ifdef _WIN32
#  ifdef JABBERD2_EXPORTS
#   define JABBERD2_API  __declspec(dllexport)
#  else /* JABBERD2_EXPORTS */
#   define JABBERD2_API  __declspec(dllimport)
#  endif /* JABBERD2_EXPORTS */
# else /* _WIN32 */
#  define JABBERD2_API extern
# endif /* _WIN32 */
#endif /* JABBERD2_API */

/* use OpenSSL functions when available */
#ifdef HAVE_SSL
#include <openssl/sha.h>

#define sha1_state_t SHA_CTX
#define sha1_init(c) SHA1_Init(c)
#define sha1_append(c, data, len) SHA1_Update(c, data, len);
#define sha1_finish(c, md) SHA1_Final(md, c)
#define sha1_hash(data, len, md) SHA1(data, len, md);

#else

#include <inttypes.h>

typedef struct sha1_state_s {
  uint32_t H[5];
  uint32_t W[80];
  int lenW;
  uint32_t sizeHi,sizeLo;
} sha1_state_t;

JABBERD2_API void sha1_init(sha1_state_t *ctx);
JABBERD2_API void sha1_append(sha1_state_t *ctx, const unsigned char *dataIn, int len);
JABBERD2_API void sha1_finish(sha1_state_t *ctx, unsigned char hashout[20]);
JABBERD2_API void sha1_hash(const unsigned char *dataIn, int len, unsigned char hashout[20]);

#endif

#endif /* HAVE_SSL */
