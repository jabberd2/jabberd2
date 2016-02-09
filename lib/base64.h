/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2004 Jeremie Miller, Thomas Muldowney,
 *                              Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/** @file util/base64.h
  * @brief Base64 encoding
  * @author Apache Software Foundation
  * $Date: 2004/05/17 05:03:13 $
  * $Revision: 1.1 $
  */

#ifndef INCL_UTIL_BASE64_H
#define INCL_UTIL_BASE64_H 1

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

/* base64 functions */
JABBERD2_API int apr_base64_decode_len(const char *bufcoded);
JABBERD2_API int apr_base64_decode(char *bufplain, const char *bufcoded);
JABBERD2_API int apr_base64_encode_len(int len);
JABBERD2_API int apr_base64_encode(char *encoded, const unsigned char *string, int len);

/* convenience, result string must be free()'d by caller */
JABBERD2_API char *b64_encode(char *buf, int len);
JABBERD2_API char *b64_decode(char *buf);

#endif
