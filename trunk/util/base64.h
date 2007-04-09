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

/* base64 functions */
extern int ap_base64decode_len(const char *bufcoded);
extern int ap_base64decode(char *bufplain, const char *bufcoded);
extern int ap_base64decode_binary(unsigned char *bufplain, const char *bufcoded);
extern int ap_base64encode_len(int len);
extern int ap_base64encode(char *encoded, const char *string, int len);
extern int ap_base64encode_binary(char *encoded, const unsigned char *string, int len);

/* convenience, result string must be free()'d by caller */
extern char *b64_encode(char *buf, int len);
extern char *b64_decode(char *buf);

#endif
