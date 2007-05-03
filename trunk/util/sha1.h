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

typedef struct sha1_state_s {
  unsigned long H[5];
  unsigned long W[80];
  int lenW;
  unsigned long sizeHi,sizeLo;
} sha1_state_t;

void sha1_init(sha1_state_t *ctx);
void sha1_append(sha1_state_t *ctx, const unsigned char *dataIn, int len);
void sha1_finish(sha1_state_t *ctx, unsigned char hashout[20]);
void sha1_hash(const unsigned char *dataIn, int len, unsigned char hashout[20]);

#endif
