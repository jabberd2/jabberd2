/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2004 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
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

#include "misc.h"

#include <stdio.h>
#include <stdlib.h>

#define BLOCKSIZE (1024)

int misc_realloc(void **blocks, int len) {
    void *nblocks;
    int nlen;

    /* round up to standard block sizes */
    nlen = (((len - 1) / BLOCKSIZE) + 1) * BLOCKSIZE;

    /* keep trying till we get it */
    if((nblocks = realloc(*blocks, nlen)) == NULL) {
        fprintf(stderr, "fatal: out of memory\n");
        abort();
    }

    *blocks = nblocks;
    return nlen;
}
