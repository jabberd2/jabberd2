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

/** @file util/xhash.h
  * @brief hashtables
  * $Date: 2004/04/30 00:53:55 $
  * $Revision: 1.1 $
  */

#ifndef INCL_UTIL_XHASH_H
#define INCL_UTIL_XHASH_H 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "pool.h"

typedef struct xhn_struct
{
    struct xhn_struct *next;
    const char *key;
    void *val;
} *xhn, _xhn;

typedef struct xht_struct
{
    pool_t p;
    int prime;
    int dirty;
    int count;
    struct xhn_struct *zen;
    int iter_bucket;
    xhn iter_node;
} *xht, _xht;

typedef void (*xhash_walker_t)(xht h, const char *key, void *val, void *arg);

JABBERD2_API xht xhash_new(int prime);
JABBERD2_API void xhash_put(xht h, const char *key, void *val);
JABBERD2_API void xhash_putx(xht h, const char *key, int len, void *val);
JABBERD2_API void *xhash_get(xht h, const char *key);
JABBERD2_API void *xhash_getx(xht h, const char *key, int len);
JABBERD2_API void xhash_zap(xht h, const char *key);
JABBERD2_API void xhash_zapx(xht h, const char *key, int len);
JABBERD2_API void xhash_free(xht h);
typedef void (*xhash_walker)(xht h, const char *key, void *val, void *arg);
JABBERD2_API void xhash_walk(xht h, xhash_walker w, void *arg);
JABBERD2_API int xhash_dirty(xht h);
JABBERD2_API int xhash_count(xht h);
JABBERD2_API pool_t xhash_pool(xht h);

/* iteration functions */
JABBERD2_API int xhash_iter_first(xht h);
JABBERD2_API int xhash_iter_next(xht h);
JABBERD2_API void xhash_iter_zap(xht h);
JABBERD2_API int xhash_iter_get(xht h, const char **key, void **val);

#endif
