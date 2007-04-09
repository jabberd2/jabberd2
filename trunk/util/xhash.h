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

/* opaque decl */
typedef struct _xhash_st *xhash_t;

typedef void (*xhash_walker_t)(xhash_t h, const char *key, void *val, void *arg);

xhash_t xhash_new(pool_t p, int prime);
void    xhash_free(xhash_t h);
pool_t  xhash_pool(xhash_t h);
void    xhash_put(xhash_t h, const char *key, void *val);
void    xhash_putx(xhash_t h, const char *key, int len, void *val);
void    *xhash_get(xhash_t h, const char *key);
void    *xhash_getx(xhash_t h, const char *key, int len);
void    xhash_zap(xhash_t h, const char *key);
void    xhash_zapx(xhash_t h, const char *key, int len);
void    xhash_walk(xhash_t h, xhash_walker_t fn, void *arg);
int     xhash_dirty(xhash_t h);
int     xhash_count(xhash_t h);
int     xhash_iter_first(xhash_t h);
int     xhash_iter_next(xhash_t h);
void    xhash_iter_zap(xhash_t h);
void    xhash_iter_get(xhash_t h, const char **key, void **val);

#endif
