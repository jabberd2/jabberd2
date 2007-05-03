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

/** @file util/xconfig.h
  * @brief XML config files
  * @author Robert Norris
  * $Revision: 1.2 $
  * $Date: 2004/05/05 23:49:38 $
  */

#ifndef INCL_UTIL_XCONFIG_H
#define INCL_UTIL_XCONFIG_H 1

#include "xhash.h"
#include "pool.h"
#include "nad.h"

typedef struct xconfig_st        *xconfig_t;
typedef struct xconfig_elem_st   *xconfig_elem_t;

/** holder for the xconfig hash and nad */
struct xconfig_st {
    pool_t              p;
    xhash_t             hash;
    nad_t               nad;
};

/** a single element */
struct xconfig_elem_st {
    char                **values;
    int                 nvalues;
    char                ***attrs;
};

extern xconfig_t        xconfig_new(pool_t p);
extern int              xconfig_load(xconfig_t c, char *file);
extern xconfig_elem_t   xconfig_get(xconfig_t c, char *key);
extern char             *xconfig_get_one(xconfig_t c, char *key, int num);
extern int              xconfig_count(xconfig_t c, char *key);
extern char             *xconfig_get_attr(xconfig_t c, char *key, int num, char *attr);

#endif
