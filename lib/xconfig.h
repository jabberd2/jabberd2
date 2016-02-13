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

#ifndef INCL_UTIL_XCONFIG_H
#define INCL_UTIL_XCONFIG_H 1

#include "nad.h"
#include "xhash.h"

/* config files */
typedef struct xconfig_elem_st   xconfig_elem_t;
typedef struct xconfig_st        xconfig_t;

/** holder for the config hash and nad */
struct xconfig_st
{
    xht                 *hash;
    nad_t               *nad;
};

/** a single element */
struct xconfig_elem_st
{
    const char          **values;
    int                 nvalues;
    const char          ***attrs;
};

JABBERD2_API xconfig_t       *xconfig_new(void);
JABBERD2_API int              xconfig_load(xconfig_t *c, const char *file);
JABBERD2_API int              xconfig_load_with_id(xconfig_t *c, const char *file, const char *id);
JABBERD2_API xconfig_elem_t  *xconfig_get(xconfig_t *c, const char *key);
JABBERD2_API const char      *xconfig_get_one(xconfig_t *c, const char *key, int num);
JABBERD2_API const char      *xconfig_get_one_default(xconfig_t *c, const char *key, int num, const char *default_value);
JABBERD2_API int              xconfig_count(xconfig_t *c, const char *key);
JABBERD2_API char            *xconfig_get_attr(xconfig_t *c, const char *key, int num, const char *attr);
JABBERD2_API char            *xconfig_expand(xconfig_t *c, const char *value); //! Replaces $(some.value) with config_get_one(c, "some.value", 0)
JABBERD2_API void             xconfig_free(xconfig_t* c);

#endif
