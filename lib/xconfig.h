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
#include "log.h"

typedef struct xconfig_st           xconfig_t;
typedef struct xconfig_elem_st      xconfig_elem_t;
typedef struct xconfig_callback_st  xconfig_callback_t;
typedef void (xconfig_callback)(const char *key, xconfig_elem_t *elem, void *data);

/** holder for the config hash and nad */
struct xconfig_st
{
    xht                 *hash;
    log_t               *log;
};

/** a single config element */
struct xconfig_elem_st
{
    const char          **values;
    unsigned int        nvalues;
    const char          ***attrs;
    nad_t               *nad;
    int                 nad_elem;
    xconfig_callback_t  *subs;
};

JABBERD2_API xconfig_t       *xconfig_new(int prime, log_t *log);
JABBERD2_API int              xconfig_load_file(xconfig_t *c, const char *prefix, const char *file);
JABBERD2_API int              xconfig_load_nad(xconfig_t *c, const char *prefix, const nad_t *nad);
JABBERD2_API int              xconfig_load_id(xconfig_t *c, const char *id);
JABBERD2_API xconfig_elem_t  *xconfig_get(xconfig_t *c, const char *key);
JABBERD2_API const char      *xconfig_get_one(xconfig_t *c, const char *key, int num, const char *default_value);
JABBERD2_API int              xconfig_count(xconfig_t *c, const char *key);
JABBERD2_API const char      *xconfig_get_attr(xconfig_t *c, const char *key, int num, const char *attr);
JABBERD2_API xconfig_elem_t  *xconfig_set(xconfig_t *c, const char *key, const char **values, int num);
JABBERD2_API xconfig_elem_t  *xconfig_set_one(xconfig_t *c, const char *key, int num, const char *value);
JABBERD2_API xconfig_elem_t  *xconfig_set_attr(xconfig_t *c, const char *key, int num, const char *attr, const char *value);
JABBERD2_API char            *xconfig_expand(xconfig_t *c, const char *value); //! Replaces $(some.value) with config_get_one(c, "some.value", 0)
JABBERD2_API void             xconfig_subscribe(xconfig_t *c, const char *key, xconfig_callback *handler, void *data);
JABBERD2_API void             xconfig_unsubscribe(xconfig_t *c, xconfig_callback *handler, void *data);
JABBERD2_API void             xconfig_free(xconfig_t* c);
JABBERD2_API const char      *xconfig_elem_get_one(xconfig_elem_t *elem, int num, const char *default_value);
JABBERD2_API int              xconfig_elem_count(xconfig_elem_t *elem);
JABBERD2_API const char      *xconfig_elem_get_attr(xconfig_elem_t *elem, int num, const char *attr);

#endif
