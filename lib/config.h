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

#ifndef INCL_UTIL_config_H
#define INCL_UTIL_config_H 1

/** config files */

#include "util.h"
#include "nad.h"
#include "xhash.h"

/** holder for the config hash and nad */
typedef struct config_st
{
    xht                 *hash;
    nad_t               *nad;
} config_t;

/** a single config element */
typedef struct config_elem_st
{
    const char          **values;
    unsigned int        nvalues;
    const char          ***attrs;
} config_elem_t;

JABBERD2_API config_t      *config_new(unsigned int prime);
JABBERD2_API int            config_load(config_t *c, const char *file);
JABBERD2_API int            config_load_with_id(config_t *c, const char *file, const char *id);
JABBERD2_API config_elem_t *config_get(config_t *c, const char *key);
JABBERD2_API const char    *config_get_one(config_t *c, const char *key, unsigned int num);
JABBERD2_API const char    *config_get_one_default(config_t *c, const char *key, unsigned int num, const char *default_value);
JABBERD2_API int            config_count(config_t *c, const char *key);
JABBERD2_API char          *config_get_attr(config_t *c, const char *key, unsigned int num, const char *attr);
JABBERD2_API char          *config_expand(config_t *c, const char *value); //! Replaces $(some.value) with config_get_one(c, "some.value", 0)
JABBERD2_API void           config_free(config_t *c);

#endif
