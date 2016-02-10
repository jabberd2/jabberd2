/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
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

#ifndef INCL_UTIL_ACCESS_H
#define INCL_UTIL_ACCESS_H 1

#include "util.h"
#include "inaddr.h"

/*
 * IP-based access controls
 */

typedef struct access_rule_st
{
    struct sockaddr_storage ip;
    int            mask;
} access_rule_t;

typedef struct access_st
{
    int             order;      /* 0 = allow,deny  1 = deny,allow */

    access_rule_t  *allow;
    int             nallow;

    access_rule_t  *deny;
    int             ndeny;
} access_t;

JABBERD2_API access_t *  access_new(int order);
JABBERD2_API void        access_free(access_t *access);
JABBERD2_API int         access_allow(access_t *access, const char *ip, const char *mask);
JABBERD2_API int         access_deny(access_t *access, const char *ip, const char *mask);
JABBERD2_API int         access_check(access_t *access, const char *ip);

#endif
