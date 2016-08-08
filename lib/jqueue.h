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

#ifndef INCL_UTIL_JQUEUE_H
#define INCL_UTIL_JQUEUE_H 1

#include "util.h"
#include "pool.h"
#include <time.h>

/*
 * priority queues
 */

typedef struct _jqueue_node_st _jqueue_node_t;
struct _jqueue_node_st {
    void            *data;

    int             priority;

    _jqueue_node_t  *next;
    _jqueue_node_t  *prev;
};

typedef struct _jqueue_st {
    pool_t          *p;
    _jqueue_node_t  *cache;

    _jqueue_node_t  *front;
    _jqueue_node_t  *back;

    int             size;
    char            *key;
    time_t          init_time;
} jqueue_t;

JABBERD2_API jqueue_t   *jqueue_new(void);
JABBERD2_API void        jqueue_free(jqueue_t *q);
JABBERD2_API void        jqueue_push(jqueue_t *q, void *data, int pri);
JABBERD2_API void       *jqueue_pull(jqueue_t *q);
JABBERD2_API int         jqueue_size(jqueue_t *q);
JABBERD2_API time_t      jqueue_age(jqueue_t *q);

#endif
