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

/** @file util/pqueue.h
  * @brief priority queues
  * @author Robert Norris
  * $Date: 2004/05/05 23:49:38 $
  * $Revision: 1.1 $
  */

#ifndef INCL_UTIL_PQUEUE_H
#define INCL_UTIL_PQUEUE_H 1

#include "pool.h"

/* opaque decl */
typedef struct _pqueue_st   *pqueue_t;

JABBERD2_API pqueue_t    pqueue_new(pool_t p);
JABBERD2_API void        pqueue_push(pqueue_t q, void *data, int pri);
JABBERD2_API void        *pqueue_pull(pqueue_t q);
JABBERD2_API int         pqueue_size(pqueue_t q);

#endif
