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

/* priority queues */

#include "pqueue.h"

#include "pool.h"

#include <stdio.h>      /* to get NULL */
#include <assert.h>

typedef struct _pqueue_node_st  *_pqueue_node_t;
struct _pqueue_node_st {
    void            *data;

    int             priority;

    _pqueue_node_t  next;
    _pqueue_node_t  prev;
};

struct _pqueue_st {
    pool_t            p;
    _pqueue_node_t  cache;

    _pqueue_node_t  front;
    _pqueue_node_t  back;

    int             size;
};

pqueue_t pqueue_new(pool_t p) {
    pqueue_t q;

    q = (pqueue_t) pmalloco(p, sizeof(struct _pqueue_st));

    q->p = p;

    return q;
}

void pqueue_push(pqueue_t q, void *data, int priority) {
    _pqueue_node_t qn, scan;

    assert((q != NULL));

    q->size++;

    /* node from the cache, or make a new one */
    qn = q->cache;
    if(qn != NULL)
        q->cache = qn->next;
    else
        qn = (_pqueue_node_t) pmalloc(q->p, sizeof(struct _pqueue_node_st));

    qn->data = data;
    qn->priority = priority;

    qn->next = NULL;
    qn->prev = NULL;

    /* first one */
    if(q->back == NULL && q->front == NULL) {
        q->back = qn;
        q->front = qn;

        return;
    }

    /* find the first node with priority <= to us */
    for(scan = q->back; scan != NULL && scan->priority > priority; scan = scan->next);

    /* didn't find one, so we have top priority - push us on the front */
    if(scan == NULL) {
        qn->prev = q->front;
        qn->prev->next = qn;
        q->front = qn;

        return;
    }

    /* push us in front of scan */
    qn->next = scan;
    qn->prev = scan->prev;

    if(scan->prev != NULL)
        scan->prev->next = qn;
    else
        q->back = qn;

    scan->prev = qn;
}

void *pqueue_pull(pqueue_t q) {
    void *data;
    _pqueue_node_t qn;

    assert((q != NULL));

    if(q->front == NULL)
        return NULL;

    data = q->front->data;

    qn = q->front;

    if(qn->prev != NULL)
        qn->prev->next = NULL;
    
    q->front = qn->prev;

    /* node to cache for later reuse */
    qn->next = q->cache;
    q->cache = qn;

    if(q->front == NULL)
        q->back = NULL;

    q->size--;

    return data;
}

int pqueue_size(pqueue_t q) {
    return q->size;
}
