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

/* manage and run the io and nad chains */

#include "sx.h"

void _sx_chain_io_plugin(sx_t s, sx_plugin_t p) {
    _sx_chain_t cn, tail;

    _sx_debug(ZONE, "adding io plugin");

    cn = (_sx_chain_t) malloc(sizeof(struct _sx_chain_st));
    cn->p = p;
    
    if(s->wio == NULL) {
        s->wio = cn;
        cn->wnext = NULL;
    } else {
        cn->wnext = s->wio;
        s->wio = cn;
    }

    if(s->rio == NULL)
        s->rio = cn;
    else {
        for(tail = s->rio; tail->rnext != NULL; tail = tail->rnext);
        tail->rnext = cn;
    }
    cn->rnext = NULL;
}

void _sx_chain_nad_plugin(sx_t s, sx_plugin_t p) {
    _sx_chain_t cn, tail;

    _sx_debug(ZONE, "adding nad plugin");

    cn = (_sx_chain_t) malloc(sizeof(struct _sx_chain_st));
    cn->p = p;
    
    if(s->wnad == NULL) {
        s->wnad = cn;
        cn->wnext = NULL;
    } else {
        cn->wnext = s->wnad;
        s->wnad = cn;
    }

    if(s->rnad == NULL)
        s->rnad = cn;
    else {
        for(tail = s->rnad; tail->rnext != NULL; tail = tail->rnext);
        tail->rnext = cn;
    }
    cn->rnext = NULL;
}

int _sx_chain_io_write(sx_t s, sx_buf_t buf) {
    _sx_chain_t scan;
    int ret = 1;

    _sx_debug(ZONE, "calling io write chain");

    for(scan = s->wio; scan != NULL; scan = scan->wnext)
        if(scan->p->wio != NULL)
            if((ret = (scan->p->wio)(s, scan->p, buf)) <= 0)
                return ret;

    return ret;
}

int _sx_chain_io_read(sx_t s, sx_buf_t buf) {
    _sx_chain_t scan;
    int ret = 1;

    _sx_debug(ZONE, "calling io read chain");

    for(scan = s->rio; scan != NULL; scan = scan->rnext)
        if(scan->p->rio != NULL)
            if((ret = (scan->p->rio)(s, scan->p, buf)) <= 0)
                return ret;

    return ret;
}

int _sx_chain_nad_write(sx_t s, nad_t nad, int elem) {
    _sx_chain_t scan;

    _sx_debug(ZONE, "calling nad write chain");

    for(scan = s->wnad; scan != NULL; scan = scan->wnext)
        if(scan->p->wnad != NULL)
            if((scan->p->wnad)(s, scan->p, nad, elem) == 0)
                return 0;

    return 1;
}

int _sx_chain_nad_read(sx_t s, nad_t nad) {
    _sx_chain_t scan;

    _sx_debug(ZONE, "calling nad read chain");

    for(scan = s->rnad; scan != NULL; scan = scan->rnext)
        if(scan->p->rnad != NULL)
            if((scan->p->rnad)(s, scan->p, nad) == 0)
                return 0;

    return 1;
}
