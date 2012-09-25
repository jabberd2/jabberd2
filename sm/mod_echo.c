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

#include "sm.h"

/** @file sm/mod_echo.c
  * @brief message echo
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.9 $
  */

static mod_ret_t _echo_pkt_sm(mod_instance_t mi, pkt_t pkt)
{
    jid_t jid;
    char *resource = (char *) mi->mod->private;

    /* answer to probes and subscription requests */
    if(pkt->type == pkt_PRESENCE_PROBE || pkt->type == pkt_S10N) {
        log_debug(ZONE, "answering presence probe/sub from %s with /echo resource", jid_full(pkt->from));

        /* send presence */
        jid = jid_new(jid_user(pkt->to), -1);
        jid_reset_components(jid, jid->node, jid->domain, resource);
        pkt_router(pkt_create(mi->mod->mm->sm, "presence", NULL, jid_user(pkt->from), jid_full(jid)));
        jid_free(jid);
    }

    /* we want messages addressed to /echo */
    if(!(pkt->type & pkt_MESSAGE) || strcmp(pkt->to->resource, "echo") != 0)
        return mod_PASS;

    log_debug(ZONE, "echo request from %s", jid_full(pkt->from));

    /* swap to and from and return it */
    pkt_router(pkt_tofrom(pkt));

    return mod_HANDLED;
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    /* store /echo resource for use when answering probes */
    mod->private = "echo";

    mod->pkt_sm = _echo_pkt_sm;
    /* data is static so nothing to free */
    /* mod->free = _echo_free; */

    return 0;
}
