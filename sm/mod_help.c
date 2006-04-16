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

/** @file sm/mod_help.c
  * @brief forward messages to administrators
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.9 $
  */

static mod_ret_t _help_pkt_sm(mod_instance_t mi, pkt_t pkt)
{
    module_t mod = mi->mod;
    jid_t all, msg, jid;

    /* we want messages addressed to the sm itself */
    if(pkt->type != pkt_MESSAGE || pkt->to->resource[0] != '\0')
        return mod_PASS;

    log_debug(ZONE, "help message from %s", jid_full(pkt->from));

    all = xhash_get(mod->mm->sm->acls, "all");
    msg = xhash_get(mod->mm->sm->acls, "messages");

    for(jid = all; jid != NULL; jid = jid->next)
    {
        log_debug(ZONE, "resending to %s", jid_full(jid));
        pkt_router(pkt_dup(pkt, jid_full(jid), mod->mm->sm->id));
    }

    for(jid = msg; jid != NULL; jid = jid->next)
        if(!jid_search(all, jid))
        {
            log_debug(ZONE, "resending to %s", jid_full(jid));
            pkt_router(pkt_dup(pkt, jid_full(jid), NULL));
        }

    /* !!! autoreply */

    pkt_free(pkt);

    return mod_HANDLED;
}

DLLEXPORT int module_init(mod_instance_t mi, char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->pkt_sm = _help_pkt_sm;

    return 0;
}
