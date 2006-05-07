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

/* for strndup */
#define _GNU_SOURCE
#include <string.h>
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
    int subj, subjectl;
    char *org_subject;
    char *subject;

    /* we want messages addressed to the sm itself */
    if(pkt->type != pkt_MESSAGE || pkt->to->resource[0] != '\0')
        return mod_PASS;

    log_debug(ZONE, "help message from %s", jid_full(pkt->from));

    all = xhash_get(mod->mm->sm->acls, "all");
    msg = xhash_get(mod->mm->sm->acls, "messages");

    nad_set_attr(pkt->nad, 1, -1, "type", NULL, 0);
    subj = nad_find_elem(pkt->nad, 1, NAD_ENS(pkt->nad, 1), "subject", 1);
    if(subj >= 0 && NAD_CDATA_L(pkt->nad, subj) > 0)
    {
        org_subject = strndup(NAD_CDATA(pkt->nad, subj), NAD_CDATA_L(pkt->nad, subj));
    } else {
        org_subject = "(none)";
    }
    subjectl = strlen(org_subject) + strlen(jid_full(pkt->to)) + 8;
    subject = (char *) malloc(sizeof(char) * subjectl);
    snprintf(subject, subjectl, "Fwd[%s]: %s", jid_full(pkt->to), org_subject);
    if(subj >= 0 && NAD_CDATA_L(pkt->nad, subj) > 0)
    {
        free(org_subject);
        nad_drop_elem(pkt->nad, subj);
    }
    nad_insert_elem(pkt->nad, 1, NAD_ENS(pkt->nad, 1), "subject", subject);

    for(jid = all; jid != NULL; jid = jid->next)
    {
        log_debug(ZONE, "resending to %s", jid_full(jid));
        pkt_router(pkt_dup(pkt, jid_full(jid), jid_full(pkt->from)));
    }

    for(jid = msg; jid != NULL; jid = jid->next)
        if(!jid_search(all, jid))
        {
            log_debug(ZONE, "resending to %s", jid_full(jid));
            pkt_router(pkt_dup(pkt, jid_full(jid), jid_full(pkt->from)));
        }

    /* !!! autoreply */

    free(subject);
    pkt_free(pkt);

    return mod_HANDLED;
}

DLLEXPORT int module_init(mod_instance_t mi, char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->pkt_sm = _help_pkt_sm;

    return 0;
}
