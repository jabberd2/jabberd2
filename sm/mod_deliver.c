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

/** @file sm/mod_deliver.c
  * @brief packet delivery
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.18 $
  */

static mod_ret_t _deliver_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt)
{
    /* ensure from is set correctly if not already by client */
    if(pkt->from == NULL || jid_compare_user(pkt->from, sess->jid) != 0) {
        if(pkt->from != NULL)
            jid_free(pkt->from);

        pkt->from = jid_dup(sess->jid);
        nad_set_attr(pkt->nad, 1, -1, "from", jid_full(pkt->from), 0);
    }

    /* no to address means its to us */
    if(pkt->to == NULL) {
        /* drop iq-result packets */
        /* user client is confirming all iq-set, but we usually do not track these
         * confirmations and we need to drop it here, not loop back to client */
        if(pkt->type == pkt_IQ_RESULT) {
            pkt_free(pkt);
            return mod_HANDLED;
        }

        /* iq packets without to should have been already handled by modules */
        if(pkt->type & pkt_IQ) {
            return -stanza_err_FEATURE_NOT_IMPLEMENTED;
        }

        /* supplant user jid as 'to' */
        pkt->to = jid_dup(sess->jid);
        nad_set_attr(pkt->nad, 1, -1, "to", jid_full(pkt->to), 0);
    }

    /* let it go on the wire */
    pkt_router(pkt);

    return mod_HANDLED;
}

static mod_ret_t _deliver_pkt_user(mod_instance_t mi, user_t user, pkt_t pkt)
{
    sess_t sess;

    /* if there's a resource, send it direct */
    if(*pkt->to->resource != '\0') {
        /* find the session */
        sess = sess_match(user, pkt->to->resource);

        /* and send it straight there */
        if(sess != NULL) {
            pkt_sess(pkt, sess);
            return mod_HANDLED;
        }

        /* no session */
        if(pkt->type & pkt_PRESENCE) {
            pkt_free(pkt);
            return mod_HANDLED;

        } else if(pkt->type & pkt_IQ)
            return -stanza_err_SERVICE_UNAVAILABLE;
        
        /* unmatched messages will fall through (XMPP-IM r20 s11 rule 2) */
    }

    return mod_PASS;
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->in_sess = _deliver_in_sess;
    mod->pkt_user = _deliver_pkt_user;

    feature_register(mod->mm->sm, "message");

    return 0;
}
