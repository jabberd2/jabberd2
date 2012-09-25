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

/** @file sm/mod_iq_ping.c
  * @brief xmpp ping
  * @author Tomasz Sieprawski
  * $Date: 2007/04/06 xx:xx:xx $
  * $Revision: 1.0 $
  */

static int ns_PING = 0;

void _iq_ping_reply(pkt_t pkt) {
    int ns, elem;

    ns = nad_find_scoped_namespace(pkt->nad, urn_PING, NULL);
    elem = nad_find_elem(pkt->nad, 1, ns, "ping", 1);
    if (elem>=0)
        nad_drop_elem(pkt->nad, elem);

    nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);

    return;
}

static mod_ret_t _iq_ping_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    if(pkt->to != NULL || pkt->type != pkt_IQ || pkt->ns != ns_PING)
        return mod_PASS;
    _iq_ping_reply(pkt);
    pkt_sess(pkt, sess);
    return mod_HANDLED;
}

static mod_ret_t _iq_ping_pkt_sm(mod_instance_t mi, pkt_t pkt) {
    if(pkt->type != pkt_IQ || pkt->ns != ns_PING)
        return mod_PASS;
    _iq_ping_reply(pkt);
    pkt_router(pkt_tofrom(pkt));
    return mod_HANDLED;
}

static void _iq_ping_free(module_t mod) {
    sm_unregister_ns(mod->mm->sm, urn_PING);
    feature_unregister(mod->mm->sm, urn_PING);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->in_sess = _iq_ping_in_sess;
    mod->pkt_sm = _iq_ping_pkt_sm;
    mod->free = _iq_ping_free;

    ns_PING = sm_register_ns(mod->mm->sm, urn_PING);
    feature_register(mod->mm->sm, urn_PING);

    return 0;
}
