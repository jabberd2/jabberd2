/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2009 Tomasz Sterna
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

/*
 * XEP-0163 is some lunatic nightmare...
 *
 * If you want it - YOU implement it!
 */

/** @file sm/mod_pep.c
  * @brief XEP-0163: Personal Eventing Protocol
  * @author Tomasz Sterna
  */

#define uri_PUBSUB   "http://jabber.org/protocol/pubsub"
static int ns_PUBSUB = 0;

static mod_ret_t _pep_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    int ns, elem;

    /* only handle private sets and gets */
    if((pkt->type != pkt_IQ && pkt->type != pkt_IQ_SET) || pkt->ns != ns_PUBSUB)
        return mod_PASS;

    /* we're only interested in no to, to our host, or to us */
    if(pkt->to != NULL && jid_compare_user(sess->jid, pkt->to) != 0 && strcmp(sess->jid->domain, jid_user(pkt->to)) != 0)
        return mod_PASS;

    ns = nad_find_scoped_namespace(pkt->nad, uri_PUBSUB, NULL);
    elem = nad_find_elem(pkt->nad, 1, ns, "pubsub", 1);

    log_debug(ZONE, "_pep_in_sess() %d %d", ns, elem);
    return mod_PASS;
}

static mod_ret_t _pep_out_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    /* add pep identity to disco results from bare JID */
    if(!(pkt->type & pkt_IQ) || pkt->ns != ns_DISCO_INFO || (pkt->from != NULL && strcmp(jid_user(sess->jid), jid_full(pkt->from))))
        return mod_PASS;

    /* add PEP identity */
    nad_append_elem(pkt->nad, -1, "identity", 3);
    nad_append_attr(pkt->nad, -1, "category", "pubsub");
    nad_append_attr(pkt->nad, -1, "type", "pep");

	nad_append_elem(pkt->nad, -1, "feature", 3);
	nad_append_attr(pkt->nad, -1, "var", uri_PUBSUB "#access-presence");
	nad_append_elem(pkt->nad, -1, "feature", 3);
	nad_append_attr(pkt->nad, -1, "var", uri_PUBSUB "#auto-create");
	nad_append_elem(pkt->nad, -1, "feature", 3);
	nad_append_attr(pkt->nad, -1, "var", uri_PUBSUB "#auto-subscribe");
	nad_append_elem(pkt->nad, -1, "feature", 3);
	nad_append_attr(pkt->nad, -1, "var", uri_PUBSUB "#filtered-notifications");
	nad_append_elem(pkt->nad, -1, "feature", 3);
	nad_append_attr(pkt->nad, -1, "var", uri_PUBSUB "#publish");

    return mod_PASS;
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->in_sess = _pep_in_sess;
    mod->out_sess = _pep_out_sess;

    ns_PUBSUB = sm_register_ns(mod->mm->sm, uri_PUBSUB);
    feature_register(mod->mm->sm, uri_PUBSUB);

    return 0;
}
