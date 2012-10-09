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

/** @file sm/mod_iq_last.c
  * @brief last activity
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.18 $
  */

#define uri_LAST    "jabber:iq:last"
static int ns_LAST = 0;

static mod_ret_t _iq_last_pkt_sm(mod_instance_t mi, pkt_t pkt) {
    module_t mod = mi->mod;
    char uptime[10];

    /* we only want to play with iq:last gets */
    if(pkt->type != pkt_IQ || pkt->ns != ns_LAST)
        return mod_PASS;

    snprintf(uptime, 10, "%d", (int) (time(NULL) - (time_t) mod->private));
    nad_set_attr(pkt->nad, 2, -1, "seconds", uptime, 0);

    /* tell them */
    nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);
    pkt_router(pkt_tofrom(pkt));

    return mod_HANDLED;
}

static mod_ret_t _iq_last_pkt_user(mod_instance_t mi, user_t user, pkt_t pkt) {
    char lasttime[10];
    time_t t;
    os_t os;
    os_object_t o;
    st_ret_t ret;

    /* we only want to play with iq:last gets */
    if(pkt->type != pkt_IQ || pkt->ns != ns_LAST)
        return mod_PASS;

    /* make sure they're allowed */
    if(!pres_trust(user, pkt->from))
        return -stanza_err_FORBIDDEN;

    /* If the IQ was sent to a JID with a resource, then XMPP-IM 11.1.1
     * requires we deliver it if that resource is available
     */
    if (*pkt->to->resource != '\0')
	return mod_PASS;

    /* If they have an available resource, we should return a query element with a
     * seconds value of 0
     */
    if(user->top != NULL)
    {
	nad_set_attr(pkt->nad, 2, -1, "seconds", "0", 0);
	nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);
	pkt_router(pkt_tofrom(pkt));

        return mod_HANDLED;
    }

    ret = storage_get(user->sm->st, "logout", jid_user(user->jid), NULL, &os);
    switch(ret) {
        case st_SUCCESS:
            t = 0;

            if(os_iter_first(os)) {
                o = os_iter_object(os);

                os_object_get_time(os, o, "time", &t);
            }

            os_free(os);

            snprintf(lasttime, 10, "%d", (int) (time(NULL) - t));
            nad_set_attr(pkt->nad, 2, -1, "seconds", lasttime, 0);

            nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);
            pkt_router(pkt_tofrom(pkt));

            return mod_HANDLED;

        case st_FAILED:
            return -stanza_err_INTERNAL_SERVER_ERROR;

        case st_NOTFOUND:
            return -stanza_err_SERVICE_UNAVAILABLE;

        case st_NOTIMPL:
            return -stanza_err_FEATURE_NOT_IMPLEMENTED;
    }

    /* we never get here */
    return -stanza_err_INTERNAL_SERVER_ERROR;
}

static void _iq_last_sess_end(mod_instance_t mi, sess_t sess) {
    time_t t;
    os_t os;
    os_object_t o;

    /* store their logout time */
    t = time(NULL);

    os = os_new();
    o = os_object_new(os);

    os_object_put_time(o, "time", &t);

    storage_replace(sess->user->sm->st, "logout", jid_user(sess->jid), NULL, os);

    os_free(os);
}

static void _iq_last_user_delete(mod_instance_t mi, jid_t jid) {
    log_debug(ZONE, "deleting logout time for %s", jid_user(jid));

    storage_delete(mi->sm->st, "logout", jid_user(jid), NULL);
}

static void _iq_last_free(module_t mod) {
    sm_unregister_ns(mod->mm->sm, uri_LAST);
    feature_unregister(mod->mm->sm, uri_LAST);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->sess_end = _iq_last_sess_end;
    mod->pkt_user = _iq_last_pkt_user;
    mod->pkt_sm = _iq_last_pkt_sm;
    mod->user_delete = _iq_last_user_delete;
    mod->free = _iq_last_free;

    /* startup time */
    mod->private = (void *) time(NULL);

    ns_LAST = sm_register_ns(mod->mm->sm, uri_LAST);
    feature_register(mod->mm->sm, uri_LAST);

    return 0;
}
