/*
 * jabberd mod_status - Jabber Open Source Server
 * Copyright (c) 2004 Lucas Nussbaum <lucas@lucas-nussbaum.net>
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

/** @file sm/mod_status.c
  * @brief status info management
  * @author Lucas Nussbaum 
  * $Date: 2004/09/01 $
  * $Revision: 1.3 $
  */

/* for strndup */
#define _GNU_SOURCE
#include <string.h>
#include "sm.h"

typedef struct _status_st {
    sm_t       sm;
    const char *resource;
} *status_t;

static void _status_os_replace(storage_t st, const char *jid, char *status, char *show, time_t *lastlogin, time_t *lastlogout, nad_t nad) {
    os_t os = os_new();
    os_object_t o = os_object_new(os);
    os_object_put(o, "status", status, os_type_STRING);
    os_object_put(o, "show", show, os_type_STRING);
    os_object_put(o, "last-login", (void **) lastlogin, os_type_INTEGER);
    os_object_put(o, "last-logout", (void **) lastlogout, os_type_INTEGER);
    if(nad != NULL) os_object_put(o, "xml", nad, os_type_NAD);
    storage_replace(st, "status", jid, NULL, os);
    os_free(os);
}

static void _status_store(storage_t st, const char *jid, pkt_t pkt, time_t *lastlogin, time_t *lastlogout) {
    char *show;
    int show_free = 0;

    switch(pkt->type) 
    {
        int elem;
        case pkt_PRESENCE_UN:
            show = "unavailable";
            break;
        default:
            elem = nad_find_elem(pkt->nad, 1, NAD_ENS(pkt->nad, 1), "show", 1);
            if (elem < 0)
            {
                show = "";
            }
            else
            {    
                if (NAD_CDATA_L(pkt->nad, elem) <= 0 || NAD_CDATA_L(pkt->nad, elem) > 19)
                    show = "";
                else
                {
                    show = strndup(NAD_CDATA(pkt->nad, elem), NAD_CDATA_L(pkt->nad, elem));
                    show_free = 1;
                }
            }
    }

    _status_os_replace(st, jid, "online", show, lastlogin, lastlogout, pkt->nad);
    if(show_free) free(show);
}

static int _status_sess_start(mod_instance_t mi, sess_t sess) {
    time_t t, lastlogout;
    os_t os;
    os_object_t o;
    st_ret_t ret;
    nad_t nad;

    /* not interested if there is other top session */
    if(sess->user->top != NULL && sess != sess->user->top)
        return mod_PASS;

    ret = storage_get(sess->user->sm->st, "status", jid_user(sess->jid), NULL, &os);
    if (ret == st_SUCCESS)
    {
        if (os_iter_first(os))
        {
            o = os_iter_object(os);
            os_object_get_time(os, o, "last-logout", &lastlogout);
	    os_object_get_nad(os, o, "xml", &nad);
	    nad = nad_copy(nad);
        }
        os_free(os);
    }
    else
    {
        lastlogout = (time_t) 0;
	nad = NULL;
    }
    
    t = time(NULL);
    _status_os_replace(sess->user->sm->st, jid_user(sess->jid), "online", "", &t, &lastlogout, nad);

    if(nad != NULL) nad_free(nad);

    return mod_PASS;
}

static void _status_sess_end(mod_instance_t mi, sess_t sess) {
    time_t t, lastlogin;
    os_t os;
    os_object_t o;
    st_ret_t ret;
    nad_t nad;

    /* not interested if there is other top session */
    if(sess->user->top != NULL && sess != sess->user->top)
        return;

    ret = storage_get(sess->user->sm->st, "status", jid_user(sess->jid), NULL, &os);
    if (ret == st_SUCCESS)
    {
        if (os_iter_first(os))
        {
            o = os_iter_object(os);
            os_object_get_time(os, o, "last-login", &lastlogin);
	    os_object_get_nad(os, o, "xml", &nad);
	    nad = nad_copy(nad);
        }
        os_free(os);
    }
    else
    {
        lastlogin = (time_t) 0;
	nad = NULL;
    }

    t = time(NULL);
    _status_os_replace(sess->user->sm->st, jid_user(sess->jid), "offline", "", &lastlogin, &t, nad);

    if(nad != NULL) nad_free(nad);
}

static mod_ret_t _status_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    time_t lastlogin, lastlogout;
    os_t os;
    os_object_t o;
    st_ret_t ret;

    /* only handle presence */
    if(!(pkt->type & pkt_PRESENCE))
        return mod_PASS;

    ret = storage_get(sess->user->sm->st, "status", jid_user(sess->jid), NULL, &os);
    if (ret == st_SUCCESS)
    {
        if (os_iter_first(os))
        {
            o = os_iter_object(os);
            os_object_get_time(os, o, "last-login", &lastlogin);
            os_object_get_time(os, o, "last-logout", &lastlogout);
        }
        os_free(os);
    }
    else
    {
        lastlogin = (time_t) 0;
        lastlogout = (time_t) 0;
    }

    /* Store only presence broadcasts. If the presence is for a specific user, ignore it. */
    if (pkt->to == NULL)
        _status_store(sess->user->sm->st, jid_user(sess->jid), pkt, &lastlogin, &lastlogout);

    return mod_PASS;
}

/* presence packets incoming from other servers */
static mod_ret_t _status_pkt_sm(mod_instance_t mi, pkt_t pkt) {
    time_t t;
    jid_t jid;
    module_t mod = mi->mod;
    status_t st = (status_t) mod->private;

    /* store presence information */
    if(pkt->type == pkt_PRESENCE || pkt->type == pkt_PRESENCE_UN) {
        log_debug(ZONE, "storing presence from %s", jid_full(pkt->from));

        t = (time_t) 0;
        
        _status_store(mod->mm->sm->st, jid_user(pkt->from), pkt, &t, &t);
    }

    /* answer to probes and subscription requests*/
    if(st->resource && (pkt->type == pkt_PRESENCE_PROBE || pkt->type == pkt_S10N)) {
        log_debug(ZONE, "answering presence probe/sub from %s with /%s resource", jid_full(pkt->from), st->resource);

        /* send presence */
        jid = jid_new(pkt->to->domain, -1);
        jid = jid_reset_components(jid, jid->node, jid->domain, st->resource);
        pkt_router(pkt_create(st->sm, "presence", NULL, jid_user(pkt->from), jid_full(jid)));
        jid_free(jid);
    }

    /* and handle over */
    return mod_PASS;

}

static void _status_user_delete(mod_instance_t mi, jid_t jid) {
    log_debug(ZONE, "deleting status information of %s", jid_user(jid));

    storage_delete(mi->sm->st, "status", jid_user(jid), NULL);
}

static void _status_free(module_t mod) {
    free(mod->private);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    status_t tr;

    if (mod->init) return 0;

    tr = (status_t) calloc(1, sizeof(struct _status_st));

    tr->sm = mod->mm->sm;
    tr->resource = config_get_one(mod->mm->sm->config, "status.resource", 0);

    mod->private = tr;

    mod->sess_start = _status_sess_start;
    mod->sess_end = _status_sess_end;
    mod->in_sess = _status_in_sess;
    mod->pkt_sm = _status_pkt_sm;
    mod->user_delete = _status_user_delete;
    mod->free = _status_free;

    return 0;
}
