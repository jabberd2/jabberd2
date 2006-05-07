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
    sm_t    sm;
} *status_t;

static int _status_sess_start(mod_instance_t mi, sess_t sess) {
    module_t mod = mi->mod;
    status_t st = (status_t) mod->private;
    time_t t, lastlogout;
    os_t os;
    os_object_t o;
    st_ret_t ret;

    ret = storage_get(sess->user->sm->st, "status", jid_user(sess->jid), NULL, &os);
    if (ret == st_SUCCESS)
    {
        if (os_iter_first(os))
        {
            o = os_iter_object(os);
            os_object_get_time(os, o, "last-logout", &lastlogout);
        }
        os_free(os);
    }
    else
    {
        lastlogout = (time_t) 0;
    }
    
    t = time(NULL);
    os = os_new();
    o = os_object_new(os);
    os_object_put(o, "status", "online", os_type_STRING);
    os_object_put(o, "show", "", os_type_STRING);
    os_object_put(o, "last-login", (void **) &t, os_type_INTEGER);
    os_object_put(o, "last-logout", (void **) &lastlogout, os_type_INTEGER);
    storage_replace(sess->user->sm->st, "status", jid_user(sess->jid), NULL, os);
    os_free(os);

    return mod_PASS;
}

static void _status_sess_end(mod_instance_t mi, sess_t sess) {
    module_t mod = mi->mod;
    status_t st = (status_t) mod->private;
    time_t t, lastlogin;
    os_t os;
    os_object_t o;
    st_ret_t ret;

    ret = storage_get(sess->user->sm->st, "status", jid_user(sess->jid), NULL, &os);
    if (ret == st_SUCCESS)
    {
        if (os_iter_first(os))
        {
            o = os_iter_object(os);
            os_object_get_time(os, o, "last-login", &lastlogin);
        }
        os_free(os);
    }
    else
    {
        lastlogin = (time_t) 0;
    }

    t = time(NULL);
    os = os_new();
    o = os_object_new(os);
    os_object_put(o, "status", "offline", os_type_STRING);
    os_object_put(o, "show", "", os_type_STRING);
    os_object_put(o, "last-login", (void **) &lastlogin, os_type_INTEGER);
    os_object_put(o, "last-logout", (void **) &t, os_type_INTEGER);
    storage_replace(sess->user->sm->st, "status", jid_user(sess->jid), NULL, os);
    os_free(os);
}

static void _status_user_delete(mod_instance_t mi, jid_t jid) {
    module_t mod = mi->mod;
    status_t st = (status_t) mod->private;

    storage_delete(mi->sm->st, "status", jid_user(jid), NULL);
}

static mod_ret_t _status_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    module_t mod = mi->mod;
    status_t st = (status_t) mod->private;
    time_t lastlogin, lastlogout;
    os_t os;
    os_object_t o;
    st_ret_t ret;
    char * show;
    int show_free = 0;

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

    /* If the presence is for a specific user, ignore it. */
    if(pkt->to == NULL)
    {
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

        os = os_new();
        o = os_object_new(os);
        os_object_put(o, "status", "online", os_type_STRING);
        os_object_put(o, "show", show, os_type_STRING);
        os_object_put(o, "last-login", (void **) &lastlogin, os_type_INTEGER);
        os_object_put(o, "last-logout", (void **) &lastlogout, os_type_INTEGER);
        storage_replace(sess->user->sm->st, "status", jid_user(sess->jid), NULL, os);
        os_free(os);
        if(show_free) free(show);
    }
    return mod_PASS;
}

DLLEXPORT int module_init(mod_instance_t mi, char *arg) {
    module_t mod = mi->mod;

    status_t tr;

    if (mod->init) return 0;

    tr = (status_t) malloc(sizeof(struct _status_st));
    memset(tr, 0, sizeof(struct _status_st));

    tr->sm = mod->mm->sm;

    mod->private = tr;

    mod->user_delete = _status_user_delete;
    mod->sess_start = _status_sess_start;
    mod->sess_end = _status_sess_end;
    mod->in_sess = _status_in_sess;

    return 0;
}
