/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
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

/** @file sm/mod_vacation.c
  * @brief vacation messages
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.13 $
  */

#define uri_VACATION    "http://jabber.org/protocol/vacation"
static int ns_VACATION = 0;

typedef struct _vacation_st {
    time_t  start;
    time_t  end;
    char    *msg;
} *vacation_t;

static mod_ret_t _vacation_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    module_t mod = mi->mod;
    vacation_t v = sess->user->module_data[mod->index];
    int ns, start, end, msg;
    char dt[30];
    pkt_t res;
    os_t os;
    os_object_t o;

    /* we only want to play with vacation iq packets */
    if((pkt->type != pkt_IQ && pkt->type != pkt_IQ_SET) || pkt->ns != ns_VACATION)
        return mod_PASS;

    /* if it has a to, throw it out */
    if(pkt->to != NULL)
        return -stanza_err_BAD_REQUEST;

    /* get */
    if(pkt->type == pkt_IQ) {
        if(v->msg == NULL) {
            res = pkt_create(mod->mm->sm, "iq", "result", NULL, NULL);
            pkt_id(pkt, res);
            pkt_free(pkt);

            pkt_sess(res, sess);

            return mod_HANDLED;
        }

        ns = nad_find_scoped_namespace(pkt->nad, uri_VACATION, NULL);

        if(v->start != 0) {
            datetime_out(v->start, dt_DATETIME, dt, 30);
            nad_insert_elem(pkt->nad, 2, ns, "start", dt);
        } else
            nad_insert_elem(pkt->nad, 2, ns, "start", NULL);

        if(v->end != 0) {
            datetime_out(v->end, dt_DATETIME, dt, 30);
            nad_insert_elem(pkt->nad, 2, ns, "end", dt);
        } else
            nad_insert_elem(pkt->nad, 2, ns, "end", NULL);

        nad_insert_elem(pkt->nad, 2, ns, "message", v->msg);

        pkt_tofrom(pkt);
        nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);

        pkt_sess(pkt, sess);

        return mod_HANDLED;
    }

    /* set */
    ns = nad_find_scoped_namespace(pkt->nad, uri_VACATION, NULL);

    start = nad_find_elem(pkt->nad, 2, ns, "start", 1);
    end = nad_find_elem(pkt->nad, 2, ns, "end", 1);
    msg = nad_find_elem(pkt->nad, 2, ns, "message", 1);

    if(start < 0 || end < 0 || msg < 0) {
        /* forget */
        if(v->msg != NULL) {
            free(v->msg);
            v->msg = NULL;
        }
        v->start = 0;
        v->end = 0;

        storage_delete(mi->sm->st, "vacation-settings", jid_user(sess->jid), NULL);

        res = pkt_create(mod->mm->sm, "iq", "result", NULL, NULL);
        pkt_id(pkt, res);
        pkt_free(pkt);

        pkt_sess(res, sess);

        return mod_HANDLED;
    }

    if(NAD_CDATA_L(pkt->nad, start) > 0) {
        strncpy(dt, NAD_CDATA(pkt->nad, start), (30 < NAD_CDATA_L(pkt->nad, start) ? 30 : NAD_CDATA_L(pkt->nad, start)));
        v->start = datetime_in(dt);
    } else
        v->start = 0;

    if(NAD_CDATA_L(pkt->nad, end) > 0) {
        strncpy(dt, NAD_CDATA(pkt->nad, end), (30 < NAD_CDATA_L(pkt->nad, end) ? 30 : NAD_CDATA_L(pkt->nad, end)));
        v->end = datetime_in(dt);
    } else
        v->end = 0;

    v->msg = (char *) malloc(sizeof(char) * (NAD_CDATA_L(pkt->nad, msg) + 1));
    strncpy(v->msg, NAD_CDATA(pkt->nad, msg), NAD_CDATA_L(pkt->nad, msg));
    v->msg[NAD_CDATA_L(pkt->nad, msg)] = '\0';

    os = os_new();
    o = os_object_new(os);
    os_object_put(o, "start", &v->start, os_type_INTEGER);
    os_object_put(o, "end", &v->end, os_type_INTEGER);
    os_object_put(o, "message", v->msg, os_type_STRING);

    if(storage_replace(mod->mm->sm->st, "vacation-settings", jid_user(sess->user->jid), NULL, os) != st_SUCCESS) {
        free(v->msg);
        v->msg = NULL;
        v->start = 0;
        v->end = 0;
        return -stanza_err_INTERNAL_SERVER_ERROR;
    }
    
    res = pkt_create(mod->mm->sm, "iq", "result", NULL, NULL);
    pkt_id(pkt, res);
    pkt_free(pkt);

    pkt_sess(res, sess);

    return mod_HANDLED;
}

static mod_ret_t _vacation_pkt_user(mod_instance_t mi, user_t user, pkt_t pkt) {
    module_t mod = mi->mod;
    vacation_t v = user->module_data[mod->index];
    time_t t;
    pkt_t res;

    if(v->msg == NULL)
        return mod_PASS;

    /* only want messages, and only if they're offline */
    if(!(pkt->type & pkt_MESSAGE) || user->top != NULL)
        return mod_PASS;

    /* reply only to real, human users - they always have full JIDs in 'from' */
    jid_expand(pkt->from);
    if(pkt->from->node[0] == '\0' || pkt->from->resource[0] == '\0') {
        pkt_free(pkt);
        return mod_HANDLED;
    }

    t = time(NULL);

    if(v->start < t && (t < v->end || v->end == 0)) {
        res = pkt_create(mod->mm->sm, "message", NULL, jid_full(pkt->from), user->jid->domain);
        nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1), "subject", "Automated reply");
        nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1), "body", v->msg);
        pkt_router(res);

        /* !!! remember that we sent this */
    }

    return mod_PASS;
}

static void _vacation_user_free(vacation_t v) {
    if(v->msg != NULL)
        free(v->msg);
    free(v);
}

static int _vacation_user_load(mod_instance_t mi, user_t user) {
    module_t mod = mi->mod;
    vacation_t v;
    os_t os;
    os_object_t o;

    v = (vacation_t) calloc(1, sizeof(struct _vacation_st));
    user->module_data[mod->index] = v;

    if(storage_get(mod->mm->sm->st, "vacation-settings", jid_user(user->jid), NULL, &os) == st_SUCCESS) {
        if(os_iter_first(os)) {
            o = os_iter_object(os);

            if(os_object_get_time(os, o, "start", &v->start) &&
               os_object_get_time(os, o, "end", &v->end) &&
               os_object_get_str(os, o, "message", &v->msg))
                v->msg = strdup(v->msg);
            else {
                v->start = 0;
                v->end = 0;
                v->msg = NULL;
            }
        }

        os_free(os);
    }

    pool_cleanup(user->p, (void (*))(void *) _vacation_user_free, v);

    return 0;
}

static void _vacation_user_delete(mod_instance_t mi, jid_t jid) {
    log_debug(ZONE, "deleting vacations settings for %s", jid_user(jid));

    storage_delete(mi->sm->st, "vacation-settings", jid_user(jid), NULL);
}

static void _vacation_free(module_t mod) {
    sm_unregister_ns(mod->mm->sm, uri_VACATION);
    feature_unregister(mod->mm->sm, uri_VACATION);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->in_sess = _vacation_in_sess;
    mod->pkt_user = _vacation_pkt_user;
    mod->user_load = _vacation_user_load;
    mod->user_delete = _vacation_user_delete;
    mod->free = _vacation_free; /* mmm good! :) */

    ns_VACATION = sm_register_ns(mod->mm->sm, uri_VACATION);
    feature_register(mod->mm->sm, uri_VACATION);

    return 0;
}
