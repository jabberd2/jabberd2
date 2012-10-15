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
#include <time.h>

/** @file sm/mod_announce.c
  * @brief announce (broadcast) messages
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.23 $
  */

/*
 * message to host/announce goes to all online sessions and to offline users next time they connect
 * message to host/announce/online goes to all online sessions
 */

typedef struct moddata_st {
    nad_t       nad;
    int         loaded;
    time_t      t;
    os_t        tos;
    int         index;
    char        *announce_resource;
    char        *online_resource;
} *moddata_t;

static void _announce_load(module_t mod, moddata_t data, const char *domain) {
    st_ret_t ret;
    os_t os;
    os_object_t o;
    nad_t nad;
    int ns, elem, attr;
    char timestamp[18], telem[5];
    struct tm tm;

    /* struct tm can vary in size depending on platform */
    memset(&tm, 0, sizeof(struct tm));

    data->loaded = 1;

    /* load the current message */
    if((ret = storage_get(mod->mm->sm->st, "motd-message", domain, NULL, &os)) == st_SUCCESS) {
        os_iter_first(os);
        o = os_iter_object(os);
        if(os_object_get_nad(os, o, "xml", &nad)) {
            /* Copy the nad, as the original is freed when the os is freed below */
            data->nad = nad_copy(nad);
            if((ns = nad_find_scoped_namespace(data->nad, uri_DELAY, NULL)) >= 0 &&
               (elem = nad_find_elem(data->nad, 1, ns, "x", 1)) >= 0 &&
               (attr = nad_find_attr(data->nad, elem, -1, "stamp", NULL)) >= 0) {
                snprintf(timestamp, 18, "%.*s", NAD_AVAL_L(data->nad, attr), NAD_AVAL(data->nad, attr));

                /* year */
                telem[0] = timestamp[0];
                telem[1] = timestamp[1];
                telem[2] = timestamp[2];
                telem[3] = timestamp[3];
                telem[4] = '\0';
                tm.tm_year = atoi(telem) - 1900;

                /* month */
                telem[0] = timestamp[4];
                telem[1] = timestamp[5];
                telem[2] = '\0';
                tm.tm_mon = atoi(telem) - 1;

                /* day */
                telem[0] = timestamp[6];
                telem[1] = timestamp[7];
                tm.tm_mday = atoi(telem);

                /* hour */
                telem[0] = timestamp[9];
                telem[1] = timestamp[10];
                tm.tm_hour = atoi(telem);

                /* minute */
                telem[0] = timestamp[12];
                telem[1] = timestamp[13];
                tm.tm_min = atoi(telem);

                /* second */
                telem[0] = timestamp[15];
                telem[1] = timestamp[16];
                tm.tm_sec = atoi(telem);
            
                data->t = timegm(&tm);
            }
        }

        os_free(os);
    }

    if(data->tos != NULL)
        os_free(data->tos);
    data->tos = os_new();
    os_object_put(os_object_new(data->tos), "time", &data->t, os_type_INTEGER);
}

static mod_ret_t _announce_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    module_t mod = mi->mod;
    moddata_t data = (moddata_t) mod->private;
    time_t t;
    nad_t nad;
    pkt_t motd;
    os_t os;
    os_object_t o;

    /* try to load data if we haven't yet */
    if(data->nad == NULL) {
        if(data->loaded)
            return mod_PASS;        /* nothing to give them */
        _announce_load(mod, data, sess->user->jid->domain);
        if(data->nad == NULL)
            return mod_PASS;
    }

    /* if they're becoming available for the first time */
    if(pkt->type == pkt_PRESENCE && pkt->to == NULL && sess->user->top == NULL) {
        /* load the time of the last motd they got */
        if((time_t) sess->user->module_data[mod->index] == 0 &&
           storage_get(sess->user->sm->st, "motd-times", jid_user(sess->jid), NULL, &os) == st_SUCCESS) {
            os_iter_first(os);
            o = os_iter_object(os);
            os_object_get_time(os, o, "time", &t);
            sess->user->module_data[mod->index] = (void *) t;
            os_free(os);
        }

        /* they've seen this one */
        if((time_t) sess->user->module_data[mod->index] >= data->t)
            return mod_PASS;

        /* a-delivering we go */
        log_debug(ZONE, "delivering stored motd to %s", jid_full(sess->jid));

        nad = nad_copy(data->nad);
        nad_set_attr(nad, 1, -1, "to", jid_full(sess->jid), strlen(jid_full(sess->jid)));
        nad_set_attr(nad, 1, -1, "from", sess->user->jid->domain, strlen(sess->user->jid->domain));

        motd = pkt_new(mod->mm->sm, nad);
        if(motd == NULL) {
            log_debug(ZONE, "invalid stored motd, not delivering");
            nad_free(nad);
        } else
            pkt_router(motd);

        sess->user->module_data[mod->index] = (void *) data->t;
        storage_replace(sess->user->sm->st, "motd-times", jid_user(sess->jid), NULL, data->tos);
    }

    return mod_PASS;
}

static void _announce_broadcast_user(const char *key, int keylen, void *val, void *arg) {
    user_t user = (user_t) val;
    moddata_t data = (moddata_t) arg;
    sess_t sess;
    nad_t nad;

    for(sess = user->sessions; sess != NULL; sess = sess->next) {
        if(!sess->available || sess->pri < 0)
            continue;

        log_debug(ZONE, "resending to '%s'", jid_full(sess->jid));

        nad = nad_copy(data->nad);
        nad_set_attr(nad, 1, -1, "to", jid_full(sess->jid), strlen(jid_full(sess->jid)));
        nad_set_attr(nad, 1, -1, "from", sess->jid->domain, strlen(sess->jid->domain));

        pkt_router(pkt_new(user->sm, nad));

        sess->user->module_data[data->index] = (void *) data->t;
        storage_replace(sess->user->sm->st, "motd-times", jid_user(sess->jid), NULL, data->tos);
    }
}

static mod_ret_t _announce_pkt_sm(mod_instance_t mi, pkt_t pkt) {
    module_t mod = mi->mod;
    moddata_t data = (moddata_t) mod->private;
    pkt_t store;
    nad_t nad;
    jid_t jid;
    time_t t;
    os_t os;
    os_object_t o;
    st_ret_t ret;
    int elem;

    /* time of this packet */
    t = time(NULL);

    /* answer to probes and subscription requests if admin */
    if((pkt->type == pkt_PRESENCE_PROBE || pkt->type == pkt_S10N) && aci_check(mod->mm->sm->acls, "broadcast", pkt->from)) {
        log_debug(ZONE, "answering presence probe/sub from %s with /announce resources", jid_full(pkt->from));

        /* send presences */
        jid = jid_new(pkt->from->domain, -1);
        jid_reset_components(jid, jid->node, jid->domain, data->announce_resource);
        pkt_router(pkt_create(mod->mm->sm, "presence", NULL, jid_user(pkt->from), jid_full(jid)));
        jid_free(jid);

        jid = jid_new(pkt->from->domain, -1);
        jid_reset_components(jid, jid->node, jid->domain, data->online_resource);
        pkt_router(pkt_create(mod->mm->sm, "presence", NULL, jid_user(pkt->from), jid_full(jid)));
        jid_free(jid);
    }

    /* we want messages addressed to /announce */
    if(!(pkt->type & pkt_MESSAGE) || strlen(pkt->to->resource) < 8 || strncmp(pkt->to->resource, data->announce_resource, 8) != 0)
        return mod_PASS;
    
    /* make sure they're allowed */
    if(!aci_check(mod->mm->sm->acls, "broadcast", pkt->from)) {
        log_debug(ZONE, "not allowing broadcast from %s", jid_full(pkt->from));
        return -stanza_err_FORBIDDEN;
    }

    /* "fix" packet a bit */
    /* force type normal */
    nad_set_attr(pkt->nad, 1, -1, "type", NULL, 0);
    /* remove sender nick */
    elem = nad_find_elem(pkt->nad, 1, -1, "nick", 1);
    if(elem >= 0) nad_drop_elem(pkt->nad, elem);

    if(pkt->to->resource[8] == '\0') {
        log_debug(ZONE, "storing message for announce later");

        store = pkt_dup(pkt, NULL, NULL);

        pkt_delay(store, t, pkt->to->domain);

        /* prepare for storage */
        os = os_new();
        o = os_object_new(os);

        os_object_put(o, "xml", store->nad, os_type_NAD);

        /* store it */
        ret = storage_replace(mod->mm->sm->st, "motd-message", pkt->to->domain, NULL, os);
        os_free(os);

        switch(ret) {
            case st_FAILED:
                pkt_free(store);
                return -stanza_err_INTERNAL_SERVER_ERROR;

            case st_NOTIMPL:
                pkt_free(store);
                return -stanza_err_FEATURE_NOT_IMPLEMENTED;

            default:
                break;
        }

        /* replace our local copy */
        if(data->nad != NULL)
            nad_free(data->nad);
        data->nad = store->nad;

        store->nad = NULL;
        pkt_free(store);

        /* update timestamp */
        data->t = t;
        if(data->tos != NULL)
            os_free(data->tos);
        data->tos = os_new();
        os_object_put(os_object_new(data->tos), "time", &t, os_type_INTEGER);
    }

    else if(strcmp(&(pkt->to->resource[8]), "/online") != 0) {
        log_debug(ZONE, "unknown announce resource '%s'", pkt->to->resource);
        pkt_free(pkt);
        return mod_HANDLED;
    }

    log_debug(ZONE, "broadcasting message to all sessions");

    /* hack */
    nad = data->nad;
    data->nad = pkt->nad;
    xhash_walk(mod->mm->sm->users, _announce_broadcast_user, (void *) data);
    data->nad = nad;

    /* done */
    pkt_free(pkt);

    return mod_HANDLED;
}

static void _announce_user_delete(mod_instance_t mi, jid_t jid) {
    log_debug(ZONE, "deleting motd time for %s", jid_user(jid));

    storage_delete(mi->sm->st, "motd-times", jid_user(jid), NULL);
}

static void _announce_free(module_t mod) {
    moddata_t data = (moddata_t) mod->private;

    if(data->nad != NULL) nad_free(data->nad);
    if(data->tos != NULL) os_free(data->tos);
    free(data);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;
    moddata_t data;

    if(mod->init) return 0;

    data = (moddata_t) calloc(1, sizeof(struct moddata_st));

    mod->private = (void *) data;

    data->index = mod->index;

    data->announce_resource = "announce";
    data->online_resource = "announce/online";

    mod->in_sess = _announce_in_sess;
    mod->pkt_sm = _announce_pkt_sm;
    mod->user_delete = _announce_user_delete;
    mod->free = _announce_free;

    return 0;
}
