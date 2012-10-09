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

/** @file sm/mod_roster.c
  * @brief roster managment & subscriptions
  * @author Robert Norris
  * $Date: 2005/09/09 05:34:13 $
  * $Revision: 1.61 $
  */

typedef struct _mod_roster_st {
    int maxitems;
} *mod_roster_t;

typedef struct _roster_walker_st {
    pkt_t  pkt;
    int    req_ver;
    int    ver;
    sess_t sess;
} *roster_walker_t;

/** free a single roster item */
static void _roster_freeuser_walker(const char *key, int keylen, void *val, void *arg)
{
    item_t item = (item_t) val;
    int i;

    jid_free(item->jid);
    
    if(item->name != NULL)
        free((void*)item->name);

    for(i = 0; i < item->ngroups; i++)
        free((void*)item->groups[i]);
    free(item->groups);

    free(item);
}

/** free the roster */
static void _roster_freeuser(user_t user)
{
    if(user->roster == NULL)
        return;

    log_debug(ZONE, "freeing roster for %s", jid_user(user->jid));

    xhash_walk(user->roster, _roster_freeuser_walker, NULL);

    xhash_free(user->roster);
    user->roster = NULL;
}

static void _roster_save_item(user_t user, item_t item) {
    os_t os;
    os_object_t o;
    char filter[4096];
    int i;

    log_debug(ZONE, "saving roster item %s for %s", jid_full(item->jid), jid_user(user->jid));

    os = os_new();
    o = os_object_new(os);

    os_object_put(o, "jid", jid_full(item->jid), os_type_STRING);

    if(item->name != NULL)
        os_object_put(o, "name", item->name, os_type_STRING);

    os_object_put(o, "to", &item->to, os_type_BOOLEAN);
    os_object_put(o, "from", &item->from, os_type_BOOLEAN);
    os_object_put(o, "ask", &item->ask, os_type_INTEGER);

    snprintf(filter, 4096, "(jid=%zu:%s)", strlen(jid_full(item->jid)), jid_full(item->jid));

    storage_replace(user->sm->st, "roster-items", jid_user(user->jid), filter, os);

    os_free(os);

    if(item->ngroups == 0) {
        storage_delete(user->sm->st, "roster-groups", jid_user(user->jid), filter);
        return;
    }

    os = os_new();
    
    for(i = 0; i < item->ngroups; i++) {
        o = os_object_new(os);

        os_object_put(o, "jid", jid_full(item->jid), os_type_STRING);
        os_object_put(o, "group", item->groups[i], os_type_STRING);
    }

    storage_replace(user->sm->st, "roster-groups", jid_user(user->jid), filter, os);

    os_free(os);
}

/** insert a roster item into this pkt, starting at elem */
static void _roster_insert_item(pkt_t pkt, item_t item, int elem)
{
    int ns, i;
    char *sub;

    ns = nad_add_namespace(pkt->nad, uri_CLIENT, NULL);
    elem = nad_insert_elem(pkt->nad, elem, ns, "item", NULL);
    nad_set_attr(pkt->nad, elem, -1, "jid", jid_full(item->jid), 0);

    if(item->to && item->from)
        sub = "both";
    else if(item->to)
        sub = "to";
    else if(item->from)
        sub = "from";
    else
        sub = "none";

    nad_set_attr(pkt->nad, elem, -1, "subscription", sub, 0);

    if(item->ask == 1)
        nad_set_attr(pkt->nad, elem, -1, "ask", "subscribe", 9);
    else if(item->ask == 2) /* XXX there is no ask='unsubscribe' in RFC bis anymore */
        nad_set_attr(pkt->nad, elem, -1, "ask", "unsubscribe", 11);

    if(item->name != NULL)
        nad_set_attr(pkt->nad, elem, -1, "name", item->name, 0);

    for(i = 0; i < item->ngroups; i++)
        nad_insert_elem(pkt->nad, elem, NAD_ENS(pkt->nad, elem), "group", item->groups[i]);
}

/** push this packet to all sessions except the given one */
static int _roster_push(user_t user, pkt_t pkt, int mod_index)
{
    sess_t scan;
    pkt_t push;
    int pushes = 0;

    /* do the push */
    for(scan = user->sessions; scan != NULL; scan = scan->next)
    {
        /* don't push to us or to anyone who hasn't loaded the roster */
        if(scan->module_data[mod_index] == NULL)
            continue;

        push = pkt_dup(pkt, jid_full(scan->jid), NULL);
        pkt_sess(push, scan);
        pushes++;
    }

    /* return the pushed packets count */
    return pushes;
}

static mod_ret_t _roster_in_sess_s10n(mod_instance_t mi, sess_t sess, pkt_t pkt)
{
    mod_roster_t mroster = (mod_roster_t) mi->mod->private;
    module_t mod = mi->mod;
    item_t item;
    pkt_t push;
    int ns, elem, ret, items = -1;

    log_debug(ZONE, "got s10n packet");

    /* s10ns have to go to someone */
    if(pkt->to == NULL)
        return -stanza_err_BAD_REQUEST;

    /* add a proper from address (no resource) */
    if(pkt->from != NULL)
        jid_free(pkt->from);

    pkt->from = jid_new(jid_user(sess->jid), -1);
    nad_set_attr(pkt->nad, 1, -1, "from", jid_full(pkt->from), 0);

    /* see if they're already on the roster */
    item = xhash_get(sess->user->roster, jid_full(pkt->to));
    if(item == NULL)
    {
        /* if they're not on the roster, there's no subscription,
         * so quietly pass it on */
        if(pkt->type == pkt_S10N_UN || pkt->type == pkt_S10N_UNED)
            return mod_PASS;

        /* check if user exceedes maximum roster items */
        if(mroster->maxitems > 0) {
            ret = storage_count(sess->user->sm->st, "roster-items", jid_user(sess->user->jid), NULL, &items);

            log_debug(ZONE, "user has %i roster-items, maximum is %i", items, mroster->maxitems);

            /* if the limit is reached, return an error */
            if (ret == st_SUCCESS && items >= mroster->maxitems)
                return -stanza_err_NOT_ACCEPTABLE;
        }

        /* make a new one */
        item = (item_t) calloc(1, sizeof(struct item_st));

        item->jid = jid_dup(pkt->to);

        /* remember it */
        xhash_put(sess->user->roster, jid_full(item->jid), (void *) item);

        log_debug(ZONE, "made new empty roster item for %s", jid_full(item->jid));
    }

    /* a request */
    if(pkt->type == pkt_S10N && ! item->to)
        item->ask = 1;
    else if(pkt->type == pkt_S10N_UN && item->to)
        item->ask = 2;

    /* changing states */
    else if(pkt->type == pkt_S10N_ED)
    {
        /* they're allowed to see us, send them presence */
        item->from = 1;
        pres_roster(sess, item);
    }
    else if(pkt->type == pkt_S10N_UNED)
    {
        /* they're not allowed to see us anymore */
        item->from = 0;
        pres_roster(sess, item);
    }

    if (sm_storage_rate_limit(sess->user->sm, jid_user(sess->user->jid)))
        return -stanza_err_RESOURCE_CONSTRAINT;

    /* save changes */
    _roster_save_item(sess->user, item);
    
    /* build a new packet to push out to everyone */
    push = pkt_create(sess->user->sm, "iq", "set", NULL, NULL);
    pkt_id_new(push);
    ns = nad_add_namespace(push->nad, uri_ROSTER, NULL);
    elem = nad_append_elem(push->nad, ns, "query", 3);

    _roster_insert_item(push, item, elem);

    /* tell everyone */
    _roster_push(sess->user, push, mod->index);

    /* everyone knows */
    pkt_free(push);

    /* pass it on */
    return mod_PASS;
}

/** build the iq:roster packet from the hash */
static void _roster_get_walker(const char *id, int idlen, void *val, void *arg)
{
    item_t item = (item_t) val;
    roster_walker_t rw = (roster_walker_t) arg;

    _roster_insert_item(rw->pkt, item, 2);

    /* remember largest item version */
    if(item->ver > rw->ver) rw->ver = item->ver;
}

/** push roster XEP-0237 updates to client */
static void _roster_update_walker(const char *id, int idlen, void *val, void *arg)
{
    pkt_t push;
    char *buf;
    int elem, ns;
    item_t item = (item_t) val;
    roster_walker_t rw = (roster_walker_t) arg;

    /* skip unneded roster items */
    if(item->ver <= rw->req_ver) return;

    /* build a interim roster push packet */
    push = pkt_create(rw->sess->user->sm, "iq", "set", NULL, NULL);
    pkt_id_new(push);
    ns = nad_add_namespace(push->nad, uri_ROSTER, NULL);
    elem = nad_append_elem(push->nad, ns, "query", 3);

    buf = (char *) malloc(sizeof(char) * 128);
    sprintf(buf, "%d", item->ver);
    nad_set_attr(push->nad, elem, -1, "ver", buf, 0);
    free(buf);

    _roster_insert_item(push, item, elem);

    pkt_sess(push, rw->sess);
}

static void _roster_set_item(pkt_t pkt, int elem, sess_t sess, mod_instance_t mi)
{
    mod_roster_t mroster = (mod_roster_t) mi->mod->private;
    module_t mod = mi->mod;
    int attr, ns, i, ret, items = -1;
    jid_t jid;
    item_t item;
    pkt_t push;
    char filter[4096];

    /* extract the jid */
    attr = nad_find_attr(pkt->nad, elem, -1, "jid", NULL);
    jid = jid_new(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
    if(jid == NULL) {
        log_debug(ZONE, "jid failed prep check, skipping");
        return;
    }

    /* check for removals */
    if(nad_find_attr(pkt->nad, elem, -1, "subscription", "remove") >= 0)
    {
        /* trash the item */
        item = xhash_get(sess->user->roster, jid_full(jid));
        if(item != NULL)
        {
            /* tell them they're unsubscribed */
            if(item->from) {
                log_debug(ZONE, "telling %s that they're unsubscribed", jid_user(item->jid));
                pkt_router(pkt_create(sess->user->sm, "presence", "unsubscribed", jid_user(item->jid), jid_user(sess->jid)));
            }
            item->from = 0;

            /* tell them to unsubscribe us */
            if(item->to) {
                log_debug(ZONE, "unsubscribing from %s", jid_user(item->jid));
                pkt_router(pkt_create(sess->user->sm, "presence", "unsubscribe", jid_user(item->jid), jid_user(sess->jid)));
            }
            item->to = 0;
        
            /* send unavailable */
            pres_roster(sess, item);

            /* kill it */
            xhash_zap(sess->user->roster, jid_full(jid));
            _roster_freeuser_walker((const char *) jid_full(jid), strlen(jid_full(jid)), (void *) item, NULL);

            snprintf(filter, 4096, "(jid=%zu:%s)", strlen(jid_full(jid)), jid_full(jid));
            storage_delete(sess->user->sm->st, "roster-items", jid_user(sess->jid), filter);
            storage_delete(sess->user->sm->st, "roster-groups", jid_user(sess->jid), filter);
        }

        log_debug(ZONE, "removed %s from roster", jid_full(jid));

        /* build a new packet to push out to everyone */
        push = pkt_create(sess->user->sm, "iq", "set", NULL, NULL);
        pkt_id_new(push);
        ns = nad_add_namespace(push->nad, uri_ROSTER, NULL);

        nad_append_elem(push->nad, ns, "query", 3);
        elem = nad_append_elem(push->nad, ns, "item", 4);
        nad_set_attr(push->nad, elem, -1, "jid", jid_full(jid), 0);
        nad_set_attr(push->nad, elem, -1, "subscription", "remove", 6);

        /* tell everyone */
        _roster_push(sess->user, push, mod->index);

        /* we're done */
        pkt_free(push);

        jid_free(jid);

        return;
    }

    /* find a pre-existing one */
    item = xhash_get(sess->user->roster, jid_full(jid));
    if(item == NULL)
    {
        /* check if user exceedes maximum roster items */
        if(mroster->maxitems > 0) {
            ret = storage_count(sess->user->sm->st, "roster-items", jid_user(sess->user->jid), NULL, &items);

            log_debug(ZONE, "user has %i roster-items, maximum is %i", items, mroster->maxitems);

            /* if the limit is reached, skip it */
            if (ret == st_SUCCESS && items >= mroster->maxitems)
                return;
        }

        /* make a new one */
        item = (item_t) calloc(1, sizeof(struct item_st));

        /* add the jid */
        item->jid = jid;

        /* add it to the roster */
        xhash_put(sess->user->roster, jid_full(item->jid), (void *) item);

        log_debug(ZONE, "created new roster item %s", jid_full(item->jid));
    }

    else
        jid_free(jid);

    /* extract the name */
    attr = nad_find_attr(pkt->nad, elem, -1, "name", NULL);
    if(attr >= 0)
    {
        /* free the old name */
        if(item->name != NULL) {
            free((void*)item->name);
            item->name = NULL;
        }

        if (NAD_AVAL_L(pkt->nad, attr) > 0)
        {
            item->name = (const char *) malloc(sizeof(char) * (NAD_AVAL_L(pkt->nad, attr) + 1));
            sprintf((char *)item->name, "%.*s", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));
        }
    }

    /* free the old groups */
    if(item->groups != NULL)
    {
        for(i = 0; i < item->ngroups; i++)
            free((void*)item->groups[i]);
        free(item->groups);
        item->ngroups = 0;
        item->groups = NULL;
    }

    /* loop over the groups, adding them to the array */
    elem = nad_find_elem(pkt->nad, elem, NAD_ENS(pkt->nad, elem), "group", 1);
    while(elem >= 0)
    {
        /* empty group tags get skipped */
        if(NAD_CDATA_L(pkt->nad, elem) >= 0)
        {
            /* make room and shove it in */
            item->groups = (const char **) realloc(item->groups, sizeof(char *) * (item->ngroups + 1));

            item->groups[item->ngroups] = (const char *) malloc(sizeof(char) * (NAD_CDATA_L(pkt->nad, elem) + 1));
            sprintf((char *)(item->groups[item->ngroups]), "%.*s", NAD_CDATA_L(pkt->nad, elem), NAD_CDATA(pkt->nad, elem));

            item->ngroups++;
        }

        elem = nad_find_elem(pkt->nad, elem, NAD_ENS(pkt->nad, elem), "group", 0);
    }

    log_debug(ZONE, "added %s to roster (to %d from %d ask %d name %s ngroups %d)", jid_full(item->jid), item->to, item->from, item->ask, item->name, item->ngroups);

    if (sm_storage_rate_limit(sess->user->sm, jid_user(sess->user->jid)))
        return;

    /* save changes */
    _roster_save_item(sess->user, item);

    /* build a new packet to push out to everyone */
    push = pkt_create(sess->user->sm, "iq", "set", NULL, NULL);
    pkt_id_new(push);
    ns = nad_add_namespace(push->nad, uri_ROSTER, NULL);
    elem = nad_append_elem(push->nad, ns, "query", 3);

    _roster_insert_item(push, item, elem);

    /* tell everyone */
    _roster_push(sess->user, push, mod->index);

    /* we're done */
    pkt_free(push);
}

/** our main handler for packets arriving from a session */
static mod_ret_t _roster_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt)
{
    module_t mod = mi->mod;
    int elem, attr, ver = 0;
    pkt_t result;
    char *buf;
    roster_walker_t rw;

    /* handle s10ns in a different function */
    if(pkt->type & pkt_S10N)
        return _roster_in_sess_s10n(mi, sess, pkt);

    /* we only want to play with iq:roster packets */
    if(pkt->ns != ns_ROSTER)
        return mod_PASS;

    /* quietly drop results, its probably them responding to a push */
    if(pkt->type == pkt_IQ_RESULT) {
        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* need gets or sets */
    if(pkt->type != pkt_IQ && pkt->type != pkt_IQ_SET)
        return mod_PASS;

    /* get */
    if(pkt->type == pkt_IQ)
    {
		/* check for "XEP-0237: Roster Versioning request" */
        if((elem = nad_find_elem(pkt->nad, 1, -1, "query", 1)) >= 0
         &&(attr = nad_find_attr(pkt->nad, elem, -1, "ver", NULL)) >= 0) {
            if (NAD_AVAL_L(pkt->nad, attr) > 0)
            {
                buf = (char *) malloc(sizeof(char) * (NAD_AVAL_L(pkt->nad, attr) + 1));
                sprintf(buf, "%.*s", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));
                ver = j_atoi(buf, 0);
                free(buf);
            }
        }

        /* build the packet */
        rw = (roster_walker_t) calloc(1, sizeof(struct _roster_walker_st));
        rw->pkt = pkt;
        rw->req_ver = ver;
        rw->sess = sess;

        nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);

        if(ver > 0) {
			/* send XEP-0237 empty result */
            nad_drop_elem(pkt->nad, elem);
            pkt_sess(pkt_tofrom(pkt), sess);
            xhash_walk(sess->user->roster, _roster_update_walker, (void *) rw);
        }
        else {
            xhash_walk(sess->user->roster, _roster_get_walker, (void *) rw);
            if(elem >= 0 && attr >= 0) {
                buf = (char *) malloc(sizeof(char) * 128);
                sprintf(buf, "%d", rw->ver);
                nad_set_attr(pkt->nad, elem, -1, "ver", buf, 0);
                free(buf);
            }
            pkt_sess(pkt_tofrom(pkt), sess);
        }

        free(rw);

        /* remember that they loaded it, so we know to push updates to them */
        sess->module_data[mod->index] = (void *) 1;
        
        return mod_HANDLED;
    }

    /* set, find the item */
    elem = nad_find_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 2), "item", 1);
    if(elem < 0)
        /* no item, abort */
        return -stanza_err_BAD_REQUEST;

    /* loop over items and stick them in */
    while(elem >= 0)
    {
        /* extract the jid */
        attr = nad_find_attr(pkt->nad, elem, -1, "jid", NULL);
        if(attr < 0 || NAD_AVAL_L(pkt->nad, attr) == 0)
        {
            log_debug(ZONE, "no jid on this item, aborting");

            /* no jid, abort */
            return -stanza_err_BAD_REQUEST;
        }

        /* utility */
        _roster_set_item(pkt, elem, sess, mi);

        /* next one */
        elem = nad_find_elem(pkt->nad, elem, NAD_ENS(pkt->nad, elem), "item", 0);
    }

    /* send the result */
    result = pkt_create(sess->user->sm, "iq", "result", NULL, NULL);

    pkt_id(pkt, result);

    /* tell them */
    pkt_sess(result, sess);

    /* free the request */
    pkt_free(pkt);

    return mod_HANDLED;
}

/** handle incoming s10ns */
static mod_ret_t _roster_pkt_user(mod_instance_t mi, user_t user, pkt_t pkt)
{
    module_t mod = mi->mod;
    item_t item;
    int ns, elem;

    /* only want s10ns */
    if(!(pkt->type & pkt_S10N))
        return mod_PASS;

    /* drop route errors */
    if(pkt->rtype & route_ERROR) {
        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* get the roster item */
    item = (item_t) xhash_get(user->roster, jid_full(pkt->from));
    if(item == NULL) {
        /* subs are handled by the client */
        if(pkt->type == pkt_S10N) {
            /* if the user is online broadcast it like roster push */
            if(user->top != NULL && _roster_push(user, pkt, mod->index) > 0) {
                /* pushed, thus handled */
                pkt_free(pkt);
                return mod_HANDLED;
            }
            else {
                /* not pushed to any online resource - pass it on (to mod_offline) */
                return mod_PASS;
            }
        }

        /* other S10Ns: we didn't ask for this, so we don't care */
        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* ignore bogus answers */
    if( (pkt->type == pkt_S10N_ED && (item->ask != 1 || item->to) )
     || (pkt->type == pkt_S10N_UNED && ! item->to) )
    {
        /* remove pending ask */
        if( (pkt->type == pkt_S10N_ED && item->ask == 1)
         || (pkt->type == pkt_S10N_UNED && item->ask == 2) )
        {
            item->ask = 0;
            /* save changes */
            _roster_save_item(user, item);
        }
        
        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* trying to subscribe */
    if(pkt->type == pkt_S10N)
    {
        if(item->from)
        {
            /* already subscribed, tell them */
            nad_set_attr(pkt->nad, 1, -1, "type", "subscribed", 10);
            pkt_router(pkt_tofrom(pkt));
            
            /* update their presence from the leading session */
            if(user->top != NULL)
                pres_roster(user->top, item);

            return mod_HANDLED;
        }

        return mod_PASS;
    }

    /* handle unsubscribe */
    if(pkt->type == pkt_S10N_UN)
    {
        if(!item->from)
        {
            /* already unsubscribed, tell them */
            nad_set_attr(pkt->nad, 1, -1, "type", "unsubscribed", 12);
            pkt_router(pkt_tofrom(pkt));

            return mod_HANDLED;
        }

        /* change state */
        item->from = 0;

        /* confirm unsubscription */
        pkt_router(pkt_create(user->sm, "presence", "unsubscribed", jid_user(pkt->from), jid_user(user->jid)));

        /* update their presence from the leading session */
        if(user->top != NULL)
            pres_roster(user->top, item);
    }

    /* update our s10n */
    if(pkt->type == pkt_S10N_ED)
    {
        item->to = 1;
        if(item->ask == 1)
            item->ask = 0;
    }
    if(pkt->type == pkt_S10N_UNED)
    {
        item->to = 0;
        if(item->ask == 2)
            item->ask = 0;
    }

    if (sm_storage_rate_limit(user->sm, jid_user(pkt->from)))
        return -stanza_err_RESOURCE_CONSTRAINT;

    /* save changes */
    _roster_save_item(user, item);

    /* if there's no sessions, then we're done */
    if(user->sessions == NULL)
        return mod_PASS;

    /* build a new packet to push out to everyone */
    pkt = pkt_create(user->sm, "iq", "set", NULL, NULL);
    pkt_id_new(pkt);
    ns = nad_add_namespace(pkt->nad, uri_ROSTER, NULL);
    elem = nad_append_elem(pkt->nad, ns, "query", 3);

    _roster_insert_item(pkt, item, elem);

    /* tell everyone */
    _roster_push(user, pkt, mod->index);

    /* everyone knows */
    pkt_free(pkt);

    return mod_PASS;
}

/** load the roster from the database */
static int _roster_user_load(mod_instance_t mi, user_t user) {
    os_t os;
    os_object_t o;
    char *str;
    item_t item, olditem;

    log_debug(ZONE, "loading roster for %s", jid_user(user->jid));

    user->roster = xhash_new(101);

    /* pull all the items */
    if(storage_get(user->sm->st, "roster-items", jid_user(user->jid), NULL, &os) == st_SUCCESS) {
        if(os_iter_first(os))
            do {
                o = os_iter_object(os);

                if(os_object_get_str(os, o, "jid", &str)) {
                    /* new one */
                    item = (item_t) calloc(1, sizeof(struct item_st));

                    item->jid = jid_new(str, -1);
                    if(item->jid == NULL) {
                        log_debug(ZONE, "eek! invalid jid %s, skipping it", str);
                        free(item);

                    } else {
                        if(os_object_get_str(os, o, "name", &str))
                            item->name = strdup(str);
                        
                        os_object_get_bool(os, o, "to", &item->to);
                        os_object_get_bool(os, o, "from", &item->from);
                        os_object_get_int(os, o, "ask", &item->ask);
                        os_object_get_int(os, o, "object-sequence", &item->ver);

                        olditem = xhash_get(user->roster, jid_full(item->jid));
                        if(olditem) {
                            log_debug(ZONE, "removing old %s roster entry", jid_full(item->jid));
                            xhash_zap(user->roster, jid_full(item->jid));
                            _roster_freeuser_walker(jid_full(item->jid), strlen(jid_full(item->jid)), (void *) olditem, NULL);
                        }

                        /* its good */
                        xhash_put(user->roster, jid_full(item->jid), (void *) item);

                        log_debug(ZONE, "added %s to roster (to %d from %d ask %d ver %d name %s)",
                                  jid_full(item->jid), item->to, item->from, item->ask, item->ver, item->name);
                    }
                }
            } while(os_iter_next(os));

       os_free(os);
    }

    /* pull the groups and match them up */
    if(storage_get(user->sm->st, "roster-groups", jid_user(user->jid), NULL, &os) == st_SUCCESS) {
        if(os_iter_first(os))
            do {
                o = os_iter_object(os);

                if(os_object_get_str(os, o, "jid", &str)) {
                    item = xhash_get(user->roster, str);

                    if(item != NULL && os_object_get_str(os, o, "group", &str)) {
                        item->groups = realloc(item->groups, sizeof(char *) * (item->ngroups + 1));
                        item->groups[item->ngroups] = strdup(str);
                        item->ngroups++;

                        log_debug(ZONE, "added group %s to item %s", str, jid_full(item->jid));
                    }
                }
            } while(os_iter_next(os));

        os_free(os);
    }

    pool_cleanup(user->p, (void (*))(void *) _roster_freeuser, user);

    return 0;
}

static void _roster_user_delete(mod_instance_t mi, jid_t jid) {
    log_debug(ZONE, "deleting roster data for %s", jid_user(jid));

    storage_delete(mi->sm->st, "roster-items", jid_user(jid), NULL);
    storage_delete(mi->sm->st, "roster-groups", jid_user(jid), NULL);
}

static void _roster_free(module_t mod)
{
    mod_roster_t mroster = (mod_roster_t) mod->private;
    free(mroster);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;
    mod_roster_t mroster;

    if(mod->init) return 0;

    mroster = (mod_roster_t) calloc(1, sizeof(struct _mod_roster_st));

    mroster->maxitems = j_atoi(config_get_one(mod->mm->sm->config, "roster.maxitems", 0), 0);

    mod->private = mroster;

    mod->in_sess = _roster_in_sess;
    mod->pkt_user = _roster_pkt_user;
    mod->user_load = _roster_user_load;
    mod->user_delete = _roster_user_delete;
    mod->free = _roster_free;

    feature_register(mod->mm->sm, uri_ROSTER);

    return 0;
}
