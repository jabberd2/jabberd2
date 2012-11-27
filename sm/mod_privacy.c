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

/** @file sm/mod_privacy.c
  * @brief XEP-0016 Privacy Lists and XEP-0191 Simple Comunications Blocking
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.32 $
  */

static int ns_PRIVACY = 0;
static int ns_BLOCKING = 0;

typedef struct zebra_st         *zebra_t;
typedef struct zebra_list_st    *zebra_list_t;
typedef struct zebra_item_st    *zebra_item_t;

typedef enum {
    zebra_NONE,
    zebra_JID,
    zebra_GROUP,
    zebra_S10N
} zebra_item_type_t;

typedef enum {
    block_NONE = 0x00,
    block_MESSAGE = 0x01,
    block_PRES_IN = 0x02,
    block_PRES_OUT = 0x04,
    block_IQ = 0x08
} zebra_block_type_t;

/** zebra data for a single user */
struct zebra_st {
    xht             lists;

    zebra_list_t    def;
};

struct zebra_list_st {
    pool_t          p;

    char            *name;

    zebra_item_t    items, last;
};

struct zebra_item_st {
    zebra_item_type_t   type;
    
    jid_t               jid;

    char                *group;

    int                 to;
    int                 from;

    int                 deny;       /* 0 = allow, 1 = deny */

    int                 order;

    zebra_block_type_t  block;

    zebra_item_t        next, prev;
};

typedef struct privacy_st {
    /* currently active list */
    zebra_list_t        active;

    /* was blocklist requested */
    int                 blocklist;
} *privacy_t;

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  zebra_list_t *z_val;
};

static void _privacy_free_z(zebra_t z) {
    zebra_list_t zlist;
    union xhashv xhv;

    log_debug(ZONE, "freeing zebra ctx");

    if(xhash_iter_first(z->lists))
        do {
            xhv.z_val = &zlist;
            xhash_iter_get(z->lists, NULL, NULL, xhv.val);
            pool_free(zlist->p);
        } while(xhash_iter_next(z->lists));

    xhash_free(z->lists);
    free(z);
}

static void _privacy_user_free(zebra_t *z) {
    if(*z != NULL)
        _privacy_free_z(*z);
}

static int _privacy_user_load(mod_instance_t mi, user_t user) {
    module_t mod = mi->mod;
    zebra_t z;
    os_t os;
    os_object_t o;
    zebra_list_t zlist;
    pool_t p;
    zebra_item_t zitem, scan;
    char *str;

    log_debug(ZONE, "loading privacy lists for %s", jid_user(user->jid));

    /* free if necessary */
    z = user->module_data[mod->index];
    if(z != NULL)
        _privacy_free_z(z);

    z = (zebra_t) calloc(1, sizeof(struct zebra_st));

    z->lists = xhash_new(101);

    user->module_data[mod->index] = z;

    pool_cleanup(user->p, (void (*))(void *) _privacy_user_free, &(user->module_data[mod->index]));

    /* pull the whole lot */
    if(storage_get(user->sm->st, "privacy-items", jid_user(user->jid), NULL, &os) == st_SUCCESS) {
        if(os_iter_first(os))
            do {
                o = os_iter_object(os);

                /* list name */
                if(!os_object_get_str(os, o, "list", &str)) {
                    log_debug(ZONE, "item with no list field, skipping");
                    continue;
                }

                log_debug(ZONE, "got item for list %s", str);

                zlist = xhash_get(z->lists, str);

                /* new list */
                if(zlist == NULL) {
                    log_debug(ZONE, "creating list %s", str);

                    p = pool_new();

                    zlist = (zebra_list_t) pmalloco(p, sizeof(struct zebra_list_st));

                    zlist->p = p;
                    zlist->name = pstrdup(p, str);

                    xhash_put(z->lists, zlist->name, (void *) zlist);
                }

                /* new item */
                zitem = (zebra_item_t) pmalloco(zlist->p, sizeof(struct zebra_item_st));

                /* item type */
                if(os_object_get_str(os, o, "type", &str))
                    switch(str[0]) {
                        case 'j':
                            zitem->type = zebra_JID;
                            break;

                        case 'g':
                            zitem->type = zebra_GROUP;
                            break;

                        case 's':
                            zitem->type = zebra_S10N;
                            break;
                    }

                /* item value, according to type */
                if(zitem->type != zebra_NONE) {
                    if(!os_object_get_str(os, o, "value", &str)) {
                        log_debug(ZONE, "no value on non-fall-through item, dropping this item");
                        continue;
                    }

                    switch(zitem->type) {

                        case zebra_JID:
                            zitem->jid = jid_new(str, strlen(str));
                            if(zitem->jid == NULL) {
                                log_debug(ZONE, "invalid jid '%s' on item, dropping this item", str);
                                continue;
                            }

                            pool_cleanup(zlist->p, (void *) jid_free, zitem->jid);

                            log_debug(ZONE, "jid item with value '%s'", jid_full(zitem->jid));

                            break;

                        case zebra_GROUP:
                            zitem->group = pstrdup(zlist->p, str);

                            log_debug(ZONE, "group item with value '%s'", zitem->group);

                            break;

                        case zebra_S10N:
                            if(strcmp(str, "to") == 0)
                                zitem->to = 1;
                            else if(strcmp(str, "from") == 0)
                                zitem->from = 1;
                            else if(strcmp(str, "both") == 0)
                                zitem->to = zitem->from = 1;
                            else if(strcmp(str, "none") != 0) {
                                log_debug(ZONE, "invalid value '%s' on s10n item, dropping this item", str);
                                continue;
                            }

                            log_debug(ZONE, "s10n item with value '%s' (to %d from %d)", str, zitem->to, zitem->from);

                            break;
                            
                        case zebra_NONE:
                            /* can't get here */
                            break;
                    }
                }

                /* action */
                os_object_get_bool(os, o, "deny", &zitem->deny);
                if(zitem->deny) {
                    log_debug(ZONE, "deny rule");
                } else {
                    log_debug(ZONE, "accept rule");
                }

                os_object_get_int(os, o, "order", &(zitem->order));
                log_debug(ZONE, "order %d", zitem->order);

                os_object_get_int(os, o, "block", (int*) &(zitem->block));
                log_debug(ZONE, "block 0x%x", zitem->block);

                /* insert it */
                for(scan = zlist->items; scan != NULL; scan = scan->next)
                    if(zitem->order < scan->order)
                        break;
                
                /* we're >= everyone, add us to the end */
                if(scan == NULL) {
                    if(zlist->last == NULL)
                        zlist->items = zlist->last = zitem;
                    else {
                        zlist->last->next = zitem;
                        zitem->prev = zlist->last;
                        zlist->last = zitem;
                    }
                }
                
                /* insert just before scan */
                else {
                    if(zlist->items == scan) {
                        zitem->next = zlist->items;
                        zlist->items = zitem;
                        scan->prev = zitem;
                    } else {
                        zitem->next = scan;
                        zitem->prev = scan->prev;
                        scan->prev->next = zitem;
                        scan->prev = zitem;
                    }
                }
            } while(os_iter_next(os));

        os_free(os);
    }

    /* default list */
    if(storage_get(user->sm->st, "privacy-default", jid_user(user->jid), NULL, &os) == st_SUCCESS) {
        if(os_iter_first(os))
            do {
                o = os_iter_object(os);

                if(os_object_get_str(os, o, "default", &str)) {
                    z->def = (zebra_list_t) xhash_get(z->lists, str);
                    if(z->def == NULL) {
                        log_debug(ZONE, "storage says the default list for %s is %s, but it doesn't exist!", jid_user(user->jid), str);
                    } else {
                        log_debug(ZONE, "user %s has default list %s", jid_user(user->jid), str);
                    }
                }
            } while(os_iter_next(os));

        os_free(os);
    }

    return 0;
}

/** returns 0 if the packet should be allowed, otherwise 1 */
static int _privacy_action(user_t user, zebra_list_t zlist, jid_t jid, pkt_type_t ptype, int in) {
    zebra_item_t scan;
    int match, i;
    item_t ritem;
    char domres[2048];

    log_debug(ZONE, "running match on list %s for %s (packet type 0x%x) (%s)", zlist->name, jid_full(jid), ptype, in ? "incoming" : "outgoing");

    /* loop over the list, trying to find a match */
    for(scan = zlist->items; scan != NULL; scan = scan->next) {
        match = 0;

        switch(scan->type) {
            case zebra_NONE:
                /* fall through, all packets match this */
                match = 1;
                break;

            case zebra_JID:
                snprintf(domres, sizeof(domres) / sizeof(domres[0]), "%s/%s", jid->domain, jid->resource);
 
                /* jid check - match node@dom/res, then node@dom, then dom/resource, then dom */
                if(jid_compare_full(scan->jid, jid) == 0 ||
                   strcmp(jid_full(scan->jid), jid_user(jid)) == 0 ||
                   strcmp(jid_full(scan->jid), domres) == 0 ||
                   strcmp(jid_full(scan->jid), jid->domain) == 0)
                    match = 1;

                break;

            case zebra_GROUP:
                /* roster group check - get the roster item, node@dom/res, then node@dom, then dom */
                ritem = xhash_get(user->roster, jid_full(jid));
                if(ritem == NULL) ritem = xhash_get(user->roster, jid_user(jid));
                if(ritem == NULL) ritem = xhash_get(user->roster, jid->domain);

                /* got it, do the check */
                if(ritem != NULL)
                    for(i = 0; i < ritem->ngroups; i++)
                        if(strcmp(scan->group, ritem->groups[i]) == 0)
                            match = 1;

                break;

            case zebra_S10N:
                /* roster item check - get the roster item, node@dom/res, then node@dom, then dom */
                ritem = xhash_get(user->roster, jid_full(jid));
                if(ritem == NULL) ritem = xhash_get(user->roster, jid_user(jid));
                if(ritem == NULL) ritem = xhash_get(user->roster, jid->domain);

                /* got it, do the check */
                if(ritem != NULL)
                    if(scan->to == ritem->to && scan->from == ritem->from)
                        match = 1;

                break;
        }

        /* if we matched a rule, we have to do packet block matching */
        if(match) {
            /* no packet blocking, matching done */
            if(scan->block == block_NONE)
                return scan->deny;

            /* incoming checks block_MESSAGE, block_PRES_IN and block_IQ */
            if(in) {
                if(ptype & pkt_MESSAGE && scan->block & block_MESSAGE)
                    return scan->deny;
                if(ptype & pkt_PRESENCE && scan->block & block_PRES_IN)
                    return scan->deny;
                if(ptype & pkt_IQ && scan->block & block_IQ)
                    return scan->deny;
            } else if((ptype & pkt_PRESENCE && scan->block & block_PRES_OUT && ptype != pkt_PRESENCE_PROBE) ||
                      (ptype & pkt_MESSAGE && scan->block & block_MESSAGE)) {
                /* outgoing check, block_PRES_OUT */
                /* XXX and block_MESSAGE for XEP-0191 while it violates XEP-0016 */
                return scan->deny;
            }
        }
    }

    /* didn't match the list, so allow */
    return 0;
}

/** check incoming packets */
static mod_ret_t _privacy_in_router(mod_instance_t mi, pkt_t pkt) {
    module_t mod = mi->mod;
    user_t user;
    zebra_t z;
    sess_t sess = NULL;
    zebra_list_t zlist = NULL;

    /* if its coming to the sm, let it in */
    if(pkt->to == NULL || pkt->to->node[0] == '\0')
        return mod_PASS;

    /* get the user */
    user = user_load(mod->mm->sm, pkt->to);
    if(user == NULL) {
        log_debug(ZONE, "no user %s, passing packet", jid_user(pkt->to));
        return mod_PASS;
    }

    /* get our lists */
    z = (zebra_t) user->module_data[mod->index];

    /* find a session */
    if(*pkt->to->resource != '\0')
        sess = sess_match(user, pkt->to->resource);

    /* didn't match a session, so use the top session */
    if(sess == NULL)
        sess = user->top;

    /* get the active list for the session */
    if(sess != NULL && sess->module_data[mod->index] != NULL)
        zlist = ((privacy_t) sess->module_data[mod->index])->active;

    /* no active list, so use the default list */
    if(zlist == NULL)
        zlist = z->def;

    /* no list, so allow everything */
    if(zlist == NULL)
        return mod_PASS;

    /* figure out the action */
    if(_privacy_action(user, zlist, pkt->from, pkt->type, 1) == 0)
        return mod_PASS;

    /* deny */
    log_debug(ZONE, "denying incoming packet based on privacy policy");

    /* iqs get special treatment */
    if(pkt->type == pkt_IQ || pkt->type == pkt_IQ_SET)
        return -stanza_err_FEATURE_NOT_IMPLEMENTED;

    /* drop it */
    pkt_free(pkt);
    return mod_HANDLED;
}

/** check outgoing packets */
static mod_ret_t _privacy_out_router(mod_instance_t mi, pkt_t pkt) {
    module_t mod = mi->mod;
    user_t user;
    zebra_t z;
    sess_t sess = NULL;
    zebra_list_t zlist = NULL;
    int err, ns;

    /* if its coming from the sm, let it go */
    if(pkt->from == NULL || pkt->from->node[0] == '\0')
        return mod_PASS;

    /* get the user */
    user = user_load(mod->mm->sm, pkt->from);
    if(user == NULL) {
        log_debug(ZONE, "no user %s, passing packet", jid_user(pkt->to));
        return mod_PASS;
    }

    /* get our lists */
    z = (zebra_t) user->module_data[mod->index];

    /* find a session */
    if(*pkt->from->resource != '\0')
        sess = sess_match(user, pkt->from->resource);

    /* get the active list for the session */
    if(sess != NULL && sess->module_data[mod->index] != NULL)
        zlist = ((privacy_t) sess->module_data[mod->index])->active;

    /* no active list, so use the default list */
    if(zlist == NULL)
        zlist = z->def;

    /* no list, so allow everything */
    if(zlist == NULL)
        return mod_PASS;

    /* figure out the action */
    if(_privacy_action(user, zlist, pkt->to, pkt->type, 0) == 0)
        return mod_PASS;

    /* deny */
    log_debug(ZONE, "denying outgoing packet based on privacy policy");

    /* messages get special treatment */
    if(pkt->type & pkt_MESSAGE) {
        /* hack the XEP-0191 error in */
        pkt_error(pkt, stanza_err_NOT_ACCEPTABLE);
        err = nad_find_elem(pkt->nad, 1, -1, "error", 1);
        ns = nad_add_namespace(pkt->nad, urn_BLOCKING_ERR, NULL);
        nad_insert_elem(pkt->nad, err, ns, "blocked", NULL);
        pkt_sess(pkt, sess);
        return mod_HANDLED;
    }

    /* drop it */
    pkt_free(pkt);
    return mod_HANDLED;
}

/** add a list to the return packet */
static void _privacy_result_builder(xht zhash, const char *name, void *val, void *arg) {
    zebra_list_t zlist = (zebra_list_t) val;
    pkt_t pkt = (pkt_t) arg;
    int ns, query, list, item;
    zebra_item_t zitem;
    char order[14];

    ns = nad_find_scoped_namespace(pkt->nad, uri_PRIVACY, NULL);
    query = nad_find_elem(pkt->nad, 1, ns, "query", 1);

    list = nad_insert_elem(pkt->nad, query, ns, "list", NULL);
    nad_set_attr(pkt->nad, list, -1, "name", zlist->name, 0);

    /* run through the items and build the nad */
    for(zitem = zlist->items; zitem != NULL; zitem = zitem->next) {
        item = nad_insert_elem(pkt->nad, list, ns, "item", NULL);

        switch(zitem->type) {
            case zebra_JID:
                nad_set_attr(pkt->nad, item, -1, "type", "jid", 0);
                nad_set_attr(pkt->nad, item, -1, "value", jid_full(zitem->jid), 0);
                break;

            case zebra_GROUP:
                nad_set_attr(pkt->nad, item, -1, "type", "group", 0);
                nad_set_attr(pkt->nad, item, -1, "value", zitem->group, 0);
                break;

            case zebra_S10N:
                nad_set_attr(pkt->nad, item, -1, "type", "subscription", 0);

                if(zitem->to == 1 && zitem->from == 1)
                    nad_set_attr(pkt->nad, item, -1, "value", "both", 4);
                else if(zitem->to == 1)
                    nad_set_attr(pkt->nad, item, -1, "value", "to", 2);
                else if(zitem->from == 1)
                    nad_set_attr(pkt->nad, item, -1, "value", "from", 4);
                else
                    nad_set_attr(pkt->nad, item, -1, "value", "none", 4);

                break;

            case zebra_NONE:
                break;
        }

        if(zitem->deny)
            nad_set_attr(pkt->nad, item, -1, "action", "deny", 4);
        else
            nad_set_attr(pkt->nad, item, -1, "action", "allow", 5);

        snprintf(order, 14, "%d", zitem->order);
        order[13] = '\0';

        nad_set_attr(pkt->nad, item, -1, "order", order, 0);

        if(zitem->block & block_MESSAGE)
            nad_insert_elem(pkt->nad, item, ns, "message", NULL);
        if(zitem->block & block_PRES_IN)
            nad_insert_elem(pkt->nad, item, ns, "presence-in", NULL);
        if(zitem->block & block_PRES_OUT)
            nad_insert_elem(pkt->nad, item, ns, "presence-out", NULL);
        if(zitem->block & block_IQ)
            nad_insert_elem(pkt->nad, item, ns, "iq", NULL);
    }
}

/** add a list to the return packet */
static void _privacy_lists_result_builder(const char *name, int namelen, void *val, void *arg) {
    zebra_list_t zlist = (zebra_list_t) val;
    pkt_t pkt = (pkt_t) arg;
    int ns, query, list;

    ns = nad_find_scoped_namespace(pkt->nad, uri_PRIVACY, NULL);
    query = nad_find_elem(pkt->nad, 1, ns, "query", 1);

    list = nad_insert_elem(pkt->nad, query, ns, "list", NULL);
    nad_set_attr(pkt->nad, list, -1, "name", zlist->name, 0);
}

/** remove jid deny ocurrences from the privacy list,
    unblock all if no jid given to match,
    then update unblocked contact with presence information */
static void _unblock_jid(user_t user, storage_t st, zebra_list_t zlist, jid_t jid) {
    char filter[1024];
    zebra_item_t scan;
    sess_t sscan;
    jid_t notify_jid = NULL;

    for(scan = zlist->items; scan != NULL; scan = scan->next) {
        if(scan->type == zebra_JID && scan->deny && (jid == NULL || jid_compare_full(scan->jid, jid) == 0)) {
            if(zlist->items == scan) {
                zlist->items = scan->next;
                if(zlist->items != NULL)
                    zlist->items->prev = NULL;
            } else {
                assert(scan->prev != NULL);
                scan->prev->next = scan->next;
                if(scan->next != NULL)
                    scan->next->prev = scan->prev;
            }

            if (zlist->last == scan)
                zlist->last = scan->prev;

            /* and from the storage */
            sprintf(filter, "(&(list=%zu:%s)(type=3:jid)(value=%zu:%s))",
					strlen(urn_BLOCKING), urn_BLOCKING, strlen(jid_full(scan->jid)), jid_full(scan->jid));
            storage_delete(st, "privacy-items", jid_user(user->jid), filter);

            /* set jid for notify */
            notify_jid = scan->jid;
        }

        /* update unblocked contact with presence information of all sessions */

        /* XXX NOTE !!! There is a possibility that we notify more than once
         * if user edited the privacy list manually, not with XEP-0191.
         * Well... We're going to live with it. ;-) */
        if(notify_jid != NULL && pres_trust(user, notify_jid))
            for(sscan = user->sessions; sscan != NULL; sscan = sscan->next) {
                /* do not update if session is not available,
                 * we sent presence direct or got error bounce */
                if(!sscan->available || jid_search(sscan->A, notify_jid) || jid_search(sscan->E, notify_jid))
                    continue;
    
                log_debug(ZONE, "updating unblocked %s with presence from %s", jid_full(notify_jid), jid_full(sscan->jid));
                pkt_router(pkt_dup(sscan->pres, jid_full(notify_jid), jid_full(sscan->jid)));
            }
    }
}

/** list management requests */
static mod_ret_t _privacy_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    module_t mod = mi->mod;
    int ns, query, list, name, active, def, item, type, value, action, order, blocking, jid, push = 0;
    char corder[14], str[256], filter[1024];
    zebra_t z;
    zebra_list_t zlist, old;
    pool_t p;
    zebra_item_t zitem, scan;
    sess_t sscan;
    jid_t jidt;
    pkt_t result;
    os_t os;
    os_object_t o;
    st_ret_t ret;

    /* we only want to play with iq:privacy and urn:xmpp:blocking packets */
    if((pkt->type != pkt_IQ && pkt->type != pkt_IQ_SET) || (pkt->ns != ns_PRIVACY && pkt->ns != ns_BLOCKING))
        return mod_PASS;

    /* if it has a to, throw it out */
    if(pkt->to != NULL)
        return -stanza_err_BAD_REQUEST;

    /* get our lists */
    z = (zebra_t) sess->user->module_data[mod->index];

    /* create session privacy description */
    if(sess->module_data[mod->index] == NULL)
        sess->module_data[mod->index] = (void *) pmalloco(sess->p, sizeof(struct privacy_st));

    /* handle XEP-0191: Simple Communications Blocking
     * as simplified frontend to default privacy list */
    if(pkt->ns == ns_BLOCKING) {
        if(pkt->type == pkt_IQ_SET) {
            /* find out what to do */
            int block;
            ns = nad_find_scoped_namespace(pkt->nad, urn_BLOCKING, NULL);
            blocking = nad_find_elem(pkt->nad, 1, ns, "block", 1);
            if(blocking >= 0)
                block = 1;
            else {
                blocking = nad_find_elem(pkt->nad, 1, ns, "unblock", 1);
                if(blocking >= 0)
                    block = 0;
                else
                    return -stanza_err_BAD_REQUEST;
            }

            /* if there is no default list, create one */
            if(!z->def) {
                /* remove any previous one */
                if((zlist = xhash_get(z->lists, urn_BLOCKING))) {
                    pool_free(zlist->p);
                    sprintf(filter, "(list=%zu:%s)", strlen(urn_BLOCKING), urn_BLOCKING);
                    storage_delete(mod->mm->sm->st, "privacy-items", jid_user(sess->user->jid), filter);
                }

                /* create new zebra list with name 'urn:xmpp:blocking' */
                p = pool_new();
                zlist = (zebra_list_t) pmalloco(p, sizeof(struct zebra_list_st));
                zlist->p = p;
                zlist->name = pstrdup(p, urn_BLOCKING);
                xhash_put(z->lists, zlist->name, (void *) zlist);
                
                /* make it default */
                z->def = zlist;

                /* and in the storage */
                os = os_new();
                o = os_object_new(os);
                os_object_put(o, "default", zlist->name, os_type_STRING);
                ret = storage_replace(mod->mm->sm->st, "privacy-default", jid_user(sess->user->jid), NULL, os);
                os_free(os);
                if(ret != st_SUCCESS)
                    return -stanza_err_INTERNAL_SERVER_ERROR;

                log_debug(ZONE, "blocking created '%s' privacy list and set it default", zlist->name);
            } else {
                /* use the default one */
                zlist = z->def;
            }
            /* activate this list */
            ((privacy_t) sess->module_data[mod->index])->active = zlist;
            log_debug(ZONE, "session '%s' has now active list '%s'", jid_full(sess->jid), zlist->name);

            item = nad_find_elem(pkt->nad, blocking, ns, "item", 1);
            if(item < 0) {
                if(block) {
                    /* cannot block unknown */
                    return -stanza_err_BAD_REQUEST;
                } else {
                    /* unblock all */
                    _unblock_jid(sess->user, mod->mm->sm->st, zlist, NULL);

                    /* mark to send blocklist push */
                    push = 1;
                }
            }

            /* loop over the items */
            while(item >= 0) {
                /* extract jid */
                jid = nad_find_attr(pkt->nad, item, -1, "jid", 0);
                if(jid < 0)
                    return -stanza_err_BAD_REQUEST;

                jidt = jid_new(NAD_AVAL(pkt->nad, jid), NAD_AVAL_L(pkt->nad, jid));
                if(jidt == NULL)
                    return -stanza_err_BAD_REQUEST;

                /* find blockitem in the list */
                for(scan = zlist->items; scan != NULL; scan = scan->next)
                    if(scan->type == zebra_JID && jid_compare_full(scan->jid, jidt) == 0)
                        break;

                /* take action */
                if(block) {
                    if(scan != NULL && scan->deny && scan->block == block_NONE) {
                            push = 0;
                    } else {
                        /* first make us unavailable if user is on roster */
                        if(pres_trust(sess->user, jidt))
                            for(sscan = sess->user->sessions; sscan != NULL; sscan = sscan->next) {
                                /* do not update if session is not available,
                                 * we sent presence direct or got error bounce */
                                if(!sscan->available || jid_search(sscan->A, jidt) || jid_search(sscan->E, jidt))
                                    continue;
                        
                                log_debug(ZONE, "forcing unavailable to %s from %s after block", jid_full(jidt), jid_full(sscan->jid));
                                pkt_router(pkt_create(sess->user->sm, "presence", "unavailable", jid_full(jidt), jid_full(sscan->jid)));
                            }

                        /* new item */
                        zitem = (zebra_item_t) pmalloco(zlist->p, sizeof(struct zebra_item_st));
                        zitem->type = zebra_JID;

                        zitem->jid = jid_new(NAD_AVAL(pkt->nad, jid), NAD_AVAL_L(pkt->nad, jid));
                        pool_cleanup(zlist->p, (void *) jid_free, zitem->jid);
                        zitem->deny = 1;
                        zitem->block = block_NONE;

                        /* insert it in front of list */
                        zitem->order = 0;
                        if(zlist->last == NULL) {
                            zlist->items = zlist->last = zitem;
                        } else {
                            zitem->next = zlist->items;
                            zlist->items->prev = zitem;
                            zlist->items = zitem;
                        }

                        /* and into the storage backend */
                        os = os_new();
                        o = os_object_new(os);
                        os_object_put(o, "list", zlist->name, os_type_STRING);
                        os_object_put(o, "type", "jid", os_type_STRING);
                        os_object_put(o, "value", jid_full(zitem->jid), os_type_STRING);
                        os_object_put(o, "deny", &zitem->deny, os_type_BOOLEAN);
                        os_object_put(o, "order", &zitem->order, os_type_INTEGER);
                        os_object_put(o, "block", &zitem->block, os_type_INTEGER);
                        ret = storage_put(mod->mm->sm->st, "privacy-items", jid_user(sess->user->jid), os);
                        os_free(os);
                        if(ret != st_SUCCESS) {
                            jid_free(jidt);
                            return -stanza_err_INTERNAL_SERVER_ERROR;
                        }

                        /* mark to send blocklist push */
                        push = 1;
                    }
                } else {
                    /* unblock action */
                    if(scan != NULL && scan->deny) {
                        /* remove all jid deny ocurrences from the privacy list */
                        _unblock_jid(sess->user, mod->mm->sm->st, zlist, jidt);

                        /* mark to send blocklist push */
                        push = 1;
                    } else {
                        jid_free(jidt);
                        return -stanza_err_ITEM_NOT_FOUND;
                    }
                }

                jid_free(jidt);

                /* next item */
                item = nad_find_elem(pkt->nad, item, ns, "item", 0);
            }

            /* return empty result */
            result = pkt_create(pkt->sm, "iq", "result", NULL, NULL);
            pkt_id(pkt, result);
            pkt_sess(result, sess);

            /* blocklist push */
            if(push) {
                for(sscan = sess->user->sessions; sscan != NULL; sscan = sscan->next) {
                    /* don't push to us or to anyone who hasn't requested blocklist */
                    if(sscan == sess || sscan->module_data[mod->index] == NULL || ((privacy_t) sscan->module_data[mod->index])->blocklist == 0)
                        continue;

                    result = pkt_dup(pkt, jid_full(sscan->jid), NULL);
                    if(result->from != NULL) {
                        jid_free(result->from);
                        nad_set_attr(result->nad, 1, -1, "from", NULL, 0);
                    }
                    pkt_id_new(result);
                    pkt_sess(result, sscan);
                }
            }

            /* and done with request */
            pkt_free(pkt);
            return mod_HANDLED;
        }

        /* it's a get */
        ns = nad_find_scoped_namespace(pkt->nad, urn_BLOCKING, NULL);
        blocking = nad_find_elem(pkt->nad, 1, ns, "blocklist", 1);
        if(blocking < 0)
            return -stanza_err_BAD_REQUEST;

        result = pkt_create(pkt->sm, "iq", "result", NULL, NULL);
        pkt_id(pkt, result);
        ns = nad_add_namespace(result->nad, urn_BLOCKING, NULL);
        blocking = nad_insert_elem(result->nad, 1, ns, "blocklist", NULL);

        /* insert items only from the default list */
        if(z->def != NULL) {
            log_debug(ZONE, "blocking list is '%s'", z->def->name);
            zlist = xhash_get(z->lists, z->def->name);
            /* run through the items and build the nad */
            for(zitem = zlist->items; zitem != NULL; zitem = zitem->next) {
                /* we're interested in items type 'jid' with action 'deny' only */
                if(zitem->type == zebra_JID && zitem->deny) {
                    item = nad_insert_elem(result->nad, blocking, -1, "item", NULL);
                    nad_set_attr(result->nad, item, -1, "jid", jid_full(zitem->jid), 0);
                }
            }

            /* mark that the blocklist was requested */
            ((privacy_t) sess->module_data[mod->index])->blocklist = 1;
        }

        /* give it to the session */
        pkt_sess(result, sess);
        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* else handle XEP-0016: Privacy Lists */

    /* find the query */
    ns = nad_find_scoped_namespace(pkt->nad, uri_PRIVACY, NULL);
    query = nad_find_elem(pkt->nad, 1, ns, "query", 1);
    if(query < 0)
        return -stanza_err_BAD_REQUEST;

    /* update lists or set the active list */
    if(pkt->type == pkt_IQ_SET) {
        /* find out what we're doing */
        list = nad_find_elem(pkt->nad, query, ns, "list", 1);
        active = nad_find_elem(pkt->nad, query, ns, "active", 1);
        def = nad_find_elem(pkt->nad, query, ns, "default", 1);
        
        /* we need something to do, but we can't do it all at once */
        if((list < 0 && active < 0 && def < 0) || (list >= 0 && (active >=0 || def >= 0)))
            return -stanza_err_BAD_REQUEST;

        /* loop over any/all lists and store them */
        if(list >= 0) {
            /* only allowed to change one list at a time */
            if(nad_find_elem(pkt->nad, list, ns, "list", 0) >= 0)
                return -stanza_err_BAD_REQUEST;

            /* get the list name */
            name = nad_find_attr(pkt->nad, list, -1, "name", NULL);
            if(name < 0) {
                log_debug(ZONE, "no list name specified, failing request");
                return -stanza_err_BAD_REQUEST;
            }

            snprintf(str, 256, "%.*s", NAD_AVAL_L(pkt->nad, name), NAD_AVAL(pkt->nad, name));
            str[255] = '\0';

            log_debug(ZONE, "updating list %s", str);

            /* make a new one */
            p = pool_new();

            zlist = (zebra_list_t) pmalloco(p, sizeof(struct zebra_list_st));

            zlist->p = p;
            zlist->name = pstrdup(p, str);

            os = os_new();

            /* loop over the items */
            item = nad_find_elem(pkt->nad, list, ns, "item", 1);
            while(item >= 0) {
                /* extract things */
                type = nad_find_attr(pkt->nad, item, -1, "type", 0);
                value = nad_find_attr(pkt->nad, item, -1, "value", 0);
                action = nad_find_attr(pkt->nad, item, -1, "action", 0);
                order = nad_find_attr(pkt->nad, item, -1, "order", 0);

                /* sanity */
                if(action < 0 || order < 0 || (type >= 0 && value < 0)) {
                    pool_free(p);
                    os_free(os);
                    return -stanza_err_BAD_REQUEST;
                }

                /* new item */
                zitem = (zebra_item_t) pmalloco(p, sizeof(struct zebra_item_st));

                /* have to store it too */
                o = os_object_new(os);
                os_object_put(o, "list", zlist->name, os_type_STRING);

                /* type & value */
                if(type >= 0) {
                    if(NAD_AVAL_L(pkt->nad, type) == 3 && strncmp("jid", NAD_AVAL(pkt->nad, type), 3) == 0) {
                        zitem->type = zebra_JID;

                        zitem->jid = jid_new(NAD_AVAL(pkt->nad, value), NAD_AVAL_L(pkt->nad, value));
                        if(zitem->jid == NULL) {
                            log_debug(ZONE, "invalid jid '%.*s', failing request", NAD_AVAL_L(pkt->nad, value), NAD_AVAL(pkt->nad, value));
                            pool_free(p);
                            os_free(os);
                            return -stanza_err_BAD_REQUEST;
                        }

                        pool_cleanup(p, (void *) jid_free, zitem->jid);

                        log_debug(ZONE, "jid item with value '%s'", jid_full(zitem->jid));

                        os_object_put(o, "type", "jid", os_type_STRING);
                        os_object_put(o, "value", jid_full(zitem->jid), os_type_STRING);
                    }

                    else if(NAD_AVAL_L(pkt->nad, type) == 5 && strncmp("group", NAD_AVAL(pkt->nad, type), 5) == 0) {
                        zitem->type = zebra_GROUP;

                        zitem->group = pstrdupx(zlist->p, NAD_AVAL(pkt->nad, value), NAD_AVAL_L(pkt->nad, value));

                        /* !!! check if the group exists */

                        log_debug(ZONE, "group item with value '%s'", zitem->group);

                        os_object_put(o, "type", "group", os_type_STRING);
                        os_object_put(o, "value", zitem->group, os_type_STRING);
                    }

                    else if(NAD_AVAL_L(pkt->nad, type) == 12 && strncmp("subscription", NAD_AVAL(pkt->nad, type), 12) == 0) {
                        zitem->type = zebra_S10N;

                        os_object_put(o, "type", "subscription", os_type_STRING);

                        if(NAD_AVAL_L(pkt->nad, value) == 2 && strncmp("to", NAD_AVAL(pkt->nad, value), 2) == 0) {
                            zitem->to = 1;
                            os_object_put(o, "value", "to", os_type_STRING);
                        } else if(NAD_AVAL_L(pkt->nad, value) == 4 && strncmp("from", NAD_AVAL(pkt->nad, value), 4) == 0) {
                            zitem->from = 1;
                            os_object_put(o, "value", "from", os_type_STRING);
                        } else if(NAD_AVAL_L(pkt->nad, value) == 4 && strncmp("both", NAD_AVAL(pkt->nad, value), 4) == 0) {
                            zitem->to = zitem->from = 1;
                            os_object_put(o, "value", "both", os_type_STRING);
                        } else if(NAD_AVAL_L(pkt->nad, value) == 4 && strncmp("none", NAD_AVAL(pkt->nad, value), 4) == 0)
                            os_object_put(o, "value", "none", os_type_STRING);
                        else {
                            log_debug(ZONE, "invalid value '%.*s' on s10n item, failing request", NAD_AVAL_L(pkt->nad, value), NAD_AVAL(pkt->nad, value));
                            pool_free(p);
                            os_free(os);
                            return -stanza_err_BAD_REQUEST;
                        }

                        log_debug(ZONE, "s10n item with value '%.*s' (to %d from %d)", NAD_AVAL_L(pkt->nad, value), NAD_AVAL(pkt->nad, value), zitem->to, zitem->from);
                    }
                }

                /* action */
                if(NAD_AVAL_L(pkt->nad, action) == 4 && strncmp("deny", NAD_AVAL(pkt->nad, action), 4) == 0) {
                    zitem->deny = 1;
                    log_debug(ZONE, "deny rule");
                } else if(NAD_AVAL_L(pkt->nad, action) == 5 && strncmp("allow", NAD_AVAL(pkt->nad, action), 5) == 0) {
                    zitem->deny = 0;
                    log_debug(ZONE, "allow rule");
                } else {
                    log_debug(ZONE, "unknown action '%.*s', failing request", NAD_AVAL_L(pkt->nad, action), NAD_AVAL(pkt->nad, action));
                    pool_free(p);
                    os_free(os);
                    return -stanza_err_BAD_REQUEST;
                }

                os_object_put(o, "deny", &zitem->deny, os_type_BOOLEAN);

                /* order */
                snprintf(corder, 14, "%.*s", NAD_AVAL_L(pkt->nad, order), NAD_AVAL(pkt->nad, order));
                corder[13] = '\0';
                zitem->order = atoi(corder);

                os_object_put(o, "order", &zitem->order, os_type_INTEGER);

                /* block types */
                if(nad_find_elem(pkt->nad, item, ns, "message", 1) >= 0)
                    zitem->block |= block_MESSAGE;
                if(nad_find_elem(pkt->nad, item, ns, "presence-in", 1) >= 0)
                    zitem->block |= block_PRES_IN;
                if(nad_find_elem(pkt->nad, item, ns, "presence-out", 1) >= 0)
                    zitem->block |= block_PRES_OUT;
                if(nad_find_elem(pkt->nad, item, ns, "iq", 1) >= 0)
                    zitem->block |= block_IQ;

                /* merge block all */
                if(zitem->block & block_MESSAGE &&
                   zitem->block & block_PRES_IN &&
                   zitem->block & block_PRES_OUT &&
                   zitem->block & block_IQ)
                    zitem->block = block_NONE;

                os_object_put(o, "block", &zitem->block, os_type_INTEGER);

                /* insert it */
                for(scan = zlist->items; scan != NULL; scan = scan->next)
                    if(zitem->order < scan->order)
                        break;
            
                /* we're >= everyone, add us to the end */
                if(scan == NULL) {
                    if(zlist->last == NULL)
                        zlist->items = zlist->last = zitem;
                    else {
                        zlist->last->next = zitem;
                        zitem->prev = zlist->last;
                        zlist->last = zitem;
                    }
                }
            
                /* insert just before scan */
                else {
                    if(zlist->items == scan) {
                        zitem->next = zlist->items;
                        zlist->items = zitem;
                        scan->prev = zitem;
                    } else {
                        zitem->next = scan;
                        zitem->prev = scan->prev;
                        scan->prev->next = zitem;
                        scan->prev = zitem;
                    }
                }

                /* next item */
                item = nad_find_elem(pkt->nad, item, ns, "item", 0);
            }

            /* write the whole list out */
            sprintf(filter, "(list=%zu:%s)", strlen(zlist->name), zlist->name);

            ret = storage_replace(mod->mm->sm->st, "privacy-items", jid_user(sess->user->jid), filter, os);
            os_free(os);

            /* failed! */
            if(ret != st_SUCCESS) {
                pool_free(zlist->p);
                return -stanza_err_INTERNAL_SERVER_ERROR;
            }

            /* old list pointer */
            old = xhash_get(z->lists, zlist->name);

            /* removed list */
            if(zlist->items == NULL) {
                log_debug(ZONE, "removed list %s", zlist->name);
                xhash_zap(z->lists, zlist->name);
                pool_free(zlist->p);
                if(old != NULL) pool_free(old->p);
                zlist = NULL;
            } else {
                log_debug(ZONE, "updated list %s", zlist->name);
                xhash_put(z->lists, zlist->name, (void *) zlist);
                if(old != NULL) pool_free(old->p);
            }

            /* if this was a new list, then noone has it active yet */
            if(old != NULL) {

                /* relink */
                log_debug(ZONE, "relinking sessions");

                /* loop through sessions, relink */
                for(sscan = sess->user->sessions; sscan != NULL; sscan = sscan->next)
                    if(sscan->module_data[mod->index] != NULL && ((privacy_t) sscan->module_data[mod->index])->active == old) {
                        ((privacy_t) sscan->module_data[mod->index])->active = zlist;
                        log_debug(ZONE, "session '%s' now has active list '%s'", jid_full(sscan->jid), (zlist != NULL) ? zlist->name : "(NONE)");
                    }

                /* default list */
                if(z->def == old) {
                    z->def = zlist;

                    if(zlist == NULL) {
                        storage_delete(mod->mm->sm->st, "privacy-default", jid_user(sess->user->jid), NULL);
                        log_debug(ZONE, "removed default list");
                    }

                    else {
                        os = os_new();
                        o = os_object_new(os);

                        os_object_put(o, "default", zlist->name, os_type_STRING);

                        storage_replace(mod->mm->sm->st, "privacy-default", jid_user(sess->user->jid), NULL, os);

                        os_free(os);

                        log_debug(ZONE, "default list is now '%s'", (zlist != NULL) ? zlist->name : "(NONE)");
                    }
                }
            }
        }

        /* set the active list */
        if(active >= 0) {
            name = nad_find_attr(pkt->nad, active, -1, "name", NULL);
            if(name < 0) {
                /* no name, no active list */
                log_debug(ZONE, "clearing active list for session '%s'", jid_full(sess->jid));
                ((privacy_t) sess->module_data[mod->index])->active = NULL;
            }

            else {
                snprintf(str, 256, "%.*s", NAD_AVAL_L(pkt->nad, name), NAD_AVAL(pkt->nad, name));
                str[255] = '\0';

                zlist = xhash_get(z->lists, str);
                if(zlist == NULL) {
                    log_debug(ZONE, "request to make list '%s' active, but there's no such list", str);
                    return -stanza_err_ITEM_NOT_FOUND;
                }

                ((privacy_t) sess->module_data[mod->index])->active = zlist;

                log_debug(ZONE, "session '%s' now has active list '%s'", jid_full(sess->jid), str);
            }
        }

        /* set the default list */
        if(def >= 0) {
            name = nad_find_attr(pkt->nad, def, -1, "name", NULL);
            if(name < 0) {
                /* no name, no default list */
                log_debug(ZONE, "clearing default list for '%s'", jid_user(sess->user->jid));
                z->def = NULL;
            }

            else {
                snprintf(str, 256, "%.*s", NAD_AVAL_L(pkt->nad, name), NAD_AVAL(pkt->nad, name));
                str[255] = '\0';

                zlist = xhash_get(z->lists, str);
                if(zlist == NULL) {
                    log_debug(ZONE, "request to make list '%s' default, but there's no such list");
                    return -stanza_err_ITEM_NOT_FOUND;
                }

                z->def = zlist;

                os = os_new();
                o = os_object_new(os);

                os_object_put(o, "default", zlist->name, os_type_STRING);

                storage_replace(mod->mm->sm->st, "privacy-default", jid_user(sess->user->jid), NULL, os);

                os_free(os);

                log_debug(ZONE, "'%s' now has default list '%s'", jid_user(sess->user->jid), str);
            }
        }

        /* done, let them know */
        result = pkt_create(pkt->sm, "iq", "result", NULL, NULL);

        pkt_id(pkt, result);

        /* done with this */
        pkt_free(pkt);

        /* give it to the session */
        pkt_sess(result, sess);

        /* all done */
        return mod_HANDLED;
    }

    /* its a get */

    /* only allowed to request one list, if any */
    list = nad_find_elem(pkt->nad, query, ns, "list", 1);
    if(list >= 0 && nad_find_elem(pkt->nad, list, ns, "list", 0) >= 0)
        return -stanza_err_BAD_REQUEST;

    result = pkt_create(pkt->sm, "iq", "result", NULL, NULL);

    pkt_id(pkt, result);

    ns = nad_add_namespace(result->nad, uri_PRIVACY, NULL);
    query = nad_insert_elem(result->nad, 1, ns, "query", NULL);

    /* just do one */
    if(list >= 0) {
        name = nad_find_attr(pkt->nad, list, -1, "name", NULL);

        zlist = xhash_getx(z->lists, NAD_AVAL(pkt->nad, name), NAD_AVAL_L(pkt->nad, name));
        if(zlist == NULL)
            return -stanza_err_ITEM_NOT_FOUND;

        _privacy_result_builder(z->lists, zlist->name, (void *) zlist, (void *) result);
    }

    else {
        /* walk the list hash and add the lists in */
        xhash_walk(z->lists, _privacy_lists_result_builder, (void *) result);
    }

    /* tell them about current active and default list if they asked for everything */
    if(list < 0) {
        /* active */
        if(((privacy_t) sess->module_data[mod->index])->active != NULL) {
            active = nad_insert_elem(result->nad, query, ns, "active", NULL);
            nad_set_attr(result->nad, active, -1, "name", ((privacy_t) sess->module_data[mod->index])->active->name, 0);
        }

        /* and the default list */
        if(z->def != NULL) {
            def = nad_insert_elem(result->nad, query, ns, "default", NULL);
            nad_set_attr(result->nad, def, -1, "name", z->def->name, 0);
        }
    }

    /* give it to the session */
    pkt_sess(result, sess);

    /* done with this */
    pkt_free(pkt);

    /* all done */
    return mod_HANDLED;
}

static void _privacy_user_delete(mod_instance_t mi, jid_t jid) {
    log_debug(ZONE, "deleting privacy data for %s", jid_user(jid));

    storage_delete(mi->sm->st, "privacy-items", jid_user(jid), NULL);
    storage_delete(mi->sm->st, "privacy-default", jid_user(jid), NULL);
}

static void _privacy_free(module_t mod) {
     sm_unregister_ns(mod->mm->sm, uri_PRIVACY);
     feature_unregister(mod->mm->sm, uri_PRIVACY);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if (mod->init) return 0;

    mod->user_load = _privacy_user_load;
    mod->in_router = _privacy_in_router;
    mod->out_router = _privacy_out_router;
    mod->in_sess = _privacy_in_sess;
    mod->user_delete = _privacy_user_delete;
    mod->free = _privacy_free;

    ns_PRIVACY = sm_register_ns(mod->mm->sm, uri_PRIVACY);
    feature_register(mod->mm->sm, uri_PRIVACY);
    ns_BLOCKING = sm_register_ns(mod->mm->sm, urn_BLOCKING);
    feature_register(mod->mm->sm, urn_BLOCKING);

    return 0;
}
