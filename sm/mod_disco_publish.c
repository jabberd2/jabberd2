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

/** @file sm/mod_disco_publish.c
  * @brief user info publishing
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.15 $
  */

/** holder for a single item */
typedef struct disco_item_st *disco_item_t;
struct disco_item_st {
    jid_t           jid;
    char            name[257];
    char            node[257];
    disco_item_t    next;
};

static mod_ret_t _disco_publish_pkt_user(mod_instance_t mi, user_t user, pkt_t pkt) {
    module_t mod = mi->mod;
    disco_item_t list, di, scan, updi;
    pkt_t res;
    int ns, elem, attr;
    char filter[4096];
    os_t os;
    os_object_t o;

    /* can only deal with disco items requests */
    if(pkt->ns != ns_DISCO_ITEMS)
        return mod_PASS;

    list = user->module_data[mod->index];

    /* get */
    if(pkt->type == pkt_IQ) {
        res = pkt_create(mod->mm->sm, "iq", "result", jid_full(pkt->from), jid_full(pkt->to));
        pkt_id(pkt, res);

        ns = nad_add_namespace(res->nad, uri_DISCO_INFO, NULL);
        nad_append_elem(res->nad, ns, "query", 2);

        pkt_free(pkt);

        for(scan = list; scan != NULL; scan = scan->next) {
            nad_append_elem(res->nad, ns, "item", 3);
            nad_append_attr(res->nad, -1, "jid", jid_full(scan->jid));
            if(scan->name[0] != '\0')
                nad_append_attr(res->nad, -1, "name", scan->name);
            if(scan->node[0] != '\0')
                nad_append_attr(res->nad, -1, "node", scan->node);
        }

        pkt_router(res);

        return mod_HANDLED;
    }

    /* only sets from here */
    if(pkt->type != pkt_IQ_SET)
        return mod_PASS;

    /* only they can modify their details */
    if(jid_compare_user(pkt->from, user->jid) != 0)
        return -stanza_err_FORBIDDEN;

    ns = nad_find_scoped_namespace(pkt->nad, uri_DISCO_INFO, NULL);

    /* extract the items */
    elem = nad_find_elem(pkt->nad, 2, ns, "item", 1);
    while(elem >= 0) {
        /* jid is required */
        attr = nad_find_attr(pkt->nad, elem, -1, "jid", NULL);
        if(attr < 0) {
            elem = nad_find_elem(pkt->nad, elem, ns, "item", 0);
            continue;       /* can't return an error halfway through, otherwise we leave things in an undefined state */
        }

        /* new item */
        di = (disco_item_t) calloc(1, sizeof(struct disco_item_st));

        /* jid */
        di->jid = jid_new(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));

        /* name */
        attr = nad_find_attr(pkt->nad, elem, -1, "name", NULL);
        if(attr >= 0)
            strncpy(di->name, NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr) > 256 ? 256 : NAD_AVAL_L(pkt->nad, attr));

        /* node */
        attr = nad_find_attr(pkt->nad, elem, -1, "node", NULL);
        if(attr >= 0)
            strncpy(di->node, NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr) > 256 ? 256 : NAD_AVAL_L(pkt->nad, attr));

        /* delete it from the list */
        if(nad_find_attr(pkt->nad, elem, -1, "action", "remove") >= 0) {
            if(list != NULL) {
                updi = NULL;

                /* first on the list */
                if(jid_compare_full(di->jid, list->jid) == 0 && strcmp(di->node, list->node) == 0) {
                    updi = list;
                    list = list->next;
                    user->module_data[mod->index] = list;
                }
                
                /* list guts */
                else {
                    for(scan = list; scan != NULL && scan->next != NULL && jid_compare_full(di->jid, scan->next->jid) != 0 && strcmp(di->node, scan->next->node) != 0; scan = scan->next);
                    if(scan->next != NULL) {
                        updi = scan->next;
                        scan->next = scan->next->next;
                    }
                }

                /* kill it */
                if(updi != NULL) {
                    jid_free(updi->jid);
                    free(updi);

                    /* make a filter */
                    if(di->node[0] == '\0')
                        /* filter is (jid=blah) */
                        sprintf(filter, "(jid=%i:%s)", strlen(jid_full(di->jid)), jid_full(di->jid));
                    else
                        /* filter is (&(jid=blah)(node=moreblah)) */
                        sprintf(filter, "(&(jid=%i:%s)(node=%i:%s))", strlen(jid_full(di->jid)), jid_full(di->jid), strlen(di->node), di->node);

                    /* sucks if it fails, but we can't do anything about it anyway */
                    storage_delete(mod->mm->sm->st, "disco-items", jid_user(user->jid), filter);
                }
            }

            /* don't need this anymore */
            jid_free(di->jid);
            free(di);
        }
        
        /* update the list */
        else {
            /* we're first */
            if(list == NULL)
                list = user->module_data[mod->index] = di;

            /* find it if it exists already */
            else {
                updi = NULL;

                /* first on the list */
                if(jid_compare_full(di->jid, list->jid) == 0 && strcmp(di->node, list->node) == 0) {
                    updi = list;
                    di->next = list->next;
                    list = user->module_data[mod->index] = di;
                }
                
                /* list guts */
                else {
                    for(scan = list; scan != NULL && scan->next != NULL && jid_compare_full(di->jid, scan->next->jid) != 0 && strcmp(di->node, scan->next->node) != 0; scan = scan->next);
                    if(scan->next != NULL) {
                        updi = scan->next;
                        scan->next = di;
                        di->next = scan->next->next;
                    }
                }

                /* didn't find it, just insert at the front */
                if(updi == NULL) {
                    di->next = list;
                    list = user->module_data[mod->index] = di;
                }

                /* nuke the old one */
                else {
                    jid_free(updi->jid);
                    free(updi);
                }
            }

            /* make a filter */
            if(di->node[0] == '\0')
                /* filter is (jid=blah) */
                sprintf(filter, "(jid=%i:%s)", strlen(jid_full(di->jid)), jid_full(di->jid));
            else
                /* filter is (&(jid=blah)(node=moreblah)) */
                sprintf(filter, "(&(jid=%i:%s)(node=%i:%s))", strlen(jid_full(di->jid)), jid_full(di->jid), strlen(di->node), di->node);

            /* prepare objects */
            os = os_new();
            o = os_object_new(os);

            os_object_put(o, "jid", jid_full(di->jid), os_type_STRING);
            if(di->name[0] != '\0')
                os_object_put(o, "name", di->name, os_type_STRING);
            if(di->node[0] != '\0')
                os_object_put(o, "node", di->node, os_type_STRING);

            storage_replace(mod->mm->sm->st, "disco-items", jid_user(user->jid), filter, os);

            os_free(os);
        }

        elem = nad_find_elem(pkt->nad, elem, ns, "item", 0);
    }

    res = pkt_create(mod->mm->sm, "iq", "result", jid_full(pkt->from), jid_full(pkt->to));
    pkt_id(pkt, res);
    
    pkt_free(pkt);

    pkt_router(res);
    
    return mod_HANDLED;
}

static void _disco_publish_user_free(disco_item_t *list) {
    disco_item_t scan, next;

    scan = *list;
    while(scan != NULL) {
        log_debug(ZONE, "freeing published disco item %s node %s", jid_full(scan->jid), scan->node);

        next = scan->next;
        jid_free(scan->jid);
        free(scan);
        scan = next;
    }
}

static int _disco_publish_user_load(mod_instance_t mi, user_t user) {
    module_t mod = mi->mod;
    disco_item_t list = user->module_data[mod->index], scan, next, di;
    os_t os;
    os_object_t o;
    char *str;

    scan = list;
    while(scan != NULL) {
        next = scan->next;
        jid_free(scan->jid);
        free(scan);
        scan = next;
    }

    list = user->module_data[mod->index] = NULL;

    pool_cleanup(user->p, (void (*))(void *) _disco_publish_user_free, &(user->module_data[mod->index]));

    if(storage_get(mod->mm->sm->st, "disco-items", jid_user(user->jid), NULL, &os) != st_SUCCESS)
        return 0;

    if(os_iter_first(os))
        do {
            o = os_iter_object(os);

            if(os_object_get_str(os, o, "jid", &str)) {
                di = (disco_item_t) calloc(1, sizeof(struct disco_item_st));

                di->jid = jid_new(str, -1);

                if(os_object_get_str(os, o, "name", &str))
                    strncpy(di->name, str, 256);
                if(os_object_get_str(os, o, "node", &str))
                    strncpy(di->node, str, 256);

                di->next = list;
                list = user->module_data[mod->index] = di;
            }
        } while(os_iter_next(os));

    os_free(os);

    return 0;
}

static void _disco_publish_user_delete(mod_instance_t mi, jid_t jid) {
    log_debug(ZONE, "deleting published disco items for %s", jid_user(jid));

    storage_delete(mi->sm->st, "disco-items", jid_user(jid), NULL);
}

DLLEXPORT int module_init(mod_instance_t mi, char *arg) {
    if(mi->mod->init) return 0;

    log_debug(ZONE, "disco publish module init");

    /* our handlers */
    mi->mod->pkt_user = _disco_publish_pkt_user;
    mi->mod->user_load = _disco_publish_user_load;
    mi->mod->user_delete = _disco_publish_user_delete;

    return 0;
}
