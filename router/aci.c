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

#include "router.h"

/** aci manager */

typedef struct aci_user_st      *aci_user_t;
struct aci_user_st {
    char        *name;
    aci_user_t  next;
};

xht aci_load(router_t r) {
    xht aci;
    int aelem, uelem, attr;
    char type[33];
    aci_user_t list_head, list_tail, user;

    log_debug(ZONE, "loading aci");

    aci = xhash_new(51);

    if((aelem = nad_find_elem(r->config->nad, 0, -1, "aci", 1)) < 0)
        return aci;

    aelem = nad_find_elem(r->config->nad, aelem, -1, "acl", 1);
    while(aelem >= 0) {
        if((attr = nad_find_attr(r->config->nad, aelem, -1, "type", NULL)) < 0) {
            aelem = nad_find_elem(r->config->nad, aelem, -1, "acl", 0);
            continue;
        }

        list_head = NULL;
        list_tail = NULL;

        snprintf(type, 33, "%.*s", NAD_AVAL_L(r->config->nad, attr), NAD_AVAL(r->config->nad, attr));

        log_debug(ZONE, "building list for '%s'", type);

        uelem = nad_find_elem(r->config->nad, aelem, -1, "user", 1);
        while(uelem >= 0) {
            if(NAD_CDATA_L(r->config->nad, uelem) > 0) {
                user = (aci_user_t) calloc(1, sizeof(struct aci_user_st));

                user->name = (char *) malloc(sizeof(char) * (NAD_CDATA_L(r->config->nad, uelem) + 1));
                sprintf(user->name, "%.*s", NAD_CDATA_L(r->config->nad, uelem), NAD_CDATA(r->config->nad, uelem));

                if(list_tail != NULL) {
                   list_tail->next = user;
                   list_tail = user;
                }

                /* record the head of the list */
                if(list_head == NULL) {
                   list_head = user;
                   list_tail = user;
                }
                
                log_debug(ZONE, "added '%s'", user->name);
            }

            uelem = nad_find_elem(r->config->nad, uelem, -1, "user", 0);
        }

        if(list_head != NULL)
            xhash_put(aci, pstrdup(xhash_pool(aci), type), (void *) list_head);

        aelem = nad_find_elem(r->config->nad, aelem, -1, "acl", 0);
    }

    return aci;
}

/** see if a username is in an acl */
int aci_check(xht aci, const char *type, const char *name) {
    aci_user_t list, scan;

    log_debug(ZONE, "checking for '%s' in acl 'all'", name);
    list = (aci_user_t) xhash_get(aci, "all");
    for(scan = list; scan != NULL; scan = scan->next)
        if(strcmp(scan->name, name) == 0)
            return 1;

    if(type != NULL) {
        log_debug(ZONE, "checking for '%s' in acl '%s'", name, type);
        list = (aci_user_t) xhash_get(aci, type);
        for(scan = list; scan != NULL; scan = scan->next)
            if(strcmp(scan->name, name) == 0)
                return 1;
    }

    return 0;
}

/** unload aci table */
void aci_unload(xht aci) {
    aci_user_t list, user;

    /* free list of users for each acl*/
    if(xhash_iter_first(aci))
        do {
            xhash_iter_get(aci, NULL, NULL, (void *) &list);
            while (list != NULL) {
               user = list;
               list = list->next;
               free(user->name);
               free(user);
            }
        } while(xhash_iter_next(aci));

    xhash_free(aci);
    return;
}
