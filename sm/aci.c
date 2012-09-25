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

/** @file sm/aci.c
  * @brief access control manager
  * @author Robert Norris
  * $Date: 2005/09/10 10:23:50 $
  * $Revision: 1.16 $
  */

xht aci_load(sm_t sm)
{
    xht acls;
    int aelem, jelem, attr;
    char type[33];
    jid_t list, jid;

    log_debug(ZONE, "loading aci");

    acls = xhash_new(51);

    if((aelem = nad_find_elem(sm->config->nad, 0, -1, "aci", 1)) < 0)
        return acls;

    aelem = nad_find_elem(sm->config->nad, aelem, -1, "acl", 1);
    while(aelem >= 0)
    {
        list = NULL;

        if((attr = nad_find_attr(sm->config->nad, aelem, -1, "type", NULL)) < 0)
        {
            aelem = nad_find_elem(sm->config->nad, aelem, -1, "acl", 0);
            continue;
        }

        snprintf(type, 33, "%.*s", NAD_AVAL_L(sm->config->nad, attr), NAD_AVAL(sm->config->nad, attr));

        log_debug(ZONE, "building list for '%s'", type);

        jelem = nad_find_elem(sm->config->nad, aelem, -1, "jid", 1);
        while(jelem >= 0)
        {
            if(NAD_CDATA_L(sm->config->nad, jelem) > 0)
            {
                jid = jid_new(NAD_CDATA(sm->config->nad, jelem), NAD_CDATA_L(sm->config->nad, jelem));
                list = jid_append(list, jid);
                
                log_debug(ZONE, "added '%s'", jid_user(jid));

                jid_free(jid);
            }

            jelem = nad_find_elem(sm->config->nad, jelem, -1, "jid", 0);
        }

        if(list != NULL) {
            xhash_put(acls, pstrdup(xhash_pool(acls), type), (void *) list);
        }

        aelem = nad_find_elem(sm->config->nad, aelem, -1, "acl", 0);
    }

    return acls;
}

/** see if a jid is in an acl */
int aci_check(xht acls, const char *type, jid_t jid)
{
    jid_t list, dup;

    dup = jid_dup(jid);
    if (dup->resource[0]) {
        /* resourceless version */
        dup->resource[0] = '\0';
        dup->dirty = 1;
    }

    log_debug(ZONE, "checking for '%s' in acl 'all'", jid_full(jid));
    list = (jid_t) xhash_get(acls, "all");
    if(jid_search(list, jid)) {
        jid_free(dup);
        return 1;
    }

    log_debug(ZONE, "checking for '%s' in acl 'all'", jid_user(dup));
    if(jid_search(list, dup)) {
        jid_free(dup);
        return 1;
    }

    if(type != NULL) {
        log_debug(ZONE, "checking for '%s' in acl '%s'", jid_full(jid), type);
        list = (jid_t) xhash_get(acls, type);
        if(jid_search(list, jid)) {
            jid_free(dup);
            return 1;
        }

        log_debug(ZONE, "checking for '%s' in acl '%s'", jid_user(dup), type);
        if(jid_search(list, dup)) {
            jid_free(dup);
            return 1;
        }
    }

    jid_free(dup);
    return 0;
}

void aci_unload(xht acls)
{ 
    jid_t list, jid;

    log_debug(ZONE, "unloading acls");

    if(xhash_iter_first(acls))
        do {
            xhash_iter_get(acls, NULL, NULL, (void *) &list);
            while (list != NULL) {
               jid = list;
               list = list->next;
               jid_free(jid);
            }
        } while(xhash_iter_next(acls));

  return;
}
