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

/** @file sm/mod_active.c
  * @brief active user management
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.8 $
  */

#include "sm.h"

static int _active_user_load(mod_instance_t mi, user_t user) {
    os_t os;
    os_object_t o;

    /* get their active status */
    if(storage_get(user->sm->st, "active", jid_user(user->jid), NULL, &os) == st_SUCCESS && os_iter_first(os)) {
        o = os_iter_object(os);
        os_object_get_time(os, o, "time", &user->active);
        os_free(os);
    } else
        /* can't load them if they're inactive */
        return 1;

    return 0;
}

static int _active_user_create(mod_instance_t mi, jid_t jid) {
    time_t t;
    os_t os;
    os_object_t o;

    log_debug(ZONE, "activating user %s", jid_user(jid));

    t = time(NULL);

    os = os_new();
    o = os_object_new(os);
    os_object_put_time(o, "time", &t);
    storage_put(mi->sm->st, "active", jid_user(jid), os);
    os_free(os);

    return 0;
}

static void _active_user_delete(mod_instance_t mi, jid_t jid) {
    log_debug(ZONE, "deactivating user %s", jid_user(jid));

    storage_delete(mi->sm->st, "active", jid_user(jid), NULL);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->user_load = _active_user_load;
    mod->user_create = _active_user_create;
    mod->user_delete = _active_user_delete;

    return 0;
}
