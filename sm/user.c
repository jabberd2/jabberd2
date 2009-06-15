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

/** @file sm/user.c
  * @brief user management
  * @author Robert Norris
  * $Date: 2005/06/02 04:48:25 $
  * $Revision: 1.23 $
  */

/** make a new one */
static user_t _user_alloc(sm_t sm, jid_t jid) {
    pool_t p;
    user_t user;

    p = pool_new();

    user = (user_t) pmalloco(p, sizeof(struct user_st));

    user->p = p;
    user->sm = sm;

    user->jid = jid_dup(jid);
    pool_cleanup(p, (void (*)(void *)) jid_free, user->jid);

    /* a place for modules to store stuff */
    user->module_data = (void **) pmalloco(p, sizeof(void *) * sm->mm->nindex);

    return user;
}

/** fetch user data */
user_t user_load(sm_t sm, jid_t jid) {
    user_t user;

    /* already loaded */
    user = xhash_get(sm->users, jid_user(jid));
    if(user != NULL) {
        log_debug(ZONE, "returning previously-created user data for %s", jid_user(jid));
        return user;
    }

    /* make a new one */
    user = _user_alloc(sm, jid);

    /* get modules to setup */
    if(mm_user_load(sm->mm, user) != 0) {
        log_debug(ZONE, "modules failed user load for %s", jid_user(jid));
        pool_free(user->p);
        return NULL;
    }

    /* save them for later */
    xhash_put(sm->users, jid_user(user->jid), (void *) user);

    log_debug(ZONE, "loaded user data for %s", jid_user(jid));

    return user;
}

void user_free(user_t user) {
    log_debug(ZONE, "freeing user %s", jid_user(user->jid));

    xhash_zap(user->sm->users, jid_user(user->jid));
    pool_free(user->p);
}

/** initialise a user */
int user_create(sm_t sm, jid_t jid) {
    user_t user;

    log_debug(ZONE, "create user request for %s", jid_user(jid));

    /* check whether it is to serviced domain */
    if(xhash_get(sm->hosts, jid->domain) == NULL) {
        log_write(sm->log, LOG_ERR, "request to create user for non-serviced domain: jid=%s", jid_user(jid));
        log_debug(ZONE, "no such domain, not creating");
        return 1;
    }

    user = user_load(sm, jid);
    if(user != NULL) {
        log_write(sm->log, LOG_ERR, "request to create already-active user: jid=%s", jid_user(jid));
        log_debug(ZONE, "user already active, not creating");
        return 1;
    }

    /* modules create */
    if(mm_user_create(sm->mm, jid) != 0) {
        log_write(sm->log, LOG_ERR, "user creation failed: jid=%s", jid_user(jid));
        log_debug(ZONE, "user create failed, forcing deletion for cleanup");
        mm_user_delete(sm->mm, jid);
        return 1;
    }

    log_write(sm->log, LOG_NOTICE, "created user: jid=%s", jid_user(jid));

    return 0;
}

/** trash a user */
void user_delete(sm_t sm, jid_t jid) {
    user_t user;
    sess_t scan, next;

    log_debug(ZONE, "delete user request for %s", jid_user(jid));

    user = user_load(sm, jid);
    if(user == NULL) {
        log_debug(ZONE, "user doesn't exist, can't delete");
        return;
    }

    /* close their sessions first (this will free user, after the last session ends) */
    scan = user->sessions;
    while(scan != NULL) {
        next = scan->next;
        sm_c2s_action(scan, "ended", NULL);
        sess_end(scan);
        scan = next;
    }

    mm_user_delete(sm->mm, jid);

    log_write(sm->log, LOG_NOTICE, "deleted user: jid=%s", jid_user(jid));
}
