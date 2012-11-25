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

/** @file sm/sess.c
  * @brief session management
  * @author Robert Norris
  * $Date: 2005/07/25 20:38:06 $
  * $Revision: 1.37 $
  */

/** send a packet to the client for this session */
void sess_route(sess_t sess, pkt_t pkt) {
    int ns;

    log_debug(ZONE, "routing pkt 0x%X to %s (%s) for %s", pkt, sess->c2s, sess->c2s_id, jid_full(sess->jid));

    if(pkt == NULL)
        return;

    /* wrap it up */
    ns = nad_append_namespace(pkt->nad, 1, uri_SESSION, "sm");

    nad_set_attr(pkt->nad, 1, ns, "c2s", sess->c2s_id, 0);
    nad_set_attr(pkt->nad, 1, ns, "sm", sess->sm_id, 0);

    nad_set_attr(pkt->nad, 0, -1, "to", sess->c2s, 0);
    nad_set_attr(pkt->nad, 0, -1, "from", sess->user->jid->domain, 0);

    /* remove error attribute */
    nad_set_attr(pkt->nad, 0, -1, "error", NULL, 0);

    /* and send it out */
    sx_nad_write(sess->user->sm->router, pkt->nad);

    /* free up the packet */
    if(pkt->rto != NULL) jid_free(pkt->rto);
    if(pkt->rfrom != NULL) jid_free(pkt->rfrom);
    if(pkt->to != NULL) jid_free(pkt->to);
    if(pkt->from != NULL) jid_free(pkt->from);
    free(pkt);
}

static void _sess_end_guts(sess_t sess) {
    sess_t scan;

    /* fake an unavailable presence from this session, so that modules and externals know we're gone */
    if(sess->available || sess->A != NULL)
        mm_in_sess(sess->user->sm->mm, sess, pkt_create(sess->user->sm, "presence", "unavailable", NULL, NULL));

    /* inform the modules */
    mm_sess_end(sess->user->sm->mm, sess);

    /* unlink it from this users sessions */
    if(sess->user->sessions == sess)
        sess->user->sessions = sess->next;
    else {
        for(scan = sess->user->sessions; scan != NULL && scan->next != sess; scan = scan->next);
        if(scan != NULL)
            scan->next = sess->next;
    }

    /* and from global sessions */
    xhash_zap(sess->user->sm->sessions, sess->sm_id);
}

void sess_end(sess_t sess) {
    log_debug(ZONE, "shutting down session %s", jid_full(sess->jid));

    _sess_end_guts(sess);

    log_write(sess->user->sm->log, LOG_NOTICE, "session ended: jid=%s", jid_full(sess->jid));

    /* if it was the last session, free the user */
    if(sess->user->sessions == NULL) {
        mm_user_unload(sess->user->sm->mm, sess->user);
        log_write(sess->user->sm->log, LOG_NOTICE, "user unloaded jid=%s", jid_user(sess->jid));
        user_free(sess->user);
    }

    /* free the session */
    pool_free(sess->p);
}

sess_t sess_start(sm_t sm, jid_t jid) {
    pool_t p;
    user_t user;
    sess_t sess, scan;
    sha1_state_t sha1;
    unsigned char hash[20];
    int replaced = 0;

    log_debug(ZONE, "session requested for %s", jid_full(jid));

    /* check whether it is to serviced domain */
    if(xhash_get(sm->hosts, jid->domain) == NULL) {
        log_write(sm->log, LOG_ERR, "request to start session in non-serviced domain: jid=%s", jid_full(jid));
        return NULL;
    }

    /* get user data for this guy */
    user = user_load(sm, jid);

    /* unknown user */
    if(user == NULL) {
        if(config_get(sm->config, "user.auto-create") == NULL) {
            log_write(sm->log, LOG_NOTICE, "user not found and user.auto-create not enabled, can't start session: jid=%s", jid_full(jid));
            return NULL;
        }

        log_debug(ZONE, "auto-creating user %s", jid_user(jid));

        if(user_create(sm, jid) != 0)
            return NULL;

        user = user_load(sm, jid);
        if(user == NULL) {
            log_write(sm->log, LOG_NOTICE, "couldn't load user, can't start session: jid=%s", jid_full(jid));
            return NULL;
        }
    }

    /* kill their old session if they have one */
    for(scan = user->sessions; scan != NULL; scan = scan->next)
        if(jid_compare_full(scan->jid, jid) == 0) {
            log_debug(ZONE, "replacing session %s (%s)", jid_full(jid), scan->c2s_id);

            /* !!! this "replaced" stuff is a hack - its really a subaction of "ended".
             *     hurrah, another control protocol rewrite is needed :(
             */
            sm_c2s_action(scan, "replaced", NULL);

            _sess_end_guts(scan);

            pool_free(scan->p);

            replaced = 1;

            break;
        }

    /* make a new session */
    p = pool_new();

    sess = (sess_t) pmalloco(p, sizeof(struct sess_st));
    sess->p = p;

    /* fill it out */
    sess->pri = 0;
    sess->user = user;

    sess->jid = jid_dup(jid);
    pool_cleanup(sess->p, (void (*))(void *) jid_free, sess->jid);

    /* a place for modules to store stuff */
    sess->module_data = (void **) pmalloco(sess->p, sizeof(void *) * sess->user->sm->mm->nindex);

    /* add it to the list */
    sess->next = user->sessions;
    user->sessions = sess;

    /* who c2s should address things to */
    sha1_init(&sha1);
    datetime_out(time(NULL), dt_DATETIME, sess->sm_id, 41);
    sha1_append(&sha1, sess->sm_id, strlen(sess->sm_id));
    sha1_append(&sha1, jid_full(sess->jid), strlen(jid_full(sess->jid)));
    sha1_finish(&sha1, hash);
    hex_from_raw(hash, 20, sess->sm_id);

    log_debug(ZONE, "smid is %s", sess->sm_id);

    /* remember it */
    xhash_put(sm->sessions, sess->sm_id, sess);

    /* inform the modules */
    /* !!! catch the return value - if its 1, don't let them in */
    mm_sess_start(sm->mm, sess);

    if(replaced)
        log_write(sm->log, LOG_NOTICE, "session replaced: jid=%s", jid_full(sess->jid));
    else
        log_write(sm->log, LOG_NOTICE, "session started: jid=%s", jid_full(sess->jid));
            
    return sess;
}

/** match a session by resource */
sess_t sess_match(user_t user, const char *resource) {
    sess_t sess;

    for(sess = user->sessions; sess != NULL; sess = sess->next) {
        /* exact matches */
        if(strcmp(sess->jid->resource, resource) == 0)
            return sess;
    }

    return NULL;
}
