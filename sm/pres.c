/* vim: set et ts=4 sw=4: */
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

/** @file sm/pres.c
  * @brief presence tracker
  * @author Robert Norris
  * $Date: 2005/06/02 04:48:25 $
  * $Revision: 1.41 $
  */

/*
 * there are four entry points
 *
 * pres_update(sess, pkt)  - presence updates from a session    (T1, T2, T3)
 * pres_in(user, pkt)      - presence updates from a remote jid (T4, T5)
 * pres_error(sess, jid)   - remote jid bounced an update       (T6)
 * pres_deliver(sess, pkt) - outgoing directed presence         (T7, T8)
 */

/** select a new top session based on current session presence */
static void _pres_top(user_t user) {
    sess_t scan;

    user->top = NULL;
    user->available = 0;

    /* loop the active sessions */
    for(scan = user->sessions; scan != NULL; scan = scan->next) {
        if(scan->available)
            user->available = 1;

        /* non available and/or negative presence and/or fake can't become top session */
        if(!scan->available || scan->pri < 0 || scan->fake) continue;

        /* if we don't have one, then this is it */
        if(user->top == NULL)
            user->top = scan;

        /* if we have higher priority than current top, we're the new top */
        if(scan->pri >= user->top->pri)
            user->top = scan;
    }

    if(user->top == NULL) {
        log_debug(ZONE, "no priority >= 0 sessions, so no top session");
    } else {
        log_debug(ZONE, "top session for %s is now %s (priority %d)", jid_user(user->jid), jid_full(user->top->jid), user->top->pri);
    }
}

/** presence updates from a session */
void pres_update(sess_t sess, pkt_t pkt) {
    item_t item;
    int self;
    jid_t scan, next;
    sess_t sscan;

    switch(pkt->type) {
        case pkt_PRESENCE:
            log_debug(ZONE, "available presence for session %s", jid_full(sess->jid));

            /* cache packet for later */
            if(sess->pres != NULL)
                pkt_free(sess->pres);
            sess->pres = pkt;

            /* B1: forward to all in T, unless in E */

            /* loop the roster, looking for trusted */
            self = 0;
            if(xhash_iter_first(sess->user->roster))
            do {
                xhash_iter_get(sess->user->roster, NULL, NULL, (void *) &item);

                /* if we're coming available, and we can see them, we need to probe them */
                if(!sess->available && item->to) {
                    log_debug(ZONE, "probing %s", jid_full(item->jid));
                    pkt_router(pkt_create(sess->user->sm, "presence", "probe", jid_full(item->jid), jid_user(sess->jid)));

                    /* flag if we probed ourselves */
                    if(strcmp(jid_user(sess->jid), jid_full(item->jid)) == 0)
                        self = 1;
                }

                /* if they can see us, forward */
                if(item->from && !jid_search(sess->E, item->jid)) {
                    log_debug(ZONE, "forwarding available to %s", jid_full(item->jid));
                    pkt_router(pkt_dup(pkt, jid_full(item->jid), jid_full(sess->jid)));
                }
            } while(xhash_iter_next(sess->user->roster));

            /* probe ourselves if we need to and didn't already */
            if(!self && !sess->available) {
                log_debug(ZONE, "probing ourselves");
                pkt_router(pkt_create(sess->user->sm, "presence", "probe", jid_user(sess->jid), jid_user(sess->jid)));
            }

            /* forward to our active sessions */
            for(sscan = sess->user->sessions; sscan != NULL; sscan = sscan->next) {
                if(sscan != sess && sscan->available && !sscan->fake) {
                    log_debug(ZONE, "forwarding available to our session %s", jid_full(sscan->jid));
                    pkt_router(pkt_dup(pkt, jid_full(sscan->jid), jid_full(sess->jid)));
                }
            }

            /* update vars */
            sess->available = 1;

            /* new priority */
            sess->pri = pkt->pri;

            /* stamp the saved presence so future probes know how old it is */
            pkt_delay(pkt, time(NULL), jid_full(pkt->from));

            break;

        case pkt_PRESENCE_UN:
            log_debug(ZONE, "unavailable presence for session %s", jid_full(sess->jid));

            /* free cached presence */
            if(sess->pres != NULL) {
                pkt_free(sess->pres);
                sess->pres = NULL;
            }

            /* B2: forward to all in T and A, unless in E */

            /* loop the roster, looking for trusted */
            if(xhash_iter_first(sess->user->roster))
            do {
                xhash_iter_get(sess->user->roster, NULL, NULL, (void *) &item);

                /* forward if they're trusted and they're not E */
                if(item->from && !jid_search(sess->E, item->jid)) {

                    log_debug(ZONE, "forwarding unavailable to %s", jid_full(item->jid));
                    pkt_router(pkt_dup(pkt, jid_full(item->jid), jid_full(sess->jid)));
                }
            } while(xhash_iter_next(sess->user->roster));

            /* walk A and forward to untrusted */
            for(scan = sess->A; scan != NULL; scan = scan->next)
                if(!pres_trust(sess->user, scan)) {
                    log_debug(ZONE, "forwarding unavailable to %s", jid_full(scan));
                    pkt_router(pkt_dup(pkt, jid_full(scan), jid_full(sess->jid)));
                }

            /* forward to our active sessions */
            for(sscan = sess->user->sessions; sscan != NULL; sscan = sscan->next) {
                if(sscan != sess && sscan->available && !sscan->fake) {
                    log_debug(ZONE, "forwarding available to our session %s", jid_full(sscan->jid));
                    pkt_router(pkt_dup(pkt, jid_full(sscan->jid), jid_full(sess->jid)));
                }
            }

            /* drop A, E */
            scan = sess->A;
            while(scan != NULL) {
                next = scan->next;
                jid_free(scan);
                scan = next;
            }
            sess->A = NULL;

            scan = sess->E;
            while(scan != NULL) {
                next = scan->next;
                jid_free(scan);
                scan = next;
            }
            sess->E = NULL;

            /* update vars */
            sess->available = 0;

            /* done */
            pkt_free(pkt);

            break;

        default:
            log_debug(ZONE, "pres_update got packet type 0x%X, this shouldn't happen", pkt->type);
            pkt_free(pkt);
            return;
    }

    /* reset the top session */
    _pres_top(sess->user);
}

/** presence updates from a remote jid - RFC 3921bis 4.3.2. */
void pres_in(user_t user, pkt_t pkt) {
    sess_t scan;

    log_debug(ZONE, "type 0x%X presence packet from %s", pkt->type, jid_full(pkt->from));

    /* handle probes */
    if(pkt->type == pkt_PRESENCE_PROBE) {
        /* unsubscribed for untrusted users */
        if(!pres_trust(user, pkt->from)) {
            log_debug(ZONE, "unsubscribed untrusted %s", jid_full(pkt->from));
            pkt_router(pkt_create(user->sm, "presence", "unsubscribed", jid_full(pkt->from), jid_full(pkt->to)));

            pkt_free(pkt);
            return;
        }

        /* respond with last unavailable presence if no available session */
        if(!user->available) {
            os_t os;
            os_object_t o;
            nad_t nad;
            pkt_t pres;

            /* get user last presence stanza */
            if(storage_get(user->sm->st, "status", jid_user(user->jid), NULL, &os) == st_SUCCESS && os_iter_first(os)) {
                o = os_iter_object(os);
                os_object_get_nad(os, o, "xml", &nad);
                if(nad != NULL) {
                    pres = pkt_new(pkt->sm, nad_copy(nad));
                    nad_set_attr(pres->nad, 1, -1, "type", "unavailable", 11);
                    pkt_router(pkt_dup(pres, jid_full(pkt->from), jid_user(user->jid)));
                    pkt_free(pres);
                }
                os_free(os);
            }
            pkt_free(pkt);
            return;
        }
    }

    /* loop over each session */
    for(scan = user->sessions; scan != NULL; scan = scan->next) {
        /* don't deliver to unavailable sessions: B4(a) */
        if(!scan->available || scan->fake)
            continue;

        /* don't deliver to ourselves, lest we presence-bomb ourselves ;) */
        if(jid_compare_full(pkt->from, scan->jid) == 0)
            continue;

        /* handle probes */
        if(pkt->type == pkt_PRESENCE_PROBE) {
            log_debug(ZONE, "probe from %s for %s", jid_full(pkt->from), jid_full(scan->jid));

            /* B3: respond (already checked for T) */
            if(pkt->to->resource[0] != '\0') {
                /* this is a direct probe */
                if(jid_compare_full(pkt->to, scan->jid) == 0) {
                    /* respond with simple stanza only */
                    log_debug(ZONE, "responding with simple presence");
                    pkt_router(pkt_create(user->sm, "presence", NULL, jid_full(pkt->from), jid_full(pkt->to)));
                }
                else
                    continue;
            }
            else {
                log_debug(ZONE, "responding with last presence update");
                pkt_router(pkt_dup(scan->pres, jid_full(pkt->from), jid_full(scan->jid)));
            }

            /* remove from E */
            scan->E = jid_zap(scan->E, pkt->from);

            continue;
        }

        /* deliver to session: B4(b) */
        log_debug(ZONE, "forwarding to %s", jid_full(scan->jid));
        pkt_sess(pkt_dup(pkt, jid_full(scan->jid), jid_full(pkt->from)), scan);
    }

    pkt_free(pkt);
}

void pres_error(sess_t sess, jid_t jid) {
    /* bounced updates: B5: add to E, remove from A  */
    log_debug(ZONE, "bounced presence from %s, adding to error list", jid_full(jid));
    sess->E = jid_append(sess->E, jid);
    sess->A = jid_zap(sess->A, jid);
}

/** outgoing directed presence */
void pres_deliver(sess_t sess, pkt_t pkt) {

    if(jid_full(pkt->to) == NULL) {
        log_debug(ZONE, "invalid jid in directed presence packet");
        pkt_free(pkt);
        return;
    }

    if(pkt->type == pkt_PRESENCE) {
        /* B6: forward, add to A (unless in T), remove from E */
        log_debug(ZONE, "delivering directed available presence to %s", jid_full(pkt->to));
        if(!pres_trust(sess->user, pkt->to))
            sess->A = jid_append(sess->A, pkt->to);
        sess->E = jid_zap(sess->E, pkt->to);
        pkt_router(pkt);
        return;
    }

    if(pkt->type == pkt_PRESENCE_UN) {
        /* B7: forward, remove from A and E */
        log_debug(ZONE, "delivering directed unavailable presence to %s", jid_full(pkt->to));
        sess->A = jid_zap(sess->A, pkt->to);
        sess->E = jid_zap(sess->E, pkt->to);
        pkt_router(pkt);
        return;
    }

    log_debug(ZONE, "don't know how to deliver presence type %d to %s, dropping", pkt->type, jid_full(pkt->to));

    pkt_free(pkt);
}

/** see if the jid is trusted (ie in the roster with s10n="from" or "both") */
int pres_trust(user_t user, jid_t jid) {
    item_t item = NULL;

    /* get roster item with bare jid*/
    item = xhash_get(user->roster, jid_user(jid));

    /* retry with full jid if not found */
    if(item == NULL)
        item = xhash_get(user->roster, jid_full(jid));

    /* trusted if they're in the roster and they can see us */
    if(item != NULL && item->from)
        return 1;

    /* always trust ourselves */
    if(jid_compare_user(user->jid, jid) == 0)
        return 1;

    return 0;
}

/** send presence based on roster changes */
void pres_roster(sess_t sess, item_t item) {
    /* if we're not available, then forget it */
    if(!sess->available)
        return;

    /* if they were trusted previously, but aren't anymore, and we haven't
     * explicitly sent them presence, then make them forget */
    if(!item->from && !jid_search(sess->A, item->jid) && !jid_search(sess->E, item->jid)) {
        log_debug(ZONE, "forcing unavailable to %s after roster change", jid_full(item->jid));
        pkt_router(pkt_create(sess->user->sm, "presence", "unavailable", jid_full(item->jid), jid_full(sess->jid)));
        return;
    }

    /* if they're now trusted and we haven't sent
     * them directed presence, then they get to see us for the first time */
    if(item->from && !jid_search(sess->A, item->jid) && !jid_search(sess->E, item->jid)) {
        log_debug(ZONE, "forcing available to %s after roster change", jid_full(item->jid));
        pkt_router(pkt_dup(sess->pres, jid_full(item->jid), jid_full(sess->jid)));
    }
}

void pres_probe(user_t user) {
    item_t item;

    log_debug(ZONE, "full roster probe for %s", jid_user(user->jid));

    /* loop the roster, looked for trusted */
    if(xhash_iter_first(user->roster))
    do {
        xhash_iter_get(user->roster, NULL, NULL, (void *) &item);

        /* don't probe unless they trust us */
        if(item->to) {
            log_debug(ZONE, "probing %s", jid_full(item->jid));
            pkt_router(pkt_create(user->sm, "presence", "probe", jid_full(item->jid), jid_user(user->jid)));
        }
    } while(xhash_iter_next(user->roster));
}
