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

/** @file sm/pkt.c
  * @brief packet abstraction
  * @author Robert Norris
  * $Date: 2005/09/09 05:34:13 $
  * $Revision: 1.35 $
  */

pkt_t pkt_error(pkt_t pkt, int err) {
    if(pkt == NULL) return NULL;

    /* if it's an error already, log, free, return */
    if(pkt->type & pkt_ERROR) {
        log_debug(ZONE, "dropping error pkt");
        pkt_free(pkt);
        return NULL;
    }

    stanza_error(pkt->nad, 1, err);

    /* update vars and attrs */
    pkt_tofrom(pkt);
    pkt->type |= pkt_ERROR;

    /* supplant route destination in case there was none in original packet */
    if(pkt->to == NULL && pkt->rto != NULL)
        pkt->to = jid_dup(pkt->rto);

    /* all done, error'd and addressed */
    log_debug(ZONE, "processed %d error pkt", err);

    return pkt;
}

/** swap a packet's to and from attributes */
pkt_t pkt_tofrom(pkt_t pkt) {
    jid_t tmp;

    if(pkt == NULL) return NULL;

    /* swap vars */
    tmp = pkt->from;
    pkt->from = pkt->to;
    pkt->to = tmp;
    tmp = pkt->rfrom;
    pkt->rfrom = pkt->rto;
    pkt->rto = tmp;

    /* update attrs */
    if(pkt->to != NULL)
        nad_set_attr(pkt->nad, 1, -1, "to", jid_full(pkt->to), 0);
    if(pkt->from != NULL)
        nad_set_attr(pkt->nad, 1, -1, "from", jid_full(pkt->from), 0);
    if(pkt->rto != NULL)
        nad_set_attr(pkt->nad, 0, -1, "to", jid_full(pkt->rto), 0);
    if(pkt->rfrom != NULL)
        nad_set_attr(pkt->nad, 0, -1, "from", jid_full(pkt->rfrom), 0);

    return pkt;
}

/** duplicate pkt, replacing addresses */
pkt_t pkt_dup(pkt_t pkt, const char *to, const char *from) {
    pkt_t pnew;

    if(pkt == NULL) return NULL;

    pnew = (pkt_t) calloc(1, sizeof(struct pkt_st));

    pnew->sm = pkt->sm;
    pnew->type = pkt->type;
    pnew->nad = nad_copy(pkt->nad);

    /* set replacement attrs */
    if(to != NULL) {
        pnew->to = jid_new(to, -1);
        nad_set_attr(pnew->nad, 1, -1, "to", jid_full(pnew->to), 0);
    } else if(pkt->to != NULL)
        pnew->to = jid_dup(pkt->to);

    if(from != NULL) {
        pnew->from = jid_new(from, -1);
        nad_set_attr(pnew->nad, 1, -1, "from", jid_full(pnew->from), 0);
    } else if(pkt->from != NULL)
        pnew->from = jid_dup(pkt->from);

    log_debug(ZONE, "duplicated packet");

    return pnew;
}

pkt_t pkt_new(sm_t sm, nad_t nad) {
    pkt_t pkt;
    int ns, attr, elem;
    char pri[20];

    log_debug(ZONE, "creating new packet");

    /* find the route */
    ns = nad_find_namespace(nad, 0, uri_COMPONENT, NULL);
    if(ns < 0) {
        log_debug(ZONE, "packet not in component namespace");
        nad_free(nad);
        return NULL;
    }

    /* create the pkt holder */
    pkt = (pkt_t) calloc(1, sizeof(struct pkt_st));

    pkt->sm = sm;
    pkt->nad = nad;

    /* routes */
    if(NAD_ENAME_L(nad, 0) == 5 && strncmp("route", NAD_ENAME(nad, 0), 5) == 0) {
        /* route element */
        if((attr = nad_find_attr(nad, 0, -1, "to", NULL)) >= 0)
            pkt->rto = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));
        if((attr = nad_find_attr(nad, 0, -1, "from", NULL)) >= 0)
            pkt->rfrom = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

        /* route type */
        attr = nad_find_attr(nad, 0, -1, "type", NULL);
        if(attr < 0)
            pkt->rtype = route_UNICAST;
        else if(NAD_AVAL_L(nad, attr) == 9 && strncmp("broadcast", NAD_AVAL(nad, attr), 9) == 0)
            pkt->rtype = route_BROADCAST;

        /* route errors */
        if(nad_find_attr(nad, 0, -1, "error", NULL) >= 0)
            pkt->rtype |= route_ERROR;

        /* client packets */
        ns = nad_find_namespace(nad, 1, uri_CLIENT, NULL);
        if(ns >= 0) {

            /* get initial addresses */
            if((attr = nad_find_attr(pkt->nad, 1, -1, "to", NULL)) >= 0 && NAD_AVAL_L(pkt->nad, attr) > 0)
                pkt->to = jid_new(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
            if((attr = nad_find_attr(pkt->nad, 1, -1, "from", NULL)) >= 0 && NAD_AVAL_L(pkt->nad, attr) > 0)
                pkt->from = jid_new(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));

            /* find type, if any */
            attr = nad_find_attr(pkt->nad, 1, -1, "type", NULL);

            /* messages are simple, only subtypes */
            if(NAD_ENAME_L(pkt->nad, 1) == 7 && strncmp("message", NAD_ENAME(pkt->nad, 1), 7) == 0) {
                pkt->type = pkt_MESSAGE;
                if(attr >= 0) {
                    if(NAD_AVAL_L(pkt->nad, attr) == 4 && strncmp("chat", NAD_AVAL(pkt->nad, attr), 4) == 0)
                        pkt->type = pkt_MESSAGE_CHAT;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 8 && strncmp("headline", NAD_AVAL(pkt->nad, attr), 8) == 0)
                        pkt->type = pkt_MESSAGE_HEADLINE;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 9 && strncmp("groupchat", NAD_AVAL(pkt->nad, attr), 9) == 0)
                        pkt->type = pkt_MESSAGE_GROUPCHAT;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 5 && strncmp("error", NAD_AVAL(pkt->nad, attr), 5) == 0)
                        pkt->type = pkt_MESSAGE | pkt_ERROR;
                }

                return pkt;
            }

            /* presence is a mixed bag, s10ns in here too */
            if(NAD_ENAME_L(pkt->nad, 1) == 8 && strncmp("presence", NAD_ENAME(pkt->nad, 1), 8) == 0) {
                pkt->type = pkt_PRESENCE;
                if(attr >= 0) {
                    if(NAD_AVAL_L(pkt->nad, attr) == 11 && strncmp("unavailable", NAD_AVAL(pkt->nad, attr), 11) == 0)
                        pkt->type = pkt_PRESENCE_UN;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 5 && strncmp("probe", NAD_AVAL(pkt->nad, attr), 5) == 0)
                        pkt->type = pkt_PRESENCE_PROBE;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 9 && strncmp("subscribe", NAD_AVAL(pkt->nad, attr), 9) == 0)
                        pkt->type = pkt_S10N;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 10 && strncmp("subscribed", NAD_AVAL(pkt->nad, attr), 10) == 0)
                        pkt->type = pkt_S10N_ED;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 11 && strncmp("unsubscribe", NAD_AVAL(pkt->nad, attr), 11) == 0)
                        pkt->type = pkt_S10N_UN;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 12 && strncmp("unsubscribed", NAD_AVAL(pkt->nad, attr), 12) == 0)
                        pkt->type = pkt_S10N_UNED;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 5 && strncmp("error", NAD_AVAL(pkt->nad, attr), 5) == 0)
                        pkt->type = pkt_PRESENCE | pkt_ERROR;
                }

                /* priority */
                if((elem = nad_find_elem(pkt->nad, 1, NAD_ENS(pkt->nad, 1), "priority", 1)) < 0)
                    return pkt;

                if(NAD_CDATA_L(pkt->nad, elem) <= 0 || NAD_CDATA_L(pkt->nad, elem) > 19)
                    return pkt;

                memcpy(pri, NAD_CDATA(pkt->nad, elem), NAD_CDATA_L(pkt->nad, elem));
                pri[NAD_CDATA_L(pkt->nad, elem)] = '\0';
                pkt->pri = atoi(pri);

                if(pkt->pri > 127) pkt->pri = 127;
                if(pkt->pri < -128) pkt->pri = -128;

                return pkt;
            }

            /* iq's are pretty easy, but also set xmlns */
            if(NAD_ENAME_L(pkt->nad, 1) == 2 && strncmp("iq", NAD_ENAME(pkt->nad, 1), 2) == 0) {
                pkt->type = pkt_IQ;
                if (attr < 0) {
                    log_write(sm->log, LOG_ERR, "dropping iq without type");
                    log_debug(ZONE, "dropping iq without type");
                    pkt_free(pkt);
                    return NULL;
                }
                if (NAD_AVAL_L(pkt->nad, attr) == 6 && strncmp("result", NAD_AVAL(pkt->nad, attr), 6) == 0) pkt->type = pkt_IQ_RESULT;
                else if (NAD_AVAL_L(pkt->nad, attr) == 5 && strncmp("error", NAD_AVAL(pkt->nad, attr), 5) == 0) pkt->type = pkt_IQ | pkt_ERROR;
                else if (NAD_AVAL_L(pkt->nad, attr) == 3 && strncmp("set", NAD_AVAL(pkt->nad, attr), 3) == 0) pkt->type = pkt_IQ_SET;
                else if (NAD_AVAL_L(pkt->nad, attr) != 3 || strncmp("get", NAD_AVAL(pkt->nad, attr), 3)) {
                    log_write(sm->log, LOG_ERR, "dropping iq with bad type \"%.*s\"", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));
                    log_debug(ZONE, "dropping iq with bad type \"%.*s\"", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));
                    pkt_free(pkt);
                    return NULL;
                }

                if(pkt->nad->ecur > 2 && (ns = NAD_ENS(pkt->nad, 2)) >= 0)
                    pkt->ns = (int) (long) xhash_getx(pkt->sm->xmlns, NAD_NURI(pkt->nad, ns), NAD_NURI_L(pkt->nad, ns));

                return pkt;
            }

            log_debug(ZONE, "unknown client namespace packet");

            return pkt;
        }

        /* sessions packets */
        ns = nad_find_namespace(nad, 1, uri_SESSION, NULL);
        if(ns >= 0) {

            /* sessions */
            if(NAD_ENAME_L(pkt->nad, 1) == 7 && strncmp("session", NAD_ENAME(pkt->nad, 1), 7) == 0) {

                /* find action */
                attr = nad_find_attr(pkt->nad, 1, -1, "action", NULL);

                if(attr >= 0) {
                    if(NAD_AVAL_L(pkt->nad, attr) == 5 && strncmp("start", NAD_AVAL(pkt->nad, attr), 5) >= 0)
                        pkt->type = pkt_SESS;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 3 && strncmp("end", NAD_AVAL(pkt->nad, attr), 3) >= 0)
                        pkt->type = pkt_SESS_END;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 6 && strncmp("create", NAD_AVAL(pkt->nad, attr), 6) >= 0)
                        pkt->type = pkt_SESS_CREATE;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 6 && strncmp("delete", NAD_AVAL(pkt->nad, attr), 6) >= 0)
                        pkt->type = pkt_SESS_DELETE;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 7 && strncmp("started", NAD_AVAL(pkt->nad, attr), 7) >= 0)
                        pkt->type = pkt_SESS | pkt_SESS_FAILED;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 5 && strncmp("ended", NAD_AVAL(pkt->nad, attr), 5) >= 0)
                        pkt->type = pkt_SESS_END | pkt_SESS_FAILED;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 7 && strncmp("created", NAD_AVAL(pkt->nad, attr), 7) >= 0)
                        pkt->type = pkt_SESS_CREATE | pkt_SESS_FAILED;
                    else if(NAD_AVAL_L(pkt->nad, attr) == 7 && strncmp("deleted", NAD_AVAL(pkt->nad, attr), 7) >= 0)
                        pkt->type = pkt_SESS_DELETE | pkt_SESS_FAILED;

                    return pkt;
                } else {
                    log_debug(ZONE, "missing action on session packet");
                    return pkt;
                }
            }

            log_debug(ZONE, "unknown session namespace packet");

            return pkt;
        }

        log_debug(ZONE, "unknown packet");

        return pkt;
    }

    /* advertisements */
    if(NAD_ENAME_L(nad, 0) == 8 && strncmp("presence", NAD_ENAME(nad, 0), 8) == 0) {
        if(nad_find_attr(nad, 0, -1, "type", "unavailable") >= 0)
            pkt->rtype = route_ADV_UN;
        else
            pkt->rtype = route_ADV;

        attr = nad_find_attr(nad, 0, -1, "from", NULL);
        if(attr >= 0)
            pkt->from = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

        return pkt;
    }

    log_debug(ZONE, "invalid component packet");

    pkt_free(pkt);
    return NULL;
}

void pkt_free(pkt_t pkt) {
    log_debug(ZONE, "freeing pkt");

    if (pkt != NULL) {
        if(pkt->rto != NULL) jid_free(pkt->rto);
        if(pkt->rfrom != NULL) jid_free(pkt->rfrom);
        if(pkt->to != NULL) jid_free(pkt->to);
        if(pkt->from != NULL) jid_free(pkt->from);
        if(pkt->nad != NULL) nad_free(pkt->nad);
        free(pkt);
    }
}

pkt_t pkt_create(sm_t sm, const char *elem, const char *type, const char *to, const char *from) {
    nad_t nad;
    int ns;

    nad = nad_new();

    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
    nad_append_elem(nad, ns, "route", 0);

    nad_add_namespace(nad, uri_SESSION, "sm");

    ns = nad_add_namespace(nad, uri_CLIENT, NULL);
    nad_append_elem(nad, ns, elem, 1);

    if(type != NULL)
        nad_append_attr(nad, -1, "type", type);
    if(to != NULL)
        nad_append_attr(nad, -1, "to", to);
    if(from != NULL)
        nad_append_attr(nad, -1, "from", from);

    return pkt_new(sm, nad);
}

/** convenience - copy the packet id from src to dest */
void pkt_id(pkt_t src, pkt_t dest) {
    int attr;

    attr = nad_find_attr(src->nad, 1, -1, "id", NULL);
    if(attr >= 0)
        nad_set_attr(dest->nad, 1, -1, "id", NAD_AVAL(src->nad, attr), NAD_AVAL_L(src->nad, attr));
    else
        nad_set_attr(dest->nad, 1, -1, "id", NULL, 0);
}

/** create an id value for new iq packets */
void pkt_id_new(pkt_t pkt) {
    char id[40];
    int i, r;

    /* as we are not using ids for tracking purposes, these can be generated randomly */
    for(i = 0; i < 40; i++) {
        r = (int) (36.0 * rand() / RAND_MAX);
        id[i] = (r >= 0 && r <= 9) ? (r + 48) : (r + 87);
    }

    nad_set_attr(pkt->nad, 1, -1, "id", id, 40);

    return;
}

void pkt_router(pkt_t pkt) {
    mod_ret_t ret;
    int ns, scan;

    if(pkt == NULL) return;

    log_debug(ZONE, "delivering pkt to router");

    if(pkt->to == NULL) {
        log_debug(ZONE, "no to address on packet, unable to route");
        pkt_free(pkt);
        return;
    }

    if(pkt->rto != NULL)
        jid_free(pkt->rto);
    pkt->rto = jid_new(pkt->to->domain, -1);

    if(pkt->rto == NULL) {
        log_debug(ZONE, "invalid to address on packet, unable to route");
        pkt_free(pkt);
        return;
    }

    nad_set_attr(pkt->nad, 0, -1, "to", pkt->rto->domain, 0);

    if(pkt->rfrom != NULL)
        jid_free(pkt->rfrom);
    pkt->rfrom = jid_new(pkt->sm->id, -1);

    if(pkt->rfrom == NULL) {
        log_debug(ZONE, "invalid from address on packet, unable to route");
        pkt_free(pkt);
        return;
    }

    nad_set_attr(pkt->nad, 0, -1, "from", pkt->rfrom->domain, 0);

    ret = mm_out_router(pkt->sm->mm, pkt);
    switch(ret) {
        case mod_HANDLED:
            return;

        case mod_PASS:
            
            /* remove sm specifics */
            ns = nad_find_namespace(pkt->nad, 1, uri_SESSION, NULL);
            /* remove them if there is no session elements in packet */
            if(ns >= 0 && nad_find_elem(pkt->nad, 0, ns, NULL, 1) < 0) {
                nad_set_attr(pkt->nad, 1, ns, "c2s", NULL, 0);
                nad_set_attr(pkt->nad, 1, ns, "sm", NULL, 0);

                /* forget about the internal namespace too */
                if(pkt->nad->elems[1].ns == ns)
                    pkt->nad->elems[1].ns = pkt->nad->nss[ns].next;

                else {
                    for(scan = pkt->nad->elems[1].ns; pkt->nad->nss[scan].next != -1 && pkt->nad->nss[scan].next != ns; scan = pkt->nad->nss[scan].next);

                    /* got it */
                    if(pkt->nad->nss[scan].next != -1)
                        pkt->nad->nss[scan].next = pkt->nad->nss[ns].next;
                }
            }

            sx_nad_write(pkt->sm->router, pkt->nad);

            /* nad already free'd, free the rest */
            pkt->nad = NULL;
            pkt_free(pkt);

            break;

        default:
            pkt_router(pkt_error(pkt, -ret));

            break;
    }
}

void pkt_sess(pkt_t pkt, sess_t sess) {
    mod_ret_t ret;

    if(pkt == NULL) return;

    log_debug(ZONE, "delivering pkt to session %s", jid_full(sess->jid));

    if(pkt->rto != NULL)
        jid_free(pkt->rto);
    pkt->rto = jid_new(sess->c2s, -1);

    if(pkt->rto == NULL) {
        log_debug(ZONE, "invalid to address on packet, unable to route");
        pkt_free(pkt);
        return;
    }

    nad_set_attr(pkt->nad, 0, -1, "to", pkt->rto->domain, 0);

    if(pkt->rfrom != NULL)
        jid_free(pkt->rfrom);
    pkt->rfrom = jid_new(pkt->sm->id, -1);

    if(pkt->rfrom == NULL) {
        log_debug(ZONE, "invalid from address on packet, unable to route");
        pkt_free(pkt);
        return;
    }

    nad_set_attr(pkt->nad, 0, -1, "from", pkt->rfrom->domain, 0);

    ret = mm_out_sess(pkt->sm->mm, sess, pkt);
    switch(ret) {
        case mod_HANDLED:
            return;

        case mod_PASS:
            sess_route(sess, pkt);

            break;

        default:
            pkt_router(pkt_error(pkt, -ret));

            break;
    }
}

/** add an x:delay stamp */
void pkt_delay(pkt_t pkt, time_t t, const char *from) {
    char timestamp[21];
    int ns, elem;

#ifdef ENABLE_SUPERSEDED
    datetime_out(t, dt_LEGACY, timestamp, 18);
    ns = nad_add_namespace(pkt->nad, uri_DELAY, NULL);
    elem = nad_insert_elem(pkt->nad, 1, ns, "x", NULL);
    nad_set_attr(pkt->nad, elem, -1, "stamp", timestamp, 0);
    if(from != NULL)
        nad_set_attr(pkt->nad, elem, -1, "from", from, 0);
    log_debug(ZONE, "added pkt XEP-0091 delay stamp %s", timestamp);
#endif
    datetime_out(t, dt_DATETIME, timestamp, 21);
    ns = nad_add_namespace(pkt->nad, uri_URN_DELAY, NULL);
    elem = nad_insert_elem(pkt->nad, 1, ns, "delay", NULL);
    nad_set_attr(pkt->nad, elem, -1, "stamp", timestamp, 0);
    if(from != NULL)
        nad_set_attr(pkt->nad, elem, -1, "from", from, 0);
    log_debug(ZONE, "added pkt XEP-0203 delay stamp %s", timestamp);
}
