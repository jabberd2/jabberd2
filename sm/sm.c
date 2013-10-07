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

/** @file sm/sm.c
  * @brief stream / io callbacks
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.51 $
  */

sig_atomic_t sm_lost_router = 0;

/** our master callback */
int sm_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    sm_t sm = (sm_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    sx_error_t *sxe;
    nad_t nad;
    pkt_t pkt;
    int len, ns, elem, attr;
    char *domain;

    switch(e) {
        case event_WANT_READ:
            log_debug(ZONE, "want read");
            mio_read(sm->mio, sm->fd);
            break;

        case event_WANT_WRITE:
            log_debug(ZONE, "want write");
            mio_write(sm->mio, sm->fd);
            break;

        case event_READ:
            log_debug(ZONE, "reading from %d", sm->fd->fd);

            /* do the read */
            len = recv(sm->fd->fd, buf->data, buf->len, 0);

            if (len < 0) {
                if (MIO_WOULDBLOCK) {
                    buf->len = 0;
                    return 0;
                }

                log_write(sm->log, LOG_NOTICE, "[%d] [router] read error: %s (%d)", sm->fd->fd, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

                sx_kill(s);
                
                return -1;
            }

            else if (len == 0) {
                /* they went away */
                sx_kill(s);

                return -1;
            }

            log_debug(ZONE, "read %d bytes", len);

            buf->len = len;

            return len;

        case event_WRITE:
            log_debug(ZONE, "writing to %d", sm->fd->fd);

            len = send(sm->fd->fd, buf->data, buf->len, 0);
            if (len >= 0) {
                log_debug(ZONE, "%d bytes written", len);
                return len;
            }

            if (MIO_WOULDBLOCK)
                return 0;

            log_write(sm->log, LOG_NOTICE, "[%d] [router] write error: %s (%d)", sm->fd->fd, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

            sx_kill(s);

            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            log_write(sm->log, LOG_NOTICE, "error from router: %s (%s)", sxe->generic, sxe->specific);

            if(sxe->code == SX_ERR_AUTH)
                sx_close(s);

            break;

        case event_STREAM:
            break;

        case event_OPEN:
            log_write(sm->log, LOG_NOTICE, "connection to router established");

            /* set connection attempts counter */
            sm->retry_left = sm->retry_lost;

            nad = nad_new();
            ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
            nad_append_elem(nad, ns, "bind", 0);
            nad_append_attr(nad, -1, "name", sm->id);
            log_debug(ZONE, "requesting component bind for '%s'", sm->id);
            sx_nad_write(sm->router, nad);

            if(xhash_iter_first(sm->hosts))
            do {
                xhash_iter_get(sm->hosts, (void *) &domain, &len, NULL);

                /* skip already requested SM id */
                if (strlen(sm->id) == len && strncmp(sm->id, domain, len) == 0)
                    continue;

                nad = nad_new();
                ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
                elem = nad_append_elem(nad, ns, "bind", 0);
                nad_set_attr(nad, elem, -1, "name", domain, len);
                nad_append_attr(nad, -1, "multi", "to");
                log_debug(ZONE, "requesting domain bind for '%.*s'", len, domain);
                sx_nad_write(sm->router, nad);
            
            } while(xhash_iter_next(sm->hosts));
            break;

        case event_PACKET:
            nad = (nad_t) data;

            /* drop unqualified packets */
            if (NAD_ENS(nad, 0) < 0) {
                nad_free(nad);
                return 0;
            }
            /* watch for the features packet */
            if (s->state == state_STREAM) {
                if (NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_STREAMS)
                    || strncmp(uri_STREAMS, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_STREAMS)) != 0
                    || NAD_ENAME_L(nad, 0) != 8 || strncmp("features", NAD_ENAME(nad, 0), 8) != 0) {
                    log_debug(ZONE, "got a non-features packet on an unauth'd stream, dropping");
                    nad_free(nad);
                    return 0;
                }

#ifdef HAVE_SSL
                /* starttls if we can */
                if (sm->sx_ssl != NULL && s->ssf == 0) {
                    ns = nad_find_scoped_namespace(nad, uri_TLS, NULL);
                    if (ns >= 0) {
                        elem = nad_find_elem(nad, 0, ns, "starttls", 1);
                        if (elem >= 0) {
                            if (sx_ssl_client_starttls(sm->sx_ssl, s, NULL, NULL) == 0) {
                                nad_free(nad);
                                return 0;
                            }
                            log_write(sm->log, LOG_NOTICE, "unable to establish encrypted session with router");
                        }
                    }
                }
#endif

                /* !!! pull the list of mechanisms, and choose the best one.
                 *     if there isn't an appropriate one, error and bail */

                /* authenticate */
                sx_sasl_auth(sm->sx_sasl, s, "jabberd-router", "DIGEST-MD5", sm->router_user, sm->router_pass);

                nad_free(nad);
                return 0;
            }

            /* watch for the bind response */
            if (s->state == state_OPEN && !sm->online) {
                if (NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT)
                    || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0
                    || NAD_ENAME_L(nad, 0) != 4 || strncmp("bind", NAD_ENAME(nad, 0), 4)) {
                    log_debug(ZONE, "got a packet from router, but we're not online, dropping");
                    nad_free(nad);
                    return 0;
                }

                /* catch errors */
                attr = nad_find_attr(nad, 0, -1, "error", NULL);
                if(attr >= 0) {
                    log_write(sm->log, LOG_NOTICE, "router refused bind request (%.*s)", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
                    exit(1);
                }

                log_debug(ZONE, "coming online");

                /* we're online */
                sm->online = sm->started = 1;
                log_write(sm->log, LOG_NOTICE, "%s ready for sessions", sm->id);

                nad_free(nad);
                return 0;
            }

            log_debug(ZONE, "got a packet");

            pkt = pkt_new(sm, nad);
            if (pkt == NULL) {
                log_debug(ZONE, "invalid packet, dropping");
                return 0;
            }

            /* go */
            dispatch(sm, pkt);

            return 0;

        case event_CLOSED:
            mio_close(sm->mio, sm->fd);
            sm->fd = NULL;
            return -1;
    }

    return 0;
}

int sm_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    sm_t sm = (sm_t) arg;
    int nbytes;

    switch (a) {
        case action_READ:
            log_debug(ZONE, "read action on fd %d", fd->fd);

            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(sm->router);
                return 0;
            }

            return sx_can_read(sm->router);

        case action_WRITE:
            log_debug(ZONE, "write action on fd %d", fd->fd);
            return sx_can_write(sm->router);

        case action_CLOSE:
            log_debug(ZONE, "close action on fd %d", fd->fd);
            log_write(sm->log, LOG_NOTICE, "connection to router closed");

            sm_lost_router = 1;

            /* we're offline */
            sm->online = 0;

            break;

        case action_ACCEPT:
            break;
    }

    return 0;
}

/** send a new action route */
void sm_c2s_action(sess_t dest, const char *action, const char *target) {
    nad_t nad;
    int rns, sns;

    nad = nad_new();

    rns = nad_add_namespace(nad, uri_COMPONENT, NULL);
    nad_append_elem(nad, rns, "route", 0);

    nad_append_attr(nad, -1, "to", dest->c2s);
    nad_append_attr(nad, -1, "from", dest->user->sm->id);

    sns = nad_add_namespace(nad, uri_SESSION, "sc");
    nad_append_elem(nad, sns, "session", 1);

    if (dest->c2s_id[0] != '\0')
        nad_append_attr(nad, sns, "c2s", dest->c2s_id);
    if (dest->sm_id[0] != '\0')
        nad_append_attr(nad, sns, "sm", dest->sm_id);

    nad_append_attr(nad, -1, "action", action);
    if (target != NULL)
        nad_append_attr(nad, -1, "target", target);

    log_debug(ZONE,
              "routing nad to %s from %s c2s %s s2s %s action %s target %s",
              dest->c2s, dest->user->sm->id, dest->c2s_id, dest->sm_id,
              action, target);

    sx_nad_write(dest->user->sm->router, nad);
}

/** this is gratuitous, but apache gets one, so why not? */
void sm_signature(sm_t sm, const char *str) {
    if (sm->siglen == 0) {
        snprintf(&sm->signature[sm->siglen], 2048 - sm->siglen, "%s", str);
        sm->siglen += strlen(str);
    } else {
        snprintf(&sm->signature[sm->siglen], 2048 - sm->siglen, " %s", str);
        sm->siglen += strlen(str) + 1;
    }
}

/** register a new global ns */
int sm_register_ns(sm_t sm, const char *uri) {
    int ns_idx;

    ns_idx = (int) (long) xhash_get(sm->xmlns, uri);
    if (ns_idx == 0) {
        ns_idx = xhash_count(sm->xmlns) + 2;
        xhash_put(sm->xmlns, pstrdup(xhash_pool(sm->xmlns), uri), (void *) (long) ns_idx);
    }
    xhash_put(sm->xmlns_refcount, uri, (void *) ((long) xhash_get(sm->xmlns_refcount, uri) + 1));

    return ns_idx;
}

/** unregister a global ns */
void sm_unregister_ns(sm_t sm, const char *uri) {
    int refcount = (int) (long) xhash_get(sm->xmlns_refcount, uri);
    if (refcount == 1) {
        xhash_zap(sm->xmlns, uri);
        xhash_zap(sm->xmlns_refcount, uri);
    } else if (refcount > 1) {
        xhash_put(sm->xmlns_refcount, uri, (void *) ((long) xhash_get(sm->xmlns_refcount, uri) - 1));
    }
}

/** get a globally registered ns */
int sm_get_ns(sm_t sm, const char *uri) {
    return (int) (long) xhash_get(sm->xmlns, uri);
}

// Rate limit check:  Prevent denial-of-service due to excessive database queries
// Make sure owner is responsible for the query!
int sm_storage_rate_limit(sm_t sm, const char *owner) {
    rate_t rt;
    user_t user;
    sess_t sess;
    item_t item;

    if (sm->query_rate_total == 0 || owner == NULL)
    return FALSE;

    user = xhash_get(sm->users, owner);
    if (user != NULL) {
        rt = (rate_t) xhash_get(sm->query_rates, owner);
        if (rt == NULL) {
            rt = rate_new(sm->query_rate_total, sm->query_rate_seconds, sm->query_rate_wait);
            xhash_put(sm->query_rates, pstrdup(xhash_pool(sm->query_rates), owner), (void *) rt);
            pool_cleanup(xhash_pool(sm->query_rates), (void (*)(void *)) rate_free, rt);
        }

        if(rate_check(rt) == 0) {
            log_write(sm->log, LOG_WARNING, "[%s] is being disconnected, too many database queries within %d seconds", owner, sm->query_rate_seconds);
            user = xhash_get(sm->users, owner);
            for (sess = user->sessions; sess != NULL; sess = sess->next) {
                sm_c2s_action(sess, "ended", NULL);
            }
            if(xhash_iter_first(user->roster))
                do {
                    xhash_iter_get(user->roster, NULL, NULL, (void *) &item);
                    if(item->to) {
                        pkt_router(pkt_create(user->sm, "presence", "unavailable", jid_full(item->jid), jid_full(user->jid)));
                    }
                } while(xhash_iter_next(user->roster));
            return TRUE;
            } else {
                rate_add(rt, 1);
            }
        } else {
            log_debug(ZONE, "Error: could not get user data for %s", owner);
    }
    return FALSE;
}
