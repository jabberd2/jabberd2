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

#include "s2s.h"

/** our master callback */
int s2s_router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    s2s_t s2s = (s2s_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    sx_error_t *sxe;
    nad_t nad;
    int len, ns, elem, attr, i;
    pkt_t pkt;

    switch(e) {
        case event_WANT_READ:
            log_debug(ZONE, "want read");
            mio_read(s2s->mio, s2s->fd);
            break;

        case event_WANT_WRITE:
            log_debug(ZONE, "want write");
            mio_write(s2s->mio, s2s->fd);
            break;

        case event_READ:
            log_debug(ZONE, "reading from %d", s2s->fd->fd);

            /* do the read */
            len = recv(s2s->fd->fd, buf->data, buf->len, 0);

            if(len < 0) {
                if(MIO_WOULDBLOCK) {
                    buf->len = 0;
                    return 0;
                }

                log_write(s2s->log, LOG_NOTICE, "[%d] [router] read error: %s (%d)", s2s->fd->fd, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

                sx_kill(s);
                
                return -1;
            }

            else if(len == 0) {
                /* they went away */
                sx_kill(s);

                return -1;
            }

            log_debug(ZONE, "read %d bytes", len);

            buf->len = len;

            return len;

        case event_WRITE:
            log_debug(ZONE, "writing to %d", s2s->fd->fd);

            len = send(s2s->fd->fd, buf->data, buf->len, 0);
            if(len >= 0) {
                log_debug(ZONE, "%d bytes written", len);
                return len;
            }

            if(MIO_WOULDBLOCK)
                return 0;

            log_write(s2s->log, LOG_NOTICE, "[%d] [router] write error: %s (%d)", s2s->fd->fd, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

            sx_kill(s);

            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            log_write(s2s->log, LOG_NOTICE, "error from router: %s (%s)", sxe->generic, sxe->specific);

            if(sxe->code == SX_ERR_AUTH)
                sx_close(s);

            break;

        case event_STREAM:
            break;

        case event_OPEN:
            log_write(s2s->log, LOG_NOTICE, "connection to router established");

            /* set connection attempts counter */
            s2s->retry_left = s2s->retry_lost;

            nad = nad_new();
            ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
            nad_append_elem(nad, ns, "bind", 0);
            nad_append_attr(nad, -1, "name", s2s->id);
            if(s2s->router_default)
                nad_append_elem(nad, ns, "default", 1);

            log_debug(ZONE, "requesting component bind for '%s'", s2s->id);

            sx_nad_write(s2s->router, nad);

            break;

        case event_PACKET:
            nad = (nad_t) data;

            /* drop unqualified packets */
            if(NAD_ENS(nad, 0) < 0) {
                nad_free(nad);
                return 0;
            }

            /* watch for the features packet */
            if(s->state == state_STREAM) {
                if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_STREAMS) || strncmp(uri_STREAMS, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_STREAMS)) != 0 || NAD_ENAME_L(nad, 0) != 8 || strncmp("features", NAD_ENAME(nad, 0), 8) != 0) {
                    log_debug(ZONE, "got a non-features packet on an unauth'd stream, dropping");
                    nad_free(nad);
                    return 0;
                }

#ifdef HAVE_SSL
                /* starttls if we can */
                if(s2s->sx_ssl != NULL && s2s->router_pemfile != NULL && s->ssf == 0) {
                    ns = nad_find_scoped_namespace(nad, uri_TLS, NULL);
                    if(ns >= 0) {
                        elem = nad_find_elem(nad, 0, ns, "starttls", 1);
                        if(elem >= 0) {
                            if(sx_ssl_client_starttls(s2s->sx_ssl, s, s2s->router_pemfile, s2s->router_private_key_password) == 0) {
                                nad_free(nad);
                                return 0;
                            }
                            log_write(s2s->log, LOG_NOTICE, "unable to establish encrypted session with router");
                        }
                    }
                }
#endif

                /* !!! pull the list of mechanisms, and choose the best one.
                 *     if there isn't an appropriate one, error and bail */

                /* authenticate */
                sx_sasl_auth(s2s->sx_sasl, s, "jabberd-router", "DIGEST-MD5", s2s->router_user, s2s->router_pass);

                nad_free(nad);
                return 0;
            }

            /* watch for the bind response */
            if(s->state == state_OPEN && !s2s->online) {
                if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT) || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0 || NAD_ENAME_L(nad, 0) != 4 || strncmp("bind", NAD_ENAME(nad, 0), 4)) {
                    log_debug(ZONE, "got a packet from router, but we're not online, dropping");
                    nad_free(nad);
                    return 0;
                }

                /* catch errors */
                attr = nad_find_attr(nad, 0, -1, "error", NULL);
                if(attr >= 0) {
                    log_write(s2s->log, LOG_NOTICE, "router refused bind request (%.*s)", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
                    exit(1);
                }

                log_debug(ZONE, "coming online");

                /* if we're coming online for the first time, setup listening sockets */
                if(s2s->server_fd == 0) {
                    if(s2s->local_port != 0) {
                        s2s->server_fd = mio_listen(s2s->mio, s2s->local_port, s2s->local_ip, in_mio_callback, (void *) s2s);
                        if(s2s->server_fd == NULL) {
                            log_write(s2s->log, LOG_ERR, "[%s, port=%d] failed to listen", s2s->local_ip, s2s->local_port);
                            exit(1);
                        } else
                            log_write(s2s->log, LOG_NOTICE, "[%s, port=%d] listening for connections", s2s->local_ip, s2s->local_port);
                    }
                }

                /* we're online */
                s2s->online = s2s->started = 1;
                log_write(s2s->log, LOG_NOTICE, "ready for connections", s2s->id);

                nad_free(nad);
                return 0;
            }

            log_debug(ZONE, "got a packet");

            /* sanity checks */
            if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT) || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0) {
                log_debug(ZONE, "unknown namespace, dropping packet");
                nad_free(nad);
                return 0;
            }

            if(NAD_ENAME_L(nad, 0) != 5 || strncmp("route", NAD_ENAME(nad, 0), 5) != 0) {
                log_debug(ZONE, "dropping non-route packet");
                nad_free(nad);
                return 0;
            }

            if(nad_find_attr(nad, 0, -1, "type", NULL) >= 0) {
                log_debug(ZONE, "dropping non-unicast packet");
                nad_free(nad);
                return 0;
            }

            /* packets to us */
            attr = nad_find_attr(nad, 0, -1, "to", NULL);
            if(NAD_AVAL_L(nad, attr) == strlen(s2s->id) && strncmp(s2s->id, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr)) == 0) {
                log_debug(ZONE, "dropping unknown or invalid packet for s2s component proper");
                nad_free(nad);

                return 0;
            }

            /* mangle error packet to create bounce */
            if((attr = nad_find_attr(nad, 0, -1, "error", NULL)) >= 0) {
                log_debug(ZONE, "bouncing error packet");
                elem = stanza_err_REMOTE_SERVER_NOT_FOUND;
                if(attr >= 0) {
                    for(i=0; _stanza_errors[i].code != NULL; i++)
                        if(strncmp(_stanza_errors[i].code, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr)) == 0) {
                            elem = stanza_err_BAD_REQUEST + i;
                            break;
                        }
                }
                stanza_tofrom(stanza_tofrom(stanza_error(nad, 1, elem), 1), 0);
                if( (elem = nad_find_attr(nad, 1, -1, "to", NULL)) >= 0 )
                    nad_set_attr(nad, 0, -1, "to",  NAD_AVAL(nad, elem), NAD_AVAL_L(nad, elem));
            }

            /* new packet */
            pkt = (pkt_t) calloc(1, sizeof(struct pkt_st));

            pkt->nad = nad;

            if((attr = nad_find_attr(pkt->nad, 1, -1, "from", NULL)) >= 0 && NAD_AVAL_L(pkt->nad, attr) > 0)
                pkt->from = jid_new(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
            else {
                attr = nad_find_attr(nad, 0, -1, "from", NULL);
                pkt->from = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));
            }

            if((attr = nad_find_attr(pkt->nad, 1, -1, "to", NULL)) >= 0 && NAD_AVAL_L(pkt->nad, attr) > 0)
                pkt->to = jid_new(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
            else {
                attr = nad_find_attr(nad, 0, -1, "to", NULL);
                pkt->to = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));
            }

            /* change the packet so it looks like it came to us, so the router won't reject it if we bounce it later */
            nad_set_attr(nad, 0, -1, "to", s2s->id, 0);

            /* flag dialback */
            if(NAD_NURI_L(pkt->nad, 0) == uri_DIALBACK_L && strncmp(uri_DIALBACK, NAD_NURI(pkt->nad, 0), uri_DIALBACK_L) == 0)
                pkt->db = 1;

            /* send it out */
            out_packet(s2s, pkt);

            return 0;

        case event_CLOSED:
            mio_close(s2s->mio, s2s->fd);
            s2s->fd = NULL;
            return -1;
    }

    return 0;
}

int s2s_router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    s2s_t s2s = (s2s_t) arg;
    int nbytes;

    switch(a) {
        case action_READ:
            log_debug(ZONE, "read action on fd %d", fd->fd);

            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(s2s->router);
                return 0;
            }

            return sx_can_read(s2s->router);

        case action_WRITE:
            log_debug(ZONE, "write action on fd %d", fd->fd);
            return sx_can_write(s2s->router);

        case action_CLOSE:
            log_debug(ZONE, "close action on fd %d", fd->fd);
            log_write(s2s->log, LOG_NOTICE, "connection to router closed");

            s2s_lost_router = 1;

            /* we're offline */
            s2s->online = 0;

            break;

        case action_ACCEPT:
            break;
    }

    return 0;
}
