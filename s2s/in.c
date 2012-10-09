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

/*
 * we handle incoming connections, and the packets that arrive on them.
 *
 * action points:
 *
 *   event_STREAM - new incoming connection
 *     - create new dbconn (key stream id)
 *     - DONE
 *
 *   event_PACKET: <result from='them' to='us'>key</result> - auth request
 *     - get dbconn for this sx
 *     - if dbconn state is valid
 *       - send result: <result to='them' from='us' type='valid'/>
 *       - DONE
 *     - out_packet(s2s, <verify to='them' from='us' id='stream id'>key</verify>)
 *     - DONE
 *   
 *   event_PACKET: <verify from='them' to='us' id='123'>key</verify> - validate their key
 *     - generate dbkey: sha1(secret+remote+id)
 *     - if their key matches dbkey
 *       - send them: <verify to='them' from='us' id='123' type='valid'/>
 *     - else
 *       - send them: <verify to='them' from='us' id='123' type='invalid'/>
 *     - DONE
 *
 *   event_PACKET - they're trying to send us something
 *     - get dbconn for this sx
 *     - if dbconn state is invalid
 *       - drop packet
 *       - DONE
 *     - write packet to router
 *     - DONE
 */

/* forward decls */
static int _in_sx_callback(sx_t s, sx_event_t e, void *data, void *arg);
static void _in_result(conn_t in, nad_t nad);
static void _in_verify(conn_t in, nad_t nad);
static void _in_packet(conn_t in, nad_t nad);

int in_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    conn_t in = (conn_t) arg;
    s2s_t s2s = (s2s_t) arg;
    struct sockaddr_storage sa;
    socklen_t namelen = sizeof(sa);
    int port, nbytes, flags = 0;
    char ipport[INET6_ADDRSTRLEN + 17];

    switch(a) {
        case action_READ:
            log_debug(ZONE, "read action on fd %d", fd->fd);

            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(in->s);
                return 0;
            }

            return sx_can_read(in->s);

        case action_WRITE:
            log_debug(ZONE, "write action on fd %d", fd->fd);
            return sx_can_write(in->s);

        case action_CLOSE:
            log_debug(ZONE, "close action on fd %d", fd->fd);

            if (fd == s2s->server_fd) break;

            /* !!! logging */
            log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] disconnect, packets: %i", fd->fd, in->ip, in->port, in->packet_count);

            jqueue_push(in->s2s->dead, (void *) in->s, 0);

            /* remove from open streams hash if online, or open connections if not */
            if (in->online)
                xhash_zap(in->s2s->in, in->key);
            else {
                snprintf(ipport, INET6_ADDRSTRLEN + 16, "%s/%d", in->ip, in->port);
                xhash_zap(in->s2s->in_accept, ipport);
            }

            jqueue_push(in->s2s->dead_conn, (void *) in, 0);

            break;

        case action_ACCEPT:
            s2s = (s2s_t) arg;

            log_debug(ZONE, "accept action on fd %d", fd->fd);
            
            getpeername(fd->fd, (struct sockaddr *) &sa, &namelen);
            port = j_inet_getport(&sa);

            log_write(s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] incoming connection", fd->fd, (char *) data, port);

            /* new conn */
            in = (conn_t) calloc(1, sizeof(struct conn_st));

            in->s2s = s2s;

            strncpy(in->ip, (char *) data, INET6_ADDRSTRLEN);
            in->port = port;

            in->states = xhash_new(101);
            in->states_time = xhash_new(101);

            in->fd = fd;

            in->init_time = time(NULL);

            in->s = sx_new(s2s->sx_env, in->fd->fd, _in_sx_callback, (void *) in);
            mio_app(m, in->fd, in_mio_callback, (void *) in);

            if(s2s->stanza_size_limit != 0)
                in->s->rbytesmax = s2s->stanza_size_limit;

            /* add to incoming connections hash */
            snprintf(ipport, INET6_ADDRSTRLEN + 16, "%s/%d", in->ip, in->port);
            xhash_put(s2s->in_accept, pstrdup(xhash_pool(s2s->in_accept),ipport), (void *) in);

            flags = S2S_DB_HEADER;
#ifdef HAVE_SSL
            if(s2s->sx_ssl != NULL)
                flags |= SX_SSL_STARTTLS_OFFER;
#endif
#ifdef HAVE_LIBZ
            if(s2s->compression)
                flags |= SX_COMPRESS_OFFER;
#endif
            sx_server_init(in->s, flags);
            break;
    }

    return 0;
}

static int _in_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    conn_t in = (conn_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    int len;
    sx_error_t *sxe;
    nad_t nad;
    char ipport[INET6_ADDRSTRLEN + 17];
    jid_t from;
    int attr;

    switch(e) {
        case event_WANT_READ:
            log_debug(ZONE, "want read");
            mio_read(in->s2s->mio, in->fd);
            break;

        case event_WANT_WRITE:
            log_debug(ZONE, "want write");
            mio_write(in->s2s->mio, in->fd);
            break;

        case event_READ:
            log_debug(ZONE, "reading from %d", in->fd->fd);

            /* do the read */
            len = recv(in->fd->fd, buf->data, buf->len, 0);

            if(len < 0) {
                if(MIO_WOULDBLOCK) {
                    buf->len = 0;
                    return 0;
                }

                log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] read error: %s (%d)", in->fd->fd, in->ip, in->port, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

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
            log_debug(ZONE, "writing to %d", in->fd->fd);

            len = send(in->fd->fd, buf->data, buf->len, 0);
            if(len >= 0) {
                log_debug(ZONE, "%d bytes written", len);
                return len;
            }

            if(MIO_WOULDBLOCK)
                return 0;

            log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] write error: %s (%d)", in->fd->fd, in->ip, in->port, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

            sx_kill(s);

            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] error: %s (%s)", in->fd->fd, in->ip, in->port, sxe->generic, sxe->specific);

            break;

        case event_STREAM:
        case event_OPEN:

            log_debug(ZONE, "STREAM or OPEN event from %s port %d (id %s)", in->ip, in->port, s->id);

            /* first time, bring them online */
            if ((!in->online)||(strcmp(in->key,s->id)!=0)) { 
                log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] incoming stream online (id %s)", in->fd->fd, in->ip, in->port, s->id);

                in->online = 1;

                /* record the id */
                if (in->key != NULL) {
                   log_debug(ZONE,"adding new SSL stream id %s for stream id %s", s->id, in->key);

                   /* remove the initial (non-SSL) stream id from the in connections hash */
                   xhash_zap(in->s2s->in, in->key);
                   free((void*)in->key);
                }

                in->key = strdup(s->id);

                /* track it - add to open streams hash and remove from new connections hash */
                xhash_put(in->s2s->in, in->key, (void *) in);

                snprintf(ipport, INET6_ADDRSTRLEN + 16, "%s/%d", in->ip, in->port);
                xhash_zap(in->s2s->in_accept, ipport);
            }  

            break;

        case event_PACKET:
            /* we're counting packets */
            in->packet_count++;
            in->s2s->packet_count++;

            nad = (nad_t) data;

            /* update last packet timestamp */
            in->last_packet = time(NULL);

            /* dialback packets */
            if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) == strlen(uri_DIALBACK) && strncmp(uri_DIALBACK, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_DIALBACK)) == 0 &&
                    (in->s2s->require_tls == 0 || s->ssf > 0)) {
                /* only result and verify mean anything */
                if(NAD_ENAME_L(nad, 0) == 6) {
                    if(strncmp("result", NAD_ENAME(nad, 0), 6) == 0) {
                        _in_result(in, nad);
                        return 0;
                    }

                    if(strncmp("verify", NAD_ENAME(nad, 0), 6) == 0) {
                        _in_verify(in, nad);
                        return 0;
                    }
                }
                
                log_debug(ZONE, "unknown dialback packet, dropping it");

                nad_free(nad);
                return 0;
            }

            /*
             * not dialback, so it has to be a normal-ish jabber packet:
             *  - jabber:client or jabber:server
             *  - message, presence or iq
             *  - has to and from attributes
             */

            if(!(
                 /* must be jabber:client or jabber:server */
                 NAD_ENS(nad, 0) >= 0 &&
                 ((NAD_NURI_L(nad, NAD_ENS(nad, 0)) == strlen(uri_CLIENT) && strncmp(uri_CLIENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_CLIENT)) == 0) ||
                 (NAD_NURI_L(nad, NAD_ENS(nad, 0)) == strlen(uri_SERVER) && strncmp(uri_SERVER, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_SERVER)) == 0)) && (
                    /* can be message */
                    (NAD_ENAME_L(nad, 0) == 7 && strncmp("message", NAD_ENAME(nad, 0), 7) == 0) ||
                    /* or presence */
                    (NAD_ENAME_L(nad, 0) == 8 && strncmp("presence", NAD_ENAME(nad, 0), 8) == 0) ||
                    /* or iq */
                    (NAD_ENAME_L(nad, 0) == 2 && strncmp("iq", NAD_ENAME(nad, 0), 2) == 0)
                 ) &&
                 /* to and from required */
                 nad_find_attr(nad, 0, -1, "to", NULL) >= 0 && nad_find_attr(nad, 0, -1, "from", NULL) >= 0
               )) {
                log_debug(ZONE, "they sent us a non-jabber looking packet, dropping it");
                nad_free(nad);
                return 0;
            }

            /* perform check against whitelist */
            attr = nad_find_attr(nad, 0, -1, "from", NULL);
            if(attr < 0 || (from = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
                log_debug(ZONE, "missing or invalid from on incoming packet, attr is %d", attr);
                nad_free(nad);
                return 0;
            }

            if (in->s2s->enable_whitelist > 0 && (s2s_domain_in_whitelist(in->s2s, from->domain) == 0)) {
                log_write(in->s2s->log, LOG_NOTICE, "received a packet not from a whitelisted domain %s, dropping it", from->domain);
                jid_free(from);
                nad_free(nad);
                return 0;
            }

            jid_free(from);

            _in_packet(in, nad);
            return 0;

        case event_CLOSED:
            if (in->fd != NULL) {
            mio_close(in->s2s->mio, in->fd);
                in->fd = NULL;
            }
            return -1;
    }

    return 0;
}

/** auth requests */
static void _in_result(conn_t in, nad_t nad) {
    int attr, ns;
    jid_t from, to;
    char *rkey;
    nad_t verify;
    pkt_t pkt;
    time_t now;

    attr = nad_find_attr(nad, 0, -1, "from", NULL);
    if(attr < 0 || (from = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid from on db result packet");
        nad_free(nad);
        return;
    }

    attr = nad_find_attr(nad, 0, -1, "to", NULL);
    if(attr < 0 || (to = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid to on db result packet");
        jid_free(from);
        nad_free(nad);
        return;
    }

    rkey = s2s_route_key(NULL, to->domain, from->domain);

    log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] received dialback auth request for route '%s'", in->fd->fd, in->ip, in->port, rkey);

    /* get current state */
    if((conn_state_t) xhash_get(in->states, rkey) == conn_VALID) {
        log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] route '%s' is already valid: sending valid", in->fd->fd, in->ip, in->port, rkey);

        /* its already valid, just reply right now */
        stanza_tofrom(nad, 0);
        nad_set_attr(nad, 0, -1, "type", "valid", 5);
        nad->elems[0].icdata = nad->elems[0].itail = -1;
        nad->elems[0].lcdata = nad->elems[0].ltail = 0;

        sx_nad_write(in->s, nad);

        free(rkey);

        jid_free(from);
        jid_free(to);

        return;
    }

    /* not valid, so we need to verify */

    /* need the key */
    if(NAD_CDATA_L(nad, 0) <= 0) {
        log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] no dialback key given with db result packet", in->fd->fd, in->ip, in->port, rkey);
        free(rkey);
        nad_free(nad);
        jid_free(from);
        jid_free(to);
        return;
    }

    log_debug(ZONE, "requesting verification for route %s", rkey);

    /* set the route status to INPROGRESS and set timestamp */
    xhash_put(in->states, pstrdup(xhash_pool(in->states), rkey), (void *) conn_INPROGRESS);

    /* record the time that we set conn_INPROGRESS state */
    now = time(NULL);
    xhash_put(in->states_time, pstrdup(xhash_pool(in->states_time), rkey), (void *) now);

    free(rkey);

    /* new packet */
    verify = nad_new();
    ns = nad_add_namespace(verify, uri_DIALBACK, "db");

    nad_append_elem(verify, ns, "verify", 0);
    nad_append_attr(verify, -1, "to", from->domain);
    nad_append_attr(verify, -1, "from", to->domain);
    nad_append_attr(verify, -1, "id", in->s->id);
    nad_append_cdata(verify, NAD_CDATA(nad, 0), NAD_CDATA_L(nad, 0), 1);

    /* new packet */
    pkt = (pkt_t) calloc(1, sizeof(struct pkt_st));

    pkt->nad = verify;

    pkt->to = from;
    pkt->from = to;

    pkt->db = 1;

    /* its away */
    out_packet(in->s2s, pkt);

    nad_free(nad);
}

/** validate their key */
static void _in_verify(conn_t in, nad_t nad) {
    int attr;
    jid_t from, to;
    char *id, *dbkey, *type;
    
    attr = nad_find_attr(nad, 0, -1, "from", NULL);
    if(attr < 0 || (from = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid from on db verify packet");
        nad_free(nad);
        return;
    }

    attr = nad_find_attr(nad, 0, -1, "to", NULL);
    if(attr < 0 || (to = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid to on db verify packet");
        jid_free(from);
        nad_free(nad);
        return;
    }

    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr < 0) {
        log_debug(ZONE, "missing id on db verify packet");
        jid_free(from);
        jid_free(to);
        nad_free(nad);
        return;
    }

    if(NAD_CDATA_L(nad, 0) <= 0) {
        log_debug(ZONE, "no cdata on db verify packet");
        jid_free(from);
        jid_free(to);
        nad_free(nad);
        return;
    }

    /* extract the id */
    id = (char *) malloc(sizeof(char) * (NAD_AVAL_L(nad, attr) + 1));
    snprintf(id, NAD_AVAL_L(nad, attr) + 1, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

    /* generate a dialback key */
    dbkey = s2s_db_key(NULL, in->s2s->local_secret, from->domain, id);

    /* valid */
    if(NAD_CDATA_L(nad, 0) == strlen(dbkey) && strncmp(dbkey, NAD_CDATA(nad, 0), NAD_CDATA_L(nad, 0)) == 0) {
        log_debug(ZONE, "valid dialback key %s, verify succeeded", dbkey);
        type = "valid";
    } else {
        log_debug(ZONE, "invalid dialback key %s, verify failed", dbkey);
        type = "invalid";
    }

    log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] checking dialback verification from %s: sending %s", in->fd->fd, in->ip, in->port, from->domain, type);

    log_debug(ZONE, "letting them know");

    /* now munge the packet and send it back to them */
    stanza_tofrom(nad, 0);
    nad_set_attr(nad, 0, -1, "type", type, 0);
    nad->elems[0].icdata = nad->elems[0].itail = -1;
    nad->elems[0].lcdata = nad->elems[0].ltail = 0;

    sx_nad_write(in->s, nad);

    free(dbkey);
    free(id);

    jid_free(from);
    jid_free(to);

    return;
}

/** they're trying to send us something */
static void _in_packet(conn_t in, nad_t nad) {
    int elem, attr, ns, sns;
    jid_t from, to;
    char *rkey;
    
    attr = nad_find_attr(nad, 0, -1, "from", NULL);
    if(attr < 0 || (from = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid from on incoming packet");
        nad_free(nad);
        return;
    }

    attr = nad_find_attr(nad, 0, -1, "to", NULL);
    if(attr < 0 || (to = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid to on incoming packet");
        jid_free(from);
        nad_free(nad);
        return;
    }

    rkey = s2s_route_key(NULL, to->domain, from->domain);

    log_debug(ZONE, "received packet from %s for %s", in->key, rkey);

    /* drop packets received on routes not valid on that connection as per XMPP 8.3.10 */
    if((conn_state_t) xhash_get(in->states, rkey) != conn_VALID) {
        log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] dropping packet on unvalidated route: '%s'", in->fd->fd, in->ip, in->port, rkey);
        free(rkey);
        nad_free(nad);
        jid_free(from);
        jid_free(to);
        return;
    }

    free(rkey);

    /* its good, off to the router with it */

    log_debug(ZONE, "incoming packet on valid route, preparing it for the router");

    /* rewrite server packets into client packets */
    ns = nad_find_namespace(nad, 0, uri_SERVER, NULL);
    if(ns >= 0) {
        if(nad->elems[0].ns == ns)
            nad->elems[0].ns = nad->nss[nad->elems[0].ns].next;
        else {
            for(sns = nad->elems[0].ns; sns >= 0 && nad->nss[sns].next != ns; sns = nad->nss[sns].next);
            nad->nss[sns].next = nad->nss[nad->nss[sns].next].next;
        }
    }

    /*
     * If stanza is not in any namespace (either because we removed the
     * jabber:server namespace above or because it's in the default
     * namespace for this stream) then this packet is intended to be
     * handled by sm (and not just routed through the server), so set the
     * jabber:client namespace.
     */
    if(ns >= 0 || nad->elems[0].ns < 0) {
        ns = nad_add_namespace(nad, uri_CLIENT, NULL);
        for(elem = 0; elem < nad->ecur; elem++)
            if(nad->elems[elem].ns == ns)
                nad->elems[elem].ns = nad->nss[nad->elems[elem].ns].next;
        nad->nss[ns].next = nad->elems[0].ns;
        nad->elems[0].ns = ns;
        nad->scope = -1;
    }

    nad->elems[0].my_ns = nad->elems[0].ns;

    /* wrap up the packet */
    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);

    nad_wrap_elem(nad, 0, ns, "route");

    nad_set_attr(nad, 0, -1, "to", to->domain, 0);
    nad_set_attr(nad, 0, -1, "from", in->s2s->id, 0);   /* route is from s2s, not packet source */

    log_debug(ZONE, "sending packet to %s", to->domain);

    /* go */
    sx_nad_write(in->s2s->router, nad);

    jid_free(from);
    jid_free(to);
}
