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
 * we handle packets going from the router to the world, and stuff
 * that comes in on connections we initiated.
 *
 * action points:
 *
 *   out_packet(s2s, nad) - send this packet out
 *     - extract to domain
 *     - check internal resolver cache for ip/port
 *     - if not found
 *       - add packet to queue for this domain
 *       - ask resolver for name
 *       - DONE
 *     - get dbconn for this ip/port
 *     - if dbconn not found
 *       - add packet to queue for this domain
 *       - create new dbconn (key ip/port)
 *       - initiate connect to ip/port
 *       - DONE
 *     - if conn in progress (tcp)
 *       - add packet to queue for this domain
 *       - DONE
 *     - if dbconn state valid for this domain, or packet is dialback
 *       - send packet
 *       - DONE
 *     - if dbconn state invalid for this domain
 *       - bounce packet (502)
 *       - DONE
 *     - add packet to queue for this domain
 *     - if dbconn state inprogress for this domain
 *       - DONE
 *     - out_dialback(dbconn, from, to)
 *
 *   out_dialback(dbconn, from, to) - initiate dialback
 *     - generate dbkey: sha1(secret+remote+stream id)
 *     - send auth request: <result to='them' from='us'>dbkey</result>
 *     - set dbconn state for this domain to inprogress
 *     - DONE
 *
 *   out_resolve(s2s, nad) - responses from resolver
 *     - store ip/port/ttl in resolver cache
 *     - flush domain queue -> out_packet(s2s, nad)
 *     - for each packet in queue for this domain
 *     - DONE
 *
 *   event_STREAM - ip/port open
 *     - get dbconn for this sx
 *     - for each route handled by this conn, out_dialback(dbconn, from, to)
 *     - DONE
 *
 *   event_PACKET: <result from='them' to='us' type='xxx'/> - response to our auth request
 *     - get dbconn for this sx
 *     - if type valid
 *       - set dbconn state for this domain to valid
 *       - flush dbconn queue for this domain -> out_packet(s2s, pkt)
 *       - DONE
 *     - set dbconn state for this domain to invalid
 *     - bounce dbconn queue for this domain (502)
 *     - DONE
 *
 *   event_PACKET: <verify from='them' to='us' id='123' type='xxx'/> - incoming stream authenticated
 *     - get dbconn for given id
 *     - if type is valid
 *       - set dbconn state for this domain to valid
 *     - send result: <result to='them' from='us' type='xxx'/>
 *     - DONE
 */

/* forward decls */
static int _out_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
static int _out_sx_callback(sx_t s, sx_event_t e, void *data, void *arg);
static void _out_result(conn_t out, nad_t nad);
static void _out_verify(conn_t out, nad_t nad);

/** queue the packet */
static void _out_packet_queue(s2s_t s2s, pkt_t pkt) {
    jqueue_t q = (jqueue_t) xhash_get(s2s->outq, pkt->to->domain);

    if(q == NULL) {
        log_debug(ZONE, "creating new out packet queue for %s", pkt->to->domain);
        q = jqueue_new();
        xhash_put(s2s->outq, pstrdup(xhash_pool(s2s->outq), pkt->to->domain), (void *) q);
    }

    log_debug(ZONE, "queueing packet for %s", pkt->to->domain);

    jqueue_push(q, (void *) pkt, 0);
}

static void _out_dialback(conn_t out, char *rkey) {
    char *c, *dbkey;
    nad_t nad;
    int ns;
    time_t now;

    now = time(NULL);

    c = strchr(rkey, '/');
    *c = '\0';
    c++;
    
    /* kick off the dialback */
    dbkey = s2s_db_key(NULL, out->s2s->local_secret, c, out->s->id);

    nad = nad_new(out->s->nad_cache);

    /* request auth */
    ns = nad_add_namespace(nad, uri_DIALBACK, "db");
    nad_append_elem(nad, ns, "result", 0);
    nad_append_attr(nad, -1, "from", rkey);
    nad_append_attr(nad, -1, "to", c);
    nad_append_cdata(nad, dbkey, strlen(dbkey), 1);

    c--;
    *c = '/';

    log_debug(ZONE, "sending auth request for %s (key %s)", rkey, dbkey);
    log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] sending dialback auth request for route '%s'", out->fd->fd, out->ip, out->port, rkey);

    /* off it goes */
    sx_nad_write(out->s, nad);

    free(dbkey);
            
    /* we're in progress now */
    xhash_put(out->states, pstrdup(xhash_pool(out->states), rkey), (void *) conn_INPROGRESS);

    /* record the time that we set conn_INPROGRESS state */
    xhash_put(out->states_time, pstrdup(xhash_pool(out->states_time), rkey), (void *) now);
}

/** send a packet out */
void out_packet(s2s_t s2s, pkt_t pkt) {
    int ns;
    dnscache_t dns;
    nad_t nad;
    char ipport[INET6_ADDRSTRLEN + 16], *rkey;
    conn_t out;
    conn_state_t state;

    /* check resolver cache for ip/port */
    dns = xhash_get(s2s->dnscache, pkt->to->domain);
    if(dns == NULL) {
        /* new resolution */
        log_debug(ZONE, "no dns for %s, preparing for resolution", pkt->to->domain);

        dns = (dnscache_t) calloc(1, sizeof(struct dnscache_st));

        strcpy(dns->name, pkt->to->domain);

        xhash_put(s2s->dnscache, dns->name, (void *) dns);

#if 0
        /* this is good for testing */
        dns->pending = 0;
        strcpy(dns->ip, "127.0.0.1");
        dns->port = 3000;
        dns->expiry = time(NULL) + 99999999;
#endif
    }

    /* resolution in progress */
    if(dns->pending) {
        log_debug(ZONE, "pending resolution, queueing packet");

        _out_packet_queue(s2s, pkt);

        return;
    }

    /* has it expired (this is 0 for new cache objects, so they're always expired */
    if(time(NULL) > dns->expiry) {
        /* it has, queue the packet */
        _out_packet_queue(s2s, pkt);

        /* resolution required */
        log_debug(ZONE, "requesting resolution for %s", pkt->to->domain);

        nad = nad_new(s2s->router->nad_cache);

        ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
        nad_append_elem(nad, ns, "route", 0);
        nad_append_attr(nad, -1, "from", s2s->id);
        nad_append_attr(nad, -1, "to", s2s->local_resolver);

        ns = nad_add_namespace(nad, uri_RESOLVER, NULL);

        nad_append_elem(nad, ns, "resolve", 1);
        nad_append_attr(nad, -1, "type", "query");
        nad_append_attr(nad, -1, "name", pkt->to->domain);

        sx_nad_write(s2s->router, nad);

        dns->init_time = time(NULL);

        dns->pending = 1;

        return;
    }

    /* dns is valid */
    strcpy(pkt->ip, dns->ip);
    pkt->port = dns->port;

    /* generate the ip/port pair, this is the hash key for the conn */
    snprintf(ipport, INET6_ADDRSTRLEN + 16, "%s/%d", pkt->ip, pkt->port);
    out = (conn_t) xhash_get(s2s->out, ipport);

    /* new route key */
    rkey = s2s_route_key(NULL, pkt->from->domain, pkt->to->domain);

    /* if no connection, queue the packet and set up connection */
    if(out == NULL) {
        _out_packet_queue(s2s, pkt);

        /* no conn, create one */
        out = (conn_t) calloc(1, sizeof(struct conn_st));

        out->s2s = s2s;

        out->key = strdup(ipport);

        strcpy(out->ip, pkt->ip);
        out->port = pkt->port;

        out->states = xhash_new(101);
        out->states_time = xhash_new(101);

        out->routes = xhash_new(101);

        out->init_time = time(NULL);

        xhash_put(s2s->out, out->key, (void *) out);

        xhash_put(out->routes, pstrdup(xhash_pool(out->routes), rkey), (void *) 1);

        /* connect */
        log_debug(ZONE, "initiating connection to %s", ipport);

        out->fd = mio_connect(s2s->mio, pkt->port, pkt->ip, _out_mio_callback, (void *) out);

        if (out->fd == NULL) {
            log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] mio_connect error: %s (%d)", -1, out->ip, out->port, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

            /* bounce queues */
            out_bounce_queue(s2s, pkt->to->domain, stanza_err_SERVICE_UNAVAILABLE);

            xhash_zap(s2s->out, out->key);

            xhash_free(out->states);
            xhash_free(out->states_time);

            xhash_free(out->routes);

            free(out->key);
            free(out);
        } else {
            log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] outgoing connection", out->fd->fd, out->ip, out->port);

            out->s = sx_new(s2s->sx_env, out->fd->fd, _out_sx_callback, (void *) out);

#ifdef HAVE_SSL
            /* Send a stream version of 1.0 if we can do STARTTLS */
            if(out->s2s->sx_ssl != NULL && out->s2s->local_pemfile != NULL) {
                sx_client_init(out->s, S2S_DB_HEADER, uri_SERVER, pkt->to->domain, NULL, "1.0");
            } else {
                sx_client_init(out->s, S2S_DB_HEADER, uri_SERVER, NULL, NULL, NULL);
            }
#else
            sx_client_init(out->s, S2S_DB_HEADER, uri_SERVER, NULL, NULL, NULL);
#endif
        }

        free(rkey);

        return;
    }

    /* connection in progress */
    if(!out->online) {
        log_debug(ZONE, "connection in progress, queueing packet");

        _out_packet_queue(s2s, pkt);

        xhash_put(out->routes, pstrdup(xhash_pool(out->routes), rkey), (void *) 1);

        free(rkey);

        return;
    }

    /* connection state */
    state = (conn_state_t) xhash_get(out->states, rkey);

    /* valid conns or dialback packets */
    if(state == conn_VALID || pkt->db) {
        log_debug(ZONE, "writing packet for %s to outgoing conn %s", rkey, ipport);

        /* send it straight out */
        if(pkt->db) {
            /* if this is a db:verify packet, increment counter and set timestamp */
            if(NAD_ENAME_L(pkt->nad, 0) == 6 && strncmp("verify", NAD_ENAME(pkt->nad, 0), 6) == 0) {
                out->verify++;
                out->last_verify = time(NULL);
            }

            /* dialback packet */
            sx_nad_write(out->s, pkt->nad);
        } else {
            /* if the outgoing stanza has a jabber:client namespace, remove it so that the stream jabber:server namespaces will apply (XMPP 11.2.2) */
            int ns = nad_find_namespace(pkt->nad, 1, uri_CLIENT, NULL);
            if(ns >= 0) { 
               /* clear the namespaces of elem 0 (internal route element) and elem 1 (message|iq|presence) */
               pkt->nad->elems[0].ns = -1;
               pkt->nad->elems[0].my_ns = -1;
               pkt->nad->elems[1].ns = -1;
               pkt->nad->elems[1].my_ns = -1;
            }

            /* send it out */
            sx_nad_write_elem(out->s, pkt->nad, 1);
        }

        /* update timestamp */
        out->last_packet = time(NULL);

        jid_free(pkt->from);
        jid_free(pkt->to);
        free(pkt);

        free(rkey);

        return;
    }

    /* can't be handled yet, queue */
    _out_packet_queue(s2s, pkt);

    /* if dialback is in progress, then we're done for now */
    if(state == conn_INPROGRESS) {
        free(rkey);
        return;
    }

    /* this is a new route - send dialback auth request to piggyback on the existing connection */
    _out_dialback(out, rkey);

    free(rkey);
}

/** responses from the resolver */
void out_resolve(s2s_t s2s, nad_t nad) {
    int attr, port = 0, ttl = 0, npkt, i;
    jid_t name;
    char ip[INET6_ADDRSTRLEN], str[16];
    dnscache_t dns;
    jqueue_t q;
    pkt_t pkt;

    attr = nad_find_attr(nad, 1, -1, "name", NULL);
    name = jid_new(s2s->pc, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

    /* no results, resolve failed */
    if(nad->ecur == 2) {
        dns = xhash_get(s2s->dnscache, name->domain);
        xhash_zap(s2s->dnscache, name->domain);
        free(dns);

        log_write(s2s->log, LOG_NOTICE, "dns lookup for %s failed", name->domain);

        /* bounce queue */
        out_bounce_queue(s2s, name->domain, stanza_err_REMOTE_SERVER_NOT_FOUND);

        /* delete queue for domain and remove domain from queue hash */
        q = (jqueue_t) xhash_get(s2s->outq, name->domain);
        if(q != NULL)
           jqueue_free(q);
        xhash_zap(s2s->outq, name->domain);

        jid_free(name);
        nad_free(nad);

        return;
    }

    snprintf(ip, INET6_ADDRSTRLEN, "%.*s", NAD_CDATA_L(nad, 2), NAD_CDATA(nad, 2));

    attr = nad_find_attr(nad, 2, -1, "port", NULL);
    if(attr >= 0) {
        snprintf(str, 16, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
        port = atoi(str);
    }
    if(port == 0)
        port = 5269;

    attr = nad_find_attr(nad, 2, -1, "ttl", NULL);
    if(attr >= 0) {
        snprintf(str, 16, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
        ttl = atoi(str);
    }

    log_debug(ZONE, "%s resolved to %s, port %d, ttl %d", name->domain, ip, port, ttl);

    /* get the cache entry */
    dns = xhash_get(s2s->dnscache, name->domain);
    if(dns == NULL) {
        log_debug(ZONE, "weird, we never requested this");
        jid_free(name);
        nad_free(nad);
        return;
    }
    
    /* fill it out */
    strcpy(dns->ip, ip);
    dns->port = port;
    dns->expiry = time(NULL) + ttl;
    dns->pending = 0;

    q = (jqueue_t) xhash_get(s2s->outq, name->domain);
    npkt = jqueue_size(q);

    if(q == NULL || npkt == 0) {
        /* weird */
        log_debug(ZONE, "nonexistent or empty queue for domain, we're done");
        jid_free(name);
        nad_free(nad);
        return;
    }

    log_debug(ZONE, "flushing %d packets to out_packet", npkt);

    for(i = 0; i < npkt; i++) {
        pkt = jqueue_pull(q);
        if(pkt)
            out_packet(s2s, pkt);
    }

    jid_free(name);
    nad_free(nad);
}

/** mio callback for outgoing conns */
static int _out_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    conn_t out = (conn_t) arg;
    char ipport[INET6_ADDRSTRLEN + 17];
    int nbytes;

    switch(a) {
        case action_READ:
            log_debug(ZONE, "read action on fd %d", fd->fd);

            /* they did something */
            out->last_activity = time(NULL);

            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(out->s);
                return 0;
            }

            return sx_can_read(out->s);

        case action_WRITE:
            log_debug(ZONE, "write action on fd %d", fd->fd);

            /* update activity timestamp */
            out->last_activity = time(NULL);

            return sx_can_write(out->s);

        case action_CLOSE:
            log_debug(ZONE, "close action on fd %d", fd->fd);

            /* bounce queues */
            out_bounce_conn_queues(out, stanza_err_SERVICE_UNAVAILABLE);

            jqueue_push(out->s2s->dead, (void *) out->s, 0);

            /* generate the ip/port pair */
            snprintf(ipport, INET6_ADDRSTRLEN + 16, "%s/%d", out->ip, out->port);

            log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] disconnect, packets: %i", fd->fd, out->ip, out->port, out->packet_count);

            xhash_zap(out->s2s->out, ipport);

            jqueue_push(out->s2s->dead_conn, (void *) out, 0);

        case action_ACCEPT:
            break;
    }

    return 0;
}

void send_dialbacks(conn_t out)
{
  char *rkey;

  if (xhash_iter_first(out->routes)) {
       log_debug(ZONE, "sending dialback packets for %s", out->key);
       do {
            xhash_iter_get(out->routes, (const char **) &rkey, NULL);
            _out_dialback(out, rkey);
          } while(xhash_iter_next(out->routes));
  }

  return;
}

static int _out_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    conn_t out = (conn_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    int len, ns, elem, starttls = 0;
    sx_error_t *sxe;
    nad_t nad;

    switch(e) {
        case event_WANT_READ:
            log_debug(ZONE, "want read");
            mio_read(out->s2s->mio, out->fd);
            break;

        case event_WANT_WRITE:
            log_debug(ZONE, "want write");
            mio_write(out->s2s->mio, out->fd);
            break;

        case event_READ:
            log_debug(ZONE, "reading from %d", out->fd->fd);

            /* do the read */
            len = recv(out->fd->fd, buf->data, buf->len, 0);

            if(len < 0) {
                if(MIO_WOULDBLOCK) {
                    buf->len = 0;
                    return 0;
                }

                log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] read error: %s (%d)", out->fd->fd, out->ip, out->port, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

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
            log_debug(ZONE, "writing to %d", out->fd->fd);

            len = send(out->fd->fd, buf->data, buf->len, 0);
            if(len >= 0) {
                log_debug(ZONE, "%d bytes written", len);
                return len;
            }

            if(MIO_WOULDBLOCK)
                return 0;

            log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] write error: %s (%d)", out->fd->fd, out->ip, out->port, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

            sx_kill(s);

            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] error: %s (%s)", out->fd->fd, out->ip, out->port, sxe->generic, sxe->specific);

            break;

        case event_OPEN:
            log_debug(ZONE, "OPEN event for %s", out->key);
            break;

        case event_STREAM:
            /* check stream version - NULl = pre-xmpp (some jabber1 servers) */
            log_debug(ZONE, "STREAM event for %s stream version is %s", out->key, out->s->res_version);

            /* first time, bring them online */
            if(!out->online) {
                log_debug(ZONE, "outgoing conn to %s is online", out->key);

                /* if no stream version from either side, kick off dialback for each route, */
                /* otherwise wait for stream features */
                if ((out->s->res_version==NULL) || (out->s2s->sx_ssl == NULL) || (out->s2s->local_pemfile == NULL)) {
                     log_debug(ZONE, "no stream version, sending dialbacks for %s immediately", out->key);
                     out->online = 1;
                     send_dialbacks(out);
                } else
                     log_debug(ZONE, "outgoing conn to %s - waiting for STREAM features", out->key);
            }

            break;

        case event_PACKET:
            /* we're counting packets */
            out->packet_count++;
            out->s2s->packet_count++;

            nad = (nad_t) data;

            /* watch for the features packet - STARTTLS and/or SASL*/
            if ((out->s->res_version!=NULL) 
                 && NAD_NURI_L(nad, NAD_ENS(nad, 0)) == strlen(uri_STREAMS)   
                 && strncmp(uri_STREAMS, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_STREAMS)) == 0
                 && NAD_ENAME_L(nad, 0) == 8 && strncmp("features", NAD_ENAME(nad, 0), 8) == 0) {
                log_debug(ZONE, "got the stream features packet");

#ifdef HAVE_SSL
                /* starttls if we can */
                if(out->s2s->sx_ssl != NULL && out->s2s->local_pemfile != NULL && s->ssf == 0) {
                    ns = nad_find_scoped_namespace(nad, uri_TLS, NULL);
                    if(ns >= 0) {
                        elem = nad_find_elem(nad, 0, ns, "starttls", 1);
                        if(elem >= 0) {
                            log_debug(ZONE, "got STARTTLS in stream features");
                            if(sx_ssl_client_starttls(out->s2s->sx_ssl, s, out->s2s->local_pemfile) == 0) {
                                starttls = 1;
                                nad_free(nad);
                                return 0;
                            }
                            log_write(out->s2s->log, LOG_ERR, "unable to establish encrypted session with peer");
                        }
                    }
                }

                /* If we're not establishing a starttls connection, send dialbacks */
                if (!starttls) {
                     log_debug(ZONE, "No STARTTLS, sending dialbacks for %s", out->key);
                     out->online = 1;
                     send_dialbacks(out);
                }
#else
                out->online = 1;
                send_dialbacks(out);
#endif
            }


            /* we only accept dialback packets */
            if(NAD_ENS(nad, 0) < 0 || NAD_NURI_L(nad, NAD_ENS(nad, 0)) != uri_DIALBACK_L || strncmp(uri_DIALBACK, NAD_NURI(nad, NAD_ENS(nad, 0)), uri_DIALBACK_L) != 0) {
                log_debug(ZONE, "got a non-dialback packet on an outgoing conn, dropping it");
                nad_free(nad);
                return 0;
            }

            /* and then only result and verify */
            if(NAD_ENAME_L(nad, 0) == 6) {
                if(strncmp("result", NAD_ENAME(nad, 0), 6) == 0) {
                    _out_result(out, nad);
                    return 0;
                }

                if(strncmp("verify", NAD_ENAME(nad, 0), 6) == 0) {
                    _out_verify(out, nad);
                    return 0;
                }
            }
                
            log_debug(ZONE, "unknown dialback packet, dropping it");

            nad_free(nad);
            return 0;

        case event_CLOSED:
            mio_close(out->s2s->mio, out->fd);
            return -1;
    }

    return 0;
}

/** process incoming auth responses */
static void _out_result(conn_t out, nad_t nad) {
    int attr;
    jid_t from, to;
    char *rkey, *c;
    jqueue_t q;
    int npkt, i;
    pkt_t pkt;

    attr = nad_find_attr(nad, 0, -1, "from", NULL);
    if(attr < 0 || (from = jid_new(out->s2s->pc, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid from on db result packet");
        nad_free(nad);
        return;
    }

    attr = nad_find_attr(nad, 0, -1, "to", NULL);
    if(attr < 0 || (to = jid_new(out->s2s->pc, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid to on db result packet");
        jid_free(from);
        nad_free(nad);
        return;
    }

    rkey = s2s_route_key(NULL, to->domain, from->domain);

    /* key is valid */
    if(nad_find_attr(nad, 0, -1, "type", "valid") >= 0) {
        log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] outgoing route '%s' is now valid%s", out->fd->fd, out->ip, out->port, rkey, out->s->ssf ? ", TLS negotiated" : "");

        xhash_put(out->states, pstrdup(xhash_pool(out->states), rkey), (void *) conn_VALID);    /* !!! small leak here */

        log_debug(ZONE, "%s valid, flushing queue", rkey);

        /* to domain */
        c = strchr(rkey, '/');
        c++;

        /* flush the queue */
        q = (jqueue_t) xhash_get(out->s2s->outq, c);
        if(q == NULL || (npkt = jqueue_size(q)) == 0) {
            /* weird */
            log_debug(ZONE, "nonexistent or empty queue for domain, we're done");
            free(rkey);
            jid_free(from);
            jid_free(to);
            nad_free(nad);
            return;
        }

        log_debug(ZONE, "flushing %d packets to out_packet", npkt);

        for(i = 0; i < npkt; i++) {
            pkt = jqueue_pull(q);
            out_packet(out->s2s, pkt);
        }

        free(rkey);

        jid_free(from);
        jid_free(to);

        nad_free(nad);

        return;
    }

    /* invalid */
    log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] outgoing route '%s' is now invalid", out->fd->fd, out->ip, out->port, rkey);

    /* close connection */
    log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] closing connection", out->fd->fd, out->ip, out->port);

    /* report stream error */
    sx_error(out->s, stream_err_INVALID_ID, "dialback negotiation failed");

    /* close the stream */
    sx_close(out->s);

    free(rkey);

    jid_free(from);
    jid_free(to);

    nad_free(nad);
}

/** incoming stream authenticated */
static void _out_verify(conn_t out, nad_t nad) {
    int attr, ns;
    jid_t from, to;
    conn_t in;
    char *rkey;
    int valid;
    
    attr = nad_find_attr(nad, 0, -1, "from", NULL);
    if(attr < 0 || (from = jid_new(out->s2s->pc, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid from on db verify packet");
        nad_free(nad);
        return;
    }

    attr = nad_find_attr(nad, 0, -1, "to", NULL);
    if(attr < 0 || (to = jid_new(out->s2s->pc, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
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

    /* get the incoming conn */
    in = xhash_getx(out->s2s->in, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));
    if(in == NULL) {
        log_debug(ZONE, "got a verify for incoming conn %.*s, but it doesn't exist, dropping the packet", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
        jid_free(from);
        jid_free(to);
        nad_free(nad);
        return;
    }

    rkey = s2s_route_key(NULL, to->domain, from->domain);

    attr = nad_find_attr(nad, 0, -1, "type", "valid");
    if(attr >= 0) {
        xhash_put(in->states, pstrdup(xhash_pool(in->states), rkey), (void *) conn_VALID);
        log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] incoming route '%s' is now valid%s", in->fd->fd, in->ip, in->port, rkey, in->s->ssf ? ", TLS negotiated" : "");
        valid = 1;
    } else {
        log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] incoming route '%s' is now invalid", in->fd->fd, in->ip, in->port, rkey);
        valid = 0;
    }

    free(rkey);

    nad_free(nad);

    /* decrement outstanding verify counter */
    --out->verify;

    /* let them know what happened */
    nad = nad_new(in->s->nad_cache);

    ns = nad_add_namespace(nad, uri_DIALBACK, "db");
    nad_append_elem(nad, ns, "result", 0);
    nad_append_attr(nad, -1, "to", from->domain);
    nad_append_attr(nad, -1, "from", to->domain);
    nad_append_attr(nad, -1, "type", valid ? "valid" : "invalid");

    /* off it goes */
    sx_nad_write(in->s, nad);

    /* if invalid, close the stream */
    if (!valid) {
        /* generate stream error */
        sx_error(in->s, stream_err_INVALID_ID, "dialback negotiation failed");

        /* close the incoming stream */
        sx_close(in->s);
    }

    jid_free(from);
    jid_free(to);
}

/* bounce all packets in the queue for domain */
int out_bounce_queue(s2s_t s2s, const char *domain, int err)
{
  jqueue_t q;
  pkt_t pkt;
  int pktcount = 0;

  q = xhash_get(s2s->outq, domain);
  if(q == NULL)
     return 0;

  while((pkt = jqueue_pull(q)) != NULL) {
     if(pkt->nad->ecur > 1 && NAD_NURI_L(pkt->nad, NAD_ENS(pkt->nad, 1)) == strlen(uri_CLIENT) && strncmp(NAD_NURI(pkt->nad, NAD_ENS(pkt->nad, 1)), uri_CLIENT, strlen(uri_CLIENT)) == 0) {
         sx_nad_write(s2s->router, stanza_tofrom(stanza_tofrom(stanza_error(pkt->nad, 1, err), 1), 0));
         pktcount++;
     }
     else
         nad_free(pkt->nad);

     jid_free(pkt->to);
     jid_free(pkt->from);
     free(pkt);
  }

  return pktcount;
}

int out_bounce_conn_queues(conn_t out, int err)
{
  char *c;
  char *rkey;

  /* bounce queues for all domains handled by this connection - iterate through routes */
  if (xhash_iter_first(out->routes)) {
       do {
             xhash_iter_get(out->routes, (const char **) &rkey, NULL);
             c = strchr(rkey, '/');
             c++;
             out_bounce_queue(out->s2s, c, err);
          } while(xhash_iter_next(out->routes));
  }

  return 0;
}
