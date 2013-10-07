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

#define _GNU_SOURCE
#include <string.h>

#include "s2s.h"

#include <idna.h>

/*
 * we handle packets going from the router to the world, and stuff
 * that comes in on connections we initiated.
 *
 * action points:
 *
 *   out_packet(s2s, nad) - send this packet out
 *     - extract to domain
 *     - get dbconn for this domain using out_route
 *       - if dbconn not available bounce packet
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
 *   out_route(s2s, route, out, allow_bad)
 *     - if dbconn not found
 *       - check internal resolver cache for domain
 *       - if not found
 *         - ask resolver for name
 *         - DONE
 *       - if outgoing ip/port is to be reused
 *         - get dbconn for any valid ip/port
 *         - if dbconn not found
 *            - create new dbconn
 *            - initiate connect to ip/port
 *            - DONE
 *       - create new dbconn
 *       - initiate connect to ip/port
 *       - DONE
 *
 *   out_dialback(dbconn, from, to) - initiate dialback
 *     - generate dbkey: sha1(secret+remote+stream id)
 *     - send auth request: <result to='them' from='us'>dbkey</result>
 *     - set dbconn state for this domain to inprogress
 *     - DONE
 *
 *   out_resolve(s2s, query) - responses from resolver
 *     - store ip/port/ttl in resolver cache
 *     - flush domain queue -> out_packet(s2s, domain)
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
static void _dns_result_aaaa(struct dns_ctx *ctx, struct dns_rr_a6 *result, void *data);
static void _dns_result_a(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data);

/** queue the packet */
static void _out_packet_queue(s2s_t s2s, pkt_t pkt) {
    char *rkey = s2s_route_key(NULL, pkt->from->domain, pkt->to->domain);
    jqueue_t q = (jqueue_t) xhash_get(s2s->outq, rkey);

    if(q == NULL) {
        log_debug(ZONE, "creating new out packet queue for '%s'", rkey);
        q = jqueue_new();
        q->key = rkey;
        xhash_put(s2s->outq, q->key, (void *) q);
    } else {
        free(rkey);
    }

    log_debug(ZONE, "queueing packet for '%s'", q->key);

    jqueue_push(q, (void *) pkt, 0);
}

static void _out_dialback(conn_t out, const char *rkey, int rkeylen) {
    char *c, *dbkey, *tmp;
    nad_t nad;
    int elem, ns;
    int from_len, to_len;
    time_t now;

    now = time(NULL);

    c = memchr(rkey, '/', rkeylen);
    from_len = c - rkey;
    c++;
    to_len = rkeylen - (c - rkey);

    /* kick off the dialback */
    tmp = strndup(c, to_len);
    dbkey = s2s_db_key(NULL, out->s2s->local_secret, tmp, out->s->id);
    free(tmp);

    nad = nad_new();

    /* request auth */
    ns = nad_add_namespace(nad, uri_DIALBACK, "db");
    elem = nad_append_elem(nad, ns, "result", 0);
    nad_set_attr(nad, elem, -1, "from", rkey, from_len);
    nad_set_attr(nad, elem, -1, "to", c, to_len);
    nad_append_cdata(nad, dbkey, strlen(dbkey), 1);

    log_debug(ZONE, "sending auth request for %.*s (key %s)", rkeylen, rkey, dbkey);
    log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] sending dialback auth request for route '%.*s'", out->fd->fd, out->ip, out->port, rkeylen, rkey);

    /* off it goes */
    sx_nad_write(out->s, nad);

    free(dbkey);

    /* we're in progress now */
    xhash_put(out->states, pstrdupx(xhash_pool(out->states), rkey, rkeylen), (void *) conn_INPROGRESS);

    /* record the time that we set conn_INPROGRESS state */
    xhash_put(out->states_time, pstrdupx(xhash_pool(out->states_time), rkey, rkeylen), (void *) now);
}

void _out_dns_mark_bad(conn_t out) {
    if (out->s2s->dns_bad_timeout > 0) {
        dnsres_t bad;
        char *ipport;

        /* mark this host as bad */
        ipport = dns_make_ipport(out->ip, out->port);
        bad = xhash_get(out->s2s->dns_bad, ipport);
        if (bad == NULL) {
            bad = (dnsres_t) calloc(1, sizeof(struct dnsres_st));
            bad->key = ipport;
            xhash_put(out->s2s->dns_bad, ipport, bad);
        }
        bad->expiry = time(NULL) + out->s2s->dns_bad_timeout;
    }
}

int dns_select(s2s_t s2s, char *ip, int *port, time_t now, dnscache_t dns, int allow_bad) {
    /* list of results */
    dnsres_t l_reuse[DNS_MAX_RESULTS];
    dnsres_t l_aaaa[DNS_MAX_RESULTS];
    dnsres_t l_a[DNS_MAX_RESULTS];
    dnsres_t l_bad[DNS_MAX_RESULTS];
    /* running weight sums of results */
    int rw_reuse[DNS_MAX_RESULTS];
    int rw_aaaa[DNS_MAX_RESULTS];
    int rw_a[DNS_MAX_RESULTS];
    int s_reuse = 0, s_aaaa = 0, s_a = 0, s_bad = 0; /* count */
    int p_reuse = 0, p_aaaa = 0, p_a = 0; /* list prio */
    int wt_reuse = 0, wt_aaaa = 0, wt_a = 0; /* weight total */
    int c_expired_good = 0;
    union xhashv xhv;
    dnsres_t res;
    const char *ipport;
    int ipport_len;
    char *c;
    int c_len;
    char *tmp;

    /* for all results:
     * - if not expired
     *   - put highest priority reuseable addrs into list1
     *   - put highest priority ipv6 addrs into list2
     *   - put highest priority ipv4 addrs into list3
     *   - put bad addrs into list4
     * - pick weighted random entry from first non-empty list
     */

    if (dns->results == NULL) {
        log_debug(ZONE, "negative cache entry for '%s'", dns->name);
        return -1;
    }
    log_debug(ZONE, "selecting DNS result for '%s'", dns->name);

    xhv.dnsres_val = &res;
    if (xhash_iter_first(dns->results)) {
        dnsres_t bad = NULL;
        do {
            xhash_iter_get(dns->results, (const char **) &ipport, &ipport_len, xhv.val);

            if (s2s->dns_bad_timeout > 0)
                bad = xhash_getx(s2s->dns_bad, ipport, ipport_len);

            if (now > res->expiry) {
                /* good host? */
                if (bad == NULL)
                    c_expired_good++;

                log_debug(ZONE, "host '%s' expired", res->key);
                continue;
            } else if (bad != NULL && !(now > bad->expiry)) {
                /* bad host (connection failure) */
                l_bad[s_bad++] = res;

                log_debug(ZONE, "host '%s' bad", res->key);
            } else if (s2s->out_reuse && xhash_getx(s2s->out_host, ipport, ipport_len) != NULL) {
                /* existing connection */
                log_debug(ZONE, "host '%s' exists", res->key);
                if (s_reuse == 0 || p_reuse > res->prio) {
                    p_reuse = res->prio;
                    s_reuse = 0;
                    wt_reuse = 0;

                    log_debug(ZONE, "reset prio list, using prio %d", res->prio);
                }
                if (res->prio <= p_reuse) {
                    l_reuse[s_reuse] = res;
                    wt_reuse += res->weight;
                    rw_reuse[s_reuse] = wt_reuse;
                    s_reuse++;

                    log_debug(ZONE, "added host with weight %d (%d), running weight %d",
                        (res->weight >> 8), res->weight, wt_reuse);
                } else {
                    log_debug(ZONE, "ignored host with prio %d", res->prio);
                }
            } else if (memchr(ipport, ':', ipport_len) != NULL) {
                /* ipv6 */
                log_debug(ZONE, "host '%s' IPv6", res->key);
                if (s_aaaa == 0 || p_aaaa > res->prio) {
                    p_aaaa = res->prio;
                    s_aaaa = 0;
                    wt_aaaa = 0;

                    log_debug(ZONE, "reset prio list, using prio %d", res->prio);
                }
                if (res->prio <= p_aaaa) {
                    l_aaaa[s_aaaa] = res;
                    wt_aaaa += res->weight;
                    rw_aaaa[s_aaaa] = wt_aaaa;
                    s_aaaa++;

                    log_debug(ZONE, "added host with weight %d (%d), running weight %d",
                        (res->weight >> 8), res->weight, wt_aaaa);
                } else {
                    log_debug(ZONE, "ignored host with prio %d", res->prio);
                }
            } else {
                /* ipv4 */
                log_debug(ZONE, "host '%s' IPv4", res->key);
                if (s_a == 0 || p_a > res->prio) {
                    p_a = res->prio;
                    s_a = 0;
                    wt_a = 0;

                    log_debug(ZONE, "reset prio list, using prio %d", res->prio);
                }
                if (res->prio <= p_a) {
                    l_a[s_a] = res;
                    wt_a += res->weight;
                    rw_a[s_a] = wt_a;
                    s_a++;

                    log_debug(ZONE, "added host with weight %d (%d), running weight %d",
                        (res->weight >> 8), res->weight, wt_a);
                } else {
                    log_debug(ZONE, "ignored host with prio %d", res->prio);
                }
            }
        } while(xhash_iter_next(dns->results));
    }

    /* pick a result at weighted random (RFC 2782)
     * all weights are guaranteed to be >= 16 && <= 16776960
     * (assuming max 50 hosts, the total/running sums won't exceed 2^31)
     */
    ipport = NULL;
    if (s_reuse > 0) {
        int i, r;

        log_debug(ZONE, "using existing hosts, total weight %d", wt_reuse);
        assert((wt_reuse + 1) > 0);

        r = rand() % (wt_reuse + 1);
        log_debug(ZONE, "random number %d", r);

        for (i = 0; i < s_reuse; i++)
            if (rw_reuse[i] >= r) {
                log_debug(ZONE, "selected host '%s', running weight %d",
                    l_reuse[i]->key, rw_reuse[i]);

                ipport = l_reuse[i]->key;
                break;
            }
    } else if (s_aaaa > 0 && (s_a == 0 || p_aaaa <= p_a)) {
        int i, r;

        log_debug(ZONE, "using IPv6 hosts, total weight %d", wt_aaaa);
        assert((wt_aaaa + 1) > 0);

        r = rand() % (wt_aaaa + 1);
        log_debug(ZONE, "random number %d", r);

        for (i = 0; i < s_aaaa; i++)
            if (rw_aaaa[i] >= r) {
                log_debug(ZONE, "selected host '%s', running weight %d",
                    l_aaaa[i]->key, rw_aaaa[i]);

                ipport = l_aaaa[i]->key;
                break;
            }
    } else if (s_a > 0) {
        int i, r;

        log_debug(ZONE, "using IPv4 hosts, total weight %d", wt_a);
        assert((wt_a + 1) > 0);

        r = rand() % (wt_a + 1);
        log_debug(ZONE, "random number %d", r);

        for (i = 0; i < s_a; i++)
            if (rw_a[i] >= r) {
                log_debug(ZONE, "selected host '%s', running weight %d",
                    l_a[i]->key, rw_a[i]);

                ipport = l_a[i]->key;
                break;
            }
    } else if (s_bad > 0) {
        ipport = l_bad[rand() % s_bad]->key;

        log_debug(ZONE, "using bad hosts, allow_bad=%d", allow_bad);

        /* there are expired good hosts, expire cache immediately */
        if (c_expired_good > 0) {
            log_debug(ZONE, "expiring this DNS cache entry, %d expired hosts",
                c_expired_good);

            dns->expiry = 0;
        }

        if (!allow_bad)
            return -1;
    }

    /* results cannot all expire before the collection does */
    assert(ipport != NULL);

    /* copy the ip and port to the packet */
    ipport_len = strlen(ipport);
    c = strchr(ipport, '/');
    strncpy(ip, ipport, c-ipport);
    ip[c-ipport] = '\0';
    c++;
    c_len = ipport_len - (c - ipport);
    tmp = strndup(c, c_len);
    *port = atoi(tmp);
    free(tmp);

    return 0;
}

/** find/make a connection for a route */
int out_route(s2s_t s2s, const char *route, int routelen, conn_t *out, int allow_bad) {
    dnscache_t dns;
    char ipport[INET6_ADDRSTRLEN + 16], *dkey, *c;
    time_t now;
    int reuse = 0;
    char ip[INET6_ADDRSTRLEN] = {0};
    int port, c_len, from_len;

    c = memchr(route, '/', routelen);
    from_len = c - route;
    c++;
    c_len = routelen - (c - route);
    dkey = strndup(c, c_len);

    log_debug(ZONE, "trying to find connection for '%s'", dkey);
    *out = (conn_t) xhash_get(s2s->out_dest, dkey);
    if(*out == NULL) {
        log_debug(ZONE, "connection for '%s' not found", dkey);

        /* check resolver cache for ip/port */
        dns = xhash_get(s2s->dnscache, dkey);
        if(dns == NULL) {
            /* new resolution */
            log_debug(ZONE, "no dns for %s, preparing for resolution", dkey);

            dns = (dnscache_t) calloc(1, sizeof(struct dnscache_st));

            strcpy(dns->name, dkey);

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
            log_debug(ZONE, "pending resolution");
            free(dkey);
            return 0;
        }

        /* has it expired (this is 0 for new cache objects, so they're always expired */
        now = time(NULL); /* each entry must be expired no earlier than the collection */
        if(now > dns->expiry) {
            /* resolution required */
            log_debug(ZONE, "requesting resolution for %s", dkey);

            dns->init_time = time(NULL);
            dns->pending = 1;

            dns_resolve_domain(s2s, dns);
            free(dkey);
            return 0;
        }

        /* dns is valid */
        if (dns_select(s2s, ip, &port, now, dns, allow_bad)) {
            /* failed to find anything acceptable */
            free(dkey);
            return -1;
        }

        /* re-request resolution if dns_select expired the data */
        if (now > dns->expiry) {
            /* resolution required */
            log_debug(ZONE, "requesting resolution for %s", dkey);

            dns->init_time = time(NULL);
            dns->pending = 1;

            dns_resolve_domain(s2s, dns);

            free(dkey);
            return 0;
        }

        /* generate the ip/port pair, this is the hash key for the conn */
        snprintf(ipport, INET6_ADDRSTRLEN + 16, "%s/%d", ip, port);

        /* try to re-use an existing connection */
        if (s2s->out_reuse)
            *out = (conn_t) xhash_get(s2s->out_host, ipport);

        if (*out != NULL) {
            log_write(s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] using connection for '%s'", (*out)->fd->fd, (*out)->ip, (*out)->port, dkey);

            /* associate existing connection with domain */
            xhash_put(s2s->out_dest, s2s->out_reuse ? pstrdup(xhash_pool((*out)->routes), dkey) : dkey, (void *) *out);

            reuse = 1;
        } else{
            /* no conn, create one */
            *out = (conn_t) calloc(1, sizeof(struct conn_st));

            (*out)->s2s = s2s;

            (*out)->key = strdup(ipport);
            if (s2s->out_reuse)
                (*out)->dkey = NULL;
            else
                (*out)->dkey = dkey;

            strcpy((*out)->ip, ip);
            (*out)->port = port;

            (*out)->states = xhash_new(101);
            (*out)->states_time = xhash_new(101);

            (*out)->routes = xhash_new(101);

            (*out)->init_time = time(NULL);

            if (s2s->out_reuse)
                xhash_put(s2s->out_host, (*out)->key, (void *) *out);
            xhash_put(s2s->out_dest, s2s->out_reuse ? pstrdup(xhash_pool((*out)->routes), dkey) : dkey, (void *) *out);

            xhash_put((*out)->routes, pstrdupx(xhash_pool((*out)->routes), route, routelen), (void *) 1);

            /* connect */
            log_debug(ZONE, "initiating connection to %s", ipport);

            /* APPLE: multiple origin_ips may be specified; use IPv6 if possible or otherwise IPv4 */
            int ip_is_v6 = 0;
            if (strchr(ip, ':') != NULL)
                ip_is_v6 = 1;
            int i;
            for (i = 0; i < s2s->origin_nips; i++) {
                // only bother with mio_connect if the src and dst IPs are of the same type
                if ((ip_is_v6 && (strchr(s2s->origin_ips[i], ':') != NULL)) ||          // both are IPv6
                            (! ip_is_v6 && (strchr(s2s->origin_ips[i], ':') == NULL)))  // both are IPv4
                    (*out)->fd = mio_connect(s2s->mio, port, ip, s2s->origin_ips[i], _out_mio_callback, (void *) *out);

                if ((*out)->fd != NULL) break;
            }

            if ((*out)->fd == NULL) {
                log_write(s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] mio_connect error: %s (%d)", -1, (*out)->ip, (*out)->port, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

                _out_dns_mark_bad(*out);

                if (s2s->out_reuse)
                   xhash_zap(s2s->out_host, (*out)->key);
                xhash_zap(s2s->out_dest, dkey);

                xhash_free((*out)->states);
                xhash_free((*out)->states_time);

                xhash_free((*out)->routes);

                free((void*)(*out)->key);
                free((void*)(*out)->dkey);
                free(*out);
                *out = NULL;

                /* try again without allowing bad hosts */
                return out_route(s2s, route, routelen, out, 0);
            } else {
                log_write(s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] outgoing connection for '%s'", (*out)->fd->fd, (*out)->ip, (*out)->port, dkey);

                (*out)->s = sx_new(s2s->sx_env, (*out)->fd->fd, _out_sx_callback, (void *) *out);

#ifdef HAVE_SSL
                /* Send a stream version of 1.0 if we can do STARTTLS */
                if(s2s->sx_ssl != NULL) {
                    sx_client_init((*out)->s, S2S_DB_HEADER, uri_SERVER, dkey, pstrdupx(xhash_pool((*out)->routes), route, from_len), "1.0");
                } else {
                    sx_client_init((*out)->s, S2S_DB_HEADER, uri_SERVER, NULL, NULL, NULL);
                }
#else
                sx_client_init((*out)->s, S2S_DB_HEADER, uri_SERVER, NULL, NULL, NULL);
#endif
                /* dkey is now used by the hash table */
                return 0;
            }
        }
    } else {
        log_debug(ZONE, "connection for '%s' found (%d %s/%d)", dkey, (*out)->fd->fd, (*out)->ip, (*out)->port);
    }

    /* connection in progress, or re-using connection: add to routes list */
    if (!(*out)->online || reuse) {
        if (xhash_getx((*out)->routes, route, routelen) == NULL)
            xhash_put((*out)->routes, pstrdupx(xhash_pool((*out)->routes), route, routelen), (void *) 1);
    }

    free(dkey);
    return 0;
}

void out_pkt_free(pkt_t pkt)
{
    nad_free(pkt->nad);
    jid_free(pkt->from);
    jid_free(pkt->to);
    free(pkt);
}

/** send a packet out */
int out_packet(s2s_t s2s, pkt_t pkt) {
    char *rkey;
    int rkeylen;
    conn_t out;
    conn_state_t state;
    int ret;

    /* perform check against whitelist */
    if (s2s->enable_whitelist > 0 &&
            (pkt->to->domain != NULL) &&
            (s2s_domain_in_whitelist(s2s, pkt->to->domain) == 0)) {
        log_write(s2s->log, LOG_NOTICE, "sending a packet to domain not in the whitelist, dropping it");
        if (pkt->to != NULL)
            jid_free(pkt->to);
        if (pkt->from != NULL)
            jid_free(pkt->from);
        if (pkt->nad != NULL)
            nad_free(pkt->nad);
        free(pkt);

        return 0;
    }

    /* new route key */
    rkey = s2s_route_key(NULL, pkt->from->domain, pkt->to->domain);
    rkeylen = strlen(rkey);

    /* get a connection */
    ret = out_route(s2s, rkey, rkeylen, &out, 1);

    if (out == NULL) {
        /* connection not available, queue packet */
        _out_packet_queue(s2s, pkt);

        /* check if out_route was successful in attempting a connection */
        if (ret) {
            /* bounce queue */
            out_bounce_route_queue(s2s, rkey, rkeylen, stanza_err_SERVICE_UNAVAILABLE);

            free(rkey);
            return -1;
        }

        free(rkey);
        return 0;
    }

    /* connection in progress */
    if(!out->online) {
        log_debug(ZONE, "connection in progress, queueing packet");

        _out_packet_queue(s2s, pkt);

        free(rkey);
        return 0;
    }

    /* connection state */
    state = (conn_state_t) xhash_get(out->states, rkey);

    /* valid conns or dialback packets */
    if(state == conn_VALID || pkt->db) {
        log_debug(ZONE, "writing packet for %s to outgoing conn %d", rkey, out->fd->fd);

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
        return 0;
    }

    /* can't be handled yet, queue */
    _out_packet_queue(s2s, pkt);

    /* if dialback is in progress, then we're done for now */
    if(state == conn_INPROGRESS) {
        free(rkey);
        return 0;
    }

    /* this is a new route - send dialback auth request to piggyback on the existing connection */
    if (out->s2s->require_tls == 0 || out->s->ssf > 0) {
    _out_dialback(out, rkey, rkeylen);
    }
    free(rkey);
    return 0;
}

char *dns_make_ipport(const char *host, int port) {
    char *c;
    assert(port > 0 && port < 65536);

    c = (char *) malloc(strlen(host) + 7);
    sprintf(c, "%s/%d", host, port);
    return c;
}

static void _dns_add_result(dnsquery_t query, const char *ip, int port, int prio, int weight, unsigned int ttl) {
    char *ipport = dns_make_ipport(ip, port);
    dnsres_t res = xhash_get(query->results, ipport);

    if (res != NULL) {
        if (prio < res->prio)
            res->prio = prio;

        if (prio < res->prio) {
            /* duplicate host at lower prio - reset weight */
            res->weight = weight;
        } else if (prio == res->prio) {
            /* duplicate host at same prio - add to weight */
            res->weight += weight;
            if (res->weight > (65535 << 8))
                res->weight = (65535 << 8);
        }

        if (ttl > res->expiry)
            res->expiry = ttl;

        if (ttl > query->expiry)
            query->expiry = ttl;

        log_debug(ZONE, "dns result updated for %s@%p: %s (%d/%d/%d)", query->name, query, ipport,
            res->prio, (res->weight >> 8), res->expiry);
    } else if (xhash_count(query->results) < DNS_MAX_RESULTS) {
        res = pmalloc(xhash_pool(query->results), sizeof(struct dnsres_st));
        res->key = pstrdup(xhash_pool(query->results), ipport);
        res->prio = prio;
        res->weight = weight;
        res->expiry = ttl;

        if (ttl > query->expiry)
            query->expiry = ttl;

        xhash_put(query->results, res->key, res);

        log_debug(ZONE, "dns result added for %s@%p: %s (%d/%d/%d)", query->name, query, ipport,
            res->prio, (res->weight >> 8), res->expiry);
    } else {
        log_debug(ZONE, "dns result ignored for %s@%p: %s (%d/%d/%d)", query->name, query, ipport,
            prio, (weight >> 8), ttl);
    }

    free(ipport);
}

static void _dns_add_host(dnsquery_t query, const char *ip, int port, int prio, int weight, unsigned int ttl) {
    char *ipport = dns_make_ipport(ip, port);
    dnsres_t res = xhash_get(query->hosts, ipport);

    /* update host weights:
     *  RFC 2482 "In the presence of records containing weights greater
     *  than 0, records with weight 0 should have a very small chance of
     *  being selected."
     * 0       -> 16
     * 1-65535 -> 256-16776960
     */
    if (weight == 0)
        weight = 1 << 4;
    else
        weight <<= 8;

    if (res != NULL) {
        if (prio < res->prio)
            res->prio = prio;

        if (prio < res->prio) {
            /* duplicate host at lower prio - reset weight */
            res->weight = weight;
        } else if (prio == res->prio) {
            /* duplicate host at same prio - add to weight */
            res->weight += weight;
            if (res->weight > (65535 << 8))
                res->weight = (65535 << 8);
        }

        if (ttl > res->expiry)
            res->expiry = ttl;

        log_debug(ZONE, "dns host updated for %s@%p: %s (%d/%d/%d)", query->name, query, ipport,
            res->prio, (res->weight >> 8), res->expiry);
    } else if (xhash_count(query->hosts) < DNS_MAX_RESULTS) {
        res = pmalloc(xhash_pool(query->hosts), sizeof(struct dnsres_st));
        res->key = pstrdup(xhash_pool(query->hosts), ipport);
        res->prio = prio;
        res->weight = weight;
        res->expiry = ttl;

        xhash_put(query->hosts, res->key, res);

        log_debug(ZONE, "dns host added for %s@%p: %s (%d/%d/%d)", query->name, query, ipport,
            res->prio, (res->weight >> 8), res->expiry);
    } else {
        log_debug(ZONE, "dns host ignored for %s@%p: %s (%d/%d/%d)", query->name, query, ipport,
            prio, (weight >> 8), ttl);
    }

    free(ipport);
}

/* this function is called with a NULL ctx to start the SRV process */
static void _dns_result_srv(struct dns_ctx *ctx, struct dns_rr_srv *result, void *data) {
    dnsquery_t query = data;
    assert(query != NULL);
    query->query = NULL;

    if (ctx != NULL && result == NULL) {
        log_debug(ZONE, "dns failure for %s@%p: SRV %s (%d)", query->name, query,
            query->s2s->lookup_srv[query->srv_i], dns_status(ctx));
    } else if (result != NULL) {
        int i;

        log_debug(ZONE, "dns response for %s@%p: SRV %s %d (%d)", query->name, query,
            result->dnssrv_qname, result->dnssrv_nrr, result->dnssrv_ttl);

        for (i = 0; i < result->dnssrv_nrr; i++) {
            if (strlen(result->dnssrv_srv[i].name) > 0
                    && result->dnssrv_srv[i].port > 0
                    && result->dnssrv_srv[i].port < 65536) {
                log_debug(ZONE, "dns response for %s@%p: SRV %s[%d] %s/%d (%d/%d)", query->name,
                    query, result->dnssrv_qname, i,
                    result->dnssrv_srv[i].name, result->dnssrv_srv[i].port,
                    result->dnssrv_srv[i].priority, result->dnssrv_srv[i].weight);

                _dns_add_host(query, result->dnssrv_srv[i].name,
                    result->dnssrv_srv[i].port, result->dnssrv_srv[i].priority,
                    result->dnssrv_srv[i].weight, result->dnssrv_ttl);
            }
        }

        free(result);
    }

    /* check next SRV service name */
    query->srv_i++;
    if (query->srv_i < query->s2s->lookup_nsrv) {
        log_debug(ZONE, "dns request for %s@%p: SRV %s", query->name, query,
            query->s2s->lookup_srv[query->srv_i]);

        query->query = dns_submit_srv(NULL, query->name, query->s2s->lookup_srv[query->srv_i], "tcp",
            DNS_NOSRCH, _dns_result_srv, query);

        /* if submit failed, call ourselves with a NULL result */
        if (query->query == NULL)
            _dns_result_srv(ctx, NULL, query);
    } else {
        /* no more SRV records to check, resolve hosts */
        if (xhash_count(query->hosts) > 0) {
            _dns_result_a(NULL, NULL, query);

        /* no SRV records returned, resolve hostname */
        } else {
            query->cur_host = strdup(query->name);
            query->cur_port = 5269;
            query->cur_prio = 0;
            query->cur_weight = 0;
            query->cur_expiry = 0;
            if (query->s2s->resolve_aaaa) {
                log_debug(ZONE, "dns request for %s@%p: AAAA %s", query->name, query, query->name);

                query->query = dns_submit_a6(NULL, query->name,
                    DNS_NOSRCH, _dns_result_aaaa, query);

                /* if submit failed, call ourselves with a NULL result */
                if (query->query == NULL)
                    _dns_result_aaaa(ctx, NULL, query);
            } else {
                log_debug(ZONE, "dns request for %s@%p: A %s", query->name, query, query->name);

                query->query = dns_submit_a4(NULL, query->name,
                    DNS_NOSRCH, _dns_result_a, query);

                /* if submit failed, call ourselves with a NULL result */
                if (query->query == NULL)
                    _dns_result_a(ctx, NULL, query);
            }
        }
    }
}

static void _dns_result_aaaa(struct dns_ctx *ctx, struct dns_rr_a6 *result, void *data) {
    dnsquery_t query = data;
    char ip[INET6_ADDRSTRLEN];
    int i;
    assert(query != NULL);
    query->query = NULL;

    if (ctx != NULL && result == NULL) {
        log_debug(ZONE, "dns failure for %s@%p: AAAA %s (%d)", query->name, query,
            query->cur_host, dns_status(ctx));
    } else if (result != NULL) {
        log_debug(ZONE, "dns response for %s@%p: AAAA %s %d (%d)", query->name, query,
            result->dnsa6_qname, result->dnsa6_nrr, result->dnsa6_ttl);

        if (query->cur_expiry > 0 && result->dnsa6_ttl > query->cur_expiry)
            result->dnsa6_ttl = query->cur_expiry;

        for (i = 0; i < result->dnsa6_nrr; i++) {
            if (inet_ntop(AF_INET6, &result->dnsa6_addr[i], ip, INET6_ADDRSTRLEN) != NULL) {
                log_debug(ZONE, "dns response for %s@%p: AAAA %s[%d] %s/%d", query->name,
                    query, result->dnsa6_qname, i, ip, query->cur_port);

                _dns_add_result(query, ip, query->cur_port,
                    query->cur_prio, query->cur_weight, result->dnsa6_ttl);
            }
        }
    }

    if (query->cur_host != NULL) {
        /* do ipv4 resolution too */
        log_debug(ZONE, "dns request for %s@%p: A %s", query->name, query, query->cur_host);

        query->query = dns_submit_a4(NULL, query->cur_host,
            DNS_NOSRCH, _dns_result_a, query);

        /* if submit failed, call ourselves with a NULL result */
        if (query->query == NULL)
            _dns_result_a(ctx, NULL, query);
    } else {
        /* uh-oh */
        log_debug(ZONE, "dns result for %s@%p: AAAA host vanished...", query->name, query);
        _dns_result_a(NULL, NULL, query);
    }

    free(result);
}

/* try /etc/hosts if the A process did not return any results */
static int _etc_hosts_lookup(const char *cszName, char *szIP, const int ciMaxIPLen) {
#define EHL_LINE_LEN 260
    int iSuccess = 0;
    size_t iLen;
    char szLine[EHL_LINE_LEN + 1]; /* one extra for the space character (*) */
    char *pcStart, *pcEnd;
    FILE *fHosts;

    do {
        /* initialization */
        fHosts = NULL;

        /* sanity checks */
        if ((cszName == NULL) || (szIP == NULL) || (ciMaxIPLen <= 0))
            break;
        szIP[0] = 0;

        /* open the hosts file */
#ifdef _WIN32
        pcStart = getenv("WINDIR");
        if (pcStart != NULL) {
            sprintf(szLine, "%s\\system32\\drivers\\etc\\hosts", pcStart);
        } else {
            strcpy(szLine, "C:\\WINDOWS\\system32\\drivers\\etc\\hosts");
        }
#else
        strcpy(szLine, "/etc/hosts");
#endif
        fHosts = fopen(szLine, "r");
        if (fHosts == NULL)
            break;

        /* read line by line ... */
        while (fgets(szLine, EHL_LINE_LEN, fHosts) != NULL) {
            /* remove comments */
            pcStart = strchr (szLine, '#');
            if (pcStart != NULL)
                *pcStart = 0;
            strcat(szLine, " "); /* append a space character for easier parsing (*) */

            /* first to appear: IP address */
            iLen = strspn(szLine, "1234567890.");
            if ((iLen < 7) || (iLen > 15)) /* superficial test for anything between x.x.x.x and xxx.xxx.xxx.xxx */
                continue;
            pcEnd = szLine + iLen;
            *pcEnd = 0;
            pcEnd++; /* not beyond the end of the line yet (*) */

            /* check strings separated by blanks, tabs or newlines */
            pcStart = pcEnd + strspn(pcEnd, " \t\n");
            while (*pcStart != 0) {
                pcEnd = pcStart + strcspn(pcStart, " \t\n");
                *pcEnd = 0;
                pcEnd++; /* not beyond the end of the line yet (*) */

                if (strcasecmp(pcStart, cszName) == 0) {
                    strncpy(szIP, szLine, ciMaxIPLen - 1);
                    szIP[ciMaxIPLen - 1] = '\0';
                    iSuccess = 1;
                    break;
                }

                pcStart = pcEnd + strspn(pcEnd, " \t\n");
            }
            if (iSuccess)
                break;
        }
    } while (0);

    if (fHosts != NULL)
        fclose(fHosts);

    return (iSuccess);
}

/* this function is called with a NULL ctx to start the A/AAAA process */
static void _dns_result_a(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data) {
    dnsquery_t query = data;
    assert(query != NULL);
    query->query = NULL;

    if (ctx != NULL && result == NULL) {
#define DRA_IP_LEN 16
        char szIP[DRA_IP_LEN];
        if (_etc_hosts_lookup (query->name, szIP, DRA_IP_LEN)) {
            log_debug(ZONE, "/etc/lookup for %s@%p: %s (%d)", query->name,
                query, szIP, query->s2s->etc_hosts_ttl);

            _dns_add_result (query, szIP, query->cur_port,
                query->cur_prio, query->cur_weight, query->s2s->etc_hosts_ttl);
        } else {
            log_debug(ZONE, "dns failure for %s@%p: A %s (%d)", query->name, query,
                query->cur_host, dns_status(ctx));
        }
    } else if (result != NULL) {
        char ip[INET_ADDRSTRLEN];
        int i;

        log_debug(ZONE, "dns response for %s@%p: A %s %d (%d)", query->name,
            query, result->dnsa4_qname, result->dnsa4_nrr, result->dnsa4_ttl);

        if (query->cur_expiry > 0 && result->dnsa4_ttl > query->cur_expiry)
            result->dnsa4_ttl = query->cur_expiry;

        for (i = 0; i < result->dnsa4_nrr; i++) {
            if (inet_ntop(AF_INET, &result->dnsa4_addr[i], ip, INET_ADDRSTRLEN) != NULL) {
                log_debug(ZONE, "dns response for %s@%p: A %s[%d] %s/%d", query->name,
                    query, result->dnsa4_qname, i, ip, query->cur_port);

                _dns_add_result(query, ip, query->cur_port,
                    query->cur_prio, query->cur_weight, result->dnsa4_ttl);
            }
        }

        free(result);
    }

    /* resolve the next host in the list */
    if (xhash_iter_first(query->hosts)) {
        char *ipport, *c, *tmp;
        int ipport_len, ip_len, port_len;
        dnsres_t res;
        union xhashv xhv;

        xhv.dnsres_val = &res;

        /* get the first entry */
        xhash_iter_get(query->hosts, (const char **) &ipport, &ipport_len, xhv.val);

        /* remove the host from the list */
        xhash_iter_zap(query->hosts);

        c = memchr(ipport, '/', ipport_len);
        ip_len = c - ipport;
        c++;
        port_len = ipport_len - (c - ipport);

        /* resolve hostname */
        free((void*)query->cur_host);
        query->cur_host = strndup(ipport, ip_len);
        tmp = strndup(c, port_len);
        query->cur_port = atoi(tmp);
        free(tmp);
        query->cur_prio = res->prio;
        query->cur_weight = res->weight;
        query->cur_expiry = res->expiry;
        log_debug(ZONE, "dns ttl for %s@%p limited to %d", query->name, query, query->cur_expiry);

        if (query->s2s->resolve_aaaa) {
            log_debug(ZONE, "dns request for %s@%p: AAAA %s", query->name, query, query->cur_host);

            query->query = dns_submit_a6(NULL, query->cur_host, DNS_NOSRCH, _dns_result_aaaa, query);

            /* if submit failed, call ourselves with a NULL result */
            if (query->query == NULL)
                _dns_result_aaaa(ctx, NULL, query);
        } else {
            log_debug(ZONE, "dns request for %s@%p: A %s", query->name, query, query->cur_host);

            query->query = dns_submit_a4(NULL, query->cur_host, DNS_NOSRCH, _dns_result_a, query);

            /* if submit failed, call ourselves with a NULL result */
            if (query->query == NULL)
                _dns_result_a(ctx, NULL, query);
        }

    /* finished */
    } else {
        time_t now = time(NULL);
        char *domain;

        free((void*)query->cur_host);
        query->cur_host = NULL;

        log_debug(ZONE, "dns requests for %s@%p complete: %d (%d)", query->name,
            query, xhash_count(query->results), query->expiry);

        /* update query TTL */
        if (query->expiry > query->s2s->dns_max_ttl)
            query->expiry = query->s2s->dns_max_ttl;

        if (query->expiry < query->s2s->dns_min_ttl)
            query->expiry = query->s2s->dns_min_ttl;

        query->expiry += now;

        /* update result TTLs - the query expiry MUST NOT be longer than all result expiries */
        if (xhash_iter_first(query->results)) {
            union xhashv xhv;
            dnsres_t res;

            xhv.dnsres_val = &res;

            do {
                xhash_iter_get(query->results, NULL, NULL, xhv.val);

                if (res->expiry > query->s2s->dns_max_ttl)
                    res->expiry = query->s2s->dns_max_ttl;

                if (res->expiry < query->s2s->dns_min_ttl)
                    res->expiry = query->s2s->dns_min_ttl;

                res->expiry += now;
            } while(xhash_iter_next(query->results));
        }

        xhash_free(query->hosts);
        query->hosts = NULL;
        if (idna_to_unicode_8z8z(query->name, &domain, 0) != IDNA_SUCCESS) {
            log_write(query->s2s->log, LOG_ERR, "idna dns decode for %s failed", query->name);
            /* fake empty results to shortcut resolution failure */
            xhash_free(query->results);
            query->results = xhash_new(71);
            query->expiry = time(NULL) + 99999999;
            domain = strdup(query->name);
        }
        out_resolve(query->s2s, domain, query->results, query->expiry);
        free(domain);
        free((void*)query->name);
        free(query);
    }
}

void dns_resolve_domain(s2s_t s2s, dnscache_t dns) {
    dnsquery_t query = (dnsquery_t) calloc(1, sizeof(struct dnsquery_st));
    char *name;

    query->s2s = s2s;
    query->results = xhash_new(71);
    if (idna_to_ascii_8z(dns->name, &name, 0) != IDNA_SUCCESS) {
        log_write(s2s->log, LOG_ERR, "idna dns encode for %s failed", dns->name);
        /* shortcut resolution failure */
        query->expiry = time(NULL) + 99999999;
        out_resolve(query->s2s, dns->name, query->results, query->expiry);
        return;
    }
    query->name = name;
    query->hosts = xhash_new(71);
    query->srv_i = -1;
    query->expiry = 0;
    query->cur_host = NULL;
    query->cur_port = 0;
    query->cur_expiry = 0;
    query->query = NULL;
    dns->query = query;

    log_debug(ZONE, "dns resolve for %s@%p started", query->name, query);

    /* - resolve all SRV records to host/port
     * - if no results, include domain/5269
     * - resolve all host/port combinations
     * - return result
     */
    _dns_result_srv(NULL, NULL, query);
}

/** responses from the resolver */
void out_resolve(s2s_t s2s, const char *domain, xht results, time_t expiry) {
    dnscache_t dns;

    /* no results, resolve failed */
    if(xhash_count(results) == 0) {
        dns = xhash_get(s2s->dnscache, domain);
        if (dns != NULL) {
            /* store negative DNS cache */
            xhash_free(dns->results);
            dns->query = NULL;
            dns->results = NULL;
            dns->expiry = expiry;
            dns->pending = 0;
        }

        log_write(s2s->log, LOG_NOTICE, "dns lookup for %s failed", domain);

        /* bounce queue */
        out_bounce_domain_queues(s2s, domain, stanza_err_REMOTE_SERVER_NOT_FOUND);

        xhash_free(results);
        return;
    }

    log_write(s2s->log, LOG_NOTICE, "dns lookup for %s returned %d result%s (ttl %d)",
        domain, xhash_count(results), xhash_count(results)!=1?"s":"", expiry - time(NULL));

    /* get the cache entry */
    dns = xhash_get(s2s->dnscache, domain);

    if(dns == NULL) {
        /* retry using punycode */
        char *punydomain;
        if (idna_to_ascii_8z(domain, &punydomain, 0) == IDNA_SUCCESS) {
            dns = xhash_get(s2s->dnscache, punydomain);
            free(punydomain);
        }
    }

    if(dns == NULL) {
        log_write(s2s->log, LOG_ERR, "weird, never requested %s resolution", domain);
        return;
    }

    /* fill it out */
    xhash_free(dns->results);
    dns->query = NULL;
    dns->results = results;
    dns->expiry = expiry;
    dns->pending = 0;

    out_flush_domain_queues(s2s, domain);

    /* delete the cache entry if caching is disabled */
    if (!s2s->dns_cache_enabled && !dns->pending) {
        xhash_free(dns->results);
        xhash_zap(s2s->dnscache, domain);
        free(dns);
    }
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

            jqueue_push(out->s2s->dead, (void *) out->s, 0);

            log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] disconnect, packets: %i", fd->fd, out->ip, out->port, out->packet_count);


            if (out->s2s->out_reuse) {
                /* generate the ip/port pair */
                snprintf(ipport, INET6_ADDRSTRLEN + 16, "%s/%d", out->ip, out->port);

                xhash_zap(out->s2s->out_host, ipport);
            }

            if (xhash_iter_first(out->routes)) {
                char *rkey;
                int rkeylen;
                char *c;
                int c_len;

                /* remove all the out_dest entries */
                do {
                    xhash_iter_get(out->routes, (const char **) &rkey, &rkeylen, NULL);
                    c = memchr(rkey, '/', rkeylen);
                    c++;
                    c_len = rkeylen - (c - rkey);

                    log_debug(ZONE, "route '%.*s'", rkeylen, rkey);
                    if (xhash_getx(out->s2s->out_dest, c, c_len) != NULL) {
                        log_debug(ZONE, "removing dest entry for '%.*s'", c_len, c);
                        xhash_zapx(out->s2s->out_dest, c, c_len);
                    }
                } while(xhash_iter_next(out->routes));
            }

            if (xhash_iter_first(out->routes)) {
                char *rkey;
                int rkeylen;
                jqueue_t q;
                int npkt;

                /* retry all the routes */
                do {
                    xhash_iter_get(out->routes, (const char **) &rkey, &rkeylen, NULL);

                    q = xhash_getx(out->s2s->outq, rkey, rkeylen);
                    if (out->s2s->retry_limit > 0 && q != NULL && jqueue_age(q) > out->s2s->retry_limit) {
                        log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] retry limit reached for '%.*s' queue", fd->fd, out->ip, out->port, rkeylen, rkey);
                        q = NULL;
                    }

                    if (q != NULL && (npkt = jqueue_size(q)) > 0 && xhash_get(out->states, rkey) != (void*) conn_INPROGRESS) {
                        conn_t retry;

                        log_debug(ZONE, "retrying connection for '%.*s' queue", rkeylen, rkey);
                        if (!out_route(out->s2s, rkey, rkeylen, &retry, 0)) {
                            log_debug(ZONE, "retry successful");

                            if (retry != NULL) {
                                /* flush queue */
                                out_flush_route_queue(out->s2s, rkey, rkeylen);
                            }
                        } else {
                            log_debug(ZONE, "retry failed");

                            /* bounce queue */
                            out_bounce_route_queue(out->s2s, rkey, rkeylen, stanza_err_SERVICE_UNAVAILABLE);
                            _out_dns_mark_bad(out);
                        }
                    } else {
                        /* bounce queue */
                        out_bounce_route_queue(out->s2s, rkey, rkeylen, stanza_err_REMOTE_SERVER_TIMEOUT);
                        _out_dns_mark_bad(out);
                    }
                } while(xhash_iter_next(out->routes));
            }

            jqueue_push(out->s2s->dead_conn, (void *) out, 0);

        case action_ACCEPT:
            break;
    }

    return 0;
}

void send_dialbacks(conn_t out)
{
  char *rkey;
  int rkeylen;

  if (out->s2s->dns_bad_timeout > 0) {
      dnsres_t bad = xhash_get(out->s2s->dns_bad, out->key);

      if (bad != NULL) {
          log_debug(ZONE, "removing bad host entry for '%s'", out->key);
          xhash_zap(out->s2s->dns_bad, out->key);
          free((void*)bad->key);
          free(bad);
      }
  }

  if (xhash_iter_first(out->routes)) {
       log_debug(ZONE, "sending dialback packets for %s", out->key);
       do {
            xhash_iter_get(out->routes, (const char **) &rkey, &rkeylen, NULL);
            _out_dialback(out, rkey, rkeylen);
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

                if (!out->online) {
                    _out_dns_mark_bad(out);
                }

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

            if (!out->online) {
                _out_dns_mark_bad(out);
            }

            sx_kill(s);

            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] error: %s (%s)", out->fd->fd, out->ip, out->port, sxe->generic, sxe->specific);

            /* mark as bad if we did not manage to connect or there is unrecoverable stream error */
            if (!out->online ||
                    (sxe->code == SX_ERR_STREAM &&
                        (strstr(sxe->specific, "host-gone") ||        /* it's not there now */
                         strstr(sxe->specific, "host-unknown") ||     /* they do not service the host */
                         strstr(sxe->specific, "not-authorized") ||   /* they do not want us there */
                         strstr(sxe->specific, "see-other-host") ||   /* we do not support redirections yet */
                         strstr(sxe->specific, "system-shutdown") ||  /* they are going down */
                         strstr(sxe->specific, "policy-violation") || /* they do not want us there */
                         strstr(sxe->specific, "remote-connection-failed") ||  /* the required remote entity is gone */
                         strstr(sxe->specific, "unsupported-encoding") ||      /* they do not like our encoding */
                         strstr(sxe->specific, "undefined-condition") ||       /* something bad happend */
                         strstr(sxe->specific, "internal-server-error") ||     /* that server is broken */
                         strstr(sxe->specific, "unsupported-version")          /* they do not support our stream version */
                        ))) {
                _out_dns_mark_bad(out);
            }

            sx_kill(s);

            return -1;

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
                if (((out->s->res_version==NULL) || (out->s2s->sx_ssl == NULL)) && out->s2s->require_tls == 0) {
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
                if(out->s2s->sx_ssl != NULL && s->ssf == 0) {
                    ns = nad_find_scoped_namespace(nad, uri_TLS, NULL);
                    if(ns >= 0) {
                        elem = nad_find_elem(nad, 0, ns, "starttls", 1);
                        if(elem >= 0) {
                            log_debug(ZONE, "got STARTTLS in stream features");
                            if(sx_ssl_client_starttls(out->s2s->sx_ssl, s, out->s2s->local_pemfile, out->s2s->local_private_key_password) == 0) {
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
                    if (out->s2s->require_tls == 0 || s->ssf > 0) {
                     log_debug(ZONE, "No STARTTLS, sending dialbacks for %s", out->key);
                     out->online = 1;
                     send_dialbacks(out);
                    } else {
                        log_debug(ZONE, "No STARTTLS, dialbacks disabled for non-TLS connections, cannot complete negotiation");
                    }
                }
#else
                if (out->s2s->require_tls == 0) {
                out->online = 1;
                send_dialbacks(out);
                }
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
            if (out->fd != NULL) {
            mio_close(out->s2s->mio, out->fd);
                out->fd = NULL;
            }
            return -1;
    }

    return 0;
}

/** process incoming auth responses */
static void _out_result(conn_t out, nad_t nad) {
    int attr;
    jid_t from, to;
    char *rkey;
    int rkeylen;

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
    rkeylen = strlen(rkey);

    /* key is valid */
    if(nad_find_attr(nad, 0, -1, "type", "valid") >= 0 && xhash_get(out->states, rkey) == (void*) conn_INPROGRESS) {
        log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] outgoing route '%s' is now valid%s%s", out->fd->fd, out->ip, out->port, rkey, (out->s->flags & SX_SSL_WRAPPER) ? ", TLS negotiated" : "", out->s->compressed ? ", ZLIB compression enabled" : "");

        xhash_put(out->states, pstrdup(xhash_pool(out->states), rkey), (void *) conn_VALID);    /* !!! small leak here */

        log_debug(ZONE, "%s valid, flushing queue", rkey);

        /* flush the queue */
        out_flush_route_queue(out->s2s, rkey, rkeylen);

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

    /* bounce queue */
    out_bounce_route_queue(out->s2s, rkey, rkeylen, stanza_err_SERVICE_UNAVAILABLE);

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
    if(attr >= 0 && xhash_get(in->states, rkey) == (void*) conn_INPROGRESS) {
        xhash_put(in->states, pstrdup(xhash_pool(in->states), rkey), (void *) conn_VALID);
        log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] incoming route '%s' is now valid%s%s", in->fd->fd, in->ip, in->port, rkey, (in->s->flags & SX_SSL_WRAPPER) ? ", TLS negotiated" : "", in->s->compressed ? ", ZLIB compression enabled" : "");
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
    nad = nad_new();

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

/* bounce all packets in the queues for domain */
int out_bounce_domain_queues(s2s_t s2s, const char *domain, int err)
{
  char *rkey;
  int rkeylen;
  int pktcount = 0;

  if (xhash_iter_first(s2s->outq)) {
      do {
          xhash_iter_get(s2s->outq, (const char **) &rkey, &rkeylen, NULL);
          if(s2s_route_key_match(NULL, (char *) domain, rkey, rkeylen))
              pktcount += out_bounce_route_queue(s2s, rkey, rkeylen, err);
      } while(xhash_iter_next(s2s->outq));
  }

  return pktcount;
}

/* bounce all packets in the queue for route */
int out_bounce_route_queue(s2s_t s2s, const char *rkey, int rkeylen, int err)
{
  jqueue_t q;
  pkt_t pkt;
  int pktcount = 0;

  q = xhash_getx(s2s->outq, rkey, rkeylen);
  if(q == NULL)
     return 0;

  while((pkt = jqueue_pull(q)) != NULL) {
     /* only packets with content, in namespace jabber:client and not already errors */
     if(pkt->nad->ecur > 1 && NAD_NURI_L(pkt->nad, NAD_ENS(pkt->nad, 1)) == strlen(uri_CLIENT) && strncmp(NAD_NURI(pkt->nad, NAD_ENS(pkt->nad, 1)), uri_CLIENT, strlen(uri_CLIENT)) == 0 && nad_find_attr(pkt->nad, 0, -1, "error", NULL) < 0) {
         sx_nad_write(s2s->router, stanza_tofrom(stanza_tofrom(stanza_error(pkt->nad, 1, err), 1), 0));
         pktcount++;
     }
     else
         nad_free(pkt->nad);

     jid_free(pkt->to);
     jid_free(pkt->from);
     free(pkt);
  }

  /* delete queue and remove domain from queue hash */
  log_debug(ZONE, "deleting out packet queue for %.*s", rkeylen, rkey);
  rkey = q->key;
  jqueue_free(q);
  xhash_zap(s2s->outq, rkey);
  free((void*)rkey);

  return pktcount;
}

int out_bounce_conn_queues(conn_t out, int err)
{
  char *rkey;
  int rkeylen;
  int pktcount = 0;

  /* bounce queues for all domains handled by this connection - iterate through routes */
  if (xhash_iter_first(out->routes)) {
      do {
          xhash_iter_get(out->routes, (const char **) &rkey, &rkeylen, NULL);
          pktcount += out_bounce_route_queue(out->s2s, rkey, rkeylen, err);
      } while(xhash_iter_next(out->routes));
  }

  return pktcount;
}

void out_flush_domain_queues(s2s_t s2s, const char *domain) {
  char *rkey;
  int rkeylen;
  char *c;
  int c_len;

  if (xhash_iter_first(s2s->outq)) {
      do {
          xhash_iter_get(s2s->outq, (const char **) &rkey, &rkeylen, NULL);
          c = memchr(rkey, '/', rkeylen);
          c++;
          c_len = rkeylen - (c - rkey);
          if (strncmp(domain, c, c_len) == 0)
              out_flush_route_queue(s2s, rkey, rkeylen);
      } while(xhash_iter_next(s2s->outq));
  }
}

void out_flush_route_queue(s2s_t s2s, const char *rkey, int rkeylen) {
    jqueue_t q;
    pkt_t pkt;
    int npkt, i, ret;

    q = xhash_getx(s2s->outq, rkey, rkeylen);
    if(q == NULL)
        return;

    npkt = jqueue_size(q);
    log_debug(ZONE, "flushing %d packets for '%.*s' to out_packet", npkt, rkeylen, rkey);

    for(i = 0; i < npkt; i++) {
        pkt = jqueue_pull(q);
        if(pkt) {
            ret = out_packet(s2s, pkt);
            if (ret) {
                /* uh-oh. the queue was deleted...
                   q and pkt have been freed
                   if q->key == rkey, rkey has also been freed */
                return;
            }
        }
    }

    /* delete queue for route and remove route from queue hash */
    if (jqueue_size(q) == 0) {
        log_debug(ZONE, "deleting out packet queue for '%.*s'", rkeylen, rkey);
        rkey = q->key;
        jqueue_free(q);
        xhash_zap(s2s->outq, rkey);
        free((void*)rkey);
    } else {
        log_debug(ZONE, "emptied queue gained more packets...");
    }
}
