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
#include "lib/str.h"
#include "lib/stanza.h"
#include "lib/jsignal.h"

#include <stringprep.h>
#ifdef HAVE_SSL
#include <openssl/rand.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

static sig_atomic_t s2s_shutdown = 0;
sig_atomic_t s2s_lost_router = 0;

static void _s2s_signal(int signum) {
    s2s_shutdown = 1;
    s2s_lost_router = 0;
}

static void _s2s_signal_usr1(int signum)
{
    log4c_category_set_priority(log4c_category_get(""), LOG4C_PRIORITY_NOTSET);
}

static void _s2s_signal_usr2(int signum)
{
    log4c_category_set_priority(log4c_category_get(""), LOG4C_PRIORITY_TRACE);
}

static int _s2s_populate_whitelist_domains(s2s_t *s2s, const char **values, int nvalues);


/** store the process id */
static void _s2s_pidfile(s2s_t *s2s) {
    const char *pidfile;
    FILE *f;
    pid_t pid;

    pidfile = config_get_one(s2s->config, "pidfile", 0);
    if(pidfile == NULL)
        return;

    pid = getpid();

    if((f = fopen(pidfile, "w+")) == NULL) {
        LOG_ERROR(s2s->log, "couldn't open %s for writing: %s", pidfile, strerror(errno));
        return;
    }

    if(fprintf(f, "%d", pid) < 0) {
        LOG_ERROR(s2s->log, "couldn't write to %s: %s", pidfile, strerror(errno));
        fclose(f);
        return;
    }

    fclose(f);

    LOG_INFO(s2s->log, "process id is %d, written to %s", pid, pidfile);
}

/** pull values out of the config file */
static void _s2s_config_expand(s2s_t *s2s) {
    char secret[41];
    config_elem_t *elem;
    int i, r;

    s2s->id = config_get_one(s2s->config, "id", 0);
    if(s2s->id == NULL)
        s2s->id = "s2s";

    s2s->router_ip = config_get_one(s2s->config, "router.ip", 0);
    if(s2s->router_ip == NULL)
        s2s->router_ip = "127.0.0.1";

    s2s->router_port = j_atoi(config_get_one(s2s->config, "router.port", 0), 5347);

    s2s->router_user = config_get_one(s2s->config, "router.user", 0);
    if(s2s->router_user == NULL)
        s2s->router_user = "jabberd";
    s2s->router_pass = config_get_one(s2s->config, "router.pass", 0);
    if(s2s->router_pass == NULL)
        s2s->router_pass = "secret";

    s2s->router_pemfile = config_get_one(s2s->config, "router.pemfile", 0);

    s2s->router_cachain = config_get_one(s2s->config, "router.cachain", 0);

    s2s->router_private_key_password = config_get_one(s2s->config, "router.private_key_password", 0);
    s2s->router_ciphers = config_get_one(s2s->config, "router.ciphers", 0);

    s2s->retry_init = j_atoi(config_get_one(s2s->config, "router.retry.init", 0), 3);
    s2s->retry_lost = j_atoi(config_get_one(s2s->config, "router.retry.lost", 0), 3);
    if((s2s->retry_sleep = j_atoi(config_get_one(s2s->config, "router.retry.sleep", 0), 2)) < 1)
        s2s->retry_sleep = 1;

    s2s->router_default = config_count(s2s->config, "router.non-default") ? 0 : 1;

    s2s->packet_stats = config_get_one(s2s->config, "stats.packet", 0);

    s2s->local_ip = config_get_one(s2s->config, "local.ip", 0);
    if(s2s->local_ip == NULL)
        s2s->local_ip = "0.0.0.0";
    if((elem = config_get(s2s->config, "local.origins.ip")) != NULL) {
        s2s->origin_ips = elem->values;
        s2s->origin_nips = elem->nvalues;
    }

    s2s->local_port = j_atoi(config_get_one(s2s->config, "local.port", 0), 0);

    if(config_get(s2s->config, "local.secret") != NULL)
        s2s->local_secret = strdup(config_get_one(s2s->config, "local.secret", 0));
    else {
#ifdef HAVE_SSL
        if (!RAND_bytes((unsigned char *)secret, 40)) {
            LOG_ERROR(s2s->log, "Failed to pull 40 RAND_bytes");
            exit(1);
        }
#else
#       warning "Using unsecure random number generator for dialback keys"
        log_write(s2s->log, LOG_WARNING, "Using unsecure random number generator for dialback keys - set local.secret to a random string!");
#endif
        for(i = 0; i < 40; i++) {
#ifdef HAVE_SSL
            r = (int) (36.0 * secret[i] / 255);
#else
            r = (int) (36.0 * rand() / RAND_MAX);
#endif
            secret[i] = (r >= 0 && r <= 9) ? (r + 48) : (r + 87);
        }
        secret[40] = '\0';
        s2s->local_secret = strdup(secret);
    }

    if(s2s->local_secret == NULL)
        s2s->local_secret = "secret";

    s2s->local_pemfile = config_get_one(s2s->config, "local.pemfile", 0);
    s2s->local_cachain = config_get_one(s2s->config, "local.cachain", 0);
    s2s->local_verify_mode = j_atoi(config_get_one(s2s->config, "local.verify-mode", 0), 0);
    s2s->local_private_key_password = config_get_one(s2s->config, "local.private_key_password", 0);
    s2s->local_ciphers = config_get_one(s2s->config, "local.ciphers", 0);

    s2s->io_max_fds = j_atoi(config_get_one(s2s->config, "io.max_fds", 0), 1024);

    s2s->compression = (config_get(s2s->config, "io.compression") != NULL);

    s2s->stanza_size_limit = j_atoi(config_get_one(s2s->config, "io.limits.stanzasize", 0), 0);
    s2s->require_tls = j_atoi(config_get_one(s2s->config, "security.require_tls", 0), 0);
    s2s->enable_whitelist = j_atoi(config_get_one(s2s->config, "security.enable_whitelist", 0), 0);
    if((elem = config_get(s2s->config, "security.whitelist_domain")) != NULL) {
        _s2s_populate_whitelist_domains(s2s, elem->values, elem->nvalues);
    }

    s2s->check_interval = j_atoi(config_get_one(s2s->config, "check.interval", 0), 60);
    s2s->check_queue = j_atoi(config_get_one(s2s->config, "check.queue", 0), 60);
    s2s->check_keepalive = j_atoi(config_get_one(s2s->config, "check.keepalive", 0), 0);
    s2s->check_idle = j_atoi(config_get_one(s2s->config, "check.idle", 0), 86400);
    s2s->check_dnscache = j_atoi(config_get_one(s2s->config, "check.dnscache", 0), 300);
    s2s->retry_limit = j_atoi(config_get_one(s2s->config, "check.retry", 0), 300);

    if((elem = config_get(s2s->config, "lookup.srv")) != NULL) {
        s2s->lookup_srv = elem->values;
        s2s->lookup_nsrv = elem->nvalues;
    }

    s2s->resolve_aaaa = config_count(s2s->config, "lookup.resolve-ipv6") ? 1 : 0;
    s2s->dns_cache_enabled = config_count(s2s->config, "lookup.no-cache") ? 0 : 1;
    s2s->dns_bad_timeout = j_atoi(config_get_one(s2s->config, "lookup.bad-host-timeout", 0), 3600);
    s2s->dns_min_ttl = j_atoi(config_get_one(s2s->config, "lookup.min-ttl", 0), 30);
    if (s2s->dns_min_ttl < 5)
        s2s->dns_min_ttl = 5;
    s2s->dns_max_ttl = j_atoi(config_get_one(s2s->config, "lookup.max-ttl", 0), 86400);
    s2s->etc_hosts_ttl = j_atoi(config_get_one(s2s->config, "lookup.etc-hosts-ttl", 0), 86400);
    s2s->out_reuse = config_count(s2s->config, "out-conn-reuse") ? 1 : 0;
}

static void _s2s_hosts_expand(s2s_t *s2s)
{
    char *realm;
    config_elem_t *elem;
    char id[1024];
    int i;

    elem = config_get(s2s->config, "local.id");

    if (elem) for(i = 0; i < elem->nvalues; i++) {
        host_t *host = pnew(xhash_pool(s2s->hosts), host_t);
        if(!host) {
            LOG_ERROR(s2s->log, "cannot allocate memory for new host, aborting");
            exit(1);
        }

        realm = j_attr((const char **) elem->attrs[i], "realm");

        /* stringprep ids (domain names) so that they are in canonical form */
        strncpy(id, elem->values[i], 1024);
        id[1023] = '\0';
        if (stringprep_nameprep(id, 1024) != 0) {
            LOG_ERROR(s2s->log, "cannot stringprep id %s, aborting", id);
            exit(1);
        }

        host->realm = (realm != NULL) ? realm : pstrdup(xhash_pool(s2s->hosts), id);

        host->host_pemfile = j_attr((const char **) elem->attrs[i], "pemfile");

        host->host_cachain = j_attr((const char **) elem->attrs[i], "cachain");

        host->host_verify_mode = j_atoi(j_attr((const char **) elem->attrs[i], "verify-mode"), 0);

        host->host_private_key_password = j_attr((const char **) elem->attrs[i], "private-key-password");

        host->host_ciphers = j_attr((const char **) elem->attrs[i], "ciphers");

#ifdef HAVE_SSL
        if(host->host_pemfile != NULL) {
            if(s2s->sx_ssl == NULL) {
                s2s->sx_ssl = sx_env_plugin(s2s->sx_env, sx_ssl_init, host->realm, host->host_pemfile, host->host_cachain, host->host_verify_mode, host->host_private_key_password, host->host_ciphers);
                if(s2s->sx_ssl == NULL) {
                    LOG_ERROR(s2s->log, "failed to load %s SSL pemfile", host->realm);
                    host->host_pemfile = NULL;
                }
            } else {
                if(sx_ssl_server_addcert(s2s->sx_ssl, host->realm, host->host_pemfile, host->host_cachain, host->host_verify_mode, host->host_private_key_password, host->host_ciphers) != 0) {
                    LOG_ERROR(s2s->log, "failed to load %s SSL pemfile", host->realm);
                    host->host_pemfile = NULL;
                }
            }
        }
#endif

        /* insert into vHosts xhash */
        xhash_put(s2s->hosts, pstrdup(xhash_pool(s2s->hosts), id), host);

        LOG_NOTICE(s2s->log, "[%s] configured; realm=%s", id, host->realm);
    }
}

static int _s2s_router_connect(s2s_t *s2s) {
    LOG_NOTICE(s2s->log, "attempting connection to router at %s, port=%d", s2s->router_ip, s2s->router_port);

    s2s->fd = mio_connect(s2s->mio, s2s->router_port, s2s->router_ip, NULL, s2s_router_mio_callback, (void *) s2s);
    if(s2s->fd == NULL) {
        if(errno == ECONNREFUSED)
            s2s_lost_router = 1;
        LOG_NOTICE(s2s->log, "connection attempt to router failed: %s (%d)", MIO_STRERROR(MIO_ERROR), MIO_ERROR);
        return 1;
    }

    s2s->router = sx_new(s2s->sx_env, s2s->router_ip, s2s->router_port, s2s_router_sx_callback, (void *) s2s);
    sx_client_init(s2s->router, 0, NULL, NULL, NULL, "1.0");

    return 0;
}

int _s2s_check_conn_routes(s2s_t *s2s, conn_t *conn, const char *direction)
{
  char *rkey;
  int rkeylen;
  conn_state_t state;
  time_t now, dialback_time;

  now = time(NULL);

  if(xhash_iter_first(conn->states))
     do {
           /* retrieve state in a separate operation, as sizeof(int) != sizeof(void *) on 64-bit platforms,
              so passing a pointer to state in xhash_iter_get is unsafe */
           xhash_iter_get(conn->states, (const char **) &rkey, &rkeylen, NULL);
           state = (conn_state_t) xhash_getx(conn->states, rkey, rkeylen);

           if (state == conn_INPROGRESS) {
              dialback_time = (time_t) xhash_getx(conn->states_time, rkey, rkeylen);

              if(now > dialback_time + s2s->check_queue) {
                 LOG_NOTICE(s2s->log, "[%d] [%s, port=%d] dialback for %s route '%.*s' timed out", conn->fd->fd, conn->ip, conn->port, direction, rkeylen, rkey);

                 xhash_zapx(conn->states, rkey, rkeylen);
                 xhash_zapx(conn->states_time, rkey, rkeylen);

                 /* stream error */
                 sx_error(conn->s, stream_err_CONNECTION_TIMEOUT, "dialback timed out");

                 /* close connection as per XMPP/RFC3920 */
                 sx_close(conn->s);

                 /* indicate that we closed the connection */
                 return 0;
              }
           }
     } while(xhash_iter_next(conn->states));

  /* all ok */
  return 1;
}

static void _s2s_time_checks(s2s_t *s2s) {
    conn_t *conn;
    time_t now;
    char *rkey, *key;
    int keylen;
    jqueue_t *q;
    dnscache_t *dns;
    char *c;
    int c_len;
    union xhashv xhv;

    now = time(NULL);

    /* queue expiry */
    if(s2s->check_queue > 0) {
        if(xhash_iter_first(s2s->outq))
            do {
                xhv.jq_val = &q;
                xhash_iter_get(s2s->outq, (const char **) &rkey, &keylen, xhv.val);

                LOG_DEBUG(s2s->log, "running time checks for %.*s", keylen, rkey);
                c = memchr(rkey, '/', keylen);
                c++;
                c_len = keylen - (c - rkey);

                /* dns lookup timeout check first */
                dns = xhash_getx(s2s->dnscache, c, c_len);
                if(dns != NULL && dns->pending) {
                    LOG_DEBUG(s2s->log, "dns lookup pending for %.*s", c_len, c);
                    if(now > dns->init_time + s2s->check_queue) {
                        LOG_NOTICE(s2s->log, "dns lookup for %.*s timed out", c_len, c);

                        /* bounce queue */
                        out_bounce_route_queue(s2s, rkey, keylen, stanza_err_REMOTE_SERVER_NOT_FOUND);

                        /* expire pending dns entry */
                        xhash_zap(s2s->dnscache, dns->name);
                        xhash_free(dns->results);
                        if (dns->query != NULL) {
                            if (dns->query->query != NULL)
                                dns_cancel(NULL, dns->query->query);
                            xhash_free(dns->query->hosts);
                            xhash_free(dns->query->results);
                            free((void*)dns->query->name);
                            free(dns->query);
                        }
                        free(dns);
                    }

                    continue;
                }

                /* get the conn */
                conn = xhash_getx(s2s->out_dest, c, c_len);
                if(conn == NULL) {
                    if(jqueue_size(q) > 0) {
                       /* no pending conn? perhaps it failed? */
                       LOG_DEBUG(s2s->log, "no pending connection for %.*s, bouncing %i packets in queue", c_len, c, jqueue_size(q));

                       /* bounce queue */
                       out_bounce_route_queue(s2s, rkey, keylen, stanza_err_REMOTE_SERVER_TIMEOUT);
                    }

                    continue;
                }

                /* connect timeout check */
                if(!conn->online && now > conn->init_time + s2s->check_queue) {
                    dnsres_t *bad;
                    char *ipport;

                    LOG_NOTICE(s2s->log, "[%d] [%s, port=%d] connection to %s timed out", conn->fd->fd, conn->ip, conn->port, c);

                    if (s2s->dns_bad_timeout > 0) {
                        /* mark this host as bad */
                        ipport = dns_make_ipport(conn->ip, conn->port);
                        bad = xhash_get(s2s->dns_bad, ipport);
                        if (bad == NULL) {
                            bad = new(dnsres_t);
                            bad->key = ipport;
                            xhash_put(s2s->dns_bad, ipport, bad);
                        } else {
                            free(ipport);
                        }
                        bad->expiry = time(NULL) + s2s->dns_bad_timeout;
                    }

                    /* close connection as per XMPP/RFC3920 */
                    /* the close function will retry or bounce the queue */
                    sx_close(conn->s);
                }
            } while(xhash_iter_next(s2s->outq));
    }

    /* expiry of connected routes in conn_INPROGRESS state */
    if(s2s->check_queue > 0) {

        /* outgoing connections */
        if(s2s->out_reuse) {
            if(xhash_iter_first(s2s->out_host))
                do {
                    xhv.conn_val = &conn;
                    xhash_iter_get(s2s->out_host, (const char **) &key, &keylen, xhv.val);
                    LOG_DEBUG(s2s->log, "checking dialback state for outgoing conn %.*s", keylen, key);
                    if (_s2s_check_conn_routes(s2s, conn, "outgoing")) {
                        LOG_DEBUG(s2s->log, "checking pending verify requests for outgoing conn %.*s", keylen, key);
                        if (conn->verify > 0 && now > conn->last_verify + s2s->check_queue) {
                            LOG_NOTICE(s2s->log, "[%d] [%s, port=%d] dialback verify request timed out", conn->fd->fd, conn->ip, conn->port);
                            sx_error(conn->s, stream_err_CONNECTION_TIMEOUT, "dialback verify request timed out");
                            sx_close(conn->s);
                        }
                    }
                } while(xhash_iter_next(s2s->out_host));
        } else {
            if(xhash_iter_first(s2s->out_dest))
                do {
                    xhv.conn_val = &conn;
                    xhash_iter_get(s2s->out_dest, (const char **) &key, &keylen, xhv.val);
                    LOG_DEBUG(s2s->log, "checking dialback state for outgoing conn %s (%s)", conn->dkey, conn->key);
                    if (_s2s_check_conn_routes(s2s, conn, "outgoing")) {
                        LOG_DEBUG(s2s->log, "checking pending verify requests for outgoing conn %s (%s)", conn->dkey, conn->key);
                        if (conn->verify > 0 && now > conn->last_verify + s2s->check_queue) {
                            LOG_NOTICE(s2s->log, "[%d] [%s, port=%d] dialback verify request timed out", conn->fd->fd, conn->ip, conn->port);
                            sx_error(conn->s, stream_err_CONNECTION_TIMEOUT, "dialback verify request timed out");
                            sx_close(conn->s);
                        }
                    }
                } while(xhash_iter_next(s2s->out_dest));
        }

        /* incoming open streams */
        if(xhash_iter_first(s2s->in))
            do {
                xhv.conn_val = &conn;
                xhash_iter_get(s2s->in, (const char **) &key, &keylen, xhv.val);

                LOG_DEBUG(s2s->log, "checking dialback state for incoming conn %.*s", keylen, key);
                if (_s2s_check_conn_routes(s2s, conn, "incoming"))
                    /* if the connection is still valid, check that dialbacks have been initiated */
                    if(!xhash_count(conn->states) && now > conn->init_time + s2s->check_queue) {
                        LOG_NOTICE(s2s->log, "[%d] [%s, port=%d] no dialback started", conn->fd->fd, conn->ip, conn->port);
                        sx_error(conn->s, stream_err_CONNECTION_TIMEOUT, "no dialback initiated");
                        sx_close(conn->s);
                    }
            } while(xhash_iter_next(s2s->in));

        /* incoming open connections (not yet streams) */
        if(xhash_iter_first(s2s->in_accept))
            do {
                xhv.conn_val = &conn;
                xhash_iter_get(s2s->in_accept, (const char **) &key, &keylen, xhv.val);

                LOG_DEBUG(s2s->log, "checking stream connection state for incoming conn %i", conn->fd->fd);
                if(!conn->online && now > conn->init_time + s2s->check_queue) {
                    LOG_NOTICE(s2s->log, "[%d] [%s, port=%d] stream initiation timed out", conn->fd->fd, conn->ip, conn->port);
                    sx_close(conn->s);
                }
            } while(xhash_iter_next(s2s->in_accept));

    }

    /* keepalives */
    if(s2s->out_reuse) {
        if(xhash_iter_first(s2s->out_host))
            do {
                xhv.conn_val = &conn;
                xhash_iter_get(s2s->out_host, NULL, NULL, xhv.val);

                if(s2s->check_keepalive > 0 && conn->last_activity > 0 && now > conn->last_activity + s2s->check_keepalive && conn->s->state >= state_STREAM) {
                    LOG_DEBUG(s2s->log, "sending keepalive for %d", conn->fd->fd);

                    sx_raw_write(conn->s, " ", 1);
                }
            } while(xhash_iter_next(s2s->out_host));
    } else {
        if(xhash_iter_first(s2s->out_dest))
            do {
                xhv.conn_val = &conn;
                xhash_iter_get(s2s->out_dest, NULL, NULL, xhv.val);

                if(s2s->check_keepalive > 0 && conn->last_activity > 0 && now > conn->last_activity + s2s->check_keepalive && conn->s->state >= state_STREAM) {
                    LOG_DEBUG(s2s->log, "sending keepalive for %d", conn->fd->fd);

                    sx_raw_write(conn->s, " ", 1);
                }
            } while(xhash_iter_next(s2s->out_dest));
    }

    /* idle timeouts - disconnect connections through which no packets have been sent for <idle> seconds */
    if(s2s->check_idle > 0) {

        /* outgoing connections */
        if(s2s->out_reuse) {
            if(xhash_iter_first(s2s->out_host))
                do {
                    xhv.conn_val = &conn;
                    xhash_iter_get(s2s->out_host, (const char **) &key, &keylen, xhv.val);
                    LOG_DEBUG(s2s->log, "checking idle state for %.*s", keylen, key);
                    if (conn->last_packet > 0 && now > conn->last_packet + s2s->check_idle && conn->s->state >= state_STREAM) {
                        LOG_NOTICE(s2s->log, "[%d] [%s, port=%d] idle timeout", conn->fd->fd, conn->ip, conn->port);
                        sx_close(conn->s);
                    }
                } while(xhash_iter_next(s2s->out_host));
        } else {
            if(xhash_iter_first(s2s->out_dest))
                do {
                    xhv.conn_val = &conn;
                    xhash_iter_get(s2s->out_dest, (const char **) &key, &keylen, xhv.val);
                    LOG_DEBUG(s2s->log, "checking idle state for %s (%s)", conn->dkey, conn->key);
                    if (conn->last_packet > 0 && now > conn->last_packet + s2s->check_idle && conn->s->state >= state_STREAM) {
                        LOG_NOTICE(s2s->log, "[%d] [%s, port=%d] idle timeout", conn->fd->fd, conn->ip, conn->port);
                        sx_close(conn->s);
                    }
                } while(xhash_iter_next(s2s->out_dest));
        }

        /* incoming connections */
        if(xhash_iter_first(s2s->in))
            do {
                xhv.conn_val = &conn;
                xhash_iter_get(s2s->in, (const char **) &key, &keylen, xhv.val);
                LOG_DEBUG(s2s->log, "checking idle state for %.*s", keylen, key);
                if (conn->last_packet > 0 && now > conn->last_packet + s2s->check_idle && conn->s->state >= state_STREAM) {
                    LOG_NOTICE(s2s->log, "[%d] [%s, port=%d] idle timeout", conn->fd->fd, conn->ip, conn->port);
                    sx_close(conn->s);
                }
            } while(xhash_iter_next(s2s->in));

    }

    return;
}

static void _s2s_dns_expiry(s2s_t *s2s) {
    time_t now;
    dnscache_t *dns = NULL;
    dnsres_t *res = NULL;
    union xhashv xhv;

    now = time(NULL);

    /* dnscache timeouts */
    if(xhash_iter_first(s2s->dnscache))
        do {
            xhv.dns_val = &dns;
            xhash_iter_get(s2s->dnscache, NULL, NULL, xhv.val);
            if (dns && !dns->pending && now > dns->expiry) {
                LOG_DEBUG(s2s->log, "expiring DNS cache for %s", dns->name);
                xhash_iter_zap(s2s->dnscache);

                xhash_free(dns->results);
                if (dns->query != NULL) {
                    if (dns->query->query != NULL)
                        dns_cancel(NULL, dns->query->query);
                    xhash_free(dns->query->hosts);
                    xhash_free(dns->query->results);
                    free((void*)dns->query->name);
                    free(dns->query);
                }
                free(dns);
            }
            else if (dns == NULL) {
                xhash_iter_zap(s2s->dnscache);
            }
        } while(xhash_iter_next(s2s->dnscache));

    if(xhash_iter_first(s2s->dns_bad))
        do {
            xhv.dnsres_val = &res;
            xhash_iter_get(s2s->dns_bad, NULL, NULL, xhv.val);
            if (res && now > res->expiry) {
                LOG_DEBUG(s2s->log, "expiring DNS bad host %s", res->key);
                xhash_iter_zap(s2s->dns_bad);

                free((void*)res->key);
                free(res);
            }
            else if (res == NULL) {
                xhash_iter_zap(s2s->dns_bad);
            }
        } while(xhash_iter_next(s2s->dns_bad));
}
/** responses from the resolver */
static int _mio_resolver_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {

    switch(a) {
        case action_READ:
            dns_ioevent(0, time(NULL));

        default:
            break;
    }

    return 0;
}

/* Populate the whitelist_domains array with the config file values */
int _s2s_populate_whitelist_domains(s2s_t *s2s, const char **values, int nvalues) {
    int i, j;
    int elem_len;
    s2s->whitelist_domains = malloc(sizeof(char*) * (nvalues));
    memset(s2s->whitelist_domains, 0, (sizeof(char *) * (nvalues)));
    for (i = 0, j = 0; i < nvalues; i++) {
        elem_len = strlen(values[i]);
        if (elem_len > MAX_DOMAIN_LEN) {
            LOG_DEBUG(s2s->log, "whitelist domain element is too large, skipping");
            continue;
        }
        if (elem_len == 0) {
            LOG_DEBUG(s2s->log, "whitelist domain element is blank, skipping");
            continue;
        }
        s2s->whitelist_domains[j] = malloc(sizeof(char) * (elem_len+1));
        strncpy(s2s->whitelist_domains[j], values[i], elem_len);
        s2s->whitelist_domains[j][elem_len] = '\0';
        LOG_DEBUG(s2s->log, "s2s whitelist domain read from file: %s\n", s2s->whitelist_domains[j]);
        j++;
    }

    s2s->n_whitelist_domains = j;
    LOG_DEBUG(s2s->log, "n_whitelist_domains = %d", s2s->n_whitelist_domains);
    return 0;
}


/* Compare a domain with whitelist values.
    The whitelist values may be FQDN or domain only (with no prepended hostname).
    returns 1 on match, 0 on failure to match
*/
int s2s_domain_in_whitelist(s2s_t *s2s, const char *in_domain) {
    int segcount = 0;
    int dotcount;
    char **segments = NULL;
    char **dst = NULL;
    char *seg_tmp = NULL;
    int seg_tmp_len;
    char matchstr[MAX_DOMAIN_LEN + 1];
    int domain_index;
    int x, i;
    int wl_index;
    int wl_len;
    int matchstr_len;
    char domain[1024];
    char *domain_ptr = &domain[0];
    int domain_len;

    strncpy(domain, in_domain, sizeof(domain));
    domain[sizeof(domain)-1] = '\0';
    domain_len = strlen((const char *)&domain);

    if (domain_len <= 0) {
        LOG_NOTICE(s2s->log, "s2s_domain_in_whitelist: in_domain is empty");
        return 0;
    }

    if (domain_len > MAX_DOMAIN_LEN) {
        LOG_NOTICE(s2s->log, "s2s_domain_in_whitelist: in_domain is longer than %d chars", MAX_DOMAIN_LEN);
        return 0;
    }

    // first try matching the FQDN with whitelist domains
    if (s2s->n_whitelist_domains <= 0)
        return 0;

    for (wl_index =0; wl_index < s2s->n_whitelist_domains; wl_index++) {
        wl_len = strlen(s2s->whitelist_domains[wl_index]);
        if (!strncmp(domain, s2s->whitelist_domains[wl_index], (domain_len > wl_len) ? domain_len : wl_len)) {
            LOG_DEBUG(s2s->log, "domain \"%s\" matches whitelist entry", domain);
            return 1;
        }
        else {
            LOG_DEBUG(s2s->log, "domain: %s (len %zd) does not match whitelist_domains[%d]: %s (len %zd)", domain, strlen(domain), wl_index, s2s->whitelist_domains[wl_index], strlen(s2s->whitelist_domains[wl_index]));
        }
    }

    // break domain into segments for domain-only comparision
    for (dotcount = 0, x = 0; domain[x] != '\0'; x++) {
        if (domain[x] == '.')
            dotcount++;
    }

    segments = malloc(sizeof(char*) * (dotcount + 1));
    if (segments == NULL) {
        LOG_ERROR(s2s->log, "s2s_domain_in_whitelist: malloc() error");
        return 0;
    }
    memset((char **)segments, 0, (sizeof(char*) * (dotcount + 1)));

    do {
        if (segcount > (dotcount+1)) {
            LOG_ERROR(s2s->log, "s2s_domain_in_whitelist: did not malloc enough room for domain segments; should never get here");
            if (seg_tmp != NULL) {
                free(seg_tmp);
                seg_tmp = NULL;
            }
            for (x = 0; x < segcount; x++) {
                free(segments[x]);
                segments[x] = NULL;
            }
            free(segments);
            segments = NULL;
            return 0;
        }
        seg_tmp = strsep(&domain_ptr, ".");
        if (seg_tmp == NULL) {
            break;
        }

        seg_tmp_len = strlen(seg_tmp);
        if (seg_tmp_len > MAX_DOMAIN_LEN) {
            LOG_NOTICE(s2s->log, "s2s_domain_in_whitelist: domain contains a segment greater than %d chars", MAX_DOMAIN_LEN);
            free(seg_tmp);
            seg_tmp = NULL;
            for (x = 0; x < segcount; x++) {
                free(segments[x]);
                segments[x] = NULL;
            }
            free(segments);
            segments = NULL;
            return 0;
        }
        dst = &segments[segcount];
        *dst = malloc(seg_tmp_len + 1);
        if (*dst != NULL) {
            strncpy(*dst, seg_tmp, seg_tmp_len + 1);
            (*dst)[seg_tmp_len] = '\0';
        } else {
            free(seg_tmp);
            seg_tmp = NULL;
            for (x = 0; x < segcount; x++) {
                free(segments[x]);
                segments[x] = NULL;
            }
            free(segments);
            segments = NULL;
            LOG_ERROR(s2s->log, "s2s_domain_in_whitelist: malloc() error");
            return 0;
        }
        segcount++;
    } while (seg_tmp != NULL);

    if (segcount > 1) {
        for (domain_index = segcount-2; domain_index > 0; domain_index--) {
            matchstr[0] = '\0';
            for (i = domain_index; i < segcount; i++) {
                if (i > domain_index) {
                    strncat((char *)&matchstr, ".", sizeof(matchstr));
                    matchstr[sizeof(matchstr)-1] = '\0';
                }
                strncat((char *)&matchstr, (char *)segments[i], sizeof(matchstr)-strlen(matchstr)-1);
                matchstr[sizeof(matchstr)-1] = '\0';
            }
            for (wl_index = 0; wl_index < s2s->n_whitelist_domains; wl_index++) {
                wl_len = strlen(s2s->whitelist_domains[wl_index]);
                matchstr_len = strlen((const char *)&matchstr);
                if (!strncmp(matchstr, s2s->whitelist_domains[wl_index], (wl_len > matchstr_len ? wl_len : matchstr_len))) {
                    LOG_DEBUG(s2s->log, "matchstr \"%s\" matches whitelist entry", matchstr);
                    for (x = 0; x < segcount; x++) {
                        free(segments[x]);
                        segments[x] = NULL;
                    }
                    free(segments);
                    segments = NULL;
                    return 1;
                }
                else {
                    LOG_DEBUG(s2s->log, "matchstr: %s (len %zd) does not match whitelist_domains[%d]: %s (len %zd)", matchstr, strlen(matchstr), wl_index, s2s->whitelist_domains[wl_index], strlen(s2s->whitelist_domains[wl_index]));
                }
            }
        }
    }
    for (x = 0; x < segcount; x++) {
        free(segments[x]);
        segments[x] = NULL;
    }
    free(segments);
    segments = NULL;

    return 0;
}

JABBER_MAIN("jabberd2s2s", "Jabber 2 S2S", "Jabber Open Source Server: Server to Server", "jabberd2router\0")
{
    s2s_t *s2s;
    char *config_file;
    int optchar;
    conn_t *conn;
    jqueue_t *q;
    dnscache_t *dns;
    dnsres_t *res;
    union xhashv xhv;
    time_t check_time = 0, now = 0;
    const char *cli_id = 0;

#ifdef HAVE_UMASK
    umask((mode_t) 0027);
#endif

    srand(time(NULL));

#ifdef HAVE_WINSOCK2_H
/* get winsock running */
    {
        WORD wVersionRequested;
        WSADATA wsaData;
        int err;

        wVersionRequested = MAKEWORD( 2, 2 );

        err = WSAStartup( wVersionRequested, &wsaData );
        if ( err != 0 ) {
            /* !!! tell user that we couldn't find a usable winsock dll */
            return 0;
        }
    }
#endif

    jabber_signal(SIGINT, _s2s_signal);
    jabber_signal(SIGTERM, _s2s_signal);
#ifdef SIGPIPE
    jabber_signal(SIGPIPE, SIG_IGN);
#endif
    jabber_signal(SIGUSR1, _s2s_signal_usr1);
    jabber_signal(SIGUSR2, _s2s_signal_usr2);

    if (log4c_init()) {
        fputs("log4c init failed\n", stderr);
        exit(EXIT_FAILURE);
    }

    s2s = new(s2s_t);

    /* load our config */
    s2s->config = config_new(0);

    config_file = CONFIG_DIR "/s2s.xml";

    /* cmdline parsing */
    while((optchar = getopt(argc, argv, "Dc:hi:?")) >= 0)
    {
        switch(optchar)
        {
            case 'c':
                config_file = optarg;
                break;
            case 'i':
                cli_id = optarg;
                break;
            case 'h': case '?': default:
                fputs(
                    "s2s - jabberd server-to-server connector (" VERSION ")\n"
                    "Usage: s2s <options>\n"
                    "Options are:\n"
                    "   -c <config>     config file to use [default: " CONFIG_DIR "/s2s.xml]\n"
                    "   -i id           Override <id> config element\n"
                    ,
                    stdout);
                config_free(s2s->config);
                free(s2s);
                return 1;
        }
    }

    if(config_load_with_id(s2s->config, config_file, cli_id) != 0) {
        fputs("s2s: couldn't load config, aborting\n", stderr);
        config_free(s2s->config);
        free(s2s);
        return 2;
    }

    _s2s_config_expand(s2s);

    s2s->log = log_get(s2s->id);
    LOG_NOTICE(s2s->log, "starting up (interval=%i, queue=%i, keepalive=%i, idle=%i)", s2s->check_interval, s2s->check_queue, s2s->check_keepalive, s2s->check_idle);

    _s2s_pidfile(s2s);

    s2s->outq = xhash_new(401);
    s2s->out_host = xhash_new(401);
    s2s->out_dest = xhash_new(401);
    s2s->in = xhash_new(401);
    s2s->in_accept = xhash_new(401);
    s2s->dnscache = xhash_new(401);
    s2s->dns_bad = xhash_new(401);

    s2s->dead = jqueue_new();
    s2s->dead_conn = jqueue_new();

    s2s->sx_env = sx_env_new();

#ifdef HAVE_SSL
    /* get the ssl context up and running */
    if(s2s->local_pemfile != NULL) {
        s2s->sx_ssl = sx_env_plugin(s2s->sx_env, sx_ssl_init, NULL, s2s->local_pemfile, s2s->local_cachain, s2s->local_verify_mode, s2s->local_private_key_password, s2s->local_ciphers);

        if(s2s->sx_ssl == NULL) {
            LOG_ERROR(s2s->log, "failed to load local SSL pemfile, SSL will not be available to peers");
            s2s->local_pemfile = NULL;
        } else
            LOG_DEBUG(s2s->log, "loaded pemfile for SSL connections to peers");
    }

    /* try and get something online, so at least we can encrypt to the router */
    if(s2s->sx_ssl == NULL && s2s->router_pemfile != NULL) {
        s2s->sx_ssl = sx_env_plugin(s2s->sx_env, sx_ssl_init, NULL, s2s->router_pemfile, s2s->router_cachain, NULL, s2s->router_private_key_password, s2s->router_ciphers);
        if(s2s->sx_ssl == NULL) {
            LOG_ERROR(s2s->log, "failed to load router SSL pemfile, channel to router will not be SSL encrypted");
            s2s->router_pemfile = NULL;
        }
    }
#endif

#ifdef HAVE_LIBZ
    /* get compression up and running */
    if(s2s->compression)
        sx_env_plugin(s2s->sx_env, sx_compress_init);
#endif

    /* get sasl online */
    s2s->sx_sasl = sx_env_plugin(s2s->sx_env, sx_sasl_init, "xmpp", NULL, NULL);
    if(s2s->sx_sasl == NULL) {
        LOG_ERROR(s2s->log, "failed to initialise SASL context, aborting");
        exit(1);
    }

    /* hosts mapping */
    s2s->hosts = xhash_new(1021);
    _s2s_hosts_expand(s2s);

    s2s->sx_db = sx_env_plugin(s2s->sx_env, s2s_db_init);

    s2s->mio = mio_new(s2s->io_max_fds);

    if((s2s->udns_fd = dns_init(NULL, 1)) < 0) {
        LOG_ERROR(s2s->log, "unable to initialize dns library, aborting");
        exit(1);
    }
    s2s->udns_mio_fd = mio_register(s2s->mio, s2s->udns_fd, _mio_resolver_callback, (void *) s2s);

    s2s->retry_left = s2s->retry_init;
    _s2s_router_connect(s2s);

    while(!s2s_shutdown) {
        mio_run(s2s->mio, dns_timeouts(0, 5, time(NULL)));

        now = time(NULL);

        if(s2s_lost_router) {
            if(s2s->retry_left < 0) {
                LOG_NOTICE(s2s->log, "attempting reconnect");
                sleep(s2s->retry_sleep);
                s2s_lost_router = 0;
                if (s2s->router) sx_free(s2s->router);
                _s2s_router_connect(s2s);
            }

            else if(s2s->retry_left == 0) {
                s2s_shutdown = 1;
            }

            else {
                LOG_NOTICE(s2s->log, "attempting reconnect (%d left)", s2s->retry_left);
                s2s->retry_left--;
                sleep(s2s->retry_sleep);
                s2s_lost_router = 0;
                if (s2s->router) sx_free(s2s->router);
                _s2s_router_connect(s2s);
            }
        }

        /* this has to be read unconditionally - we could receive replies to queries we cancelled */
          mio_read(s2s->mio, s2s->udns_mio_fd);

        /* cleanup dead sx_ts */
        while(jqueue_size(s2s->dead) > 0)
            sx_free(jqueue_pull(s2s->dead));

        /* cleanup dead conn_ts */
        while(jqueue_size(s2s->dead_conn) > 0) {
            conn = jqueue_pull(s2s->dead_conn);
            xhash_free(conn->states);
            xhash_free(conn->states_time);
            xhash_free(conn->routes);

            free((void*)conn->key);
            free((void*)conn->dkey);
            free(conn);
        }

        /* time checks */
        if(s2s->check_interval > 0 && now >= s2s->next_check) {
            LOG_DEBUG(s2s->log, "running time checks");

            _s2s_time_checks(s2s);

            s2s->next_check = now + s2s->check_interval;
            LOG_DEBUG(s2s->log, "next time check check in %d: %lld", s2s->check_interval, (long long)s2s->next_check);
        }

        /* dnscache expiry */
        if(s2s->check_dnscache > 0 && now >= s2s->next_expiry) {
            LOG_DEBUG(s2s->log, "running dns expiry");

            _s2s_dns_expiry(s2s);

            s2s->next_expiry = now + s2s->check_dnscache;
            LOG_DEBUG(s2s->log, "next dns expiry in %d: %lld", s2s->check_dnscache, (long long)s2s->next_expiry);
        }

        if(now > check_time + 60) {
#ifdef POOL_DEBUG
            pool_stat(1);
#endif
            if(s2s->packet_stats != NULL) {
                int fd = open(s2s->packet_stats, O_TRUNC | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
                if(fd >= 0) {
                    char buf[100];
                    int len = snprintf(buf, 100, "%lld\n", s2s->packet_count);
                    write(fd, buf, len);
                    close(fd);
                } else {
                    LOG_ERROR(s2s->log, "failed to write packet statistics to: %s (%s)", s2s->packet_stats, strerror(errno));
                    s2s_shutdown = 1;
                }
            }

            check_time = now;
        }
    }

    LOG_NOTICE(s2s->log, "shutting down");

    /* close active streams gracefully  */
    xhv.conn_val = &conn;
    if(s2s->out_reuse) {
        if(xhash_iter_first(s2s->out_host))
            do {
                xhash_iter_get(s2s->out_host, NULL, NULL, xhv.val);
                if(conn) {
                    sx_error(conn->s, stream_err_SYSTEM_SHUTDOWN, "s2s shutdown");
                    out_bounce_conn_queues(conn, stanza_err_SERVICE_UNAVAILABLE);
                    sx_close(conn->s);
                }
            } while(xhash_iter_next(s2s->out_host));
    } else {
        if(xhash_iter_first(s2s->out_dest))
            do {
                xhash_iter_get(s2s->out_dest, NULL, NULL, xhv.val);
                if(conn) {
                    sx_error(conn->s, stream_err_SYSTEM_SHUTDOWN, "s2s shutdown");
                    out_bounce_conn_queues(conn, stanza_err_SERVICE_UNAVAILABLE);
                    sx_close(conn->s);
                }
            } while(xhash_iter_next(s2s->out_dest));
    }

    if(xhash_iter_first(s2s->in))
        do {
            xhash_iter_get(s2s->in, NULL, NULL, xhv.val);
            if(conn) {
                sx_error(conn->s, stream_err_SYSTEM_SHUTDOWN, "s2s shutdown");
                out_bounce_conn_queues(conn, stanza_err_SERVICE_UNAVAILABLE);
                sx_close(conn->s);
            }
        } while(xhash_iter_next(s2s->in));

    if(xhash_iter_first(s2s->in_accept))
        do {
            xhash_iter_get(s2s->in_accept, NULL, NULL, xhv.val);
            if(conn) {
                out_bounce_conn_queues(conn, stanza_err_SERVICE_UNAVAILABLE);
                sx_close(conn->s);
            }
        } while(xhash_iter_next(s2s->in_accept));


    /* remove dead streams */
    while(jqueue_size(s2s->dead) > 0)
        sx_free(jqueue_pull(s2s->dead));

    /* cleanup dead conn_ts */
    while(jqueue_size(s2s->dead_conn) > 0) {
        conn = jqueue_pull(s2s->dead_conn);
        xhash_free(conn->states);
        xhash_free(conn->states_time);
        xhash_free(conn->routes);

        if(conn->key != NULL) free((void*)conn->key);
        if(conn->dkey != NULL) free((void*)conn->dkey);
        free(conn);
    }

    /* free outgoing queues  */
    xhv.jq_val = &q;
    if(xhash_iter_first(s2s->outq))
        do {
             xhash_iter_get(s2s->outq, NULL, NULL, xhv.val);
             while (jqueue_size(q) > 0)
                 out_pkt_free(jqueue_pull(q));
             free(q->key);
             jqueue_free(q);
        } while(xhash_iter_next(s2s->outq));

    /* walk & free resolve queues */
    xhv.dns_val = &dns;
    if(xhash_iter_first(s2s->dnscache))
        do {
             xhash_iter_get(s2s->dnscache, NULL, NULL, xhv.val);
             xhash_free(dns->results);
             if (dns->query != NULL) {
                 if (dns->query->query != NULL)
                     dns_cancel(NULL, dns->query->query);
                 xhash_free(dns->query->hosts);
                 xhash_free(dns->query->results);
                 free((void*)dns->query->name);
                 free(dns->query);
             }
             free(dns);
        } while(xhash_iter_next(s2s->dnscache));

    xhv.dnsres_val = &res;
    if(xhash_iter_first(s2s->dns_bad))
        do {
             xhash_iter_get(s2s->dns_bad, NULL, NULL, xhv.val);
             free((void*)res->key);
             free(res);
        } while(xhash_iter_next(s2s->dns_bad));

    if (dns_active(NULL) > 0)
        LOG_DEBUG(s2s->log, "there are still active dns queries (%d)", dns_active(NULL));
    dns_close(NULL);

    /* close mio */
    mio_close(s2s->mio, s2s->udns_mio_fd);
    if(s2s->fd != NULL)
        mio_close(s2s->mio, s2s->fd);
    if(s2s->server_fd != NULL)
        mio_close(s2s->mio, s2s->server_fd);

    /* free hashes */
    xhash_free(s2s->outq);
    xhash_free(s2s->out_host);
    xhash_free(s2s->out_dest);
    xhash_free(s2s->in);
    xhash_free(s2s->in_accept);
    xhash_free(s2s->dnscache);
    xhash_free(s2s->dns_bad);
    xhash_free(s2s->hosts);

    jqueue_free(s2s->dead);
    jqueue_free(s2s->dead_conn);

    sx_free(s2s->router);

    sx_env_free(s2s->sx_env);

    mio_free(s2s->mio);

    config_free(s2s->config);

    free((void*)s2s->local_secret);
    free(s2s);

#ifdef POOL_DEBUG
    pool_stat(1);
#endif

    /* shutdown logging system - should be last before exit! */
    if (log4c_fini()) {
        fputs("log4c finish failed\n", stderr);
        exit(EXIT_FAILURE);
    }

    return 0;
}
