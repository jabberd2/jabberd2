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

#include "resolver.h"

static sig_atomic_t resolver_shutdown = 0;
static sig_atomic_t resolver_lost_router = 0;
static sig_atomic_t resolver_logrotate = 0;

static void _resolver_signal(int signum)
{
    resolver_shutdown = 1;
    resolver_lost_router = 0;
}

static void _resolver_signal_hup(int signum)
{
    resolver_logrotate = 1;
}

/** store the process id */
static void _resolver_pidfile(resolver_t r) {
    char *pidfile;
    FILE *f;
    pid_t pid;

    pidfile = config_get_one(r->config, "pidfile", 0);
    if(pidfile == NULL)
        return;

    pid = getpid();

    if((f = fopen(pidfile, "w+")) == NULL) {
        log_write(r->log, LOG_ERR, "couldn't open %s for writing: %s", pidfile, strerror(errno));
        return;
    }

    if(fprintf(f, "%d", pid) < 0) {
        log_write(r->log, LOG_ERR, "couldn't write to %s: %s", pidfile, strerror(errno));
        fclose(f);
        return;
    }

    fclose(f);

    log_write(r->log, LOG_INFO, "process id is %d, written to %s", pid, pidfile);
}

/** pull values out of the config file */
static void _resolver_config_expand(resolver_t r)
{
    char *str;
    config_elem_t elem;

    r->id = config_get_one(r->config, "id", 0);
    if(r->id == NULL)
        r->id = "resolver";

    r->router_ip = config_get_one(r->config, "router.ip", 0);
    if(r->router_ip == NULL)
        r->router_ip = "127.0.0.1";

    r->router_port = j_atoi(config_get_one(r->config, "router.port", 0), 5347);

    r->router_user = config_get_one(r->config, "router.user", 0);
    if(r->router_user == NULL)
        r->router_user = "jabberd";
    r->router_pass = config_get_one(r->config, "router.pass", 0);
    if(r->router_pass == NULL)
        r->router_pass = "secret";

    r->router_pemfile = config_get_one(r->config, "router.pemfile", 0);

    r->retry_init = j_atoi(config_get_one(r->config, "router.retry.init", 0), 3);
    r->retry_lost = j_atoi(config_get_one(r->config, "router.retry.lost", 0), 3);
    if((r->retry_sleep = j_atoi(config_get_one(r->config, "router.retry.sleep", 0), 2)) < 1)
        r->retry_sleep = 1;
    
    r->log_type = log_STDOUT;
    if(config_get(r->config, "log") != NULL) {
        if((str = config_get_attr(r->config, "log", 0, "type")) != NULL) {
            if(strcmp(str, "file") == 0)
                r->log_type = log_FILE;
            else if(strcmp(str, "syslog") == 0)
                r->log_type = log_SYSLOG;
        }
    }

    if(r->log_type == log_SYSLOG) {
        r->log_facility = config_get_one(r->config, "log.facility", 0);
        r->log_ident = config_get_one(r->config, "log.ident", 0);
        if(r->log_ident == NULL)
            r->log_ident = "jabberd/resolver";
    } else if(r->log_type == log_FILE)
        r->log_ident = config_get_one(r->config, "log.file", 0);

    if((elem = config_get(r->config, "lookup.srv")) != NULL) {
        r->lookup_srv = elem->values;
        r->lookup_nsrv = elem->nvalues;
    }

    r->resolve_aaaa = config_count(r->config, "ipv6") ? 1 : 0;
}

static int _resolver_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    resolver_t r = (resolver_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    sx_error_t *sxe;
    int elem, len, attr, ns, aname, eip, srv, nres;
    nad_t nad;
    char zone[256], num[10];
    dns_host_t srvs, srvscan, as, ascan;

    switch(e) {
        case event_WANT_READ:
            log_debug(ZONE, "want read");
            mio_read(r->mio, r->fd);
            break;

        case event_WANT_WRITE:
            log_debug(ZONE, "want write");
            mio_write(r->mio, r->fd);
            break;

        case event_READ:
            log_debug(ZONE, "reading from %d", r->fd->fd);

            /* do the read */
            len = recv(r->fd->fd, buf->data, buf->len, 0);

            if(len < 0) {
                if(MIO_WOULDBLOCK) {
                    buf->len = 0;
                    return 0;
                }

                log_write(r->log, LOG_NOTICE, "[%d] [router] read error: %s (%d)", r->fd->fd, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

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
            log_debug(ZONE, "writing to %d", r->fd->fd);

            len = send(r->fd->fd, buf->data, buf->len, 0);
            if(len >= 0) {
                log_debug(ZONE, "%d bytes written", len);
                return len;
            }

            if(MIO_WOULDBLOCK)
                return 0;

            log_write(r->log, LOG_NOTICE, "[%d] [router] write error: %s (%d)", r->fd->fd, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

            sx_kill(s);

            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            log_write(r->log, LOG_NOTICE, "error from router: %s (%s)", sxe->generic, sxe->specific);

            if(sxe->code == SX_ERR_AUTH)
                sx_close(s);

            break;

        case event_STREAM:
            break;

        case event_OPEN:
            log_write(r->log, LOG_NOTICE, "connection to router established");

            /* reset connection attempts counter */
            r->retry_left = r->retry_init;

            nad = nad_new(r->router->nad_cache);
            ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
            nad_append_elem(nad, ns, "bind", 0);
            nad_append_attr(nad, -1, "name", r->id);

            log_debug(ZONE, "requesting component bind for '%s'", r->id);

            sx_nad_write(r->router, nad);

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
                if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_STREAMS) || strncmp(uri_STREAMS, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_STREAMS)) != 0 || NAD_ENAME_L(nad, 0) != 8 || strncmp("features", NAD_ENAME(nad, 0), 8)) {
                    log_debug(ZONE, "got a non-features packet on an unauth'd stream, dropping");
                    nad_free(nad);
                    return 0;
                }

#ifdef HAVE_SSL
                /* starttls if we can */
                if(r->sx_ssl != NULL && s->ssf == 0) {
                    ns = nad_find_scoped_namespace(nad, uri_TLS, NULL);
                    if(ns >= 0) {
                        elem = nad_find_elem(nad, 0, ns, "starttls", 1);
                        if(elem >= 0) {
                            if(sx_ssl_client_starttls(r->sx_ssl, s, NULL) == 0) {
                                nad_free(nad);
                                return 0;
                            }
                            log_write(r->log, LOG_NOTICE, "unable to establish encrypted session with router");
                        }
                    }
                }
#endif

                /* !!! pull the list of mechanisms, and choose the best one.
                 *     if there isn't an appropriate one, error and bail */

                /* authenticate */
                sx_sasl_auth(r->sx_sasl, s, "jabberd-router", "DIGEST-MD5", r->router_user, r->router_pass);

                nad_free(nad);
                return 0;
            }

            /* watch for the bind response */
            if(s->state == state_OPEN && !r->online) {
                if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT) || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0 || NAD_ENAME_L(nad, 0) != 4 || strncmp("bind", NAD_ENAME(nad, 0), 4)) {
                    log_debug(ZONE, "got a packet from router, but we're not online, dropping");
                    nad_free(nad);
                    return 0;
                }

                /* catch errors */
                attr = nad_find_attr(nad, 0, -1, "error", NULL);
                if(attr >= 0) {
                    log_write(r->log, LOG_NOTICE, "router refused bind request (%.*s)", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
                    exit(1);
                }

                log_debug(ZONE, "coming online");

                /* we're online */
                r->online = r->started = 1;
                r->retry_left = r->retry_lost;

                log_write(r->log, LOG_NOTICE, "ready to resolve", r->id);

                nad_free(nad);
                return 0;
            }

            /* drop errors */
            if(nad_find_attr(nad, 1, -1, "type", "error") >= 0) {
                nad_free(nad);
                return 0;
            }

            /* check packet, extract needed info */
            if(!(
               /* subpacket exists */
               nad->ecur > 1 &&
               /* packet is in the component namespace */
               (NAD_NURI_L(nad, NAD_ENS(nad, 0)) == strlen(uri_COMPONENT) && strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) == 0) &&
               /* packet is a route */
               (NAD_ENAME_L(nad, 0) == 5 && strncmp("route", NAD_ENAME(nad, 0), 5) == 0) &&
               /* subpacket is in the resolver namespace */
               (NAD_NURI_L(nad, NAD_ENS(nad, 1)) == strlen(uri_RESOLVER) && strncmp(uri_RESOLVER, NAD_NURI(nad, NAD_ENS(nad, 1)), strlen(uri_RESOLVER)) == 0) &&
               /* packet has a subelement "resolve" in that namespace */
               (NAD_ENAME_L(nad, 1) == 7 && strncmp("resolve", NAD_ENAME(nad, 1), 7) == 0) &&
               /* resolve has a "type" of "query" */
               nad_find_attr(nad, 1, -1, "type", "query") >= 0 &&
               /* resolve has a "name" attribute */
               (aname = nad_find_attr(nad, 1, -1, "name", NULL)) >= 0))
            {
                /* yes, we're very intolerent of people who can't speak to us properly .. we are internal, after all */
                nad_free(nad);
                return 0;
            }

            srv = 0; nres = 0;
            while(srv < r->lookup_nsrv && nres == 0) {
                /* do the lookup */
                snprintf(zone, 256, "%s.%.*s", r->lookup_srv[srv], NAD_AVAL_L(nad, aname), NAD_AVAL(nad, aname));

                log_debug(ZONE, "trying srv lookup for %s", zone);
            
                srvs = dns_resolve(zone, DNS_QUERY_TYPE_SRV);

                if(srvs != NULL) {
                    /* resolve to A records */
                    for(srvscan = srvs; srvscan != NULL; srvscan = srvscan->next) {
                        log_debug(ZONE, "%s has srv %s, doing A lookup", zone, ((dns_srv_t) srvscan->rr)->name);

                        as = dns_resolve(((dns_srv_t) srvscan->rr)->name, DNS_QUERY_TYPE_A);

                        for(ascan = as; ascan != NULL; ascan = ascan->next) {
                            log_write(r->log, LOG_NOTICE, "[%s] resolved to %s:%d (%d seconds to live)", zone, (char *) ascan->rr, ((dns_srv_t) srvscan->rr)->port, ascan->ttl);

                            eip = nad_insert_elem(nad, 1, NAD_ENS(nad, 1), "ip", (char *) ascan->rr);

                            snprintf(num, 10, "%d", ((dns_srv_t) srvscan->rr)->port);
                            nad_set_attr(nad, eip, -1, "port", num, 0);

                            snprintf(num, 10, "%d", ascan->ttl);
                            nad_set_attr(nad, eip, -1, "ttl", num, 0);

                            nres++;
                        }

                        dns_free(as);
                    }

                    /* resolve to AAAA records */
                    if(r->resolve_aaaa) {
                        for(srvscan = srvs; srvscan != NULL; srvscan = srvscan->next) {
                            log_debug(ZONE, "%s has srv %s, doing AAAA lookup", zone, ((dns_srv_t) srvscan->rr)->name);

                            as = dns_resolve(((dns_srv_t) srvscan->rr)->name, DNS_QUERY_TYPE_AAAA);

                            for(ascan = as; ascan != NULL; ascan = ascan->next) {
                                log_write(r->log, LOG_NOTICE, "[%s] resolved to [%s]:%d (%d seconds to live)", zone, (char *)ascan->rr, ((dns_srv_t) srvscan->rr)->port, ascan->ttl);

                                eip = nad_insert_elem(nad, 1, NAD_ENS(nad, 1), "ip", (char *)ascan->rr);

                                snprintf(num, 10, "%d", ((dns_srv_t) srvscan->rr)->port);
                                nad_set_attr(nad, eip, -1, "port", num, 0);

                                snprintf(num, 10, "%d", ascan->ttl);
                                nad_set_attr(nad, eip, -1, "ttl", num, 0);

                                nres++;
                            }

                            dns_free(as);
                        }
                    }

                    dns_free(srvs);
                }

                srv++;
            }

            /* AAAA/A fallback */
            if(nres == 0) {
                snprintf(zone, 256, "%.*s", NAD_AVAL_L(nad, aname), NAD_AVAL(nad, aname));

                /* A lookup */
                log_debug(ZONE, "doing A lookup for %s", zone);

                as = dns_resolve(zone, DNS_QUERY_TYPE_A);
                for(ascan = as; ascan != NULL; ascan = ascan->next) {
                    log_write(r->log, LOG_NOTICE, "[%s] resolved to [%s:5269] (%d seconds to live)", zone, (char *) ascan->rr, ascan->ttl);

                    eip = nad_insert_elem(nad, 1, NAD_ENS(nad, 1), "ip", (char *) ascan->rr);

                    nad_set_attr(nad, eip, -1, "port", "5269", 4);

                    snprintf(num, 10, "%d", ascan->ttl);
                    nad_set_attr(nad, eip, -1, "ttl", num, 0);

                    nres++;
                }

                dns_free(as);

                /* AAAA lookup */
                if(r->resolve_aaaa) {
                    log_debug(ZONE, "doing AAAA lookup for %s", zone);

                    as = dns_resolve(zone, DNS_QUERY_TYPE_AAAA);
                    for(ascan = as; ascan != NULL; ascan = ascan->next)
                    {
                        log_write(r->log, LOG_NOTICE, "[%s] resolved to [%s]:5269 (%d seconds to live)", zone, (char *)ascan->rr, ascan->ttl);

                        eip = nad_insert_elem(nad, 1, NAD_ENS(nad, 1), "ip", (char *)ascan->rr);

                        nad_set_attr(nad, eip, -1, "port", "5269", 4);

                        snprintf(num, 10, "%d", ascan->ttl);
                        nad_set_attr(nad, eip, -1, "ttl", num, 0);

                        nres++;
                    }

                    dns_free(as);
                }
            }

            nad_set_attr(nad, 1, -1, "type", "result", 6);
            sx_nad_write(r->router, stanza_tofrom(nad, 0));

            if (nres == 0) {
               log_write(r->log, LOG_NOTICE, "[%s] could not be resolved", zone);
            }

            break;
        
        case event_CLOSED:
            mio_close(r->mio, r->fd);
            return -1;
    }

    return 0;
}

static int _resolver_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    resolver_t r = (resolver_t) arg;
    int nbytes;

    switch(a) {
        case action_READ:

            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(r->router);
                return 0;
            }

            log_debug(ZONE, "read action on fd %d", fd->fd);
            return sx_can_read(r->router);

        case action_WRITE:
            log_debug(ZONE, "write action on fd %d", fd->fd);
            return sx_can_write(r->router);

        case action_CLOSE:
            log_debug(ZONE, "close action on fd %d", fd->fd);
            log_write(r->log, LOG_NOTICE, "connection to router closed");

            resolver_lost_router = 1;

            /* we're offline */
            r->online = 0;

            break;

        case action_ACCEPT:
            break;
    }

    return 0;
}

static int _resolver_router_connect(resolver_t r) {
    log_write(r->log, LOG_NOTICE, "attempting connection to router at %s, port=%d", r->router_ip, r->router_port);

    r->fd = mio_connect(r->mio, r->router_port, r->router_ip, _resolver_mio_callback, (void *) r);
    if(r->fd == NULL) {
        if(errno == ECONNREFUSED)
            resolver_lost_router = 1;
        log_write(r->log, LOG_NOTICE, "connection attempt to router failed: %s (%d)", MIO_STRERROR(MIO_ERROR), MIO_ERROR);
        return 1;
    }

    r->router = sx_new(r->sx_env, r->fd->fd, _resolver_sx_callback, (void *) r);
    sx_client_init(r->router, 0, NULL, NULL, NULL, "1.0");

    return 0;
}

JABBER_MAIN("jabberd2resolver", "Jabber 2 Resolver", "Jabber Open Source Server: Resolver", "jabberd2router\0")
{
    resolver_t r;
    char *config_file;
    int optchar;
#ifdef POOL_DEBUG
    time_t pool_time = 0;
#endif

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

    jabber_signal(SIGINT, _resolver_signal);
    jabber_signal(SIGTERM, _resolver_signal);
#ifdef SIGHUP
    jabber_signal(SIGHUP, _resolver_signal_hup);
#endif
#ifdef SIGPIPE
    jabber_signal(SIGPIPE, SIG_IGN);
#endif

    r = (resolver_t) calloc(1, sizeof(struct resolver_st));

    /* load our config */
    r->config = config_new();

    config_file = CONFIG_DIR "/resolver.xml";

    /* cmdline parsing */
    while((optchar = getopt(argc, argv, "Dc:h?")) >= 0)
    {
        switch(optchar)
        {
            case 'c':
                config_file = optarg;
                break;
            case 'D':
#ifdef DEBUG
                set_debug_flag(1);
#else
                printf("WARN: Debugging not enabled.  Ignoring -D.\n");
#endif
                break;
            case 'h': case '?': default:
                fputs(
                    "resolver - jabberd asynchronous dns resolver (" VERSION ")\n"
                    "Usage: resolver <options>\n"
                    "Options are:\n"
                    "   -c <config>     config file to use [default: " CONFIG_DIR "/resolver.xml]\n"
#ifdef DEBUG
                    "   -D              Show debug output\n"
#endif
                    ,
                    stdout);
                config_free(r->config);
                free(r);
                return 1;
        }
    }

    if(config_load(r->config, config_file) != 0)
    {
        fputs("resolver: couldn't load config, aborting\n", stderr);
        config_free(r->config);
        free(r);
        return 2;
    }

    _resolver_config_expand(r);

    r->log = log_new(r->log_type, r->log_ident, r->log_facility);
    log_write(r->log, LOG_NOTICE, "starting up");

    _resolver_pidfile(r);

    r->sx_env = sx_env_new();

#ifdef HAVE_SSL
    if(r->router_pemfile != NULL) {
        r->sx_ssl = sx_env_plugin(r->sx_env, sx_ssl_init, NULL, r->router_pemfile, NULL, NULL);
        if(r->sx_ssl == NULL) {
            log_write(r->log, LOG_ERR, "failed to load SSL pemfile, SSL disabled");
            r->router_pemfile = NULL;
        }
    }
#endif

    /* get sasl online */
    r->sx_sasl = sx_env_plugin(r->sx_env, sx_sasl_init, "xmpp", NULL, NULL);
    if(r->sx_sasl == NULL) {
        log_write(r->log, LOG_ERR, "failed to initialise SASL context, aborting");
        exit(1);
    }

    r->mio = mio_new(MIO_MAXFD);

    r->retry_left = r->retry_init;
    _resolver_router_connect(r);

    while(!resolver_shutdown) {
        mio_run(r->mio, 5);

        if(resolver_logrotate) {
            log_write(r->log, LOG_NOTICE, "reopening log ...");
            log_free(r->log);
            r->log = log_new(r->log_type, r->log_ident, r->log_facility);
            log_write(r->log, LOG_NOTICE, "log started");

            resolver_logrotate = 0;
        }

        if(resolver_lost_router) {
            if(r->retry_left < 0) {
                log_write(r->log, LOG_NOTICE, "attempting reconnect");
                sleep(r->retry_sleep);
                resolver_lost_router = 0;
                _resolver_router_connect(r);
            }

            else if(r->retry_left == 0) {
                resolver_shutdown = 1;
            }

            else {
                log_write(r->log, LOG_NOTICE, "attempting reconnect (%d left)", r->retry_left);
                r->retry_left--;
                sleep(r->retry_sleep);
                resolver_lost_router = 0;
                _resolver_router_connect(r);
            }
        }

#ifdef POOL_DEBUG
        if(time(NULL) > pool_time + 60) {
            pool_stat(1);
            pool_time = time(NULL);
        }
#endif
    }

    log_write(r->log, LOG_NOTICE, "shutting down");
    
    sx_free(r->router);

    sx_env_free(r->sx_env);

    mio_free(r->mio);
    
    log_free(r->log);

    config_free(r->config);

    free(r);

#ifdef POOL_DEBUG
    pool_stat(1);
#endif

#ifdef HAVE_WINSOCK2_H
    WSACleanup();
#endif

    return 0;
}
