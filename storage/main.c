/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2004 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#include "storage.h"

static int storage_shutdown = 0;
static int storage_lost_router = 0;
static int storage_logrotate = 0;

static void _storage_signal(int signum) {
    storage_shutdown = 1;
    storage_lost_router = 0;
}

static void _storage_signal_hup(int signum) {
    storage_logrotate = 1;
}

/** store the process id */
static void _storage_pidfile(storage_t st) {
    char *pidfile;
    FILE *f;
    pid_t pid;

    pidfile = config_get_one(st->config, "pidfile", 0);
    if(pidfile == NULL)
        return;

    pid = getpid();

    if((f = fopen(pidfile, "w+")) == NULL) {
        log_write(st->log, LOG_ERR, "couldn't open %s for writing: %s", pidfile, strerror(errno));
        return;
    }

    if(fprintf(f, "%d", pid) < 0) {
        log_write(st->log, LOG_ERR, "couldn't write to %s: %s", pidfile, strerror(errno));
        return;
    }

    fclose(f);

    log_write(st->log, LOG_INFO, "process id is %d, written to %s", pid, pidfile);
}

/** pull values out of the config file */
static void _storage_config_expand(storage_t st) {
    char *str;

    st->id = config_get_one(st->config, "id", 0);
    if(st->id == NULL)
        st->id = "storage";

    st->router_ip = config_get_one(st->config, "router.ip", 0);
    if(st->router_ip == NULL)
        st->router_ip = "127.0.0.1";

    st->router_port = j_atoi(config_get_one(st->config, "router.port", 0), 5347);

    st->router_user = config_get_one(st->config, "router.user", 0);
    if(st->router_user == NULL)
        st->router_user = "jabberd";
    st->router_pass = config_get_one(st->config, "router.pass", 0);
    if(st->router_pass == NULL)
        st->router_pass = "secret";

    st->router_pemfile = config_get_one(st->config, "router.pemfile", 0);

    st->retry_init = j_atoi(config_get_one(st->config, "router.retry.init", 0), 3);
    st->retry_lost = j_atoi(config_get_one(st->config, "router.retry.lost", 0), 3);
    if((st->retry_sleep = j_atoi(config_get_one(st->config, "router.retry.sleep", 0), 2)) < 1)
        st->retry_sleep = 1;
    
    st->log_type = log_STDOUT;
    if(config_get(st->config, "log") != NULL) {
        if((str = config_get_attr(st->config, "log", 0, "type")) != NULL) {
            if(strcmp(str, "file") == 0)
                st->log_type = log_FILE;
            else if(strcmp(str, "syslog") == 0)
                st->log_type = log_SYSLOG;
        }
    }

    if(st->log_type == log_SYSLOG) {
        st->log_facility = config_get_one(st->config, "log.facility", 0);
        st->log_ident = config_get_one(st->config, "log.ident", 0);
        if(st->log_ident == NULL)
            st->log_ident = "jabberd/storage";
    } else if(st->log_type == log_FILE)
        st->log_ident = config_get_one(st->config, "log.file", 0);
}

static int _storage_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    storage_t st = (storage_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    sx_error_t *sxe;
    int elem, len, ns, attr;
    nad_t nad;

    switch(e) {
        case event_WANT_READ:
            log_debug("want read");
            mio_read(st->mio, st->fd);
            break;

        case event_WANT_WRITE:
            log_debug("want write");
            mio_write(st->mio, st->fd);
            break;

        case event_READ:
            log_debug("reading from %d", st->fd);

            /* do the read */
            len = recv(st->fd, buf->data, buf->len, 0);

            if(len < 0) {
                if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN) {
                    buf->len = 0;
                    return 0;
                }

                log_write(st->log, LOG_NOTICE, "[%d] [router] read error: %s (%d)", st->fd, strerror(errno), errno);

                sx_kill(s);
                
                return -1;
            }

            else if(len == 0) {
                /* they went away */
                sx_kill(s);

                return -1;
            }

            log_debug("read %d bytes", len);

            buf->len = len;

            return len;

        case event_WRITE:
            log_debug("writing to %d", st->fd);

            len = send(st->fd, buf->data, buf->len, 0);
            if(len >= 0) {
                log_debug("%d bytes written", len);
                return len;
            }

            if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)
                return 0;

            log_write(st->log, LOG_NOTICE, "[%d] [router] write error: %s (%d)", st->fd, strerror(errno), errno);

            sx_kill(s);

            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            log_write(st->log, LOG_NOTICE, "error from router: %s (%s)", sxe->generic, sxe->specific);

            if(sxe->code == SX_ERR_AUTH)
                sx_close(s);

            break;

        case event_STREAM:
            break;

        case event_OPEN:
            log_write(st->log, LOG_NOTICE, "connection to router established");

            nad = nad_new(st->router->nad_cache);
            ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
            nad_append_elem(nad, ns, "bind", 0);
            nad_append_attr(nad, -1, "name", st->id);

            log_debug("requesting component bind for '%s'", st->id);

            sx_nad_write(st->router, nad);

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
                    log_debug("got a non-features packet on an unauth'd stream, dropping");
                    nad_free(nad);
                    return 0;
                }

#ifdef HAVE_SSL
                /* starttls if we can */
                if(st->sx_ssl != NULL && s->ssf == 0) {
                    ns = nad_find_scoped_namespace(nad, uri_TLS, NULL);
                    if(ns >= 0) {
                        elem = nad_find_elem(nad, 0, ns, "starttls", 1);
                        if(elem >= 0) {
                            if(sx_ssl_client_starttls(st->sx_ssl, s, NULL) == 0) {
                                nad_free(nad);
                                return 0;
                            }
                            log_write(st->log, LOG_NOTICE, "unable to establish encrypted session with router");
                        }
                    }
                }
#endif

                /* !!! pull the list of mechanirs, and choose the best one.
                 *     if there isn't an appropriate one, error and bail */

                /* authenticate */
                sx_sasl_auth(st->sx_sasl, s, "DIGEST-MD5", st->router_user, st->router_pass, NULL);

                nad_free(nad);
                return 0;
            }

            /* watch for the bind response */
            if(s->state == state_OPEN && !st->online) {
                if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT) || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0 || NAD_ENAME_L(nad, 0) != 4 || strncmp("bind", NAD_ENAME(nad, 0), 4)) {
                    log_debug("got a packet from router, but we're not online, dropping");
                    nad_free(nad);
                    return 0;
                }

                /* catch errors */
                attr = nad_find_attr(nad, 0, -1, "error", NULL);
                if(attr >= 0) {
                    log_write(st->log, LOG_NOTICE, "router refused bind request (%.*s)", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
                    exit(1);
                }

                log_debug("coming online");

                /* we're online */
                st->online = st->started = 1;
                st->retry_left = st->retry_lost;

                log_write(st->log, LOG_NOTICE, "ready for requests", st->id);

                nad_free(nad);
                return 0;
            }

            break;
        
        case event_CLOSED:
            mio_close(st->mio, st->fd);
            break;
    }

    return 0;
}

static int _storage_mio_callback(mio_t m, mio_action_t a, int fd, void *data, void *arg) {
    storage_t st = (storage_t) arg;
    int nbytes;

    switch(a) {
        case action_READ:

            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(st->router);
                return 0;
            }

            log_debug("read action on fd %d", fd);
            return sx_can_read(st->router);

        case action_WRITE:
            log_debug("write action on fd %d", fd);
            return sx_can_write(st->router);

        case action_CLOSE:
            log_debug("close action on fd %d", fd);
            log_write(st->log, LOG_NOTICE, "connection to router closed");

            storage_lost_router = 1;

            /* we're offline */
            st->online = 0;

            break;

        case action_ACCEPT:
            break;
    }

    return 0;
}

static int _storage_router_connect(storage_t st) {
    log_write(st->log, LOG_NOTICE, "attempting connection to router at %s, port=%d", st->router_ip, st->router_port);

    st->fd = mio_connect(st->mio, st->router_port, st->router_ip, _storage_mio_callback, (void *) st);
    if(st->fd < 0) {
        if(errno == ECONNREFUSED)
            storage_lost_router = 1;
        log_write(st->log, LOG_NOTICE, "connection attempt to router failed: %s (%d)", strerror(errno), errno);
        return 1;
    }

    st->router = sx_new(st->sx_env, st->fd, _storage_sx_callback, (void *) st);
    sx_client_init(st->router, 0, NULL, NULL, NULL, "1.0");

    return 0;
}

int main(int argc, char **argv)
{
    storage_t st;
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

    signal(SIGINT, _storage_signal);
    signal(SIGTERM, _storage_signal);
#ifdef SIGHUP
    signal(SIGHUP, _storage_signal_hup);
#endif
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    st = (storage_t) malloc(sizeof(struct storage_st));
    memset(st, 0, sizeof(struct storage_st));

    /* load our config */
    st->config = config_new();

    config_file = CONFIG_DIR "/storage.xml";

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
                    "storage - jabberd storage manager (" VERSION ")\n"
                    "Usage: storage <options>\n"
                    "Options are:\n"
                    "   -c <config>     config file to use [default: " CONFIG_DIR "/storage.xml]\n"
#ifdef DEBUG
                    "   -D              Show debug output\n"
#endif
                    ,
                    stdout);
                config_free(st->config);
                free(st);
                return 1;
        }
    }

    if(config_load(st->config, config_file) != 0)
    {
        fputs("storage: couldn't load config, aborting\n", stderr);
        config_free(st->config);
        free(st);
        return 2;
    }

    _storage_config_expand(st);

    st->log = log_new(st->log_type, st->log_ident, st->log_facility);
    log_write(st->log, LOG_NOTICE, "starting up");

    _storage_pidfile(st);

    st->sx_env = sx_env_new();

#ifdef HAVE_SSL
    if(st->router_pemfile != NULL) {
        st->sx_ssl = sx_env_plugin(st->sx_env, sx_ssl_init, st->router_pemfile);
        if(st->sx_ssl == NULL) {
            log_write(st->log, LOG_ERR, "failed to load SSL pemfile, SSL disabled");
            st->router_pemfile = NULL;
        }
    }
#endif

    /* get sasl online */
    st->sx_sasl = sx_env_plugin(st->sx_env, sx_sasl_init, NULL, NULL, 0);
    if(st->sx_sasl == NULL) {
        log_write(st->log, LOG_ERR, "failed to initialise SASL context, aborting");
        exit(1);
    }

    st->mio = mio_new(1023);

    st->retry_left = st->retry_init;
    _storage_router_connect(st);

    while(!storage_shutdown) {
        mio_run(st->mio, 5);

        if(storage_logrotate) {
            log_write(st->log, LOG_NOTICE, "reopening log ...");
            log_free(st->log);
            st->log = log_new(st->log_type, st->log_ident, st->log_facility);
            log_write(st->log, LOG_NOTICE, "log started");

            storage_logrotate = 0;
        }

        if(storage_lost_router) {
            if(st->retry_left < 0) {
                log_write(st->log, LOG_NOTICE, "attempting reconnect");
                sleep(st->retry_sleep);
                storage_lost_router = 0;
                _storage_router_connect(st);
            }

            else if(st->retry_left == 0) {
                storage_shutdown = 1;
            }

            else {
                log_write(st->log, LOG_NOTICE, "attempting reconnect (%d left)", st->retry_left);
                st->retry_left--;
                sleep(st->retry_sleep);
                storage_lost_router = 0;
                _storage_router_connect(st);
            }
        }

#ifdef POOL_DEBUG
        if(time(NULL) > pool_time + 60) {
            pool_stat(1);
            pool_time = time(NULL);
        }
#endif
    }

    log_write(st->log, LOG_NOTICE, "shutting down");
    
    sx_free(st->router);

    sx_env_free(st->sx_env);

    mio_free(st->mio);
    
    log_free(st->log);

    config_free(st->config);

    free(st);

#ifdef POOL_DEBUG
    pool_stat(1);
#endif

#ifdef HAVE_WINSOCK2_H
    WSACleanup();
#endif

    return 0;
}
