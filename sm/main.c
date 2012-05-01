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
#include <stringprep.h>

/** @file sm/main.c
  * @brief initialisation
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.57 $
  */

static sig_atomic_t sm_shutdown = 0;
static sig_atomic_t sm_logrotate = 0;
static sm_t sm = NULL;
static char* config_file;

static void _sm_signal(int signum)
{
    sm_shutdown = 1;
    sm_lost_router = 0;
}

static void _sm_signal_hup(int signum)
{
    config_t conf;

    log_write(sm->log, LOG_NOTICE, "HUP handled. reloading modules...");

    sm_logrotate = 1;

    /* reload dynamic modules */
    conf = config_new();
    if (conf && config_load(conf, config_file) == 0) {
        config_free(sm->config);
        sm->config = conf;
        /*_sm_config_expand(sm);*/ /* we want to reload modules only */
    } else {
        log_write(sm->log, LOG_WARNING, "couldn't reload config (%s)", config_file);
        if (conf) config_free(conf);
    }
    mm_free(sm->mm);
    sm->mm = mm_new(sm);
}

static void _sm_signal_usr1(int signum)
{
    set_debug_flag(0);
}

static void _sm_signal_usr2(int signum)
{
    set_debug_flag(1);
}

/** store the process id */
static void _sm_pidfile(sm_t sm) {
    char *pidfile;
    FILE *f;
    pid_t pid;

    pidfile = config_get_one(sm->config, "pidfile", 0);
    if(pidfile == NULL)
        return;

    pid = getpid();

    if((f = fopen(pidfile, "w+")) == NULL) {
        log_write(sm->log, LOG_ERR, "couldn't open %s for writing: %s", pidfile, strerror(errno));
        return;
    }

    if(fprintf(f, "%d", pid) < 0) {
        log_write(sm->log, LOG_ERR, "couldn't write to %s: %s", pidfile, strerror(errno));
        fclose(f);
        return;
    }

    fclose(f);

    log_write(sm->log, LOG_INFO, "process id is %d, written to %s", pid, pidfile);
}

/** pull values out of the config file */
static void _sm_config_expand(sm_t sm)
{
    char *str;
    config_elem_t elem;

    set_debug_log_from_config(sm->config);

    sm->id = config_get_one(sm->config, "id", 0);
    if(sm->id == NULL)
        sm->id = "sm";

    sm->router_ip = config_get_one(sm->config, "router.ip", 0);
    if(sm->router_ip == NULL)
        sm->router_ip = "127.0.0.1";

    sm->router_port = j_atoi(config_get_one(sm->config, "router.port", 0), 5347);

    sm->router_user = config_get_one(sm->config, "router.user", 0);
    if(sm->router_user == NULL)
        sm->router_user = "jabberd";
    sm->router_pass = config_get_one(sm->config, "router.pass", 0);
    if(sm->router_pass == NULL)
        sm->router_pass = "secret";

    sm->router_pemfile = config_get_one(sm->config, "router.pemfile", 0);

    sm->retry_init = j_atoi(config_get_one(sm->config, "router.retry.init", 0), 3);
    sm->retry_lost = j_atoi(config_get_one(sm->config, "router.retry.lost", 0), 3);
    if((sm->retry_sleep = j_atoi(config_get_one(sm->config, "router.retry.sleep", 0), 2)) < 1)
        sm->retry_sleep = 1;

    sm->log_type = log_STDOUT;
    if(config_get(sm->config, "log") != NULL) {
        if((str = config_get_attr(sm->config, "log", 0, "type")) != NULL) {
            if(strcmp(str, "file") == 0)
                sm->log_type = log_FILE;
            else if(strcmp(str, "syslog") == 0)
                sm->log_type = log_SYSLOG;
        }
    }

    if(sm->log_type == log_SYSLOG) {
        sm->log_facility = config_get_one(sm->config, "log.facility", 0);
        sm->log_ident = config_get_one(sm->config, "log.ident", 0);
        if(sm->log_ident == NULL)
            sm->log_ident = "jabberd/sm";
    } else if(sm->log_type == log_FILE)
        sm->log_ident = config_get_one(sm->config, "log.file", 0);
        
    elem = config_get(sm->config, "storage.limits.queries");
    if(elem != NULL)
    {
        sm->query_rate_total = j_atoi(elem->values[0], 0);
        if(sm->query_rate_total != 0)
        {
            sm->query_rate_seconds = j_atoi(j_attr((const char **) elem->attrs[0], "seconds"), 5);
            sm->query_rate_wait = j_atoi(j_attr((const char **) elem->attrs[0], "throttle"), 60);
        }
    }
}

static void _sm_hosts_expand(sm_t sm)
{
    config_elem_t elem;
    char id[1024];
    int i;

    elem = config_get(sm->config, "local.id");
    if(!elem) {
        /* use SM id */
        xhash_put(sm->hosts, pstrdup(xhash_pool(sm->hosts), sm->id), sm);
        log_write(sm->log, LOG_NOTICE, "id: %s", sm->id);
        return;
    }

    for(i = 0; i < elem->nvalues; i++) {
        /* stringprep ids (domain names) so that they are in canonical form */
        strncpy(id, elem->values[i], 1024);
        id[1023] = '\0';
        if (stringprep_nameprep(id, 1024) != 0) {
            log_write(sm->log, LOG_ERR, "cannot stringprep id %s, aborting", id);
            exit(1);
        }

        /* insert into vHosts xhash */
        xhash_put(sm->hosts, pstrdup(xhash_pool(sm->hosts), id), sm);

        log_write(sm->log, LOG_NOTICE, "[%s] configured", id);
    }
}

static int _sm_router_connect(sm_t sm) {
    log_write(sm->log, LOG_NOTICE, "attempting connection to router at %s, port=%d", sm->router_ip, sm->router_port);

    sm->fd = mio_connect(sm->mio, sm->router_port, sm->router_ip, NULL, sm_mio_callback, (void *) sm);
    if(sm->fd == NULL) {
        if(errno == ECONNREFUSED)
            sm_lost_router = 1;
        log_write(sm->log, LOG_NOTICE, "connection attempt to router failed: %s (%d)", MIO_STRERROR(MIO_ERROR), MIO_ERROR);
        return 1;
    }

    sm->router = sx_new(sm->sx_env, sm->fd->fd, sm_sx_callback, (void *) sm);
    sx_client_init(sm->router, 0, NULL, NULL, NULL, "1.0");

    return 0;
}

JABBER_MAIN("jabberd2sm", "Jabber 2 Session Manager", "Jabber Open Source Server: Session Manager", "jabberd2router\0")
{
    int optchar;
    sess_t sess;
    char id[1024];
#ifdef POOL_DEBUG
    time_t pool_time = 0;
#endif
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

    jabber_signal(SIGINT, _sm_signal);
    jabber_signal(SIGTERM, _sm_signal);
#ifdef SIGHUP
    jabber_signal(SIGHUP, _sm_signal_hup);
#endif
#ifdef SIGPIPE
    jabber_signal(SIGPIPE, SIG_IGN);
#endif
    jabber_signal(SIGUSR1, _sm_signal_usr1);
    jabber_signal(SIGUSR2, _sm_signal_usr2);


    sm = (sm_t) calloc(1, sizeof(struct sm_st));

    /* load our config */
    sm->config = config_new();

    config_file = CONFIG_DIR "/sm.xml";

    /* cmdline parsing */
    while((optchar = getopt(argc, argv, "Dc:hi:?")) >= 0)
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
            case 'i':
                cli_id = optarg;
                break;
            case 'h': case '?': default:
                fputs(
                    "sm - jabberd session manager (" VERSION ")\n"
                    "Usage: sm <options>\n"
                    "Options are:\n"
                    "   -c <config>     config file to use [default: " CONFIG_DIR "/sm.xml]\n"
                    "   -i id           Override <id> config element\n"
#ifdef DEBUG
                    "   -D              Show debug output\n"
#endif
                    ,
                    stdout);
                config_free(sm->config);
                free(sm);
                return 1;
        }
    }

    if(config_load_with_id(sm->config, config_file, cli_id) != 0)
    {
        fputs("sm: couldn't load config, aborting\n", stderr);
        config_free(sm->config);
        free(sm);
        return 2;
    }

    _sm_config_expand(sm);

    sm->log = log_new(sm->log_type, sm->log_ident, sm->log_facility);
    log_write(sm->log, LOG_NOTICE, "starting up");

    /* stringprep id (domain name) so that it's in canonical form */
    strncpy(id, sm->id, 1024);
    id[sizeof(id)-1] = '\0';
    if (stringprep_nameprep(id, 1024) != 0) {
        log_write(sm->log, LOG_ERR, "cannot stringprep id %s, aborting", sm->id);
        exit(1);
    }
    sm->id = id;

    _sm_pidfile(sm);

    sm_signature(sm, PACKAGE " sm " VERSION);

    /* start storage */
    sm->st = storage_new(sm->config, sm->log);
    if (sm->st == NULL) {
        log_write(sm->log, LOG_ERR, "failed to initialise one or more storage drivers, aborting");
        exit(1);
    }

    /* pre-index known namespaces */
    sm->xmlns = xhash_new(101);
    xhash_put(sm->xmlns, uri_AUTH, (void *) ns_AUTH);
    xhash_put(sm->xmlns, uri_REGISTER, (void *) ns_REGISTER);
    xhash_put(sm->xmlns, uri_ROSTER, (void *) ns_ROSTER);
    xhash_put(sm->xmlns, uri_AGENTS, (void *) ns_AGENTS);
    xhash_put(sm->xmlns, uri_DELAY, (void *) ns_DELAY);
    xhash_put(sm->xmlns, uri_BROWSE, (void *) ns_BROWSE);
    xhash_put(sm->xmlns, uri_EVENT, (void *) ns_EVENT);
    xhash_put(sm->xmlns, uri_GATEWAY, (void *) ns_GATEWAY);
    xhash_put(sm->xmlns, uri_EXPIRE, (void *) ns_EXPIRE);
    xhash_put(sm->xmlns, uri_SEARCH, (void *) ns_SEARCH);
    xhash_put(sm->xmlns, uri_DISCO, (void *) ns_DISCO);
    xhash_put(sm->xmlns, uri_DISCO_ITEMS, (void *) ns_DISCO_ITEMS);
    xhash_put(sm->xmlns, uri_DISCO_INFO, (void *) ns_DISCO_INFO);
    sm->xmlns_refcount = xhash_new(101);

    /* supported features */
    sm->features = xhash_new(101);

    /* load acls */
    sm->acls = aci_load(sm);

    /* the core supports iq, everything else is handled by the modules */
    feature_register(sm, "iq");

    /* startup the modules */
    sm->mm = mm_new(sm);

    log_write(sm->log, LOG_NOTICE, "version: %s", sm->signature);

    sm->sessions = xhash_new(401);

    sm->users = xhash_new(401);

    sm->query_rates = xhash_new(101);

    sm->sx_env = sx_env_new();

#ifdef HAVE_SSL
    if(sm->router_pemfile != NULL) {
        sm->sx_ssl = sx_env_plugin(sm->sx_env, sx_ssl_init, NULL, sm->router_pemfile, NULL, NULL);
        if(sm->sx_ssl == NULL) {
            log_write(sm->log, LOG_ERR, "failed to load SSL pemfile, SSL disabled");
            sm->router_pemfile = NULL;
        }
    }
#endif

    /* get sasl online */
    sm->sx_sasl = sx_env_plugin(sm->sx_env, sx_sasl_init, "xmpp", NULL, NULL);
    if(sm->sx_sasl == NULL) {
        log_write(sm->log, LOG_ERR, "failed to initialise SASL context, aborting");
        exit(1);
    }

    sm->mio = mio_new(MIO_MAXFD);

    /* vHosts map */
    sm->hosts = xhash_new(1021);
    _sm_hosts_expand(sm);

    sm->retry_left = sm->retry_init;
    _sm_router_connect(sm);
    
    while(!sm_shutdown) {
        mio_run(sm->mio, 5);

        if(sm_logrotate) {
            set_debug_log_from_config(sm->config);

            log_write(sm->log, LOG_NOTICE, "reopening log ...");
            log_free(sm->log);
            sm->log = log_new(sm->log_type, sm->log_ident, sm->log_facility);
            log_write(sm->log, LOG_NOTICE, "log started");

            sm_logrotate = 0;
        }

        if(sm_lost_router) {
            if(sm->retry_left < 0) {
                log_write(sm->log, LOG_NOTICE, "attempting reconnect");
                sleep(sm->retry_sleep);
                sm_lost_router = 0;
                if (sm->router) sx_free(sm->router);
                _sm_router_connect(sm);
            }

            else if(sm->retry_left == 0) {
                sm_shutdown = 1;
            }

            else {
                log_write(sm->log, LOG_NOTICE, "attempting reconnect (%d left)", sm->retry_left);
                sm->retry_left--;
                sleep(sm->retry_sleep);
                sm_lost_router = 0;
                if (sm->router) sx_free(sm->router);
                _sm_router_connect(sm);
            }
        }

#ifdef POOL_DEBUG
        if(time(NULL) > pool_time + 60) {
            pool_stat(1);
            pool_time = time(NULL);
        }
#endif
    }

    log_write(sm->log, LOG_NOTICE, "shutting down");

    /* shut down sessions */
    if(xhash_iter_first(sm->sessions))
        do {
            xhash_iter_get(sm->sessions, NULL, NULL, (void *) &sess);
            sm_c2s_action(sess, "ended", NULL);
            sess_end(sess);
        } while (xhash_iter_next(sm->sessions));

    xhash_free(sm->sessions);

    if (sm->fd) mio_close(sm->mio, sm->fd);
    mio_free(sm->mio);

    mm_free(sm->mm);
    storage_free(sm->st);

    aci_unload(sm->acls);
    xhash_free(sm->acls);
    xhash_free(sm->features);
    xhash_free(sm->xmlns);
    xhash_free(sm->xmlns_refcount);
    xhash_free(sm->users);
    xhash_free(sm->hosts);
    xhash_free(sm->query_rates);

    sx_free(sm->router);

    sx_env_free(sm->sx_env);

    log_free(sm->log);

    config_free(sm->config);

    free(sm);

#ifdef POOL_DEBUG
    pool_stat(1);
#endif

#ifdef HAVE_WINSOCK2_H
    WSACleanup();
#endif

    return 0;
}
