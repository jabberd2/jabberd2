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

#include "router.h"

static sig_atomic_t router_shutdown = 0;
static sig_atomic_t router_logrotate = 0;

static void router_signal(int signum)
{
    router_shutdown = 1;
}

static void router_signal_hup(int signum)
{
    router_logrotate = 1;
}

static void router_signal_usr1(int signum)
{
    set_debug_flag(0);
}

static void router_signal_usr2(int signum)
{
    set_debug_flag(1);
}

/** store the process id */
static void _router_pidfile(router_t r) {
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
static void _router_config_expand(router_t r)
{
    char *str, *ip, *mask, *name, *target;
    config_elem_t elem;
    int i, len;
    alias_t alias;

    r->id = config_get_one(r->config, "id", 0);
    if(r->id == NULL)
        r->id = "router";

    set_debug_log_from_config(r->config);

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
            r->log_ident = "jabberd/router";
    } else if(r->log_type == log_FILE)
        r->log_ident = config_get_one(r->config, "log.file", 0);

    r->local_ip = config_get_one(r->config, "local.ip", 0);
    if(r->local_ip == NULL)
        r->local_ip = "0.0.0.0";

    r->local_port = j_atoi(config_get_one(r->config, "local.port", 0), 5347);

    r->local_secret = config_get_one(r->config, "local.secret", 0);

    r->local_pemfile = config_get_one(r->config, "local.pemfile", 0);

    r->io_max_fds = j_atoi(config_get_one(r->config, "io.max_fds", 0), 1024);

    elem = config_get(r->config, "io.limits.bytes");
    if(elem != NULL)
    {
        r->byte_rate_total = j_atoi(elem->values[0], 0);
        if(r->byte_rate_total != 0)
        {
            r->byte_rate_seconds = j_atoi(j_attr((const char **) elem->attrs[0], "seconds"), 5);
            r->byte_rate_wait = j_atoi(j_attr((const char **) elem->attrs[0], "throttle"), 5);
        }
    }

    elem = config_get(r->config, "io.limits.connects");
    if(elem != NULL)
    {
        r->conn_rate_total = j_atoi(elem->values[0], 0);
        if(r->conn_rate_total != 0)
        {
            r->conn_rate_seconds = j_atoi(j_attr((const char **) elem->attrs[0], "seconds"), 5);
            r->conn_rate_wait = j_atoi(j_attr((const char **) elem->attrs[0], "throttle"), 5);
        }
    }

    str = config_get_one(r->config, "io.access.order", 0);
    if(str == NULL || strcmp(str, "deny,allow") != 0)
        r->access = access_new(0);
    else
        r->access = access_new(1);

    elem = config_get(r->config, "io.access.allow");
    if(elem != NULL)
    {
        for(i = 0; i < elem->nvalues; i++)
        {
            ip = j_attr((const char **) elem->attrs[i], "ip");
            mask = j_attr((const char **) elem->attrs[i], "mask");

            if(ip == NULL)
                continue;

            if(mask == NULL)
                mask = "255.255.255.255";

            access_allow(r->access, ip, mask);
        }
    }

    elem = config_get(r->config, "io.access.deny");
    if(elem != NULL)
    {
        for(i = 0; i < elem->nvalues; i++)
        {
            ip = j_attr((const char **) elem->attrs[i], "ip");
            mask = j_attr((const char **) elem->attrs[i], "mask");

            if(ip == NULL)
                continue;

            if(mask == NULL)
                mask = "255.255.255.255";

            access_deny(r->access, ip, mask);
        }
    }

    /* aliases */
    elem = config_get(r->config, "aliases.alias");
    if(elem != NULL)
        for(i = 0; i < elem->nvalues; i++) {
            name = j_attr((const char **) elem->attrs[i], "name");
            target = j_attr((const char **) elem->attrs[i], "target");

            if(name == NULL || target == NULL)
                continue;

            alias = (alias_t) calloc(1, sizeof(struct alias_st));

            alias->name = name;
            alias->target = target;

            alias->next = r->aliases;
            r->aliases = alias;
        }

    /* message logging to flat file */
    r->message_logging_enabled = j_atoi(config_get_one(r->config, "message_logging.enabled", 0), 0);
    r->message_logging_file = config_get_one(r->config, "message_logging.file", 0);

    r->check_interval = j_atoi(config_get_one(r->config, "check.interval", 0), 60);
    r->check_keepalive = j_atoi(config_get_one(r->config, "check.keepalive", 0), 0);
}

static int _router_sx_sasl_callback(int cb, void *arg, void ** res, sx_t s, void *cbarg) {
    router_t r = (router_t) cbarg;
    sx_sasl_creds_t creds;
    static char buf[1024];
    char *pass;

    switch(cb) {
        case sx_sasl_cb_GET_REALM:
            strcpy(buf, "jabberd-router");
            *res = (void *)buf;
            return sx_sasl_ret_OK;
            break;

        case sx_sasl_cb_GET_PASS:
            creds = (sx_sasl_creds_t) arg;

            log_debug(ZONE, "sx sasl callback: get pass (authnid=%s, realm=%s)", creds->authnid, creds->realm);

            pass = xhash_get(r->users, creds->authnid);
            if(pass == NULL)
                return sx_sasl_ret_FAIL;

            *res = (void *)pass;
            return sx_sasl_ret_OK;
            break;

        case sx_sasl_cb_CHECK_PASS:
            creds = (sx_sasl_creds_t) arg;

            log_debug(ZONE, "sx sasl callback: check pass (authnid=%s, realm=%s)", creds->authnid, creds->realm);

            pass = xhash_get(r->users, creds->authnid);
            if(pass == NULL || strcmp(creds->pass, pass) != 0)
                return sx_sasl_ret_OK;

            return sx_sasl_ret_FAIL;
            break;

        case sx_sasl_cb_CHECK_AUTHZID:
        creds = (sx_sasl_creds_t) arg;

        if (strcmp(creds->authnid, creds->authzid) == 0)
                return sx_sasl_ret_OK;
        else
                return sx_sasl_ret_FAIL;
            break;

        case sx_sasl_cb_CHECK_MECH:

            if (strcasecmp((char *)arg,"DIGEST-MD5")==0)
                return sx_sasl_ret_OK;

            return sx_sasl_ret_FAIL;
            break;

        default:
            break;
    }

    return sx_sasl_ret_FAIL;
}

static void _router_time_checks(router_t r) {
   component_t target;
   time_t now;
   union xhashv xhv;

   now = time(NULL);

   /* loop the components and distribute an space on idle connections*/
   if(xhash_iter_first(r->components))
       do {
          xhv.comp_val = &target;
          xhash_iter_get(r->components, NULL, NULL, xhv.val);

         if(r->check_keepalive > 0 && target->last_activity > 0 && now > target->last_activity + r->check_keepalive && target->s->state >= state_STREAM) {
               log_debug(ZONE, "sending keepalive for %d", target->fd->fd);
               sx_raw_write(target->s, " ", 1);
          }
       } while(xhash_iter_next(r->components));
   return;
}


JABBER_MAIN("jabberd2router", "Jabber 2 Router", "Jabber Open Source Server: Router", NULL)
{
    router_t r;
    char *config_file;
    int optchar;
    rate_t rt;
    component_t comp;
    union xhashv xhv;
    int close_wait_max;
    const char *cli_id = 0;

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

    jabber_signal(SIGINT, router_signal);
    jabber_signal(SIGTERM, router_signal);
#ifdef SIGHUP
    jabber_signal(SIGHUP, router_signal_hup);
#endif
#ifdef SIGPIPE
    jabber_signal(SIGPIPE, SIG_IGN);
#endif
    jabber_signal(SIGUSR1, router_signal_usr1);
    jabber_signal(SIGUSR2, router_signal_usr2);

    r = (router_t) calloc(1, sizeof(struct router_st));

    /* load our config */
    r->config = config_new();

    config_file = CONFIG_DIR "/router.xml";

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
                    "router - jabberd router (" VERSION ")\n"
                    "Usage: router <options>\n"
                    "Options are:\n"
                    "   -c <config>     config file to use [default: " CONFIG_DIR "/router.xml]\n"
                    "   -i id           Override <id> config element\n"
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

    if(config_load_with_id(r->config, config_file, cli_id) != 0)
    {
        fputs("router: couldn't load config, aborting\n", stderr);
        config_free(r->config);
        free(r);
        return 2;
    }

    _router_config_expand(r);

    r->log = log_new(r->log_type, r->log_ident, r->log_facility);
    log_write(r->log, LOG_NOTICE, "starting up");

    _router_pidfile(r);

    user_table_load(r);

    r->aci = aci_load(r);

    if(filter_load(r)) exit(1);

    r->conn_rates = xhash_new(101);

    r->components = xhash_new(101);
    r->routes = xhash_new(101);

    r->log_sinks = xhash_new(101);

    r->dead = jqueue_new();
    r->closefd = jqueue_new();
    r->deadroutes = jqueue_new();

    r->sx_env = sx_env_new();

#ifdef HAVE_SSL
    if(r->local_pemfile != NULL) {
        r->sx_ssl = sx_env_plugin(r->sx_env, sx_ssl_init, NULL, r->local_pemfile, NULL, NULL);
        if(r->sx_ssl == NULL)
            log_write(r->log, LOG_ERR, "failed to load SSL pemfile, SSL disabled");
    }
#endif

    /* get sasl online */
    r->sx_sasl = sx_env_plugin(r->sx_env, sx_sasl_init, "jabberd-router", _router_sx_sasl_callback, (void *) r);
    if(r->sx_sasl == NULL) {
        log_write(r->log, LOG_ERR, "failed to initialise SASL context, aborting");
        exit(1);
    }

    r->mio = mio_new(r->io_max_fds);

    r->fd = mio_listen(r->mio, r->local_port, r->local_ip, router_mio_callback, (void *) r);
    if(r->fd == NULL) {
        log_write(r->log, LOG_ERR, "[%s, port=%d] unable to listen (%s)", r->local_ip, r->local_port, MIO_STRERROR(MIO_ERROR));
        exit(1);
    }

    log_write(r->log, LOG_NOTICE, "[%s, port=%d] listening for incoming connections", r->local_ip, r->local_port, MIO_STRERROR(MIO_ERROR));

    while(!router_shutdown)
    {
        mio_run(r->mio, 5);

        if(router_logrotate)
        {
            set_debug_log_from_config(r->config);

            log_write(r->log, LOG_NOTICE, "reopening log ...");
            log_free(r->log);
            r->log = log_new(r->log_type, r->log_ident, r->log_facility);
            log_write(r->log, LOG_NOTICE, "log started");

            log_write(r->log, LOG_NOTICE, "reloading filter ...");
            filter_unload(r);
            filter_load(r);

            log_write(r->log, LOG_NOTICE, "reloading users ...");
            user_table_unload(r);
            user_table_load(r);

            router_logrotate = 0;
        }

        /* cleanup dead sx_ts */
        while(jqueue_size(r->dead) > 0)
            sx_free((sx_t) jqueue_pull(r->dead));

        /* cleanup closed fd */
        while(jqueue_size(r->closefd) > 0)
            mio_close(r->mio, (mio_fd_t) jqueue_pull(r->closefd));

        /* cleanup dead routes */
        while(jqueue_size(r->deadroutes) > 0)
            routes_free((routes_t) jqueue_pull(r->deadroutes));

        /* time checks */
        if(r->check_interval > 0 && time(NULL) >= r->next_check) {
            log_debug(ZONE, "running time checks");

            _router_time_checks(r);

            r->next_check = time(NULL) + r->check_interval;
            log_debug(ZONE, "next time check at %d", r->next_check);
        }

#ifdef POOL_DEBUG
        if(time(NULL) > pool_time + 60) {
            pool_stat(1);
            pool_time = time(NULL);
        }
#endif
    }

    log_write(r->log, LOG_NOTICE, "shutting down");

    /* stop accepting new connections */
    if (r->fd) {
        // HACK Do not call router_mio_callback(action_CLOSE) for listenning socket, Just close it and forget.
        mio_app(r->mio, r->fd, NULL, NULL);
        mio_close(r->mio, r->fd);
    }

    /*
     * !!! issue remote shutdowns to each service, so they can clean up.
     *     we'll need to mio_run() until they all disconnect, so that
     *     the the last packets (eg sm presence unavailables) can get to
     *     their destinations
     */

    close_wait_max = 30; /* time limit for component shutdown */

    /* close connections to components */
    xhv.comp_val = &comp;
    if(xhash_iter_first(r->components))
        do {
            xhash_iter_get(r->components, NULL, NULL, xhv.val);
            log_debug(ZONE, "close component %p", comp);
            if (comp) sx_close(comp->s);
            mio_run(r->mio, 5000);
            if (1 > close_wait_max--) break;
            sleep(1);
            while(jqueue_size(r->closefd) > 0)
                mio_close(r->mio, (mio_fd_t) jqueue_pull(r->closefd));
        } while (xhash_iter_next(r->components));

    xhash_free(r->components);

    /* cleanup dead sx_ts */
    while(jqueue_size(r->dead) > 0)
       sx_free((sx_t) jqueue_pull(r->dead));
    jqueue_free(r->dead);

    while(jqueue_size(r->closefd) > 0)
        mio_close(r->mio, (mio_fd_t) jqueue_pull(r->closefd));
    jqueue_free(r->closefd);

    /* cleanup dead routes - probably just showed up (route was just closed) */
    while(jqueue_size(r->deadroutes) > 0)
        routes_free((routes_t) jqueue_pull(r->deadroutes));
    jqueue_free(r->deadroutes);

    /* walk r->conn_rates and free */
    xhv.rt_val = &rt;
    if(xhash_iter_first(r->conn_rates))
        do {
            xhash_iter_get(r->conn_rates, NULL, NULL, xhv.val);
            rate_free(rt);
        } while(xhash_iter_next(r->conn_rates));

    xhash_free(r->conn_rates);

    xhash_free(r->log_sinks);

    /* walk r->routes and free */
    if (xhash_iter_first(r->routes))
        do {
            routes_t p;
            xhash_iter_get(r->routes, NULL, NULL, (void *) &p);
            routes_free(p);
        } while(xhash_iter_next(r->routes));
    xhash_free(r->routes);

    /* unload users */
    user_table_unload(r);

    /* unload acls */
    aci_unload(r->aci);

    /* unload filter */
    filter_unload(r);

    sx_env_free(r->sx_env);

    mio_free(r->mio);

    access_free(r->access);

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
