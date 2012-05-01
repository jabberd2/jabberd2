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

#include "c2s.h"

#include <stringprep.h>

static sig_atomic_t c2s_shutdown = 0;
sig_atomic_t c2s_lost_router = 0;
static sig_atomic_t c2s_logrotate = 0;
static sig_atomic_t c2s_sighup = 0;

static void _c2s_signal(int signum)
{
    c2s_shutdown = 1;
    c2s_lost_router = 0;
}

static void _c2s_signal_hup(int signum)
{
    c2s_logrotate = 1;
    c2s_sighup = 1;
}

static void _c2s_signal_usr1(int signum)
{
    set_debug_flag(0);
}

static void _c2s_signal_usr2(int signum)
{
    set_debug_flag(1);
}

/** store the process id */
static void _c2s_pidfile(c2s_t c2s) {
    char *pidfile;
    FILE *f;
    pid_t pid;

    pidfile = config_get_one(c2s->config, "pidfile", 0);
    if(pidfile == NULL)
        return;

    pid = getpid();

    if((f = fopen(pidfile, "w+")) == NULL) {
        log_write(c2s->log, LOG_ERR, "couldn't open %s for writing: %s", pidfile, strerror(errno));
        return;
    }

    if(fprintf(f, "%d", pid) < 0) {
        log_write(c2s->log, LOG_ERR, "couldn't write to %s: %s", pidfile, strerror(errno));
        fclose(f);
        return;
    }

    fclose(f);

    log_write(c2s->log, LOG_INFO, "process id is %d, written to %s", pid, pidfile);
}
/** pull values out of the config file */
static void _c2s_config_expand(c2s_t c2s)
{
    char *str, *ip, *mask;
    char *req_domain, *to_address, *to_port;
    config_elem_t elem;
    int i;
    stream_redirect_t sr;

    set_debug_log_from_config(c2s->config);

    c2s->id = config_get_one(c2s->config, "id", 0);
    if(c2s->id == NULL)
        c2s->id = "c2s";

    c2s->router_ip = config_get_one(c2s->config, "router.ip", 0);
    if(c2s->router_ip == NULL)
        c2s->router_ip = "127.0.0.1";

    c2s->router_port = j_atoi(config_get_one(c2s->config, "router.port", 0), 5347);

    c2s->router_user = config_get_one(c2s->config, "router.user", 0);
    if(c2s->router_user == NULL)
        c2s->router_user = "jabberd";
    c2s->router_pass = config_get_one(c2s->config, "router.pass", 0);
    if(c2s->router_pass == NULL)
        c2s->router_pass = "secret";

    c2s->router_pemfile = config_get_one(c2s->config, "router.pemfile", 0);

    c2s->retry_init = j_atoi(config_get_one(c2s->config, "router.retry.init", 0), 3);
    c2s->retry_lost = j_atoi(config_get_one(c2s->config, "router.retry.lost", 0), 3);
    if((c2s->retry_sleep = j_atoi(config_get_one(c2s->config, "router.retry.sleep", 0), 2)) < 1)
        c2s->retry_sleep = 1;

    c2s->log_type = log_STDOUT;
    if(config_get(c2s->config, "log") != NULL) {
        if((str = config_get_attr(c2s->config, "log", 0, "type")) != NULL) {
            if(strcmp(str, "file") == 0)
                c2s->log_type = log_FILE;
            else if(strcmp(str, "syslog") == 0)
                c2s->log_type = log_SYSLOG;
        }
    }

    if(c2s->log_type == log_SYSLOG) {
        c2s->log_facility = config_get_one(c2s->config, "log.facility", 0);
        c2s->log_ident = config_get_one(c2s->config, "log.ident", 0);
        if(c2s->log_ident == NULL)
            c2s->log_ident = "jabberd/c2s";
    } else if(c2s->log_type == log_FILE)
        c2s->log_ident = config_get_one(c2s->config, "log.file", 0);

    c2s->packet_stats = config_get_one(c2s->config, "stats.packet", 0);

    c2s->local_ip = config_get_one(c2s->config, "local.ip", 0);
    if(c2s->local_ip == NULL)
        c2s->local_ip = "0.0.0.0";

    c2s->local_port = j_atoi(config_get_one(c2s->config, "local.port", 0), 0);

    c2s->local_pemfile = config_get_one(c2s->config, "local.pemfile", 0);

    c2s->local_cachain = config_get_one(c2s->config, "local.cachain", 0);

    c2s->local_verify_mode = j_atoi(config_get_one(c2s->config, "local.verify-mode", 0), 0);

    c2s->local_ssl_port = j_atoi(config_get_one(c2s->config, "local.ssl-port", 0), 0);

    c2s->http_forward = config_get_one(c2s->config, "local.httpforward", 0);

    c2s->io_max_fds = j_atoi(config_get_one(c2s->config, "io.max_fds", 0), 1024);

    c2s->compression = (config_get(c2s->config, "io.compression") != NULL);

    c2s->io_check_interval = j_atoi(config_get_one(c2s->config, "io.check.interval", 0), 0);
    c2s->io_check_idle = j_atoi(config_get_one(c2s->config, "io.check.idle", 0), 0);
    c2s->io_check_keepalive = j_atoi(config_get_one(c2s->config, "io.check.keepalive", 0), 0);

    c2s->pbx_pipe = config_get_one(c2s->config, "pbx.pipe", 0);

    elem = config_get(c2s->config, "stream_redirect.redirect");
    if(elem != NULL)
    {
        for(i = 0; i < elem->nvalues; i++)
        {
            sr = (stream_redirect_t) pmalloco(xhash_pool(c2s->stream_redirects), sizeof(struct stream_redirect_st));
            if(!sr) {
                log_write(c2s->log, LOG_ERR, "cannot allocate memory for new stream redirection record, aborting");
                exit(1);
            }
            req_domain = j_attr((const char **) elem->attrs[i], "requested_domain");
            to_address = j_attr((const char **) elem->attrs[i], "to_address");
            to_port = j_attr((const char **) elem->attrs[i], "to_port");

            if(req_domain == NULL || to_address == NULL || to_port == NULL) {
                log_write(c2s->log, LOG_ERR, "Error reading a stream_redirect.redirect element from file, skipping");
                continue;
            }

            // Note that to_address should be RFC 3986 compliant
            sr->to_address = to_address;
            sr->to_port = to_port;
            
            xhash_put(c2s->stream_redirects, pstrdup(xhash_pool(c2s->stream_redirects), req_domain), sr);
        }
    }

    c2s->ar_module_name = config_get_one(c2s->config, "authreg.module", 0);

    if(config_get(c2s->config, "authreg.mechanisms.traditional.plain") != NULL) c2s->ar_mechanisms |= AR_MECH_TRAD_PLAIN;
    if(config_get(c2s->config, "authreg.mechanisms.traditional.digest") != NULL) c2s->ar_mechanisms |= AR_MECH_TRAD_DIGEST;

    if(config_get(c2s->config, "authreg.ssl-mechanisms.traditional.plain") != NULL) c2s->ar_ssl_mechanisms |= AR_MECH_TRAD_PLAIN;
    if(config_get(c2s->config, "authreg.ssl-mechanisms.traditional.digest") != NULL) c2s->ar_ssl_mechanisms |= AR_MECH_TRAD_DIGEST;

    elem = config_get(c2s->config, "io.limits.bytes");
    if(elem != NULL)
    {
        c2s->byte_rate_total = j_atoi(elem->values[0], 0);
        if(c2s->byte_rate_total != 0)
        {
            c2s->byte_rate_seconds = j_atoi(j_attr((const char **) elem->attrs[0], "seconds"), 1);
            c2s->byte_rate_wait = j_atoi(j_attr((const char **) elem->attrs[0], "throttle"), 5);
        }
    }

    elem = config_get(c2s->config, "io.limits.stanzas");
    if(elem != NULL)
    {
        c2s->stanza_rate_total = j_atoi(elem->values[0], 0);
        if(c2s->stanza_rate_total != 0)
        {
            c2s->stanza_rate_seconds = j_atoi(j_attr((const char **) elem->attrs[0], "seconds"), 1);
            c2s->stanza_rate_wait = j_atoi(j_attr((const char **) elem->attrs[0], "throttle"), 5);
        }
    }

    elem = config_get(c2s->config, "io.limits.connects");
    if(elem != NULL)
    {
        c2s->conn_rate_total = j_atoi(elem->values[0], 0);
        if(c2s->conn_rate_total != 0)
        {
            c2s->conn_rate_seconds = j_atoi(j_attr((const char **) elem->attrs[0], "seconds"), 5);
            c2s->conn_rate_wait = j_atoi(j_attr((const char **) elem->attrs[0], "throttle"), 5);
        }
    }

    c2s->stanza_size_limit = j_atoi(config_get_one(c2s->config, "io.limits.stanzasize", 0), 0);

    /* tweak timed checks with rate times */
    if(c2s->io_check_interval == 0) {
        if(c2s->byte_rate_total != 0)
            c2s->io_check_interval = c2s->byte_rate_wait;

        if(c2s->stanza_rate_total != 0 && c2s->io_check_interval > c2s->stanza_rate_wait)
            c2s->io_check_interval = c2s->stanza_rate_wait;
    }

    str = config_get_one(c2s->config, "io.access.order", 0);
    if(str == NULL || strcmp(str, "deny,allow") != 0)
        c2s->access = access_new(0);
    else
        c2s->access = access_new(1);

    elem = config_get(c2s->config, "io.access.allow");
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

            access_allow(c2s->access, ip, mask);
        }
    }

    elem = config_get(c2s->config, "io.access.deny");
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

            access_deny(c2s->access, ip, mask);
        }
    }
}

static void _c2s_hosts_expand(c2s_t c2s)
{
    char *realm;
    config_elem_t elem;
    char id[1024];
    int i;

    elem = config_get(c2s->config, "local.id");
    if(!elem) {
        log_write(c2s->log, LOG_NOTICE, "no local.id configured - skipping local domains configuration");
        return;
    }
    for(i = 0; i < elem->nvalues; i++) {
        host_t host = (host_t) pmalloco(xhash_pool(c2s->hosts), sizeof(struct host_st));
        if(!host) {
            log_write(c2s->log, LOG_ERR, "cannot allocate memory for new host, aborting");
            exit(1);
        }

        realm = j_attr((const char **) elem->attrs[i], "realm");

        /* stringprep ids (domain names) so that they are in canonical form */
        strncpy(id, elem->values[i], 1024);
        id[1023] = '\0';
        if (stringprep_nameprep(id, 1024) != 0) {
            log_write(c2s->log, LOG_ERR, "cannot stringprep id %s, aborting", id);
            exit(1);
        }

        host->realm = (realm != NULL) ? realm : pstrdup(xhash_pool(c2s->hosts), id);

        host->host_pemfile = j_attr((const char **) elem->attrs[i], "pemfile");

        host->host_cachain = j_attr((const char **) elem->attrs[i], "cachain");

        host->host_verify_mode = j_atoi(j_attr((const char **) elem->attrs[i], "verify-mode"), 0);

#ifdef HAVE_SSL
        if(host->host_pemfile != NULL) {
            if(c2s->sx_ssl == NULL) {
                c2s->sx_ssl = sx_env_plugin(c2s->sx_env, sx_ssl_init, host->realm, host->host_pemfile, host->host_cachain, host->host_verify_mode);
                if(c2s->sx_ssl == NULL) {
                    log_write(c2s->log, LOG_ERR, "failed to load %s SSL pemfile", host->realm);
                    host->host_pemfile = NULL;
                }
            } else {
                if(sx_ssl_server_addcert(c2s->sx_ssl, host->realm, host->host_pemfile, host->host_cachain, host->host_verify_mode) != 0) {
                    log_write(c2s->log, LOG_ERR, "failed to load %s SSL pemfile", host->realm);
                    host->host_pemfile = NULL;
                }
            }
        }
#endif

        host->host_require_starttls = (j_attr((const char **) elem->attrs[i], "require-starttls") != NULL);

        host->ar_register_enable = (j_attr((const char **) elem->attrs[i], "register-enable") != NULL);
        host->ar_register_oob = j_attr((const char **) elem->attrs[i], "register-oob");
        if(host->ar_register_enable || host->ar_register_oob) {
            host->ar_register_instructions = j_attr((const char **) elem->attrs[i], "instructions");
            if(host->ar_register_instructions == NULL) {
                if(host->ar_register_oob)
                    host->ar_register_instructions = "Only web based registration is possible with this server.";
                else
                    host->ar_register_instructions = "Enter a username and password to register with this server.";
            }
        } else
            host->ar_register_password = (j_attr((const char **) elem->attrs[i], "password-change") != NULL);

        /* check for empty <id/> CDATA - XXX this "1" is VERY config.c dependant !!! */
        if(! strcmp(id, "1")) {
            /* remove the realm even if set */
            host->realm = NULL;

            /* skip if vHost already configured */
            if(! c2s->vhost)
                c2s->vhost = host;

            /* add meaningful log "id" */
            strcpy(id, "default vHost");
        } else {
            /* insert into vHosts xhash */
            xhash_put(c2s->hosts, pstrdup(xhash_pool(c2s->hosts), id), host);
        }

        log_write(c2s->log, LOG_NOTICE, "[%s] configured; realm=%s, registration %s, using PEM:%s",
                  id, (host->realm != NULL ? host->realm : "no realm set"), (host->ar_register_enable ? "enabled" : "disabled"),
                  (host->host_pemfile ? host->host_pemfile : "Default"));
    }
}

static int _c2s_router_connect(c2s_t c2s) {
    log_write(c2s->log, LOG_NOTICE, "attempting connection to router at %s, port=%d", c2s->router_ip, c2s->router_port);

    c2s->fd = mio_connect(c2s->mio, c2s->router_port, c2s->router_ip, NULL, c2s_router_mio_callback, (void *) c2s);
    if(c2s->fd == NULL) {
        if(errno == ECONNREFUSED)
            c2s_lost_router = 1;
        log_write(c2s->log, LOG_NOTICE, "connection attempt to router failed: %s (%d)", MIO_STRERROR(MIO_ERROR), MIO_ERROR);
        return 1;
    }

    c2s->router = sx_new(c2s->sx_env, c2s->fd->fd, c2s_router_sx_callback, (void *) c2s);
    sx_client_init(c2s->router, 0, NULL, NULL, NULL, "1.0");

    return 0;
}

static int _c2s_sx_sasl_callback(int cb, void *arg, void **res, sx_t s, void *cbarg) {
    c2s_t c2s = (c2s_t) cbarg;
    char *my_realm, *mech;
    sx_sasl_creds_t creds;
    static char buf[3072];
    char mechbuf[256];
    struct jid_st jid;
    jid_static_buf jid_buf;
    int i, r;

    /* init static jid */
    jid_static(&jid,&jid_buf);

    switch(cb) {
        case sx_sasl_cb_GET_REALM:

            if(s->req_to == NULL)   /* this shouldn't happen */
                my_realm = "";

            else {
                host_t host;
                /* get host for request */
                host = xhash_get(c2s->hosts, s->req_to);
                if(host == NULL) {
                    log_write(c2s->log, LOG_ERR, "SASL callback for non-existing host: %s", s->req_to);
                    *res = (void *)NULL;
                    return sx_sasl_ret_FAIL;
                }

                my_realm = host->realm;
                if(my_realm == NULL)
                    my_realm = s->req_to;
            }

            strncpy(buf, my_realm, 256);
            *res = (void *)buf;

            log_debug(ZONE, "sx sasl callback: get realm: realm is '%s'", buf);
            return sx_sasl_ret_OK;
            break;

        case sx_sasl_cb_GET_PASS:
            creds = (sx_sasl_creds_t) arg;

            log_debug(ZONE, "sx sasl callback: get pass (authnid=%s, realm=%s)", creds->authnid, creds->realm);

            if(c2s->ar->get_password && (c2s->ar->get_password)(c2s->ar, (char *)creds->authnid, (creds->realm != NULL) ? (char *)creds->realm: "", buf) == 0) {
                *res = buf;
                return sx_sasl_ret_OK;
            }

            return sx_sasl_ret_FAIL;

        case sx_sasl_cb_CHECK_PASS:
            creds = (sx_sasl_creds_t) arg;

            log_debug(ZONE, "sx sasl callback: check pass (authnid=%s, realm=%s)", creds->authnid, creds->realm);

            if(c2s->ar->check_password != NULL) {
                if ((c2s->ar->check_password)(c2s->ar, (char *)creds->authnid, (creds->realm != NULL) ? (char *)creds->realm : "", (char *)creds->pass) == 0)
                    return sx_sasl_ret_OK;
                else
                    return sx_sasl_ret_FAIL;
            }

            if(c2s->ar->get_password != NULL) {
                if ((c2s->ar->get_password)(c2s->ar, (char *)creds->authnid, (creds->realm != NULL) ? (char *)creds->realm : "", buf) != 0)
                    return sx_sasl_ret_FAIL;

                if (strcmp(creds->pass, buf)==0)
                    return sx_sasl_ret_OK;
            }

            return sx_sasl_ret_FAIL;
            break;

        case sx_sasl_cb_CHECK_AUTHZID:
            creds = (sx_sasl_creds_t) arg;

            /* we need authzid to validate */
            if(creds->authzid == NULL || creds->authzid[0] == '\0')
                return sx_sasl_ret_FAIL;

            /* authzid must be a valid jid */
            if(jid_reset(&jid, creds->authzid, -1) == NULL)
                return sx_sasl_ret_FAIL;

            /* and have domain == stream to addr */
            if(!s->req_to || (strcmp(jid.domain, s->req_to) != 0))
                return sx_sasl_ret_FAIL;

            /* and have no resource */
            if(jid.resource[0] != '\0')
                return sx_sasl_ret_FAIL;

            /* and user has right to authorize as */
            if (c2s->ar->user_authz_allowed) {
                if (c2s->ar->user_authz_allowed(c2s->ar, (char *)creds->authnid, (char *)creds->realm, (char *)creds->authzid))
                        return sx_sasl_ret_OK;
            } else {
                if (strcmp(creds->authnid, jid.node) == 0 &&
                    (c2s->ar->user_exists)(c2s->ar, jid.node, jid.domain))
                    return sx_sasl_ret_OK;
            }

            return sx_sasl_ret_FAIL;

        case sx_sasl_cb_GEN_AUTHZID:
            /* generate a jid for SASL ANONYMOUS */
            jid_reset(&jid, s->req_to, -1);

            /* make node a random string */
            jid_random_part(&jid, jid_NODE);

            strcpy(buf, jid.node);

            *res = (void *)buf;

            return sx_sasl_ret_OK;
            break;

        case sx_sasl_cb_CHECK_MECH:
            mech = (char *)arg;

            i=0;
            while(i<sizeof(mechbuf) && mech[i]!='\0') {
                mechbuf[i]=tolower(mech[i]);
                i++;
            }
            mechbuf[i]='\0';

            /* Determine if our configuration will let us use this mechanism.
             * We support different mechanisms for both SSL and normal use */

            if (strcmp(mechbuf, "digest-md5") == 0) {
                /* digest-md5 requires that our authreg support get_password */
                if (c2s->ar->get_password == NULL)
                    return sx_sasl_ret_FAIL;
            } else if (strcmp(mechbuf, "plain") == 0) {
                /* plain requires either get_password or check_password */
                if (c2s->ar->get_password == NULL && c2s->ar->check_password == NULL)
                    return sx_sasl_ret_FAIL;
            }

            /* Using SSF is potentially dangerous, as SASL can also set the
             * SSF of the connection. However, SASL shouldn't do so until after
             * we've finished mechanism establishment
             */
            if (s->ssf>0) {
                r = snprintf(buf, sizeof(buf), "authreg.ssl-mechanisms.sasl.%s",mechbuf);
                if (r < -1 || r > sizeof(buf))
                    return sx_sasl_ret_FAIL;
                if(config_get(c2s->config,buf) != NULL)
                    return sx_sasl_ret_OK;
            }

            r = snprintf(buf, sizeof(buf), "authreg.mechanisms.sasl.%s",mechbuf);
            if (r < -1 || r > sizeof(buf))
                return sx_sasl_ret_FAIL;

            /* Work out if our configuration will let us use this mechanism */
            if(config_get(c2s->config,buf) != NULL)
                return sx_sasl_ret_OK;
            else
                return sx_sasl_ret_FAIL;
        default:
            break;
    }

    return sx_sasl_ret_FAIL;
}
static void _c2s_time_checks(c2s_t c2s) {
    sess_t sess;
    time_t now;
    union xhashv xhv;

    now = time(NULL);

    if(xhash_iter_first(c2s->sessions))
        do {
            xhv.sess_val = &sess;
            xhash_iter_get(c2s->sessions, NULL, NULL, xhv.val);

            if(c2s->io_check_idle > 0 && sess->s && now > sess->last_activity + c2s->io_check_idle) {
                log_write(c2s->log, LOG_NOTICE, "[%d] [%s, port=%d] timed out", sess->fd->fd, sess->ip, sess->port);

                sx_error(sess->s, stream_err_HOST_GONE, "connection timed out");
                sx_close(sess->s);

                continue;
            }

            if(c2s->io_check_keepalive > 0 && now > sess->last_activity + c2s->io_check_keepalive && sess->s->state >= state_STREAM) {
                log_debug(ZONE, "sending keepalive for %d", sess->fd->fd);

                sx_raw_write(sess->s, " ", 1);
            }

            if(sess->rate != NULL && sess->rate->bad != 0 && rate_check(sess->rate) != 0) {
                /* read the pending bytes when rate limit is no longer in effect */
                log_debug(ZONE, "reading throttled %d", sess->fd->fd);
                sess->s->want_read = 1;
                sx_can_read(sess->s);
            }

        } while(xhash_iter_next(c2s->sessions));
}

JABBER_MAIN("jabberd2c2s", "Jabber 2 C2S", "Jabber Open Source Server: Client to Server", "jabberd2router\0")
{
    c2s_t c2s;
    char *config_file;
    int optchar;
    int mio_timeout;
    sess_t sess;
    bres_t res;
    union xhashv xhv;
    time_t check_time = 0;
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

    jabber_signal(SIGINT, _c2s_signal);
    jabber_signal(SIGTERM, _c2s_signal);
#ifdef SIGHUP
    jabber_signal(SIGHUP, _c2s_signal_hup);
#endif
#ifdef SIGPIPE
    jabber_signal(SIGPIPE, SIG_IGN);
#endif
    jabber_signal(SIGUSR1, _c2s_signal_usr1);
    jabber_signal(SIGUSR2, _c2s_signal_usr2);


    c2s = (c2s_t) calloc(1, sizeof(struct c2s_st));

    /* load our config */
    c2s->config = config_new();

    config_file = CONFIG_DIR "/c2s.xml";

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
                    "c2s - jabberd client-to-server connector (" VERSION ")\n"
                    "Usage: c2s <options>\n"
                    "Options are:\n"
                    "   -c <config>     config file to use [default: " CONFIG_DIR "/c2s.xml]\n"
                    "   -i id           Override <id> config element\n"
#ifdef DEBUG
                    "   -D              Show debug output\n"
#endif
                    ,
                    stdout);
                config_free(c2s->config);
                free(c2s);
                return 1;
        }
    }

    if(config_load_with_id(c2s->config, config_file, cli_id) != 0)
    {
        fputs("c2s: couldn't load config, aborting\n", stderr);
        config_free(c2s->config);
        free(c2s);
        return 2;
    }

    c2s->stream_redirects = xhash_new(523);

    _c2s_config_expand(c2s);

    c2s->log = log_new(c2s->log_type, c2s->log_ident, c2s->log_facility);
    log_write(c2s->log, LOG_NOTICE, "starting up");

    _c2s_pidfile(c2s);

    if(c2s->ar_module_name == NULL) {
        log_write(c2s->log, LOG_NOTICE, "no authreg module specified in config file");
    }
    else if((c2s->ar = authreg_init(c2s, c2s->ar_module_name)) == NULL) {
        access_free(c2s->access);
        config_free(c2s->config);
        log_free(c2s->log);
        free(c2s);
        exit(1);
    }

    c2s->sessions = xhash_new(1023);

    c2s->conn_rates = xhash_new(101);

    c2s->dead = jqueue_new();

    c2s->dead_sess = jqueue_new();

    c2s->sx_env = sx_env_new();

#ifdef HAVE_SSL
    /* get the ssl context up and running */
    if(c2s->local_pemfile != NULL) {
        c2s->sx_ssl = sx_env_plugin(c2s->sx_env, sx_ssl_init, NULL, c2s->local_pemfile, c2s->local_cachain, c2s->local_verify_mode);
        if(c2s->sx_ssl == NULL) {
            log_write(c2s->log, LOG_ERR, "failed to load local SSL pemfile, SSL will not be available to clients");
            c2s->local_pemfile = NULL;
        }
    }

    /* try and get something online, so at least we can encrypt to the router */
    if(c2s->sx_ssl == NULL && c2s->router_pemfile != NULL) {
        c2s->sx_ssl = sx_env_plugin(c2s->sx_env, sx_ssl_init, NULL, c2s->router_pemfile, NULL, NULL);
        if(c2s->sx_ssl == NULL) {
            log_write(c2s->log, LOG_ERR, "failed to load router SSL pemfile, channel to router will not be SSL encrypted");
            c2s->router_pemfile = NULL;
        }
    }
#endif

#ifdef HAVE_LIBZ
    /* get compression up and running */
    if(c2s->compression)
        sx_env_plugin(c2s->sx_env, sx_compress_init);
#endif

#ifdef ENABLE_EXPERIMENTAL
    /* get stanza ack up */
    sx_env_plugin(c2s->sx_env, sx_ack_init);

    /* and user IP address plugin */
    sx_env_plugin(c2s->sx_env, sx_address_init);
#endif

    /* get sasl online */
    c2s->sx_sasl = sx_env_plugin(c2s->sx_env, sx_sasl_init, "xmpp", _c2s_sx_sasl_callback, (void *) c2s);
    if(c2s->sx_sasl == NULL) {
        log_write(c2s->log, LOG_ERR, "failed to initialise SASL context, aborting");
        exit(1);
    }

    /* get bind up */
    sx_env_plugin(c2s->sx_env, bind_init, c2s);

    c2s->mio = mio_new(c2s->io_max_fds);
    if(c2s->mio == NULL) {
        log_write(c2s->log, LOG_ERR, "failed to create MIO, aborting");
        exit(1);
    }

    /* hosts mapping */
    c2s->hosts = xhash_new(1021);
    _c2s_hosts_expand(c2s);
    c2s->sm_avail = xhash_new(1021);

    c2s->retry_left = c2s->retry_init;
    _c2s_router_connect(c2s);

    mio_timeout = ((c2s->io_check_interval != 0 && c2s->io_check_interval < 5) ?
        c2s->io_check_interval : 5);

    while(!c2s_shutdown) {
        mio_run(c2s->mio, mio_timeout);

        if(c2s_logrotate) {
            set_debug_log_from_config(c2s->config);

            log_write(c2s->log, LOG_NOTICE, "reopening log ...");
            log_free(c2s->log);
            c2s->log = log_new(c2s->log_type, c2s->log_ident, c2s->log_facility);
            log_write(c2s->log, LOG_NOTICE, "log started");

            c2s_logrotate = 0;
        }

        if(c2s_sighup) {
            log_write(c2s->log, LOG_NOTICE, "reloading some configuration items ...");
            config_t conf;
            conf = config_new();
            if (conf && config_load(conf, config_file) == 0) {
                xhash_free(c2s->stream_redirects);
                c2s->stream_redirects = xhash_new(523);

                char *req_domain, *to_address, *to_port;
                config_elem_t elem;
                int i;
                stream_redirect_t sr;

                elem = config_get(conf, "stream_redirect.redirect");
                if(elem != NULL)
                {
                    for(i = 0; i < elem->nvalues; i++)
                    {
                        sr = (stream_redirect_t) pmalloco(xhash_pool(c2s->stream_redirects), sizeof(struct stream_redirect_st));
                        if(!sr) {
                            log_write(c2s->log, LOG_ERR, "cannot allocate memory for new stream redirection record, aborting");
                            exit(1);
                        }
                        req_domain = j_attr((const char **) elem->attrs[i], "requested_domain");
                        to_address = j_attr((const char **) elem->attrs[i], "to_address");
                        to_port = j_attr((const char **) elem->attrs[i], "to_port");

                        if(req_domain == NULL || to_address == NULL || to_port == NULL) {
                            log_write(c2s->log, LOG_ERR, "Error reading a stream_redirect.redirect element from file, skipping");
                            continue;
                        }

                        // Note that to_address should be RFC 3986 compliant
                        sr->to_address = to_address;
                        sr->to_port = to_port;
                        
                        xhash_put(c2s->stream_redirects, pstrdup(xhash_pool(c2s->stream_redirects), req_domain), sr);
                    }
                }
                config_free(conf);
            } else {
                log_write(c2s->log, LOG_WARNING, "couldn't reload config (%s)", config_file);
                if (conf) config_free(conf);
            }
            c2s_sighup = 0;
        }

        if(c2s_lost_router) {
            if(c2s->retry_left < 0) {
                log_write(c2s->log, LOG_NOTICE, "attempting reconnect");
                sleep(c2s->retry_sleep);
                c2s_lost_router = 0;
                if (c2s->router) sx_free(c2s->router);
                _c2s_router_connect(c2s);
            }

            else if(c2s->retry_left == 0) {
                c2s_shutdown = 1;
            }

            else {
                log_write(c2s->log, LOG_NOTICE, "attempting reconnect (%d left)", c2s->retry_left);
                c2s->retry_left--;
                sleep(c2s->retry_sleep);
                c2s_lost_router = 0;
                if (c2s->router) sx_free(c2s->router);
                _c2s_router_connect(c2s);
            }
        }

        /* cleanup dead sess (before sx_t as sess->result uses sx_t nad cache) */
        while(jqueue_size(c2s->dead_sess) > 0) {
            sess = (sess_t) jqueue_pull(c2s->dead_sess);

            /* free sess data */
            if(sess->ip != NULL) free(sess->ip);
            if(sess->smcomp != NULL) free(sess->smcomp);
            if(sess->result != NULL) nad_free(sess->result);
            if(sess->resources != NULL)
                for(res = sess->resources; res != NULL;) {
                    bres_t tmp = res->next;
                    jid_free(res->jid);
                    free(res);
                    res = tmp;
                }
            if(sess->rate != NULL) rate_free(sess->rate);
            if(sess->stanza_rate != NULL) rate_free(sess->stanza_rate);

            free(sess);
        }

        /* cleanup dead sx_ts */
        while(jqueue_size(c2s->dead) > 0)
            sx_free((sx_t) jqueue_pull(c2s->dead));

        /* time checks */
        if(c2s->io_check_interval > 0 && time(NULL) >= c2s->next_check) {
            log_debug(ZONE, "running time checks");

            _c2s_time_checks(c2s);

            c2s->next_check = time(NULL) + c2s->io_check_interval;
            log_debug(ZONE, "next time check at %d", c2s->next_check);
        }

        if(time(NULL) > check_time + 60) {
#ifdef POOL_DEBUG
            pool_stat(1);
#endif
            if(c2s->packet_stats != NULL) {
                int fd = open(c2s->packet_stats, O_TRUNC | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
                if (fd >= 0) {
                    char buf[100];
                    int len = snprintf(buf, 100, "%lld\n", c2s->packet_count);
                    if (write(fd, buf, len) != len) {
                        close(fd);
                        fd = -1;
                    } else close(fd);
                }
                if (fd < 0) {
                    log_write(c2s->log, LOG_ERR, "failed to write packet statistics to: %s", c2s->packet_stats);
                    c2s_shutdown = 1;
                }
            }

            check_time = time(NULL);
        }
    }

    log_write(c2s->log, LOG_NOTICE, "shutting down");

    if(xhash_iter_first(c2s->sessions))
        do {
            xhv.sess_val = &sess;
            xhash_iter_get(c2s->sessions, NULL, NULL, xhv.val);

            if(sess->active && sess->s)
                sx_close(sess->s);

        } while(xhash_iter_next(c2s->sessions));

    /* cleanup dead sess */
    while(jqueue_size(c2s->dead_sess) > 0) {
        sess = (sess_t) jqueue_pull(c2s->dead_sess);

        /* free sess data */
        if(sess->ip != NULL) free(sess->ip);
        if(sess->result != NULL) nad_free(sess->result);
        if(sess->resources != NULL)
            for(res = sess->resources; res != NULL;) {
                bres_t tmp = res->next;
                jid_free(res->jid);
                free(res);
                res = tmp;
            }

        free(sess);
    }

    while(jqueue_size(c2s->dead) > 0)
        sx_free((sx_t) jqueue_pull(c2s->dead));

    if (c2s->fd != NULL) mio_close(c2s->mio, c2s->fd);
    sx_free(c2s->router);

    sx_env_free(c2s->sx_env);

    mio_free(c2s->mio);

    xhash_free(c2s->sessions);

    authreg_free(c2s->ar);

    xhash_free(c2s->conn_rates);

    xhash_free(c2s->stream_redirects);

    xhash_free(c2s->sm_avail);

    xhash_free(c2s->hosts);

    jqueue_free(c2s->dead);

    jqueue_free(c2s->dead_sess);

    access_free(c2s->access);

    log_free(c2s->log);

    config_free(c2s->config);

    free(c2s);

#ifdef POOL_DEBUG
    pool_stat(1);
#endif

#ifdef HAVE_WINSOCK2_H
    WSACleanup();
#endif

    return 0;
}
