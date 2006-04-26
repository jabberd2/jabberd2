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

static int _c2s_client_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    sess_t sess = (sess_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    int rlen, len, ns, elem, attr, i, r;
    sx_error_t *sxe;
    nad_t nad;
    char root[9];

    switch(e) {
        case event_WANT_READ:
            log_debug(ZONE, "want read");
            mio_read(sess->c2s->mio, sess->fd);
            break;

        case event_WANT_WRITE:
            log_debug(ZONE, "want write");
            mio_write(sess->c2s->mio, sess->fd);
            break;

        case event_READ:
            log_debug(ZONE, "reading from %d", sess->fd->fd);

            /* check rate limits */
            if(sess->rate != NULL) {
                if(rate_check(sess->rate) == 0) {

                    /* inform the app if we haven't already */
                    if(!sess->rate_log) {
                        if(s->state >= state_STREAM && sess->jid != NULL)
                            log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s] is being byte rate limited", sess->fd->fd, sess->jid);
                        else
                            log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s, port=%d] is being byte rate limited", sess->fd->fd, sess->ip, sess->port);

                        sess->rate_log = 1;
                    }

                    log_debug(ZONE, "%d is throttled, delaying read", sess->fd->fd);

                    buf->len = 0;
                    return 0;
                }

                /* find out how much we can have */
                rlen = rate_left(sess->rate);
                if(rlen > buf->len)
                    rlen = buf->len;
            }

            /* do the read */
            len = recv(sess->fd->fd, buf->data, buf->len, 0);

            if(len < 0) {
                if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN) {
                    buf->len = 0;
                    return 0;
                }

                if(s->state >= state_STREAM && sess->jid != NULL)
                    log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s] read error: %s (%d)", sess->fd->fd, jid_full(sess->jid), strerror(errno), errno);
                else
                    log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s, port=%d] read error: %s (%d)", sess->fd->fd, sess->ip, sess->port, strerror(errno), errno);

                sx_kill(s);
                
                return -1;
            }

            else if(len == 0) {
                /* they went away */
                sx_kill(s);

                return -1;
            }

            log_debug(ZONE, "read %d bytes", len);

            if (!sess->active && !sess->authd) {
+    /* If the first char is G then it's for HTTP (GET ....)
+       and if we configured http client forwarding to a real http server */
+    if (first[0] == 'G' && c->c2s->http_forward)
+    {
+	char* http =
+		"HTTP/1.0 301 Found\r\n"
+		"Location: %s\r\n"
+		"Server: jadc2s " VERSION "\r\n"
+		"Expires: Fri, 10 Oct 1997 10:10:10 GMT\r\n"
+		"Pragma: no-cache\r\n"
+		"Cache-control: private\r\n"
+		"Connection: close\r\n\r\n";
+	char *buf;
+	
+	buf = malloc((strlen(c->c2s->http_forward) + strlen(http)) * sizeof(char));
+	sprintf (buf, http, c->c2s->http_forward);
+	
+	log_debug(ZONE, "This is an incoming HTTP connection - forwarding to: %s", c->c2s->http_forward);
+	
+	/* read all incoming data */
+	while(_read_actual(c,fd,first,1) > 0) { }
+
+	_write_actual(c,fd,buf,strlen(buf));
+	
+	/* close connection */
+        mio_close(c->c2s->mio, c->fd);
+	
+	free(buf);
+	
+	return;
            
            }

            buf->len = len;

            return len;

        case event_WRITE:
            log_debug(ZONE, "writing to %d", sess->fd->fd);

            len = send(sess->fd->fd, buf->data, buf->len, 0);
            if(len >= 0) {
                log_debug(ZONE, "%d bytes written", len);
                return len;
            }

            if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)
                return 0;
            
            if(s->state >= state_OPEN && sess->jid != NULL)
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s] write error: %s (%d)", sess->fd->fd, jid_full(sess->jid), strerror(errno), errno);
            else
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s. port=%d] write error: %s (%d)", sess->fd->fd, sess->ip, sess->port, strerror(errno), errno);
        
            sx_kill(s);
        
            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            if(sess->jid != NULL)
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s] error: %s (%s)", sess->fd->fd, jid_full(sess->jid), sxe->generic, sxe->specific);
            else
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s, port=%d] error: %s (%s)", sess->fd->fd, sess->ip, sess->port, sxe->generic, sxe->specific);

            break;
            
        case event_STREAM:

            if(s->req_to == NULL) {
                log_debug(ZONE, "no stream to provided, closing");
                sx_error(s, stream_err_HOST_UNKNOWN, "no 'to' attribute on stream header");
                sx_close(s);

                return 0;
            }

            /* setup the realm */
            sess->realm = xhash_get(sess->c2s->realms, s->req_to);

            if(sess->realm == NULL) {
                log_debug(ZONE, "no service available for requested domain '%s'", s->req_to);
                sx_error(s, stream_err_HOST_UNKNOWN, "service requested for unknown domain");
                sx_close(s);
                
                return 0;
            }

            if(xhash_get(sess->c2s->sm_avail, s->req_to) == NULL) {
                log_debug(ZONE, "sm for domain '%s' is not online", s->req_to);
                sx_error(s, stream_err_HOST_GONE, "session manager for requested domain is not available");
                sx_close(s);

                return 0;
            }

            break;

        case event_PACKET:
            nad = (nad_t) data;

            /* we only want (message|presence|iq) in jabber:client, everything else gets dropped */
            snprintf(root, 9, "%.*s", NAD_ENAME_L(nad, 0), NAD_ENAME(nad, 0));
            if(NAD_ENS(nad, 0) != nad_find_namespace(nad, 0, uri_CLIENT, NULL) ||
               (strcmp(root, "message") != 0 && strcmp(root, "presence") != 0 && strcmp(root, "iq") != 0)) {
                nad_free(nad);
                return 0;
            }

            /* pre-session requests */
            if(!sess->active && sess->sasl_authd && sess->result == NULL && strcmp(root, "iq") == 0 && nad_find_attr(nad, 0, -1, "type", "set") >= 0) {
                /* resource bind */
                if(!sess->bound && (ns = nad_find_scoped_namespace(nad, uri_BIND, NULL)) >= 0 && (elem = nad_find_elem(nad, 0, ns, "bind", 1)) >= 0) {
                    sess->jid = jid_new(sess->c2s->pc, sess->s->auth_id, -1);

                    /* get the resource */
                    elem = nad_find_elem(nad, elem, ns, "resource", 1);

                    /* user-specified resource */
                    if(elem >= 0) {
                        char resource_buf[1024];

                        if(NAD_CDATA_L(nad, elem) == 0) {
                            log_debug(ZONE, "no resource specified on bind");
                            sx_nad_write(sess->s, stanza_error(nad, 0, stanza_err_BAD_REQUEST));

                            return 0;
                        }

                        /* Put resource into JID */
                        snprintf(resource_buf, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
                        if (jid_reset_components(sess->jid,sess->jid->node,sess->jid->domain,resource_buf) == NULL) {
                            sess->jid = NULL;

                            sx_nad_write(sess->s, stanza_error(nad, 0, stanza_err_BAD_REQUEST));
                            
                            return 0;
                        }

                        /* !!! xmpp-core-19 requires that the resource be unused, and that an
                         *     error be returned if its not. this is hard for us todo, and
                         *     might not be the right thing anyway (it basically gets rid
                         *     of the session replacement functionality, though that is not
                         *     as important now that resources can be generated). clarification
                         *     sought from the xmppwg */
                    }

                    /* generated resource */
                    else {
                        /* generate random resource */
                        jid_random_part(sess->jid, jid_RESOURCE);
                    }

                    log_write(sess->c2s->log, LOG_NOTICE, "[%d] bound: jid=%s", sess->s->tag, jid_full(sess->jid));

                    sess->bound = 1;

                    sess->result = nad_new(sess->s->nad_cache);

                    ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

                    nad_append_elem(sess->result, ns, "iq", 0);
                    nad_set_attr(sess->result, 0, -1, "type", "result", 6);

                    attr = nad_find_attr(nad, 0, -1, "id", NULL);
                    if(attr >= 0)
                        nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

                    ns = nad_add_namespace(sess->result, uri_BIND, NULL);

                    nad_append_elem(sess->result, ns, "bind", 1);
                    nad_append_elem(sess->result, ns, "jid", 2);
                    nad_append_cdata(sess->result, jid_full(sess->jid), strlen(jid_full(sess->jid)), 3);

                    sx_nad_write(sess->s, stanza_tofrom(sess->result, 0));

                    sess->result = NULL;

                    nad_free(nad);

                    return 0;
                }

                /* new-style session request */
                else if(sess->bound && (ns = nad_find_scoped_namespace(nad, uri_XSESSION, NULL)) >= 0 && (elem = nad_find_elem(nad, 0, ns, "session", 1)) >= 0) {
                    /* our local id */
                    sprintf(sess->c2s_id, "%d", sess->s->tag);

                    log_write(sess->c2s->log, LOG_NOTICE, "[%d] requesting session: jid=%s", sess->s->tag, jid_full(sess->jid));

                    /* build a result packet, we'll send this back to the client after we have a session for them */
                    sess->result = nad_new(sess->s->nad_cache);

                    ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

                    nad_append_elem(sess->result, ns, "iq", 0);
                    nad_set_attr(sess->result, 0, -1, "type", "result", 6);

                    attr = nad_find_attr(nad, 0, -1, "id", NULL);
                    if(attr >= 0)
                        nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

                    /* start a session with the sm */
                    sm_start(sess);

                    /* finished with the nad */
                    nad_free(nad);

                    /* handled */
                    return 0;
                }

                log_debug(ZONE, "unrecognised pre-session packet, bye");
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] unrecognized pre-session packet, closing stream", sess->s->tag);

                sx_error(s, stream_err_NOT_AUTHORIZED, "unrecognized pre-session stanza");
                sx_close(s);

                nad_free(nad);
                return 0;
            }

#ifdef HAVE_SSL
            /* drop packets if they have to starttls and they haven't */
            if((sess->s->flags & SX_SSL_STARTTLS_REQUIRE) && sess->s->ssf == 0) {
                nad_free(nad);
                return 0;
            }
#endif

            /* handle iq:auth packets */
            if(authreg_process(sess->c2s, sess, nad) == 0)
                return 0;

            /* drop it if no session */
            if(!sess->active) {
                log_debug(ZONE, "pre-session packet, bye");
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] packet sent before session start, closing stream", sess->s->tag);

                sx_error(s, stream_err_NOT_AUTHORIZED, "stanza sent before session start");
                sx_close(s);

                nad_free(nad);
                return 0;
            }

            /* pass it on to the session manager */
            sm_packet(sess, nad);

            break;
        
        case event_OPEN:

            /* only send a result and bring us online if this wasn't a sasl auth */
            if(strlen(s->auth_method) < 4 || strncmp("SASL", s->auth_method, 4) != 0) {
                /* return the auth result to the client */
                sx_nad_write(s, sess->result);
                sess->result = NULL;

                /* we're good to go */
                sess->active = 1;
            }

            /* they sasl auth'd, so we only want the new-style session start */
            else {
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] SASL authentication succeeded: mechanism=%s; authzid=%s", sess->s->tag, &sess->s->auth_method[5], sess->s->auth_id);
                sess->sasl_authd = 1;
            }

            break;

        case event_CLOSED:
            mio_close(sess->c2s->mio, sess->fd);
            return -1;
    }

    return 0;
}

static int _c2s_client_accept_check(c2s_t c2s, mio_fd_t fd, char *ip) {
    rate_t rt;

    if(access_check(c2s->access, ip) == 0) {
        log_write(c2s->log, LOG_NOTICE, "[%d] [%s] access denied by configuration", fd->fd, ip);
        return 1;
    }

    if(c2s->conn_rate_total != 0) {
        rt = (rate_t) xhash_get(c2s->conn_rates, ip);
        if(rt == NULL) {
            rt = rate_new(c2s->conn_rate_total, c2s->conn_rate_seconds, c2s->conn_rate_wait);
            xhash_put(c2s->conn_rates, pstrdup(xhash_pool(c2s->conn_rates), ip), (void *) rt);
            pool_cleanup(xhash_pool(c2s->conn_rates), (void (*)(void *)) rate_free, rt);
        }

        if(rate_check(rt) == 0) {
            log_write(c2s->log, LOG_NOTICE, "[%d] [%s] is being rate limited", fd->fd, ip);
            return 1;
        }

        rate_add(rt, 1);
    }

    return 0;
}

static int _c2s_client_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    sess_t sess = (sess_t) arg;
    c2s_t c2s = (c2s_t) arg;
    struct sockaddr_storage sa;
    int namelen = sizeof(sa), port, nbytes;

    switch(a) {
        case action_READ:
            log_debug(ZONE, "read action on fd %d", fd->fd);

            /* they did something */
            sess->last_activity = time(NULL);

            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(sess->s);
                return 0;
            }

            return sx_can_read(sess->s);

        case action_WRITE:
            log_debug(ZONE, "write action on fd %d", fd->fd);

            return sx_can_write(sess->s);

        case action_CLOSE:
            log_debug(ZONE, "close action on fd %d", fd->fd);

            log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s, port=%d] disconnect", sess->fd->fd, sess->ip, sess->port);

            /* tell the sm to close their session */
            if(sess->active)
                sm_end(sess);

            jqueue_push(sess->c2s->dead, (void *) sess->s, 0);

            xhash_zap(sess->c2s->sessions, sess->skey);

            jqueue_push(sess->c2s->dead_sess, (void *) sess, 0);

            break;

        case action_ACCEPT:
            log_debug(ZONE, "accept action on fd %d", fd->fd);

            getpeername(fd->fd, (struct sockaddr *) &sa, &namelen);
            port = j_inet_getport(&sa);

            log_write(c2s->log, LOG_NOTICE, "[%d] [%s, port=%d] connect", fd->fd, (char *) data, port);

            if(_c2s_client_accept_check(c2s, fd, (char *) data) != 0)
                return 1;

            sess = (sess_t) malloc(sizeof(struct sess_st));
            memset(sess, 0, sizeof(struct sess_st));

            sess->c2s = c2s;

            sess->fd = fd;

            sess->ip = strdup((char *) data);
            sess->port = port;

            /* they did something */
            sess->last_activity = time(NULL);

            sess->s = sx_new(c2s->sx_env, fd->fd, _c2s_client_sx_callback, (void *) sess);
            mio_app(m, fd, _c2s_client_mio_callback, (void *) sess);

            if(c2s->byte_rate_total != 0)
                sess->rate = rate_new(c2s->byte_rate_total, c2s->byte_rate_seconds, c2s->byte_rate_wait);

            /* find out which port this is */
            getsockname(fd->fd, (struct sockaddr *) &sa, &namelen);
            port = j_inet_getport(&sa);

            /* remember it */
            sprintf(sess->skey, "%d", fd->fd);
            xhash_put(c2s->sessions, sess->skey, (void *) sess);

#ifdef HAVE_SSL
            /* go ssl wrappermode if they're on the ssl port */
            if(port == c2s->local_ssl_port)
                sx_server_init(sess->s, SX_SSL_WRAPPER | SX_SASL_OFFER);
            else
                sx_server_init(sess->s, ((c2s->local_pemfile != NULL) ? SX_SSL_STARTTLS_OFFER : 0) | SX_SASL_OFFER |
                    (c2s->local_require_starttls ? SX_SSL_STARTTLS_REQUIRE : 0));
#else
            sx_server_init(sess->s, SX_SASL_OFFER);
#endif
            break;
    }

    return 0;
}

static void _c2s_component_presence(c2s_t c2s, nad_t nad) {
    int attr;
    char from[1024];
    sess_t sess;
    union xhashv xhv;

    if((attr = nad_find_attr(nad, 0, -1, "from", NULL)) < 0) {
        nad_free(nad);
        return;
    }

    strncpy(from, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));
    from[NAD_AVAL_L(nad, attr)] = '\0';

    if(nad_find_attr(nad, 0, -1, "type", NULL) < 0) {
        log_debug(ZONE, "component available from '%s'", from);

        if(xhash_get(c2s->realms, from) != NULL) {
            log_debug(ZONE, "sm for serviced domain '%s' online", from);

            xhash_put(c2s->sm_avail, pstrdup(xhash_pool(c2s->realms), from), (void *) 1);
        }

        nad_free(nad);
        return;
    }

    if(nad_find_attr(nad, 0, -1, "type", "unavailable") < 0) {
        nad_free(nad);
        return;
    }

    log_debug(ZONE, "component unavailable from '%s'", from);

    if(xhash_get(c2s->sm_avail, from) != NULL) {
        log_debug(ZONE, "sm for serviced domain '%s' offline", from);

        if(xhash_iter_first(c2s->sessions))
            do {
                xhv.sess_val = &sess;
                xhash_iter_get(c2s->sessions, NULL, xhv.val);

                if(sess->jid != NULL && strcmp(sess->jid->domain, from) == 0) {
                    log_debug(ZONE, "killing session %s", jid_full(sess->jid));

                    sess->active = 0;
                    sx_close(sess->s);
                }
            } while(xhash_iter_next(c2s->sessions));
        
        xhash_zap(c2s->sm_avail, from);
    }
}

int c2s_router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    c2s_t c2s = (c2s_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    sx_error_t *sxe;
    nad_t nad;
    int len, elem, from, c2sid, smid, action, id, ns, attr, scan, replaced;
    char skey[10];
    sess_t sess;

    switch(e) {
        case event_WANT_READ:
            log_debug(ZONE, "want read");
            mio_read(c2s->mio, c2s->fd);
            break;

        case event_WANT_WRITE:
            log_debug(ZONE, "want write");
            mio_write(c2s->mio, c2s->fd);
            break;

        case event_READ:
            log_debug(ZONE, "reading from %d", c2s->fd->fd);

            /* do the read */
            len = recv(c2s->fd->fd, buf->data, buf->len, 0);

            if(len < 0) {
                if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN) {
                    buf->len = 0;
                    return 0;
                }

                log_write(c2s->log, LOG_NOTICE, "[%d] [router] read error: %s (%d)", c2s->fd->fd, strerror(errno), errno);

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
            log_debug(ZONE, "writing to %d", c2s->fd->fd);

            len = send(c2s->fd->fd, buf->data, buf->len, 0);
            if(len >= 0) {
                log_debug(ZONE, "%d bytes written", len);
                return len;
            }

            if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN) 
                return 0;

            log_write(c2s->log, LOG_NOTICE, "[%d] [router] write error: %s (%d)", c2s->fd->fd, strerror(errno), errno);
        
            sx_kill(s);
        
            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            log_write(c2s->log, LOG_NOTICE, "error from router: %s (%s)", sxe->generic, sxe->specific);

            if(sxe->code == SX_ERR_AUTH)
                sx_close(s);

            break;

        case event_STREAM:
            break;

        case event_OPEN:
            log_write(c2s->log, LOG_NOTICE, "connection to router established");

            /* reset connection attempts counter */
            c2s->retry_left = c2s->retry_init;

            nad = nad_new(c2s->router->nad_cache);
            ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
            nad_append_elem(nad, ns, "bind", 0);
            nad_append_attr(nad, -1, "name", c2s->id);

            log_debug(ZONE, "requesting component bind for '%s'", c2s->id);

            sx_nad_write(c2s->router, nad);

            return 0;

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
                if(c2s->sx_ssl != NULL && c2s->router_pemfile != NULL && s->ssf == 0) {
                    ns = nad_find_scoped_namespace(nad, uri_TLS, NULL);
                    if(ns >= 0) {
                        elem = nad_find_elem(nad, 0, ns, "starttls", 1);
                        if(elem >= 0) {
                            if(sx_ssl_client_starttls(c2s->sx_ssl, s, c2s->router_pemfile) == 0) {
                                nad_free(nad);
                                return 0;
                            }
                            log_write(c2s->log, LOG_ERR, "unable to establish encrypted session with router");
                        }
                    }
                }
#endif

                /* !!! pull the list of mechanisms, and choose the best one.
                 *     if there isn't an appropriate one, error and bail */

                /* authenticate */
                sx_sasl_auth(c2s->sx_sasl, s, "jabberd-router", "DIGEST-MD5", c2s->router_user, c2s->router_pass);

                nad_free(nad);
                return 0;
            }

            /* watch for the bind response */
            if(s->state == state_OPEN && !c2s->online) {
                if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT) || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0 || NAD_ENAME_L(nad, 0) != 4 || strncmp("bind", NAD_ENAME(nad, 0), 4) != 0) {
                    log_debug(ZONE, "got a packet from router, but we're not online, dropping");
                    nad_free(nad);
                    return 0;
                }

                /* catch errors */
                attr = nad_find_attr(nad, 0, -1, "error", NULL);
                if(attr >= 0) {
                    log_write(c2s->log, LOG_ERR, "router refused bind request (%.*s)", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
                    exit(1);
                }

                log_debug(ZONE, "coming online");

                /* if we're coming online for the first time, setup listening sockets */
#ifdef HAVE_SSL
                if(c2s->server_fd == 0 && c2s->server_ssl_fd == 0) {
#else
                if(c2s->server_fd == 0) {
#endif
                    if(c2s->local_port != 0) {
                        c2s->server_fd = mio_listen(c2s->mio, c2s->local_port, c2s->local_ip, _c2s_client_mio_callback, (void *) c2s);
                        if(c2s->server_fd == NULL)
                            log_write(c2s->log, LOG_ERR, "[%s, port=%d] failed to listen", c2s->local_ip, c2s->local_port);
                        else
                            log_write(c2s->log, LOG_NOTICE, "[%s, port=%d] listening for connections", c2s->local_ip, c2s->local_port);
                    } else
                        c2s->server_fd = NULL;
            
#ifdef HAVE_SSL
                    if(c2s->local_ssl_port != 0 && c2s->local_pemfile != NULL) {
                        c2s->server_ssl_fd = mio_listen(c2s->mio, c2s->local_ssl_port, c2s->local_ip, _c2s_client_mio_callback, (void *) c2s);
                        if(c2s->server_ssl_fd == NULL)
                            log_write(c2s->log, LOG_ERR, "[%s, port=%d] failed to listen", c2s->local_ip, c2s->local_ssl_port);
                        else
                            log_write(c2s->log, LOG_NOTICE, "[%s, port=%d] listening for SSL connections", c2s->local_ip, c2s->local_ssl_port);
                    } else
                        c2s->server_ssl_fd = NULL;
#endif
                }

#ifdef HAVE_SSL
                if(c2s->server_fd == NULL && c2s->server_ssl_fd == NULL) {
                    log_write(c2s->log, LOG_ERR, "both normal and SSL ports are disabled, nothing to do!");
#else
                if(c2s->server_fd == NULL) {
                    log_write(c2s->log, LOG_ERR, "server port is disabled, nothing to do!");
#endif
                    exit(1);
                }
            
                /* we're online */
                c2s->online = c2s->started = 1;
                log_write(c2s->log, LOG_NOTICE, "ready for connections", c2s->id);

                nad_free(nad);
                return 0;
            }

            /* need component packets */
            if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT) || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0) {
                log_debug(ZONE, "wanted component packet, dropping");
                nad_free(nad);
                return 0;
            }

            /* component presence */
            if(NAD_ENAME_L(nad, 0) == 8 && strncmp("presence", NAD_ENAME(nad, 0), 8) == 0) {
                _c2s_component_presence(c2s, nad);
                return 0;
            }

            /* we want route */
            if(NAD_ENAME_L(nad, 0) != 5 || strncmp("route", NAD_ENAME(nad, 0), 5) != 0) { 
                log_debug(ZONE, "wanted {component}route, dropping");
                nad_free(nad);
                return 0;
            }

            /* only handle unicasts */
            if(nad_find_attr(nad, 0, -1, "type", NULL) >= 0) {
                log_debug(ZONE, "non-unicast packet, dropping");
                nad_free(nad);
                return 0;
            }

            /* need some payload */
            if(nad->ecur == 1) {
                log_debug(ZONE, "no route payload, dropping");
                nad_free(nad);
                return 0;
            }

            ns = nad_find_namespace(nad, 1, uri_SESSION, NULL);
            if(ns < 0) {
                log_debug(ZONE, "not a c2s packet, dropping");
                nad_free(nad);
                return 0;
            }

            /* figure out the session */
            c2sid = nad_find_attr(nad, 1, ns, "c2s", NULL);
            if(c2sid < 0) {
                log_debug(ZONE, "no c2s id on payload, dropping");
                nad_free(nad);
                return 0;
            }
            snprintf(skey, 10, "%.*s", NAD_AVAL_L(nad, c2sid), NAD_AVAL(nad, c2sid));

            /* find the session, quietly drop if we don't have it */
            sess = xhash_get(c2s->sessions, skey);
            if(sess == NULL) {
                /* !!! might want to send a stop to the sm; maybe it thinks we're still here? */
                log_debug(ZONE, "no session for %s", skey);

                nad_free(nad);
                return 0;
            }

            /* if they're pre-stream, then this is leftovers from a previous session */
            if(sess->s->state < state_STREAM) {
                log_debug(ZONE, "session %s is pre-stream", skey);

                nad_free(nad);
                return 0;
            }

            /* check the sm session id if they gave us one */
            smid = nad_find_attr(nad, 1, ns, "sm", NULL);
            if(smid >= 0 && sess->sm_id[0] != '\0' && (strlen(sess->sm_id) != NAD_AVAL_L(nad, smid) || strncmp(sess->sm_id, NAD_AVAL(nad, smid), NAD_AVAL_L(nad, smid)) != 0)) {
                log_debug(ZONE, "expected packet from sm session %s, but got one from %.*s, dropping", sess->sm_id, NAD_AVAL_L(nad, smid), NAD_AVAL(nad, smid));
                nad_free(nad);
                return 0;
            }

            /* it has to have come from the session manager */
            from = nad_find_attr(nad, 0, -1, "from", NULL);
            if(strlen(sess->s->req_to) != NAD_AVAL_L(nad, from) || strncmp(sess->s->req_to, NAD_AVAL(nad, from), NAD_AVAL_L(nad, from)) != 0) {
                log_debug(ZONE, "packet from '%.*s' for %s, but they're not the sm for this sess", NAD_AVAL_L(nad, from), NAD_AVAL(nad, from), skey);
                nad_free(nad);
                return 0;
            }

            /* route errors */
            if(nad_find_attr(nad, 0, -1, "error", NULL) >= 0) {
                log_debug(ZONE, "routing error");

                /* !!! kill the session */

                nad_free(nad);
                return 0;
            }

            /* session control packets */
            if(NAD_ENS(nad, 1) == ns) {
                action = nad_find_attr(nad, 1, -1, "action", NULL);
                id = nad_find_attr(nad, 1, -1, "id", NULL);

                /* failed requests */
                if(nad_find_attr(nad, 1, ns, "failed", NULL) >= 0) {
                    /* make sure the id matches */
                    if(id < 0 || sess->sm_request[0] == '\0' || strlen(sess->sm_request) != NAD_AVAL_L(nad, id) || strncmp(sess->sm_request, NAD_AVAL(nad, id), NAD_AVAL_L(nad, id)) != 0) {
                        if(id >= 0) {
                            log_debug(ZONE, "got a response with id %.*s, but we were expecting %s", NAD_AVAL_L(nad, id), NAD_AVAL(nad, id), sess->sm_request);
                        } else {
                            log_debug(ZONE, "got a response with no id, but we were expecting %s", sess->sm_request);
                        }

                        nad_free(nad);
                        return 0;
                    }

                    /* handled request */
                    sess->sm_request[0] = '\0';

                    /* we only care about failed start and create */
                    if((NAD_AVAL_L(nad, action) == 5 && strncmp("start", NAD_AVAL(nad, action), 5) == 0) ||
                       (NAD_AVAL_L(nad, action) == 6 && strncmp("create", NAD_AVAL(nad, action), 6) == 0)) {

                        /* create failed, so we need to remove them from authreg */
                        if(NAD_AVAL_L(nad, action) == 6 && c2s->ar->delete_user != NULL) {
                            if((c2s->ar->delete_user)(c2s->ar, sess->jid->node, sess->realm) != 0)
                                log_write(c2s->log, LOG_NOTICE, "[%d] user creation failed, and unable to delete user credentials: user=%s, realm=%s", sess->s->tag, sess->jid->node, sess->realm);
                            else
                                log_write(c2s->log, LOG_NOTICE, "[%d] user creation failed, so deleted user credentials: user=%s, realm=%s", sess->s->tag, sess->jid->node, sess->realm);
                        }

                        /* error the result and return it to the client */
                        sx_nad_write(sess->s, stanza_error(sess->result, 0, stanza_err_INTERNAL_SERVER_ERROR));
                        sess->result = NULL;

                        jid_free(sess->jid);
                        sess->jid = NULL;

                        nad_free(nad);
                        return 0;
                    }

                    log_debug(ZONE, "weird, got a failed session response, with a matching id, but the action is bogus *shrug*");

                    nad_free(nad);
                    return 0;
                }

                /* if we're not active yet, then we only want "started" or "created" responses */
                if(!sess->active) {
                    /* make sure the id matches */
                    if(id < 0 || sess->sm_request[0] == '\0' || strlen(sess->sm_request) != NAD_AVAL_L(nad, id) || strncmp(sess->sm_request, NAD_AVAL(nad, id), NAD_AVAL_L(nad, id)) != 0) {
                        if(id >= 0) {
                            log_debug(ZONE, "got a response with id %.*s, but we were expecting %s", NAD_AVAL_L(nad, id), NAD_AVAL(nad, id), sess->sm_request);
                        } else {
                            log_debug(ZONE, "got a response with no id, but we were expecting %s", sess->sm_request);
                        }

                        nad_free(nad);
                        return 0;
                    }

                    /* session started */
                    if(NAD_AVAL_L(nad, action) == 7 && strncmp("started", NAD_AVAL(nad, action), 7) == 0) {
                        /* handled request */
                        sess->sm_request[0] = '\0';

                        /* copy the sm id */
                        if(smid >= 0)
                            snprintf(sess->sm_id, 41, "%.*s", NAD_AVAL_L(nad, smid), NAD_AVAL(nad, smid));

                        nad_free(nad);

                        /* bring them online, old-skool */
                        if(!sess->sasl_authd) {
                            sx_auth(sess->s, "traditional", jid_user(sess->jid));
                            return 0;
                        }

                        /* return the auth result to the client */
                        sx_nad_write(sess->s, sess->result);
                        sess->result = NULL;

                        /* we're good to go */
                        sess->active = 1;

                        return 0;
                    }

                    /* user created */
                    if(NAD_AVAL_L(nad, action) == 7 && strncmp("created", NAD_AVAL(nad, action), 7) == 0) {
                        /* handled request */
                        sess->sm_request[0] = '\0';

                        nad_free(nad);

                        /* return the result to the client */
                        sx_nad_write(sess->s, sess->result);
                        sess->result = NULL;

                        return 0;
                    }

                    /* anything else gets thrown out */
                    log_debug(ZONE, "got a packet for %s, but they don't have an active session yes", jid_full(sess->jid));

                    nad_free(nad);

                    return 0;
                }

                /* end responses */

                /* !!! this "replaced" stuff is a hack - its really a subaction of "ended".
                 *     hurrah, another control protocol rewrite is needed :(
                 */

                replaced = 0;
                if(NAD_AVAL_L(nad, action) == 8 && strncmp("replaced", NAD_AVAL(nad, action), NAD_AVAL_L(nad, action)) == 0)
                    replaced = 1;
                if(replaced || (NAD_AVAL_L(nad, action) == 5 && strncmp("ended", NAD_AVAL(nad, action), NAD_AVAL_L(nad, action)) == 0)) {
                    sess->active = 0;
                
                    if(replaced)
                        sx_error(sess->s, stream_err_CONFLICT, NULL);
                    
                    /* close them */
                    sx_close(sess->s);

                    nad_free(nad);
                    return 0;
                }

                /* make sure the id matches */
                if(id < 0 || sess->sm_request[0] == '\0' || strncmp(sess->sm_request, NAD_AVAL(nad, id), NAD_AVAL_L(nad, id)) != 0) {
                    if(id >= 0) {
                        log_debug(ZONE, "got a response with id %.*s, but we were expecting %s", NAD_AVAL_L(nad, id), NAD_AVAL(nad, id), sess->sm_request);
                    } else {
                        log_debug(ZONE, "got a response with no id, but we were expecting %s", sess->sm_request);
                    }

                    nad_free(nad);
                    return 0;
                }

                /* handled request */
                sess->sm_request[0] = '\0';

                log_debug(ZONE, "unknown action %.*s", NAD_AVAL_L(nad, id), NAD_AVAL(nad, id));

                nad_free(nad);

                return 0;
            }

            /* client packets */
            if(NAD_NURI_L(nad, NAD_ENS(nad, 1)) == strlen(uri_CLIENT) && strncmp(uri_CLIENT, NAD_NURI(nad, NAD_ENS(nad, 1)), strlen(uri_CLIENT)) == 0) {
                if(!sess->active) {
                    /* its a strange world .. */
                    nad_free(nad);
                    return 0;
                }

                /* sm is bouncing something */
                if(nad_find_attr(nad, 1, ns, "failed", NULL) >= 0) {
                    /* there's really no graceful way to handle this */
                    sx_error(s, stream_err_INTERNAL_SERVER_ERROR, "session manager failed control action");
                    sx_close(s);

                    nad_free(nad);
                    return 0;
                }

                /* remove sm specifics */
                nad_set_attr(nad, 1, ns, "c2s", NULL, 0);
                nad_set_attr(nad, 1, ns, "sm", NULL, 0);

                /* forget about the internal namespace too */
                if(nad->elems[1].ns == ns)
                    nad->elems[1].ns = nad->nss[ns].next;

                else {
                    for(scan = nad->elems[1].ns; nad->nss[scan].next != -1 && nad->nss[scan].next != ns; scan = nad->nss[scan].next);

                    /* got it */
                    if(nad->nss[scan].next != -1)
                        nad->nss[scan].next = nad->nss[ns].next;
                }

                sx_nad_write_elem(sess->s, nad, 1);

                return 0;
            }

            /* its something else */
            log_debug(ZONE, "unknown packet, dropping");

            nad_free(nad);
            return 0;

        case event_CLOSED:
            mio_close(c2s->mio, c2s->fd);
            return -1;
    }

    return 0;
}

int c2s_router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    c2s_t c2s = (c2s_t) arg;
    int nbytes;

    switch(a) {
        case action_READ:
            log_debug(ZONE, "read action on fd %d", fd->fd);

            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(c2s->router);
                return 0;
            }

            return sx_can_read(c2s->router);

        case action_WRITE:
            log_debug(ZONE, "write action on fd %d", fd->fd);
            return sx_can_write(c2s->router);

        case action_CLOSE:
            log_debug(ZONE, "close action on fd %d", fd->fd);
            log_write(c2s->log, LOG_NOTICE, "connection to router closed");

            c2s_lost_router = 1;

            /* we're offline */
            c2s->online = 0;

            break;

        case action_ACCEPT:
            break;
    }

    return 0;
}
