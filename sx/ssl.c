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

/**
 * this plugin implements the traditional SSL "wrappermode" streams and
 * STARTTLS extension documented in xmpp-core
 */

#include "sx.h"
#include <openssl/x509_vfy.h>


/* code stolen from SSL_CTX_set_verify(3) */
static int _sx_ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    char    buf[256];
    X509   *err_cert;
    int     err, depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    /*
     * Ignore errors when we can't get CRLs in the certificate
     */
    if (!preverify_ok && err == X509_V_ERR_UNABLE_TO_GET_CRL) {
    	_sx_debug(ZONE, "ignoring verify error:num=%d:%s:depth=%d:%s\n", err,
    	                 X509_verify_cert_error_string(err), depth, buf);
    	preverify_ok = 1;
    }

    /*
     * Retrieve the pointer to the SSL of the connection currently treated
     * and the application specific data stored into the SSL object.
     */
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    if (!preverify_ok) {
        _sx_debug(ZONE, "verify error:num=%d:%s:depth=%d:%s\n", err,
                 X509_verify_cert_error_string(err), depth, buf);
    }
    else
    {
        _sx_debug(ZONE, "OK! depth=%d:%s", depth, buf);
    }

    /*
     * At this point, err contains the last verification error. We can use
     * it for something special
     */
    if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT))
    {
      X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
      _sx_debug(ZONE, "issuer= %s\n", buf);
    }

    return preverify_ok;
 }

static int _sx_pem_passwd_callback(char *buf, int size, int rwflag, void *password)
{
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return(strlen(buf));
}

static void _sx_ssl_starttls_notify_proceed(sx_t s, void *arg) {
    char *to = NULL;
    _sx_debug(ZONE, "preparing for starttls");

    /* store the destination so we can select an ssl context */
    if(s->req_to != NULL) to = strdup(s->req_to);

    _sx_reset(s);

    /* restore destination */
    if(s->req_to == NULL)
        s->req_to = to;
    else /* ? */
        free(to);

    /* start listening */
    sx_server_init(s, s->flags | SX_SSL_WRAPPER);
}

static int _sx_ssl_process(sx_t s, sx_plugin_t p, nad_t nad) {
    int flags;
    char *ns = NULL, *to = NULL, *from = NULL, *version = NULL;
    sx_error_t sxe;

    /* not interested if we're a server and we never offered it */
    if(s->type == type_SERVER && !(s->flags & SX_SSL_STARTTLS_OFFER))
        return 1;

    /* only want tls packets */
    if(NAD_ENS(nad, 0) < 0 || NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_TLS) || strncmp(NAD_NURI(nad, NAD_ENS(nad, 0)), uri_TLS, strlen(uri_TLS)) != 0)
        return 1;

    /* starttls from client */
    if(s->type == type_SERVER) {
        if(NAD_ENAME_L(nad, 0) == 8 && strncmp(NAD_ENAME(nad, 0), "starttls", 8) == 0) {
            nad_free(nad);

            /* can't go on if we've been here before */
            if(s->ssf > 0) {
                _sx_debug(ZONE, "starttls requested on already encrypted channel, dropping packet");
                return 0;
            }

            /* can't go on if we're on compressed stream */
            if(s->compressed > 0) {
                _sx_debug(ZONE, "starttls requested on already compressed channel, dropping packet");
                return 0;
            }

            _sx_debug(ZONE, "starttls requested, setting up");

            /* go ahead */
            jqueue_push(s->wbufq, _sx_buffer_new("<proceed xmlns='" uri_TLS "'/>", strlen(uri_TLS) + 19, _sx_ssl_starttls_notify_proceed, NULL), 0);
            s->want_write = 1;

            /* handled the packet */
            return 0;
        }
    }

    else if(s->type == type_CLIENT) {
        /* kick off the handshake */
        if(NAD_ENAME_L(nad, 0) == 7 && strncmp(NAD_ENAME(nad, 0), "proceed", 7) == 0) {
            nad_free(nad);

            /* save interesting bits */
            flags = s->flags;

            if(s->ns != NULL) ns = strdup(s->ns);

            if(s->req_to != NULL) to = strdup(s->req_to);
            if(s->req_from != NULL) from = strdup(s->req_from);
            if(s->req_version != NULL) version = strdup(s->req_version);

            /* reset state */
            _sx_reset(s);

            _sx_debug(ZONE, "server ready for ssl, starting");

            /* second time round */
            sx_client_init(s, flags | SX_SSL_WRAPPER, ns, to, from, version);

            /* free bits */
            if(ns != NULL) free(ns);
            if(to != NULL) free(to);
            if(from != NULL) free(from);
            if(version != NULL) free(version);

            return 0;
        }

        /* busted server */
        if(NAD_ENAME_L(nad, 0) == 7 && strncmp(NAD_ENAME(nad, 0), "failure", 7) == 0) {
            nad_free(nad);

            /* free the pemfile arg */
            if(s->plugin_data[p->index] != NULL) {
                if( ((_sx_ssl_conn_t)s->plugin_data[p->index])->pemfile != NULL )
                    free(((_sx_ssl_conn_t)s->plugin_data[p->index])->pemfile);
                if( ((_sx_ssl_conn_t)s->plugin_data[p->index])->private_key_password != NULL )
                    free(((_sx_ssl_conn_t)s->plugin_data[p->index])->private_key_password);
                free(s->plugin_data[p->index]);
                s->plugin_data[p->index] = NULL;
            }

            _sx_debug(ZONE, "server can't handle ssl, business as usual");

            _sx_gen_error(sxe, SX_ERR_STARTTLS_FAILURE, "STARTTLS failure", "Server was unable to prepare for the TLS handshake");
            _sx_event(s, event_ERROR, (void *) &sxe);

            return 0;
        }
    }

    _sx_debug(ZONE, "unknown starttls namespace element '%.*s', dropping packet", NAD_ENAME_L(nad, 0), NAD_ENAME(nad, 0));
    nad_free(nad);
    return 0;
}

static void _sx_ssl_features(sx_t s, sx_plugin_t p, nad_t nad) {
    int ns;

    /* if the session is already encrypted, or the app told us not to,
     * or session is compressed then we don't offer anything */
    if(s->state > state_STREAM || s->ssf > 0 || !(s->flags & SX_SSL_STARTTLS_OFFER) || s->compressed)
        return;

    _sx_debug(ZONE, "offering starttls");

    ns = nad_add_namespace(nad, uri_TLS, NULL);
    nad_append_elem(nad, ns, "starttls", 1);

    if(s->flags & SX_SSL_STARTTLS_REQUIRE)
        nad_append_elem(nad, ns, "required", 2);
}

/* Extract id-on-xmppAddr from the certificate */
static void _sx_ssl_get_external_id(sx_t s, _sx_ssl_conn_t sc) {
    X509 *cert;
    X509_NAME *name;
    X509_NAME_ENTRY *entry;
    // subjectAltName parsing
    X509_EXTENSION *extension;
    STACK_OF(GENERAL_NAME) *altnames;
    GENERAL_NAME *altname;
    OTHERNAME *othername;
    char * buff;
    // new object identifiers
    int id_on_xmppAddr_nid;
    ASN1_OBJECT *id_on_xmppAddr_obj;
    //  iterators
    int i, j, count,  id = 0, len;

    /* If there's not peer cert, quit */
	if ((cert = SSL_get_peer_certificate(sc->ssl) ) == NULL)
		return;
	_sx_debug(ZONE, "external_id: Got peer certificate");

	/* Allocate new id-on-xmppAddr object. See rfc3921bis 15.2.1.2 */
	id_on_xmppAddr_nid = OBJ_create("1.3.6.1.5.5.7.8.5", "id-on-xmppAddr", "XMPP Address Identity");
	id_on_xmppAddr_obj = OBJ_nid2obj(id_on_xmppAddr_nid);
	_sx_debug(ZONE, "external_id: Created id-on-xmppAddr SSL object");

	/* Iterate through all subjectAltName x509v3 extensions. Get id-on-xmppAddr and dDnsName */
	for (i = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
		 i != -1;
		 i = X509_get_ext_by_NID(cert, NID_subject_alt_name, i)) {
		// Get this subjectAltName x509v3 extension
		if ((extension = X509_get_ext(cert, i)) == NULL) {
			_sx_debug(ZONE, "external_id: Can't get subjectAltName. Possibly malformed cert.");
			goto end;
		}
		// Get the collection of AltNames
		if ((altnames = X509V3_EXT_d2i(extension)) == NULL) {
			_sx_debug(ZONE, "external_id: Can't get all AltNames. Possibly malformed cert.");
			goto end;
		}
		/* Iterate through all altNames and get id-on-xmppAddr and dNSName */
		count = sk_GENERAL_NAME_num(altnames);
		for (j = 0; j < count; j++) {
			if ((altname = sk_GENERAL_NAME_value(altnames, j)) == NULL) {
				_sx_debug(ZONE, "external_id: Can't get AltName. Possibly malformed cert.");
				goto end;
			}
			/* Check if its otherName id-on-xmppAddr */
			if (altname->type == GEN_OTHERNAME &&
				OBJ_cmp(altname->d.otherName->type_id, id_on_xmppAddr_obj) == 0) {
				othername = altname->d.otherName;
				len = ASN1_STRING_to_UTF8((unsigned char **) &buff, othername->value->value.utf8string);
				if (len <= 0)
					continue;
				sc->external_id[id] = (char *) malloc(sizeof(char) *  (len + 1));
				memcpy(sc->external_id[id], buff, len);
				sc->external_id[id][len] = '\0'; // just to make sure
				_sx_debug(ZONE, "external_id: Found(%d) subjectAltName/id-on-xmppAddr: '%s'", id, sc->external_id[id]);
				id++;
				OPENSSL_free(buff);
			} else if (altname->type == GEN_DNS) {
				len = ASN1_STRING_length(altname->d.dNSName);
				sc->external_id[id] = (char *) malloc(sizeof(char) *  (len + 1));
				memcpy(sc->external_id[id], ASN1_STRING_data(altname->d.dNSName), len);
				sc->external_id[id][len] = '\0'; // just to make sure
				_sx_debug(ZONE, "external_id: Found(%d) subjectAltName/dNSName: '%s'", id, sc->external_id[id]);
				id++;
			}
			/* Check if we're not out of space */
			if (id == SX_CONN_EXTERNAL_ID_MAX_COUNT) {
				sk_GENERAL_NAME_pop_free(altnames, GENERAL_NAME_free);
				goto end;
			}
		}

		sk_GENERAL_NAME_pop_free(altnames, GENERAL_NAME_free);
	}
	/* Get CNs */
	name = X509_get_subject_name(cert);
	for (i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
		 i != -1;
		 i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) {
		// Get the commonName entry
		if ((entry = X509_NAME_get_entry(name, i)) == NULL) {
			_sx_debug(ZONE, "external_id: Can't get commonName(%d). Possibly malformed cert. Continuing.", i);
			continue;
		}
		// Get the commonName as UTF8 string
		len = ASN1_STRING_to_UTF8((unsigned char **) &buff, X509_NAME_ENTRY_get_data(entry));
		if (len <= 0) {
			continue;
		}
		sc->external_id[id] = (char *) malloc(sizeof(char) *  (len + 1));
		memcpy(sc->external_id[id], buff, len);
		sc->external_id[id][len] = '\0'; // just to make sure
		_sx_debug(ZONE, "external_id: Found(%d) commonName: '%s'", id, sc->external_id[id]);
		OPENSSL_free(buff);
		/* Check if we're not out of space */
		if (id == SX_CONN_EXTERNAL_ID_MAX_COUNT)
			goto end;
	}

end:
    X509_free(cert);
    return;
}

static int _sx_ssl_handshake(sx_t s, _sx_ssl_conn_t sc) {
    int ret, err;
    char *errstring;
    sx_error_t sxe;

    /* work on establishing the channel */
    while(!SSL_is_init_finished(sc->ssl)) {
        _sx_debug(ZONE, "secure channel not established, handshake in progress");

        /* we can't handshake if they want to read, but there's nothing to read */
        if(sc->last_state == SX_SSL_STATE_WANT_READ && BIO_pending(sc->rbio) == 0)
            return 0;

        /* more handshake */
        if(s->type == type_CLIENT)
            ret = SSL_connect(sc->ssl);
        else
            ret = SSL_accept(sc->ssl);

        /* check if we're done */
        if(ret == 1) {
            _sx_debug(ZONE, "secure channel established");
            sc->last_state = SX_SSL_STATE_NONE;

            s->ssf = SSL_get_cipher_bits(sc->ssl, NULL);

            _sx_debug(ZONE, "using cipher %s (%d bits)", SSL_get_cipher_name(sc->ssl), s->ssf);
            _sx_ssl_get_external_id(s, sc);

            return 1;
        }

        /* error checking */
        else if(ret <= 0) {
            err = SSL_get_error(sc->ssl, ret);

            if(err == SSL_ERROR_WANT_READ)
                sc->last_state = SX_SSL_STATE_WANT_READ;
            else if(err == SSL_ERROR_WANT_WRITE)
                sc->last_state = SX_SSL_STATE_WANT_WRITE;

            else {
                /* fatal error */
                sc->last_state = SX_SSL_STATE_ERROR;

                errstring = ERR_error_string(ERR_get_error(), NULL);
                _sx_debug(ZONE, "openssl error: %s", errstring);

                /* do not throw an error if in wrapper mode and pre-stream */
                if(!(s->state < state_STREAM && s->flags & SX_SSL_WRAPPER)) {
                    _sx_gen_error(sxe, SX_ERR_SSL, "SSL handshake error", errstring);
                    _sx_event(s, event_ERROR, (void *) &sxe);
                    sx_error(s, stream_err_UNDEFINED_CONDITION, errstring);
                }

                sx_close(s);

                /* !!! drop queue */

                return -1;
            }
        }
    }

    return 1;
}

static int _sx_ssl_wio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    _sx_ssl_conn_t sc = (_sx_ssl_conn_t) s->plugin_data[p->index];
    int est, ret, err;
    sx_buf_t wbuf;
    char *errstring;
    sx_error_t sxe;

    /* do not encrypt when error */
    if(sc->last_state == SX_SSL_STATE_ERROR)
        return 1;

    _sx_debug(ZONE, "in _sx_ssl_wio");

    /* queue the buffer */
    if(buf->len > 0) {
        _sx_debug(ZONE, "queueing buffer for write");

        jqueue_push(sc->wq, _sx_buffer_new(buf->data, buf->len, buf->notify, buf->notify_arg), 0);
        _sx_buffer_clear(buf);
        buf->notify = NULL;
        buf->notify_arg = NULL;
    }

    /* handshake */
    est = _sx_ssl_handshake(s, sc);
    if(est < 0)
        return -2;  /* fatal error */

    /* channel established, do some real writing */
    wbuf = NULL;
    if(est > 0 && jqueue_size(sc->wq) > 0) {
        _sx_debug(ZONE, "preparing queued buffer for write");

        wbuf = jqueue_pull(sc->wq);

        ret = SSL_write(sc->ssl, wbuf->data, wbuf->len);
        if(ret <= 0) {
            /* something's wrong */
            _sx_debug(ZONE, "write failed, requeuing buffer");

            /* requeue the buffer */
            jqueue_push(sc->wq, wbuf, (sc->wq->front != NULL) ? sc->wq->front->priority + 1 : 0);

            /* error checking */
            err = SSL_get_error(sc->ssl, ret);

            if(err == SSL_ERROR_ZERO_RETURN) {
                /* ssl channel closed, we're done */
                _sx_close(s);
            }

            if(err == SSL_ERROR_WANT_READ) {
                /* we'll be renegotiating next time */
                _sx_debug(ZONE, "renegotiation started");
                sc->last_state = SX_SSL_STATE_WANT_READ;
            }

            else {
                sc->last_state = SX_SSL_STATE_ERROR;

                /* something very bad */
                errstring = ERR_error_string(ERR_get_error(), NULL);
                _sx_debug(ZONE, "openssl error: %s", errstring);

                /* do not throw an error if in wrapper mode and pre-stream */
                if(!(s->state < state_STREAM && s->flags & SX_SSL_WRAPPER)) {
                    _sx_gen_error(sxe, SX_ERR_SSL, "SSL handshake error", errstring);
                    _sx_event(s, event_ERROR, (void *) &sxe);
                    sx_error(s, stream_err_UNDEFINED_CONDITION, errstring);
                }

                sx_close(s);

                /* !!! drop queue */

                return -2;  /* fatal */
            }
        }
    }

    /* prepare the buffer with stuff to write */
    if(BIO_pending(sc->wbio) > 0) {
        int bytes_pending = BIO_pending(sc->wbio);
        assert(buf->len == 0);
        _sx_buffer_alloc_margin(buf, 0, bytes_pending);
        BIO_read(sc->wbio, buf->data, bytes_pending);
        buf->len += bytes_pending;

        /* restore notify and clean up */
        if(wbuf != NULL) {
            buf->notify = wbuf->notify;
            buf->notify_arg = wbuf->notify_arg;
            _sx_buffer_free(wbuf);
        }

        _sx_debug(ZONE, "prepared %d ssl bytes for write", buf->len);
    }

    /* flag if we want to read */
    if(sc->last_state == SX_SSL_STATE_WANT_READ || sc->last_state == SX_SSL_STATE_NONE)
        s->want_read = 1;

    return 1;
}

static int _sx_ssl_rio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    _sx_ssl_conn_t sc = (_sx_ssl_conn_t) s->plugin_data[p->index];
    int est, ret, err, pending;
    char *errstring;
    sx_error_t sxe;

    /* sanity */
    if(sc->last_state == SX_SSL_STATE_ERROR)
        return -1;

    _sx_debug(ZONE, "in _sx_ssl_rio");

    /* move the data into the ssl read buffer */
    if(buf->len > 0) {
        _sx_debug(ZONE, "loading %d bytes into ssl read buffer", buf->len);

        BIO_write(sc->rbio, buf->data, buf->len);

        _sx_buffer_clear(buf);
    }

    /* handshake */
    est = _sx_ssl_handshake(s, sc);
    if(est < 0)
        return -1;  /* fatal error */

    /* channel is up, slurp up the read buffer */
    if(est > 0) {

        pending = SSL_pending(sc->ssl);
        if(pending == 0)
            pending = BIO_pending(sc->rbio);

        /* get it all */
        while((pending = SSL_pending(sc->ssl)) > 0 || (pending = BIO_pending(sc->rbio)) > 0) {
            _sx_buffer_alloc_margin(buf, 0, pending);

            ret = SSL_read(sc->ssl, &(buf->data[buf->len]), pending);

            if (ret == 0)
            {
                /* ret will equal zero if the SSL stream was closed.
                   (See the SSL_read manpage.) */

                /* If the SSL Shutdown happened properly,
                   (i.e. we got an SSL "close notify")
                   then proccess the last packet recieved. */
                if (SSL_get_shutdown(sc->ssl) == SSL_RECEIVED_SHUTDOWN)
                {
                  _sx_close(s);
                  break;
                }

                /* If the SSL stream was just closed and not shutdown,
                   drop the last packet recieved.
                   WARNING: This may cause clients that use SSLv2 and
                   earlier to not log out properly. */

                err = SSL_get_error(sc->ssl, ret);

                _sx_buffer_clear(buf);


                if(err == SSL_ERROR_ZERO_RETURN) {
                    /* ssl channel closed, we're done */
                    _sx_close(s);
                }

                return -1;
            }
            else if(ret < 0) {
                /* ret will be negative if the SSL stream needs
                   more data, or if there was a SSL error.
                   (See the SSL_read manpage.) */
                err = SSL_get_error(sc->ssl, ret);

                /* ssl block incomplete, need more */
                if(err == SSL_ERROR_WANT_READ) {
                    sc->last_state = SX_SSL_STATE_WANT_READ;

                    break;
                }

                /* something's wrong */
                _sx_buffer_clear(buf);


                /* !!! need checks for renegotiation */

                sc->last_state = SX_SSL_STATE_ERROR;

                errstring = ERR_error_string(ERR_get_error(), NULL);
                _sx_debug(ZONE, "openssl error: %s", errstring);

                /* do not throw an error if in wrapper mode and pre-stream */
                if(!(s->state < state_STREAM && s->flags & SX_SSL_WRAPPER)) {
                    _sx_gen_error(sxe, SX_ERR_SSL, "SSL handshake error", errstring);
                    _sx_event(s, event_ERROR, (void *) &sxe);
                    sx_error(s, stream_err_UNDEFINED_CONDITION, errstring);
                }

                sx_close(s);

                /* !!! drop queue */

                return -1;
            }

            buf->len += ret;
        }
    }

    /* flag if stuff to write */
    if(BIO_pending(sc->wbio) > 0 || (est > 0 && jqueue_size(sc->wq) > 0))
        s->want_write = 1;

    /* flag if we want to read */
    if(sc->last_state == SX_SSL_STATE_WANT_READ || sc->last_state == SX_SSL_STATE_NONE)
        s->want_read = 1;

    if(buf->len == 0)
        return 0;

    return 1;
}

static void _sx_ssl_client(sx_t s, sx_plugin_t p) {
    _sx_ssl_conn_t sc;
    SSL_CTX *ctx;
    char *pemfile = NULL;
    int ret, i;
    char *pemfile_password = NULL;

    /* only bothering if they asked for wrappermode */
    if(!(s->flags & SX_SSL_WRAPPER) || s->ssf > 0)
        return;

    _sx_debug(ZONE, "preparing for ssl connect for %d from %s", s->tag, s->req_from);

    /* find the ssl context for this source */
    ctx = xhash_get((xht) p->private, s->req_from);
    if(ctx == NULL) {
        _sx_debug(ZONE, "using default ssl context for %d", s->tag);
        ctx = xhash_get((xht) p->private, "*");
    } else {
        _sx_debug(ZONE, "using configured ssl context for %d", s->tag);
    }
    assert((int) (ctx != NULL));

    sc = (_sx_ssl_conn_t) calloc(1, sizeof(struct _sx_ssl_conn_st));

    /* create the buffers */
    sc->rbio = BIO_new(BIO_s_mem());
    sc->wbio = BIO_new(BIO_s_mem());

    /* new ssl conn */
    sc->ssl = SSL_new(ctx);
    SSL_set_bio(sc->ssl, sc->rbio, sc->wbio);
    SSL_set_connect_state(sc->ssl);
    SSL_set_options(sc->ssl, SSL_OP_NO_TICKET);
#ifdef ENABLE_EXPERIMENTAL
    SSL_set_ssl_method(sc->ssl, TLSv1_2_client_method());
#else
    SSL_set_ssl_method(sc->ssl, TLSv1_client_method());
#endif

    /* empty external_id */
    for (i = 0; i < SX_CONN_EXTERNAL_ID_MAX_COUNT; i++)
    	sc->external_id[i] = NULL;

    /* alternate pemfile */
    /* !!! figure out how to error correctly here - just returning will cause
     *     us to send a normal unencrypted stream start while the server is
     *     waiting for ClientHelo. the server will flag an error, but it won't
     *     help the admin at all to figure out what happened */
    if(s->plugin_data[p->index] != NULL) {
        pemfile = ((_sx_ssl_conn_t)s->plugin_data[p->index])->pemfile;
        pemfile_password = ((_sx_ssl_conn_t)s->plugin_data[p->index])->private_key_password;
        free(s->plugin_data[p->index]);
        s->plugin_data[p->index] = NULL;
    }
    if(pemfile != NULL) {
        /* load the certificate */
        ret = SSL_use_certificate_file(sc->ssl, pemfile, SSL_FILETYPE_PEM);
        if(ret != 1) {
            _sx_debug(ZONE, "couldn't load alternate certificate from %s", pemfile);
            SSL_free(sc->ssl);
            free(sc);
            free(pemfile);
            return;
        }

        /* set callback giving a password for pemfile */
        SSL_CTX_set_default_passwd_cb_userdata(sc->ssl->ctx, (void *)pemfile_password);
        SSL_CTX_set_default_passwd_cb(sc->ssl->ctx, &_sx_pem_passwd_callback);

        /* load the private key */
        ret = SSL_use_PrivateKey_file(sc->ssl, pemfile, SSL_FILETYPE_PEM);
        if(ret != 1) {
            _sx_debug(ZONE, "couldn't load alternate private key from %s", pemfile);
            SSL_free(sc->ssl);
            free(sc);
            free(pemfile);
            return;
        }

        /* check the private key matches the certificate */
        ret = SSL_check_private_key(sc->ssl);
        if(ret != 1) {
            _sx_debug(ZONE, "private key does not match certificate public key");
            SSL_free(sc->ssl);
            free(sc);
            free(pemfile);
            return;
        }

        _sx_debug(ZONE, "loaded alternate pemfile %s", pemfile);

        free(pemfile);
    }

    /* buffer queue */
    sc->wq = jqueue_new();

    s->plugin_data[p->index] = (void *) sc;

    /* bring the plugin online */
    _sx_chain_io_plugin(s, p);
}

static void _sx_ssl_server(sx_t s, sx_plugin_t p) {
    _sx_ssl_conn_t sc;
    SSL_CTX *ctx;
    int i;

    /* only bothering if they asked for wrappermode */
    if(!(s->flags & SX_SSL_WRAPPER) || s->ssf > 0)
        return;

    _sx_debug(ZONE, "preparing for ssl accept for %d to %s", s->tag, s->req_to);

    /* find the ssl context for this destination */
    ctx = xhash_get((xht) p->private, s->req_to);
    if(ctx == NULL) {
        _sx_debug(ZONE, "using default ssl context for %d", s->tag);
        ctx = xhash_get((xht) p->private, "*");
    } else {
        _sx_debug(ZONE, "using configured ssl context for %d", s->tag);
    }
    assert((int) (ctx != NULL));

    sc = (_sx_ssl_conn_t) calloc(1, sizeof(struct _sx_ssl_conn_st));

    /* create the buffers */
    sc->rbio = BIO_new(BIO_s_mem());
    sc->wbio = BIO_new(BIO_s_mem());

    /* new ssl conn */
    sc->ssl = SSL_new(ctx);
    SSL_set_bio(sc->ssl, sc->rbio, sc->wbio);
    SSL_set_accept_state(sc->ssl);
    SSL_set_options(sc->ssl, SSL_OP_NO_SSLv3);

    /* empty external_id */
    for (i = 0; i < SX_CONN_EXTERNAL_ID_MAX_COUNT; i++)
    	sc->external_id[i] = NULL;

    /* buffer queue */
    sc->wq = jqueue_new();

    s->plugin_data[p->index] = (void *) sc;

    /* bring the plugin online */
    _sx_chain_io_plugin(s, p);
}

/** cleanup */
static void _sx_ssl_free(sx_t s, sx_plugin_t p) {
    _sx_ssl_conn_t sc = (_sx_ssl_conn_t) s->plugin_data[p->index];
    sx_buf_t buf;
    int i;

    if(sc == NULL)
        return;

    log_debug(ZONE, "cleaning up conn state");

    if(s->type == type_NONE) {
        free(sc);
        return;
    }

    for (i = 0; i < SX_CONN_EXTERNAL_ID_MAX_COUNT; i++)
    	if(sc->external_id[i] != NULL)
    		free(sc->external_id[i]);
    	else
    		break;

    if(sc->pemfile != NULL) free(sc->pemfile);

    if(sc->private_key_password != NULL) free(sc->private_key_password);

    if(sc->ssl != NULL) SSL_free(sc->ssl);      /* frees wbio and rbio too */

    if(sc->wq != NULL) {
        while((buf = jqueue_pull(sc->wq)) != NULL)
            _sx_buffer_free(buf);

        jqueue_free(sc->wq);
    }

    free(sc);

    s->plugin_data[p->index] = NULL;
}

static void _sx_ssl_unload(sx_plugin_t p) {
    xht contexts = (xht) p->private;
    void *ctx;

    if(xhash_iter_first(contexts))
        do {
            xhash_iter_get(contexts, NULL, NULL, &ctx);
            SSL_CTX_free((SSL_CTX *) ctx);
        } while(xhash_iter_next(contexts));

    xhash_free(contexts);
}

int sx_openssl_initialized = 0;

/** args: name, pemfile, cachain, mode */
int sx_ssl_init(sx_env_t env, sx_plugin_t p, va_list args) {
    const char *name, *pemfile, *cachain, *password;
    int ret;
    int mode;

    _sx_debug(ZONE, "initialising ssl plugin");

    name = va_arg(args, const char *);
    pemfile = va_arg(args, const char *);
    if(pemfile == NULL)
        return 1;

    if(p->private != NULL)
        return 1;

    cachain = va_arg(args, const char *);
    mode = va_arg(args, int);
    password = va_arg(args, char *);

    /* !!! output openssl error messages to the debug log */

    /* openssl startup */
    if(!sx_openssl_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
    }
    sx_openssl_initialized = 1;

    ret = sx_ssl_server_addcert(p, name, pemfile, cachain, mode, password);
    if(ret)
        return 1;

    p->magic = SX_SSL_MAGIC;

    p->unload = _sx_ssl_unload;

    p->client = _sx_ssl_client;
    p->server = _sx_ssl_server;
    p->rio = _sx_ssl_rio;
    p->wio = _sx_ssl_wio;
    p->features = _sx_ssl_features;
    p->process = _sx_ssl_process;
    p->free = _sx_ssl_free;

    return 0;
}

RSA *rsa_512 = NULL;
RSA *rsa_1024 = NULL;
static RSA *sx_ssl_tmp_rsa_callback(SSL *ssl, int export, int keylength) {
 RSA *rsa_tmp = NULL;
 if (keylength == 512) {
 if (!rsa_512)
 rsa_512 = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
 rsa_tmp = rsa_512;
 }
 else {
 if (!rsa_1024)
 rsa_1024 = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
 rsa_tmp = rsa_1024;
 }
 return rsa_tmp;
}

static unsigned char dh512_p[] = {
 0xEC,0xAC,0xF9,0x92,0x4C,0x4E,0x5F,0x56,0xEC,0x15,0x7D,0xFD,
 0xFD,0xAC,0x0B,0xC6,0xDB,0xAD,0x0D,0x62,0x76,0x43,0x07,0xAB,
 0x1D,0x5A,0x8C,0xB6,0xE2,0xA7,0x48,0xEA,0xBE,0x91,0x22,0x9A,
 0x6E,0xB2,0xC8,0xF6,0x4F,0xF5,0x7A,0xA5,0x7F,0x6E,0x08,0x7D,
 0x4A,0x89,0xA0,0x54,0x2A,0x68,0x2D,0x06,0x59,0x89,0x32,0xF3,
 0x3D,0xF7,0x74,0x1B,
};
static unsigned char dh512_g[] = {
 0x02,
};

static DH *get_dh512(void) {
 DH *dh;

 if (!(dh = DH_new()))
 return NULL;

 dh->p = BN_bin2bn(dh512_p, sizeof(dh512_p), NULL);
 dh->g = BN_bin2bn(dh512_g, sizeof(dh512_g), NULL);
 if (!(dh->p && dh->g)) {
 DH_free(dh);
 return NULL;
 }

 return dh;
}

static unsigned char dh1024_p[] = {
 0xDF,0x0A,0xB8,0xCD,0x84,0xBB,0x91,0xF7,0xA1,0x8F,0x75,0xBB,
 0x20,0xC9,0x54,0x9D,0x50,0x89,0xC4,0x1A,0x0D,0xD5,0x40,0x6D,
 0x66,0x76,0x02,0x5F,0xD7,0xB2,0xB4,0xB9,0x88,0xFB,0xF8,0xD5,
 0xE9,0x6C,0xBB,0x17,0x51,0x9F,0x5B,0x7C,0xD1,0x0D,0x82,0x3F,
 0xCD,0xA2,0xF5,0x16,0x01,0x3C,0x4A,0xDF,0xC7,0x6A,0x66,0x2B,
 0x83,0x00,0x50,0x5D,0x81,0x93,0x16,0x1C,0xA5,0x92,0xA4,0x75,
 0x8E,0x32,0x92,0xDF,0xCA,0x51,0x98,0x16,0xFB,0x37,0x06,0xD3,
 0xFE,0x52,0xD8,0xBE,0x0F,0x4D,0xA8,0xA6,0xDF,0xF0,0x16,0x09,
 0xD6,0x84,0xAB,0xF6,0x3E,0xDD,0x29,0x42,0x3C,0xE5,0xCA,0xEA,
 0x70,0xFF,0x33,0x33,0x6C,0xEB,0x54,0xA2,0x28,0x58,0xFF,0xFC,
 0x38,0xFE,0x70,0xC0,0xE8,0xA8,0x53,0x1B,
};
static unsigned char dh1024_g[] = {
 0x02,
};

static DH *get_dh1024(void) {
 DH *dh;

 if (!(dh = DH_new()))
 return NULL;

 dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
 dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);
 if (!(dh->p && dh->g)) {
 DH_free(dh);
 return NULL;
 }

 return dh;
}

DH *dh_512 = NULL;
DH *dh_1024 = NULL;
static DH *sx_ssl_tmp_dh_callback(SSL *ssl, int export, int keylength) {
 DH *dh_tmp = NULL;
 if (keylength == 512) {
 if (!dh_512)
 dh_512 = get_dh512();
 dh_tmp = dh_512;
 }
 else {
 if (!dh_1024)
 dh_1024 = get_dh1024();
 dh_tmp = dh_1024;
 }
 return dh_tmp;
}

EC_KEY *ec_256 = NULL;
static EC_KEY *sx_ssl_tmp_ecdh_callback(SSL *ssl, int export, int keylength) {
 EC_KEY *ec_tmp = NULL;
 if (!ec_256) {
 ec_256 = EC_KEY_new();
 EC_KEY_set_group(ec_256, EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
 }
 ec_tmp = ec_256;
 return ec_tmp;
}

/** args: name, pemfile, cachain, mode */
int sx_ssl_server_addcert(sx_plugin_t p, const char *name, const char *pemfile, const char *cachain, int mode, const char *password) {
    xht contexts = (xht) p->private;
    SSL_CTX *ctx;
    SSL_CTX *tmp;
    STACK_OF(X509_NAME) *cert_names;
    X509_STORE * store;
    int ret;

    if(!sx_openssl_initialized) {
        _sx_debug(ZONE, "ssl plugin not initialised");
        return 1;
    }

    if(name == NULL)
        name = "*";

    if(pemfile == NULL)
        return 1;

    /* begin with fresh error stack */
    ERR_clear_error();

    /* create the context */
#ifdef ENABLE_EXPERIMENTAL
    ctx = SSL_CTX_new(TLSv1_2_method());
#else
    ctx = SSL_CTX_new(SSLv23_method());
#endif
    if(ctx == NULL) {
        _sx_debug(ZONE, "ssl context creation failed; %s", ERR_error_string(ERR_get_error(), NULL));
        return 1;
    }

     SSL_CTX_set_tmp_rsa_callback(ctx, sx_ssl_tmp_rsa_callback);
     SSL_CTX_set_tmp_dh_callback(ctx, sx_ssl_tmp_dh_callback);
     SSL_CTX_set_tmp_ecdh_callback(ctx, sx_ssl_tmp_ecdh_callback);

    // Set allowed ciphers
       if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:HIGH:!MD5:!LOW:!SSLv2:!EXP:!aNULL:!EDH:!RC4") != 1) {
        _sx_debug(ZONE, "Can't set cipher list for SSL context: %s", ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Load the CA chain, if configured */
    if (cachain != NULL) {
        ret = SSL_CTX_load_verify_locations (ctx, cachain, NULL);
        if(ret != 1) {
            _sx_debug(ZONE, "WARNING: couldn't load CA chain: %s; %s", cachain, ERR_error_string(ERR_get_error(), NULL));
        } else {
        	_sx_debug(ZONE, "Loaded CA verify location chain: %s", cachain);
        }
        cert_names = SSL_load_client_CA_file(cachain);
        if (cert_names != NULL) {
        	SSL_CTX_set_client_CA_list(ctx, cert_names);
        	_sx_debug(ZONE, "Loaded client CA chain: %s", cachain);
        } else {
        	_sx_debug(ZONE, "WARNING: couldn't load client CA chain: %s", cachain);
        }
    } else {
    	/* Load the default OpenlSSL certs from /etc/ssl/certs
    	 We must assume that the client certificate's CA is there

    	 Note: We don't send client_CA_list here. Will possibly break some clients.
    	 */
    	SSL_CTX_set_default_verify_paths(ctx);
    	_sx_debug(ZONE, "No CA chain specified. Loading SSL default CA certs: /etc/ssl/certs");
    }
    /* Add server CRL verificaition */
    store = SSL_CTX_get_cert_store(ctx);
    // Not sure if this should be X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL
    // or only X509_V_FLAG_CRL_CHECK
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

    /* load the certificate */
    ret = SSL_CTX_use_certificate_chain_file(ctx, pemfile);
    if(ret != 1) {
        _sx_debug(ZONE, "couldn't load certificate from %s; %s", pemfile, ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ctx);
        return 1;
    }

    /* set callback giving a password for pemfile */
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)password);
    SSL_CTX_set_default_passwd_cb(ctx, &_sx_pem_passwd_callback);

    /* load the private key */
    ret = SSL_CTX_use_PrivateKey_file(ctx, pemfile, SSL_FILETYPE_PEM);
    if(ret != 1) {
        _sx_debug(ZONE, "couldn't load private key from %s; %s", pemfile, ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ctx);
        return 1;
    }

    /* check the private key matches the certificate */
    ret = SSL_CTX_check_private_key(ctx);
    if(ret != 1) {
        _sx_debug(ZONE, "private key does not match certificate public key; %s", ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ctx);
        return 1;
    }

    _sx_debug(ZONE, "setting ssl context '%s' verify mode to %02x", name, mode);
    SSL_CTX_set_verify(ctx, mode, _sx_ssl_verify_callback);

    /* create hash and create default context */
    if(contexts == NULL) {
        contexts = xhash_new(1021);
        p->private = (void *) contexts;

        /* this is the first context, if it's not the default then make a copy of it as the default */
        if(!(name[0] == '*' && name[1] == 0)) {
            int ret = sx_ssl_server_addcert(p, "*", pemfile, cachain, mode, password);

            if(ret) {
                /* uh-oh */
                xhash_free(contexts);
                p->private = NULL;
                return 1;
            }
        }
    }

    _sx_debug(ZONE, "ssl context '%s' initialised; certificate and key loaded from %s", name, pemfile);

    /* remove an existing context with the same name before replacing it */
    tmp = xhash_get(contexts, name);
    if(tmp != NULL)
        SSL_CTX_free((SSL_CTX *) tmp);

    xhash_put(contexts, name, ctx);

    return 0;
}

int sx_ssl_client_starttls(sx_plugin_t p, sx_t s, const char *pemfile, const char *private_key_password) {
    assert((int) (p != NULL));
    assert((int) (s != NULL));

    /* sanity */
    if(s->type != type_CLIENT || s->state != state_STREAM) {
        _sx_debug(ZONE, "wrong conn type or state for client starttls");
        return 1;
    }

    /* check if we're already encrypted or compressed */
    if(s->ssf > 0 || s->compressed) {
        _sx_debug(ZONE, "encrypted channel already established");
        return 1;
    }

    _sx_debug(ZONE, "initiating starttls sequence");

    /* save the given pemfile for later */
    if(pemfile != NULL) {
        s->plugin_data[p->index] = (_sx_ssl_conn_t) calloc(1, sizeof(struct _sx_ssl_conn_st));
        ((_sx_ssl_conn_t)s->plugin_data[p->index])->pemfile = strdup(pemfile);

         /* save the given password for later */
         if(private_key_password != NULL)
             ((_sx_ssl_conn_t)s->plugin_data[p->index])->private_key_password = strdup(private_key_password);
    }

    /* go */
    jqueue_push(s->wbufq, _sx_buffer_new("<starttls xmlns='" uri_TLS "'/>", strlen(uri_TLS) + 20, NULL, NULL), 0);
    s->want_write = 1;
    _sx_event(s, event_WANT_WRITE, NULL);

    return 0;
}
