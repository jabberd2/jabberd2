/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2007 Tomasz Sterna
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
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
 * this plugin implements the XEP-0138: Stream Compression
 */

#include "sx.h"

static void _sx_compress_notify_compress(sx_t s, void *arg) {

    _sx_debug(ZONE, "preparing for compress");

    _sx_reset(s);

    /* start listening */
    sx_server_init(s, s->flags | SX_COMPRESS_WRAPPER);
}

static int _sx_compress_process(sx_t s, sx_plugin_t p, nad_t nad) {
    int flags;
    char *ns = NULL, *to = NULL, *from = NULL, *version = NULL;
    sx_error_t sxe;

    /* not interested if we're a server and we never offered it */
    if(s->type == type_SERVER && !(s->flags & SX_COMPRESS_OFFER))
        return 1;

    /* only want compress packets */
    if(NAD_ENS(nad, 0) < 0 || NAD_NURI_L(nad, NAD_ENS(nad, 0)) != sizeof(uri_COMPRESS)-1 || strncmp(NAD_NURI(nad, NAD_ENS(nad, 0)), uri_COMPRESS, sizeof(uri_COMPRESS)-1) != 0)
        return 1;

    /* compress from client */
    if(s->type == type_SERVER) {
        if(NAD_ENAME_L(nad, 0) == 8 && strncmp(NAD_ENAME(nad, 0), "compress", 8) == 0) {
            nad_free(nad);

            /* can't go on if we've been here before */
            if(s->compressed) {
                _sx_debug(ZONE, "compress requested on already compressed channel, dropping packet");
                return 0;
            }

            _sx_debug(ZONE, "compress requested, setting up");

            /* go ahead */
            jqueue_push(s->wbufq, _sx_buffer_new("<compressed xmlns='" uri_COMPRESS "'/>", sizeof(uri_COMPRESS)-1 + 22, _sx_compress_notify_compress, NULL), 0);
            s->want_write = 1;

            /* handled the packet */
            return 0;
        }
    }

    else if(s->type == type_CLIENT) {
        /* kick off the handshake */
        if(NAD_ENAME_L(nad, 0) == 7 && strncmp(NAD_ENAME(nad, 0), "compressed", 7) == 0) {
            nad_free(nad);

            /* save interesting bits */
            flags = s->flags;

            if(s->ns != NULL) ns = strdup(s->ns);

            if(s->req_to != NULL) to = strdup(s->req_to);
            if(s->req_from != NULL) from = strdup(s->req_from);
            if(s->req_version != NULL) version = strdup(s->req_version);

            /* reset state */
            _sx_reset(s);

            _sx_debug(ZONE, "server ready for compression, starting");

            /* second time round */
            sx_client_init(s, flags | SX_COMPRESS_WRAPPER, ns, to, from, version);

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

            _sx_debug(ZONE, "server can't handle compression, business as usual");

            _sx_gen_error(sxe, SX_ERR_COMPRESS_FAILURE, "compress failure", "Server was unable to establish compression");
            _sx_event(s, event_ERROR, (void *) &sxe);

            return 0;
        }
    }

    _sx_debug(ZONE, "unknown compress namespace element '%.*s', dropping packet", NAD_ENAME_L(nad, 0), NAD_ENAME(nad, 0));
    nad_free(nad);
    return 0;
}

static void _sx_compress_features(sx_t s, sx_plugin_t p, nad_t nad) {
    int ns;

    /* if the session is already compressed, or the app told us not to,
	 * or STARTTLS is required and stream is not encrypted yet, then we don't offer anything */
    if(s->compressed || !(s->flags & SX_COMPRESS_OFFER) || ((s->flags & SX_SSL_STARTTLS_REQUIRE) && s->ssf == 0))
        return;

    _sx_debug(ZONE, "offering compression");

    ns = nad_add_namespace(nad, uri_COMPRESS_FEATURE, NULL);
    nad_append_elem(nad, ns, "compression", 1);
    nad_append_elem(nad, ns, "method", 2);
    nad_append_cdata(nad, "zlib", 4, 3);
}

static int _sx_compress_wio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    _sx_compress_conn_t sc = (_sx_compress_conn_t) s->plugin_data[p->index];
    int ret;
    sx_error_t sxe;

    /* only bothering if they asked for wrappermode */
    if(!(s->flags & SX_COMPRESS_WRAPPER) || !s->compressed)
        return 1;

    _sx_debug(ZONE, "in _sx_compress_wio");

    /* move the data into the zlib write buffer */
    if(buf->len > 0) {
        _sx_debug(ZONE, "loading %d bytes into zlib write buffer", buf->len);

        _sx_buffer_alloc_margin(sc->wbuf, 0, buf->len);
        memcpy(sc->wbuf->data + sc->wbuf->len, buf->data, buf->len);
        sc->wbuf->len += buf->len;

        _sx_buffer_clear(buf);
    }

    /* compress the data */
    if(sc->wbuf->len > 0) {
        sc->wstrm.avail_in = sc->wbuf->len;
        sc->wstrm.next_in = (Bytef*)sc->wbuf->data;
        /* deflate() on write buffer until there is data to compress */
        do {
            /* make place for deflated data */
            _sx_buffer_alloc_margin(buf, 0, sc->wbuf->len + SX_COMPRESS_CHUNK);

                sc->wstrm.avail_out = sc->wbuf->len + SX_COMPRESS_CHUNK;
            sc->wstrm.next_out = (Bytef*)(buf->data + buf->len);

            ret = deflate(&(sc->wstrm), Z_SYNC_FLUSH);
            assert(ret != Z_STREAM_ERROR);

            buf->len += sc->wbuf->len + SX_COMPRESS_CHUNK - sc->wstrm.avail_out;

        } while (sc->wstrm.avail_out == 0);

        if(ret != Z_OK || sc->wstrm.avail_in != 0) {
            /* throw an error */
            _sx_gen_error(sxe, SX_ERR_COMPRESS, "compression error", "Error during compression");
            _sx_event(s, event_ERROR, (void *) &sxe);

            sx_error(s, stream_err_INTERNAL_SERVER_ERROR, "Error during compression");
            sx_close(s);

            return -2;  /* fatal */
        }

        sc->wbuf->len = sc->wstrm.avail_in;
        sc->wbuf->data = (char*)sc->wstrm.next_in;
    }

    _sx_debug(ZONE, "passing %d bytes from zlib write buffer", buf->len);

    return 1;
}

static int _sx_compress_rio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    _sx_compress_conn_t sc = (_sx_compress_conn_t) s->plugin_data[p->index];
    int ret;
    sx_error_t sxe;

    /* only bothering if they asked for wrappermode */
    if(!(s->flags & SX_COMPRESS_WRAPPER) || !s->compressed)
        return 1;

    _sx_debug(ZONE, "in _sx_compress_rio");

    /* move the data into the zlib read buffer */
    if(buf->len > 0) {
        _sx_debug(ZONE, "loading %d bytes into zlib read buffer", buf->len);

        _sx_buffer_alloc_margin(sc->rbuf, 0, buf->len);
        memcpy(sc->rbuf->data + sc->rbuf->len, buf->data, buf->len);
        sc->rbuf->len += buf->len;

        _sx_buffer_clear(buf);
    }

    /* decompress the data */
    if(sc->rbuf->len > 0) {
        sc->rstrm.avail_in = sc->rbuf->len;
        sc->rstrm.next_in = (Bytef*)sc->rbuf->data;
        /* run inflate() on read buffer while able to fill the output buffer */
        do {
            /* make place for inflated data */
            _sx_buffer_alloc_margin(buf, 0, SX_COMPRESS_CHUNK);

            sc->rstrm.avail_out = SX_COMPRESS_CHUNK;
            sc->rstrm.next_out = (Bytef*)(buf->data + buf->len);

            ret = inflate(&(sc->rstrm), Z_SYNC_FLUSH);
            assert(ret != Z_STREAM_ERROR);
            switch (ret) {
            case Z_NEED_DICT:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                /* throw an error */
                _sx_gen_error(sxe, SX_ERR_COMPRESS, "compression error", "Error during decompression");
                _sx_event(s, event_ERROR, (void *) &sxe);

                sx_error(s, stream_err_INVALID_XML, "Error during decompression");
                sx_close(s);

                return -2;
            }

            buf->len += SX_COMPRESS_CHUNK - sc->rstrm.avail_out;

        } while (sc->rstrm.avail_out == 0);

        sc->rbuf->len = sc->rstrm.avail_in;
        sc->rbuf->data = (char*)sc->rstrm.next_in;
    }

    _sx_debug(ZONE, "passing %d bytes from zlib read buffer", buf->len);

    /* flag if we want to read */
    if(sc->rbuf->len > 0)
    s->want_read = 1;

    if(buf->len == 0)
        return 0;

    return 1;
}

static void _sx_compress_new(sx_t s, sx_plugin_t p) {
    _sx_compress_conn_t sc;

    /* only bothering if they asked for wrappermode */
    if(!(s->flags & SX_COMPRESS_WRAPPER) || s->compressed)
        return;

    _sx_debug(ZONE, "preparing for compressed connect for %d", s->tag);

    sc = (_sx_compress_conn_t) calloc(1, sizeof(struct _sx_compress_conn_st));

    /* initialize streams */
    sc->rstrm.zalloc = Z_NULL;
    sc->rstrm.zfree = Z_NULL;
    sc->rstrm.opaque = Z_NULL;
    sc->rstrm.avail_in = 0;
    sc->rstrm.next_in = Z_NULL;
    inflateInit(&(sc->rstrm));

    sc->wstrm.zalloc = Z_NULL;
    sc->wstrm.zfree = Z_NULL;
    sc->wstrm.opaque = Z_NULL;
    deflateInit(&(sc->wstrm), Z_DEFAULT_COMPRESSION);

    /* read and write buffers */
    sc->rbuf = _sx_buffer_new(NULL, 0, NULL, NULL);
    sc->wbuf = _sx_buffer_new(NULL, 0, NULL, NULL);

    s->plugin_data[p->index] = (void *) sc;

    /* bring the plugin online */
    _sx_chain_io_plugin(s, p);

    /* mark stream compressed */
    s->compressed = 1;
}

/** cleanup */
static void _sx_compress_free(sx_t s, sx_plugin_t p) {
    _sx_compress_conn_t sc = (_sx_compress_conn_t) s->plugin_data[p->index];

    if(sc == NULL)
        return;

    log_debug(ZONE, "cleaning up compression state");

    if(s->type == type_NONE) {
        free(sc);
        return;
    }

    /* end streams */
    inflateEnd(&(sc->rstrm));
    deflateEnd(&(sc->wstrm));

    /* free buffers */
    _sx_buffer_free(sc->rbuf);
    _sx_buffer_free(sc->wbuf);

    free(sc);

    s->plugin_data[p->index] = NULL;
}

/** args: none */
int sx_compress_init(sx_env_t env, sx_plugin_t p, va_list args) {

    _sx_debug(ZONE, "initialising compression plugin");

    p->client = _sx_compress_new;
    p->server = _sx_compress_new;
    p->rio = _sx_compress_rio;
    p->wio = _sx_compress_wio;
    p->features = _sx_compress_features;
    p->process = _sx_compress_process;
    p->free = _sx_compress_free;

    return 0;
}

int sx_compress_client_compress(sx_plugin_t p, sx_t s, const char *pemfile) {
    assert((int) (p != NULL));
    assert((int) (s != NULL));

    /* sanity */
    if(s->type != type_CLIENT || s->state != state_STREAM) {
        _sx_debug(ZONE, "wrong conn type or state for client compress");
        return 1;
    }

    /* check if we're already compressed */
    if((s->flags & SX_COMPRESS_WRAPPER) || s->compressed) {
        _sx_debug(ZONE, "channel already compressed");
        return 1;
    }

    _sx_debug(ZONE, "initiating compress sequence");

    /* go */
    jqueue_push(s->wbufq, _sx_buffer_new("<compress xmlns='" uri_COMPRESS "'><method>zlib</method></compress>", sizeof(uri_COMPRESS)-1 + 51, NULL, NULL), 0);
    s->want_write = 1;
    _sx_event(s, event_WANT_WRITE, NULL);

    return 0;
}
