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
#include <lib/uri.h>
#include <lib/log.h>
#include <lib/miniz.h>

#include <string.h>
#include <assert.h>

/* allocation chunk for decompression */
#define SX_COMPRESS_CHUNK       16384

/** a single conn */
typedef struct _sx_compress_conn_st {
    /* miniz *flators */
    tinfl_decompressor  inflator;
    tdefl_compressor    deflator;

    /* buffers for compressed and decompressed data */
    sx_buf_t   *wbuf, *rbuf;

} _sx_compress_conn_t;

#define LOG_CATEGORY "sx.compress"
static log4c_category_t *log;

static void _sx_compress_notify_compress(sx_t *s, __attribute__ ((unused)) void *arg) {

    LOG_DEBUG(log, "preparing for compress");

    _sx_reset(s);

    /* start listening */
    sx_server_init(s, s->flags | SX_COMPRESS_WRAPPER);
}

static int _sx_compress_process(sx_t *s, __attribute__ ((unused)) sx_plugin_t *p, nad_t *nad) {
    int flags;
    char *ns = NULL, *to = NULL, *from = NULL, *version = NULL;
    sx_error_t sxe;

    /* not interested if we're a server and we never offered it */
    if (s->type == type_SERVER && !(s->flags & SX_COMPRESS_OFFER))
        return 1;

    /* only want compress packets */
    if (NAD_ENS(nad, 0) < 0 || NAD_NURI_L(nad, NAD_ENS(nad, 0)) != sizeof(uri_COMPRESS)-1 || strncmp(NAD_NURI(nad, NAD_ENS(nad, 0)), uri_COMPRESS, sizeof(uri_COMPRESS)-1) != 0)
        return 1;

    /* compress from client */
    if (s->type == type_SERVER) {
        if (NAD_ENAME_L(nad, 0) == 8 && strncmp(NAD_ENAME(nad, 0), "compress", 8) == 0) {
            nad_free(nad);

            /* can't go on if we've been here before */
            if (s->flags & SX_COMPRESS_WRAPPER) {
                LOG_WARN(log, "compress requested on already compressed channel, dropping packet");
                return 0;
            }

            LOG_DEBUG(log, "compress requested, setting up");

            /* go ahead */
            jqueue_push(s->wbufq, _sx_buffer_new("<compressed xmlns='" uri_COMPRESS "'/>", sizeof(uri_COMPRESS)-1 + 22, _sx_compress_notify_compress, NULL), 0);
            s->want_write = 1;

            /* handled the packet */
            return 0;
        }
    }

    else if (s->type == type_CLIENT) {
        /* kick off the handshake */
        if (NAD_ENAME_L(nad, 0) == 7 && strncmp(NAD_ENAME(nad, 0), "compressed", 7) == 0) {
            nad_free(nad);

            /* save interesting bits */
            flags = s->flags;

            if(s->ns != NULL) ns = strdup(s->ns);

            if (s->req_to != NULL) to = strdup(s->req_to);
            if (s->req_from != NULL) from = strdup(s->req_from);
            if (s->req_version != NULL) version = strdup(s->req_version);

            /* reset state */
            _sx_reset(s);

            LOG_DEBUG(log, "server ready for compression, starting");

            /* second time round */
            sx_client_init(s, flags | SX_COMPRESS_WRAPPER, ns, to, from, version);

            /* free bits */
            if (ns != NULL) free(ns);
            if (to != NULL) free(to);
            if (from != NULL) free(from);
            if (version != NULL) free(version);

            return 0;
        }

        /* busted server */
        if (NAD_ENAME_L(nad, 0) == 7 && strncmp(NAD_ENAME(nad, 0), "failure", 7) == 0) {
            nad_free(nad);

            LOG_NOTICE(log, "server can't handle compression, business as usual");

            _sx_gen_error(sxe, SX_ERR_COMPRESS_FAILURE, "compress failure", "Server was unable to establish compression");
            _sx_event(s, event_ERROR, (void *) &sxe);

            return 0;
        }
    }

    LOG_WARN(log, "unknown compress namespace element '%.*s', dropping packet", NAD_ENAME_L(nad, 0), NAD_ENAME(nad, 0));
    nad_free(nad);
    return 0;
}

static void _sx_compress_features(sx_t *s, __attribute__ ((unused)) sx_plugin_t *p, nad_t *nad) {
    int ns;

    /* if the session is already compressed, or the app told us not to, or we are on WebSocket framing,
        * or STARTTLS is required and stream is not encrypted yet, then we don't offer anything */
    if ((s->flags & SX_COMPRESS_WRAPPER) || !(s->flags & SX_COMPRESS_OFFER) || ((s->flags & SX_SSL_STARTTLS_REQUIRE) && s->ssf == 0) || (s->flags & SX_WEBSOCKET_WRAPPER))
        return;

    LOG_DEBUG(log, "offering compression");

    ns = nad_add_namespace(nad, uri_COMPRESS_FEATURE, NULL);
    nad_append_elem(nad, ns, "compression", 1);
    nad_append_elem(nad, ns, "method", 2);
    nad_append_cdata(nad, "zlib", 4, 3);
}

static int _sx_compress_wio(sx_t *s, sx_plugin_t *p, sx_buf_t *buf) {
    _sx_compress_conn_t *sc = (_sx_compress_conn_t*) s->plugin_data[p->index];
    sx_error_t sxe;

    /* only bothering if they asked for wrappermode */
    if (!(s->flags & SX_COMPRESS_WRAPPER))
        return 1;

    LOG_TRACE(log, "in _sx_compress_wio");

    /* move the data into the zlib write buffer */
    if (buf->len > 0) {
        LOG_TRACE(log, "loading %d bytes into zlib write buffer", buf->len);

        _sx_buffer_alloc_margin(sc->wbuf, 0, buf->len);
        memcpy(sc->wbuf->data + sc->wbuf->len, buf->data, buf->len);
        sc->wbuf->len += buf->len;

        _sx_buffer_clear(buf);
    }

    /* compress the data */
    if (sc->wbuf->len > 0) {
        tdefl_status status;
        size_t in_bytes, out_bytes, avail_out;

        /* deflate() on write buffer until there is data to compress */
        do {
            /* make place for deflated data */
            avail_out = sc->wbuf->len + SX_COMPRESS_CHUNK;
            _sx_buffer_alloc_margin(buf, 0, avail_out);

            in_bytes = sc->wbuf->len;
            out_bytes = avail_out;

            status = tdefl_compress(&sc->deflator, sc->wbuf->data, &in_bytes, buf->data + buf->len, &out_bytes, TDEFL_SYNC_FLUSH);
            if (status != TDEFL_STATUS_OKAY) break;

            sc->wbuf->data += in_bytes;
            sc->wbuf->len -= in_bytes;

            avail_out -= out_bytes;
            buf->len += out_bytes;

        } while (avail_out == 0);

        if (status != TDEFL_STATUS_OKAY || sc->wbuf->len != 0) {
            /* throw an error */
            _sx_gen_error(sxe, SX_ERR_COMPRESS, "compression error", "Error during compression");
            _sx_event(s, event_ERROR, (void *) &sxe);

            sx_error(s, stream_err_INTERNAL_SERVER_ERROR, "Error during compression");
            sx_close(s);

            return -2;  /* fatal */
        }
    }

    LOG_TRACE(log, "passing %d bytes from zlib write buffer", buf->len);

    return 1;
}

static int _sx_compress_rio(sx_t *s, sx_plugin_t *p, sx_buf_t *buf) {
    _sx_compress_conn_t *sc = (_sx_compress_conn_t*) s->plugin_data[p->index];
    sx_error_t sxe;

    /* only bothering if they asked for wrappermode */
    if (!(s->flags & SX_COMPRESS_WRAPPER))
        return 1;

    LOG_TRACE(log, "in _sx_compress_rio");

    /* move the data into the zlib read buffer */
    if (buf->len > 0) {
        LOG_TRACE(log, "loading %d bytes into zlib read buffer", buf->len);

        _sx_buffer_alloc_margin(sc->rbuf, 0, buf->len);
        memcpy(sc->rbuf->data + sc->rbuf->len, buf->data, buf->len);
        sc->rbuf->len += buf->len;

        _sx_buffer_clear(buf);
    }

    /* decompress the data */
    if (sc->rbuf->len > 0) {
        tinfl_status status;
        size_t in_bytes, out_bytes, avail_out;
        mz_uint8 *buf_start = (mz_uint8 *)buf->data;

        /* run inflate() on read buffer while able to fill the output buffer */
        do {
            /* make place for inflated data */
            avail_out = SX_COMPRESS_CHUNK;
            _sx_buffer_alloc_margin(buf, 0, SX_COMPRESS_CHUNK);

            in_bytes = sc->rbuf->len;
            out_bytes = avail_out;

            status = tinfl_decompress(&sc->inflator, (const mz_uint8 *)sc->rbuf->data, &in_bytes, buf_start, (mz_uint8 *)(buf->data + buf->len), &out_bytes, TINFL_FLAG_HAS_MORE_INPUT | TINFL_FLAG_PARSE_ZLIB_HEADER);

            sc->rbuf->data += in_bytes;
            sc->rbuf->len -= in_bytes;

            avail_out -= out_bytes;
            buf->len += out_bytes;

            if (status <= TINFL_STATUS_DONE || buf->len > s->rbytesmax) {
                /* throw an error */
                _sx_gen_error(sxe, SX_ERR_COMPRESS, "compression error", "Error during decompression");
                _sx_event(s, event_ERROR, (void *) &sxe);

                sx_error(s, stream_err_INVALID_XML, "Error during decompression");
                sx_close(s);

                return -2;
            }


        } while (avail_out == 0);
    }

    LOG_TRACE(log, "passing %d bytes from zlib read buffer", buf->len);

    /* flag if we want to read */
    if (sc->rbuf->len > 0)
    s->want_read = 1;

    if (buf->len == 0)
        return 0;

    return 1;
}

static void _sx_compress_new(sx_t *s, sx_plugin_t *p) {
    _sx_compress_conn_t *sc = (_sx_compress_conn_t*) s->plugin_data[p->index];

    /* only bothering if they asked for wrappermode and not already active */
    if (!(s->flags & SX_COMPRESS_WRAPPER) || sc)
        return;

    LOG_DEBUG(log, "preparing for compressed connect for %s:%d", s->ip, s->port);

    sc = new(_sx_compress_conn_t);

    /* initialize inflator */
    tinfl_init(&sc->inflator);

    /* initialize deflator */
    // The number of dictionary probes to use at each compression level (0-10). 0=implies fastest/minimal possible probing.
    static const mz_uint s_tdefl_num_probes[11] = { 0, 1, 6, 32,  16, 32, 128, 256,  512, 768, 1500 };
    // create tdefl() compatible flags (we have to compose the low-level flags ourselves, or use tdefl_create_comp_flags_from_zip_params() but that means MINIZ_NO_ZLIB_APIS can't be defined).
    mz_uint comp_flags = TDEFL_WRITE_ZLIB_HEADER | s_tdefl_num_probes[MZ_DEFAULT_LEVEL] | ((MZ_DEFAULT_LEVEL <= 3) ? TDEFL_GREEDY_PARSING_FLAG : 0);
    if (!MZ_DEFAULT_LEVEL) comp_flags |= TDEFL_FORCE_ALL_RAW_BLOCKS;

    tdefl_status status = tdefl_init(&sc->deflator, NULL, NULL, comp_flags);
    if (status != TDEFL_STATUS_OKAY) {
        LOG_WARN(log, "failure %d initializing deflator for %s:%d", status, s->ip, s->port);
        s->flags &= !SX_COMPRESS_WRAPPER;
        return;
    }

    /* read and write buffers */
    sc->rbuf = _sx_buffer_new(NULL, 0, NULL, NULL);
    sc->wbuf = _sx_buffer_new(NULL, 0, NULL, NULL);

    s->plugin_data[p->index] = (void *) sc;

    /* bring the plugin online */
    _sx_chain_io_plugin(s, p);
}

/** cleanup */
static void _sx_compress_free(sx_t *s, sx_plugin_t *p) {
    _sx_compress_conn_t *sc = (_sx_compress_conn_t*) s->plugin_data[p->index];

    if (sc == NULL)
        return;

    LOG_DEBUG(log, "cleaning up compression state");

    if (s->type == type_NONE) {
        free(sc);
        return;
    }

    /* free buffers */
    _sx_buffer_free(sc->rbuf);
    _sx_buffer_free(sc->wbuf);

    free(sc);

    s->plugin_data[p->index] = NULL;
}

/** args: none */
int sx_compress_init(__attribute__ ((unused)) sx_env_t *env, sx_plugin_t *p, __attribute__ ((unused)) va_list args) {

    log = log4c_category_get(LOG_CATEGORY);
    LOG_INFO(log, "initialising compression sx plugin");

    p->client = _sx_compress_new;
    p->server = _sx_compress_new;
    p->rio = _sx_compress_rio;
    p->wio = _sx_compress_wio;
    p->features = _sx_compress_features;
    p->process = _sx_compress_process;
    p->free = _sx_compress_free;

    return 0;
}

int sx_compress_client_compress(sx_plugin_t *p, sx_t *s, __attribute__ ((unused)) const char *pemfile) {
    assert((int) (p != NULL));
    assert((int) (s != NULL));

    /* sanity */
    if (s->type != type_CLIENT || s->state != state_STREAM) {
        LOG_WARN(log, "wrong conn type or state for client compress");
        return 1;
    }

    /* check if we're already compressed */
    if ((s->flags & SX_COMPRESS_WRAPPER)) {
        LOG_WARN(log, "channel already compressed");
        return 1;
    }

    LOG_DEBUG(log, "initiating compress sequence");

    /* go */
    jqueue_push(s->wbufq, _sx_buffer_new("<compress xmlns='" uri_COMPRESS "'><method>zlib</method></compress>", sizeof(uri_COMPRESS)-1 + 51, NULL, NULL), 0);
    s->want_write = 1;
    _sx_event(s, event_WANT_WRITE, NULL);

    return 0;
}
