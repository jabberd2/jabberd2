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

#include "sx.h"

static void _sx_server_notify_header(sx_t s, void *arg) {
    int i, ns, len;
    nad_t nad;
    const char *c;
    sx_buf_t buf;

    _sx_debug(ZONE, "stream established");

    /* get the plugins to setup */
    if(s->env != NULL)
        for(i = 0; i < s->env->nplugins; i++)
            if(s->env->plugins[i]->stream != NULL)
                (s->env->plugins[i]->stream)(s, s->env->plugins[i]);

    /* bump us to stream if a plugin didn't do it already */
    if(s->state < state_STREAM) {
        _sx_state(s, state_STREAM);
        _sx_event(s, event_STREAM, NULL);
    }

    /* next, build the features */
    if(s->req_version != NULL && strcmp(s->req_version, "1.0") == 0) {
        _sx_debug(ZONE, "building features nad");

        nad = nad_new();

        ns = nad_add_namespace(nad, uri_STREAMS, "stream");
        nad_append_elem(nad, ns, "features", 0);

        /* get the plugins to populate it */
        if(s->env != NULL)
            for(i = 0; i < s->env->nplugins; i++)
                if(s->env->plugins[i]->features != NULL)
                    (s->env->plugins[i]->features)(s, s->env->plugins[i], nad);

        /* new buffer for the nad */
        nad_print(nad, 0, &c, &len);
        buf = _sx_buffer_new(c, len, NULL, NULL);
        nad_free(nad);

        /* send this off too */
        /* !!! should this go via wnad/rnad? */
        jqueue_push(s->wbufq, buf, 0);
        s->want_write = 1;
    }

    /* if they sent packets before the stream was established, process the now */
    if(jqueue_size(s->rnadq) > 0 && (s->state == state_STREAM || s->state == state_OPEN)) {
        _sx_debug(ZONE, "processing packets sent before stream, naughty them");
        _sx_process_read(s, _sx_buffer_new(c, 0, NULL, NULL));
    }
}

static void _sx_server_element_start(void *arg, const char *name, const char **atts) {
    sx_t s = (sx_t) arg;
    int tflag = 0, fflag = 0, vflag = 0, len, i, r;
    const char **attr;
    char *c, id[41];
    sx_buf_t buf;
    sx_error_t sxe;

    if(s->fail) return;

    /* check element and namespace */
    i = strlen(uri_STREAMS) + 7;
    if(strlen(name) < i || strncmp(name, uri_STREAMS "|stream", i) != 0 || (name[i] != '\0' && name[i] != '|')) {
        /* throw an error */
        _sx_gen_error(sxe, SX_ERR_STREAM, "Stream error", "Expected stream start");
        _sx_event(s, event_ERROR, (void *) &sxe);
        _sx_error(s, stream_err_BAD_FORMAT, NULL);
        s->fail = 1;
        return;
    }

    /* pull interesting things out of the header */
    attr = atts;
    while(attr[0] != NULL) {
        if(!tflag && strcmp(attr[0], "to") == 0) {
            if(s->req_to != NULL) free((void*)s->req_to);
            s->req_to = strdup(attr[1]);
            tflag = 1;
        }

        if(!fflag && strcmp(attr[0], "from") == 0) {
            s->req_from = strdup(attr[1]);
            fflag = 1;
        }

        if(!vflag && strcmp(attr[0], "version") == 0) {
            s->req_version = strdup(attr[1]);
            vflag = 1;
        }

        attr += 2;
    }

    _sx_debug(ZONE, "stream request: to %s from %s version %s", s->req_to, s->req_from, s->req_version);

    /* check version */
    if(s->req_version != NULL && strcmp(s->req_version, "1.0") != 0) {
        /* throw an error */
        _sx_gen_error(sxe, SX_ERR_STREAM, "Stream error", "Unsupported version");
        _sx_event(s, event_ERROR, (void *) &sxe);
        _sx_error(s, stream_err_UNSUPPORTED_VERSION, NULL);
        s->fail = 1;
        return;
    }

    /* !!! get the app to verify this stuff? */

    /* bump */
    _sx_state(s, state_STREAM_RECEIVED);

    /* response attributes */
    if(s->req_to != NULL) s->res_from = strdup(s->req_to);
    if(s->req_from != NULL) s->res_to = strdup(s->req_from);

    /* Only send 1.0 version if client has indicated a stream version - c/f XMPP 4.4.1 para 4 */
    if(s->req_version != NULL) s->res_version = strdup("1.0");

    /* stream id */
    for(i = 0; i < 40; i++) {
        r = (int) (36.0 * rand() / RAND_MAX);
        id[i] = (r >= 0 && r <= 9) ? (r + 48) : (r + 87);
    }
    id[40] = '\0';

    s->id = strdup(id);

    _sx_debug(ZONE, "stream id is %s", id);

    /* build the response */
    len = strlen(uri_STREAMS) + 99;

    if(s->ns != NULL) len += 9 + strlen(s->ns);
    if(s->res_to != NULL) len += 6 + strlen(s->res_to);
    if(s->res_from != NULL) len += 8 + strlen(s->res_from);
    if(s->res_version != NULL) len += 11 + strlen(s->res_version);

    buf = _sx_buffer_new(NULL, len, _sx_server_notify_header, NULL);

    c = buf->data;
    strcpy(c, "<?xml version='1.0'?><stream:stream xmlns:stream='" uri_STREAMS "'");

    if(s->ns != NULL) { c = strchr(c, '\0'); sprintf(c, " xmlns='%s'", s->ns); }
    if(s->res_to != NULL) { c = strchr(c, '\0'); sprintf(c, " to='%s'", s->res_to); }
    if(s->res_from != NULL) { c = strchr(c, '\0'); sprintf(c, " from='%s'", s->res_from); }
    if(s->res_version != NULL) { c = strchr(c, '\0'); sprintf(c, " version='%s'", s->res_version); }

    c = strchr(c, '\0'); sprintf(c, " id='%s'>", id);
    assert(buf->len == strlen(buf->data) + 1); /* post-facto overrun detection */
    buf->len --;

    /* plugins can mess with the header too */
    if(s->env != NULL)
        for(i = 0; i < s->env->nplugins; i++)
            if(s->env->plugins[i]->header != NULL)
                (s->env->plugins[i]->header)(s, s->env->plugins[i], buf);

    _sx_debug(ZONE, "prepared stream response: %.*s", buf->len, buf->data);

    /* off it goes */
    jqueue_push(s->wbufq, buf, 0);

    s->depth++;

    /* we're alive */
    XML_SetElementHandler(s->expat, (void *) _sx_element_start, (void *) _sx_element_end);
    XML_SetCharacterDataHandler(s->expat, (void *) _sx_cdata);
    XML_SetStartNamespaceDeclHandler(s->expat, (void *) _sx_namespace_start);

    /* we have stuff to write */
    s->want_write = 1;
}

static void _sx_server_element_end(void *arg, const char *name) {
    sx_t s = (sx_t) arg;

    if(s->fail) return;

    s->depth--;
}

/** catch the application namespace so we can get the response right */
static void _sx_server_ns_start(void *arg, const char *prefix, const char *uri) {
    sx_t s = (sx_t) arg;

    /* only want the default namespace */
    if(prefix != NULL)
        return;

    /* sanity; MSXML-based clients have been known to send xmlns='' from time to time */
    if(uri == NULL)
        return;

    /* sanity check (should never happen if expat is doing its job) */
    if(s->ns != NULL)
        return;

    s->ns = strdup(uri);

    /* done */
    XML_SetStartNamespaceDeclHandler(s->expat, NULL);
}

void sx_server_init(sx_t s, unsigned int flags) {
    int i;

    assert((int) (s != NULL));

    /* can't do anything if we're alive already */
    if(s->state != state_NONE)
        return;

    _sx_debug(ZONE, "doing server init for sx %d", s->tag);

    s->type = type_SERVER;
    s->flags = flags;

    /* plugin */
    if(s->env != NULL)
        for(i = 0; i < s->env->nplugins; i++)
            if(s->env->plugins[i]->server != NULL)
                (s->env->plugins[i]->server)(s, s->env->plugins[i]);

    /* we want to read */
    XML_SetElementHandler(s->expat, (void *) _sx_server_element_start, (void *) _sx_server_element_end);
    XML_SetStartNamespaceDeclHandler(s->expat, (void *) _sx_server_ns_start);

    _sx_debug(ZONE, "waiting for stream header");

    s->want_read = 1;
    _sx_event(s, event_WANT_READ, NULL);
}
