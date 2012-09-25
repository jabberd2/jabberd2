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

static void _sx_client_element_start(void *arg, const char *name, const char **atts) {
    sx_t s = (sx_t) arg;
    int tflag = 0, fflag = 0, vflag = 0, iflag = 0, i;
    const char **attr;
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
            s->res_to = strdup(attr[1]);
            tflag = 1;
        }

        if(!fflag && strcmp(attr[0], "from") == 0) {
            s->res_from = strdup(attr[1]);
            fflag = 1;
        }

        if(!vflag && strcmp(attr[0], "version") == 0) {
            s->res_version = strdup(attr[1]);
            vflag = 1;
        }

        if(!iflag && strcmp(attr[0], "id") == 0) {
            s->id = strdup(attr[1]);
            iflag = 1;
        }

        attr += 2;
    }

    s->depth++;

    _sx_debug(ZONE, "stream response: to %s from %s version %s id %s", s->res_to, s->res_from, s->res_version, s->id);

    /* we're alive */
    XML_SetElementHandler(s->expat, (void *) _sx_element_start, (void *) _sx_element_end);
    XML_SetCharacterDataHandler(s->expat, (void *) _sx_cdata);
    XML_SetStartNamespaceDeclHandler(s->expat, (void *) _sx_namespace_start);

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
}

static void _sx_client_element_end(void *arg, const char *name) {
    sx_t s = (sx_t) arg;

    if(s->fail) return;

    s->depth--;
}

static void _sx_client_notify_header(sx_t s, void *arg) {
    /* expat callbacks */
    XML_SetElementHandler(s->expat, (void *) _sx_client_element_start, (void *) _sx_client_element_end);
    
    /* state change */
    _sx_state(s, state_STREAM_SENT);

    _sx_debug(ZONE, "stream header sent, waiting for reply");

    /* waiting for a response */
    s->want_read = 1;
}

void sx_client_init(sx_t s, unsigned int flags, const char *ns, const char *to, const char *from, const char *version) {
    sx_buf_t buf;
    char *c;
    int i, len;

    assert((int) (s != NULL));

    /* can't do anything if we're alive already */
    if(s->state != state_NONE)
        return;

    _sx_debug(ZONE, "doing client init for sx %d", s->tag);

    s->type = type_CLIENT;
    s->flags = flags;

    if(ns != NULL) s->ns = strdup(ns);
    if(to != NULL) s->req_to = strdup(to);
    if(from != NULL) s->req_from = strdup(from);
    if(version != NULL) s->req_version = strdup(version);

    /* plugin */
    if(s->env != NULL)
        for(i = 0; i < s->env->nplugins; i++)
            if(s->env->plugins[i]->client != NULL)
                (s->env->plugins[i]->client)(s, s->env->plugins[i]);

    _sx_debug(ZONE, "stream request: ns %s to %s from %s version %s", ns, to, from, version);

    /* build the stream start */
    len = strlen(uri_STREAMS) + 52;

    if(ns != NULL) len += 9 + strlen(ns);
    if(to != NULL) len += 6 + strlen(to);
    if(from != NULL) len += 8 + strlen(from);
    if(version != NULL) len += 11 + strlen(version);

    buf = _sx_buffer_new(NULL, len+1, _sx_client_notify_header, NULL);
    c = buf->data;
    strcpy(c, "<?xml version='1.0'?><stream:stream xmlns:stream='" uri_STREAMS "'");

    if(ns != NULL) { c = strchr(c, '\0'); sprintf(c, " xmlns='%s'", ns); }
    if(to != NULL) { c = strchr(c, '\0'); sprintf(c, " to='%s'", to); }
    if(from != NULL) { c = strchr(c, '\0'); sprintf(c, " from='%s'", from); }
    if(version != NULL) { c = strchr(c, '\0'); sprintf(c, " version='%s'", version); }

    c = strchr(c, '\0'); sprintf(c, ">");

    assert(buf->len == strlen(buf->data)+1);
    buf->len --;

    /* plugins can mess with the header too */
    if(s->env != NULL)
        for(i = 0; i < s->env->nplugins; i++)
            if(s->env->plugins[i]->header != NULL)
                (s->env->plugins[i]->header)(s, s->env->plugins[i], buf);

    _sx_debug(ZONE, "prepared stream header: %.*s", buf->len, buf->data);

    /* off it goes */
    jqueue_push(s->wbufq, buf, 0);

    /* we have stuff to write */
    s->want_write = 1;
    _sx_event(s, event_WANT_WRITE, NULL);
}

