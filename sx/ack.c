/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2007 Tomasz Sterna
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License
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

/*
 * this sx plugin implements stanza acknowledgements
 * as described in XEP-0198: Stanza Acknowledgements
 */

#include "sx.h"

#define STREAM_ACK_NS_DECL      " xmlns:ack='" uri_ACK "'"

static void _sx_ack_header(sx_t s, sx_plugin_t p, sx_buf_t buf) {

    log_debug(ZONE, "hacking ack namespace decl onto stream header");

    /* get enough space */
    _sx_buffer_alloc_margin(buf, 0, strlen(STREAM_ACK_NS_DECL) + 2);

    /* overwrite the trailing ">" with a decl followed by a new ">" */
    memcpy(&buf->data[buf->len - 1], STREAM_ACK_NS_DECL ">", strlen(STREAM_ACK_NS_DECL)+1);
    buf->len += strlen(STREAM_ACK_NS_DECL);
}

/** sx features callback */
static void _sx_ack_features(sx_t s, sx_plugin_t p, nad_t nad) {
    /* offer feature only when authenticated and not enabled yet */
    if(s->state == state_OPEN && s->plugin_data[p->index] == NULL)
        nad_append_elem(nad, -1, "ack:ack", 1);
}

/** process handshake packets from the client */
static int _sx_ack_process(sx_t s, sx_plugin_t p, nad_t nad) {
    int attr;

    /* not interested if we're not a server */
    if(s->type != type_SERVER)
        return 1;

    /* only want ack packets */
    if((NAD_ENS(nad, 0) < 0 || NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_ACK) || strncmp(NAD_NURI(nad, NAD_ENS(nad, 0)), uri_ACK, strlen(uri_ACK)) != 0))
        return 1;

    /* pings */
    if(NAD_ENAME_L(nad, 0) == 4 && strncmp(NAD_ENAME(nad, 0), "ping", 4) == 0) {
        jqueue_push(s->wbufq, _sx_buffer_new("<ack:pong/>", 11, NULL, NULL), 0);
        s->want_write = 1;

        /* handled the packet */
        nad_free(nad);
        return 0;
    }

    /* enable only when authenticated */
    if(s->state == state_OPEN && NAD_ENAME_L(nad, 0) == 6 && strncmp(NAD_ENAME(nad, 0), "enable", 6) == 0) {
        jqueue_push(s->wbufq, _sx_buffer_new("<ack:enabled/>", 14, NULL, NULL), 254);
        s->want_write = 1;

        s->plugin_data[p->index] = (void *) 1;

        /* handled the packet */
        nad_free(nad);
        return 0;
    }

    /* 'r' or 'a' when enabled */
    if(s->plugin_data[p->index] != NULL && NAD_ENAME_L(nad, 0) == 1 && (strncmp(NAD_ENAME(nad, 0), "r", 1) == 0 || strncmp(NAD_ENAME(nad, 0), "a", 1) == 0) ) {
        attr = nad_find_attr(nad, 0, -1, "c", NULL);
        if(attr >= 0) {
            char *buf = (char *) malloc(sizeof(char) * (NAD_AVAL_L(nad, attr) + 13 + 1));
            snprintf(buf, NAD_AVAL_L(nad, attr) + 13 + 1, "<ack:a b='%.*s'/>", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
            jqueue_push(s->wbufq, _sx_buffer_new(buf, NAD_AVAL_L(nad, attr) + 13, NULL, NULL), 255);
            free(buf);
            s->want_write = 1;
        }
        
        /* handled the packet */
        nad_free(nad);
        return 0;
    }

    _sx_debug(ZONE, "unhandled ack namespace element '%.*s', dropping packet", NAD_ENAME_L(nad, 0), NAD_ENAME(nad, 0));
    nad_free(nad);
    return 0;
}

/** args: none */
int sx_ack_init(sx_env_t env, sx_plugin_t p, va_list args) {
    log_debug(ZONE, "initialising stanza acknowledgements sx plugin");

    p->header = _sx_ack_header;
    p->features = _sx_ack_features;
    p->process = _sx_ack_process;

    return 0;
}
