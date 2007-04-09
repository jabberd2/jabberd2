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

/** if you change these, reflect your changes in the defines in sx.h */
static const char *_stream_errors[] = {
    "bad-format",
    "bad-namespace-prefix",
    "conflict",
    "connection-timeout",
    "host-gone",
    "host-unknown",
    "improper-addressing",
    "internal-server-error",
    "invalid-from",
    "invalid-id",
    "invalid-namespace",
    "invalid-xml",
    "not-authorized",
    "policy-violation",
    "remote-connection-failed",
    "restricted-xml",
    "resource-constraint",
    "see-other-host",
    "system-shutdown",
    "undefined-condition",
    "unsupported-encoding",
    "unsupported-stanza-type",
    "unsupported-version",
    "xml-not-well-formed",
    NULL
};

/** send an error */
void _sx_error(sx_t s, int err, const char *text) {
    int len = 0;
    sx_buf_t buf;

    /* build the string */
    if(s->state < state_STREAM) len = strlen(uri_STREAMS) + 61;
    len += strlen(uri_STREAMS) + strlen(uri_STREAM_ERR) + strlen(_stream_errors[err]) + 58;
    if(text != NULL) len += strlen(uri_STREAM_ERR) + strlen(text) + 22;

    buf = _sx_buffer_new(NULL, len, NULL, NULL);
    len = 0;

    if(s->state < state_STREAM)
        len = sprintf(buf->data, "<stream:stream xmlns:stream='" uri_STREAMS "' version='1.0'>");

    if(text == NULL)
        len += sprintf(&(buf->data[len]), "<stream:error xmlns:stream='" uri_STREAMS "'><%s xmlns='" uri_STREAM_ERR "'/></stream:error>", _stream_errors[err]);
    else
        len += sprintf(&(buf->data[len]), "<stream:error xmlns:stream='" uri_STREAMS "'><%s xmlns='" uri_STREAM_ERR "'/><text xmlns='" uri_STREAM_ERR "'>%s</text></stream:error>", _stream_errors[err], text);

    if(s->state < state_STREAM)
        len += sprintf(&(buf->data[len]), "</stream:stream>");

    buf->len--;
    assert(len == buf->len);

    _sx_debug(ZONE, "prepared error: %.*s", buf->len, buf->data);

    /* go */
    jqueue_push(s->wbufq, buf, 0);

    /* stuff to write */
    s->want_write = 1;
}

void sx_error(sx_t s, int err, const char *text) {
    assert(s != NULL);
    assert(err >= 0 && err < stream_err_LAST);

    _sx_error(s, err, text);

    _sx_event(s, event_WANT_WRITE, NULL);
}

