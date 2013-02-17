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

/** handler for read data */
void _sx_process_read(sx_t s, sx_buf_t buf) {
    sx_error_t sxe;
    nad_t nad;
    char *errstring;
    int i;
    int ns, elem;

    /* Note that buf->len can validly be 0 here, if we got data from
       the socket but the plugin didn't return anything to us (e.g. a
       SSL packet was split across a tcp segment boundary) */

    /* count bytes read */
    s->rbytes += buf->len;

    /* parse it */
    if(XML_Parse(s->expat, buf->data, buf->len, 0) == 0) {
        /* only report error we haven't already */
        if(!s->fail) {
            /* parse error */
            errstring = (char *) XML_ErrorString(XML_GetErrorCode(s->expat));

            _sx_debug(ZONE, "XML parse error: %s; line: %d, column: %d, buffer: %.*s", errstring, XML_GetCurrentLineNumber(s->expat), XML_GetCurrentColumnNumber(s->expat), buf->len, buf->data);
            _sx_gen_error(sxe, SX_ERR_XML_PARSE, "XML parse error", errstring);
            _sx_event(s, event_ERROR, (void *) &sxe);

            _sx_error(s, stream_err_XML_NOT_WELL_FORMED, errstring);
            _sx_close(s);

            _sx_buffer_free(buf);

            return;
        }

        /* !!! is this the right thing to do? we should probably set
         *     s->fail and let the code further down handle it. */
        _sx_buffer_free(buf);

        return;
    }

    /* check if the stanza size limit is exceeded (it wasn't reset by parser) */
    if(s->rbytesmax && s->rbytes > s->rbytesmax) {
        /* parse error */
        _sx_debug(ZONE, "maximum stanza size (%d) exceeded by reading %d bytes", s->rbytesmax, s->rbytes);

        errstring = (char *) XML_ErrorString(XML_GetErrorCode(s->expat));

        _sx_gen_error(sxe, SX_ERR_XML_PARSE, "stream read error", "Maximum stanza size exceeded");
        _sx_event(s, event_ERROR, (void *) &sxe);

        _sx_error(s, stream_err_POLICY_VIOLATION, errstring);
        _sx_close(s);

        _sx_buffer_free(buf);

        return;
    }

    /* done with the buffer */
    _sx_buffer_free(buf);

    /* process completed nads */
    if(s->state >= state_STREAM)
        while((nad = jqueue_pull(s->rnadq)) != NULL) {
            int plugin_error;
#ifdef SX_DEBUG
            const char *out; int len;
            nad_print(nad, 0, &out, &len);
            _sx_debug(ZONE, "completed nad: %.*s", len, out);
#endif

            /* check for errors */
            if(NAD_ENS(nad, 0) >= 0 && NAD_NURI_L(nad, NAD_ENS(nad, 0)) == strlen(uri_STREAMS) && strncmp(NAD_NURI(nad, NAD_ENS(nad, 0)), uri_STREAMS, strlen(uri_STREAMS)) == 0 && NAD_ENAME_L(nad, 0) == 5 && strncmp(NAD_ENAME(nad, 0), "error", 5) == 0) {

                errstring = NULL;

                /* get text error description if available - XMPP 4.7.2 */
                if((ns = nad_find_scoped_namespace(nad, uri_STREAM_ERR, NULL)) >= 0) 
                    if((elem = nad_find_elem(nad, 0, ns, "text", 1)) >= 0)
                        if(NAD_CDATA_L(nad, elem) > 0) {
                            errstring = (char *) malloc(sizeof(char) * (NAD_CDATA_L(nad, elem) + 1));
                            sprintf(errstring, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
                        }

                /* if not available, look for legacy error text as in <stream:error>description</stream:error> */
                if (errstring == NULL && NAD_CDATA_L(nad, 0) > 0) {
                    errstring = (char *) malloc(sizeof(char) * (NAD_CDATA_L(nad, 0) + 1));
                    sprintf(errstring, "%.*s", NAD_CDATA_L(nad, 0), NAD_CDATA(nad, 0));
                }

                /* if not available, log the whole packet for debugging */
                if (errstring == NULL) {
                    const char *xml;
                    int xlen;

                    nad_print(nad, 0, &xml, &xlen);
                    errstring = (char *) malloc(sizeof(char) * (xlen + 1));
                    sprintf(errstring, "%.*s", xlen, xml);
                }

                if(s->state < state_CLOSING) {
                    _sx_gen_error(sxe, SX_ERR_STREAM, "Stream error", errstring);
                    _sx_event(s, event_ERROR, (void *) &sxe);
                    _sx_state(s, state_CLOSING);
                }

                if(errstring != NULL) free(errstring);

                nad_free(nad);

                break;
            }

            /* run it by the plugins */
            if(_sx_chain_nad_read(s, nad) == 0)
                return;

            /* now let the plugins process the completed nad */
            plugin_error = 0;
            if(s->env != NULL)
                for(i = 0; i < s->env->nplugins; i++)
                    if(s->env->plugins[i]->process != NULL) {
                        int plugin_ret;
                        plugin_ret = (s->env->plugins[i]->process)(s, s->env->plugins[i], nad);
                        if(plugin_ret == 0) {
                            plugin_error ++;
                            break;
                        }
                    }

            /* hand it to the app */
            if ((plugin_error == 0) && (s->state < state_CLOSING))
                _sx_event(s, event_PACKET, (void *) nad);
        }

    /* something went wrong, bail */
    if(s->fail) {
        _sx_close(s);

        return;
    }

    /* stream was closed */
    if(s->depth < 0 && s->state < state_CLOSING) {
        /* close the stream if necessary */
        if(s->state >= state_STREAM_SENT) {
            jqueue_push(s->wbufq, _sx_buffer_new("</stream:stream>", 16, NULL, NULL), 0);
            s->want_write = 1;
        }

        _sx_state(s, state_CLOSING);

        return;
    }
}

/** we can read */
int sx_can_read(sx_t s) {
    sx_buf_t in, out;
    int read, ret;

    assert((int) (s != NULL));

    /* do we care? */
    if(!s->want_read && s->state < state_CLOSING)
        return 0;           /* no more thanks */

    _sx_debug(ZONE, "%d ready for reading", s->tag);

    /* new buffer */
    in = _sx_buffer_new(NULL, 1024, NULL, NULL);

    /* get them to read stuff */
    read = _sx_event(s, event_READ, (void *) in);

    /* bail if something went wrong */
    if(read < 0) {
        _sx_buffer_free(in);
        s->want_read = 0;
        s->want_write = 0;
        return 0;
    }

    if(read == 0) {
        /* nothing to read
         * should never happen because we did get a read event,
         * thus there is something to read, or error handled
         * via (read < 0) block before (errors return -1) */
        _sx_debug(ZONE, "decoded 0 bytes read data - this should not happen");
        _sx_buffer_free(in);

    } else {
        _sx_debug(ZONE, "passed %d read bytes", in->len);

        /* make a copy for processing */
        out = _sx_buffer_new(in->data, in->len, in->notify, in->notify_arg);

        /* run it by the plugins */
        ret = _sx_chain_io_read(s, out);
        if(ret <= 0) {
            if(ret < 0) {
                /* permanent failure, its all over */
                /* !!! shut down */
                s->want_read = s->want_write = 0;
            }

            _sx_buffer_free(in);
            _sx_buffer_free(out);

            /* done */
            if(s->want_write) _sx_event(s, event_WANT_WRITE, NULL);
            return s->want_read;
        }

        _sx_buffer_free(in);

        _sx_debug(ZONE, "decoded read data (%d bytes): %.*s", out->len, out->len, out->data);

        /* into the parser with you */
        _sx_process_read(s, out);
    }

    /* if we've written everything, and we're closed, then inform the app it can kill us */
    if(s->want_write == 0 && s->state == state_CLOSING) {
        _sx_state(s, state_CLOSED);
        _sx_event(s, event_CLOSED, NULL);
        return 0;
    }

    if(s->state == state_CLOSED)
        return 0;

    if(s->want_write) _sx_event(s, event_WANT_WRITE, NULL);
    return s->want_read;
}

/** we can write */
static int _sx_get_pending_write(sx_t s) {
    sx_buf_t in, out;
    int ret;

    assert(s != NULL);

    if (s->wbufpending != NULL) {
    /* there's already a pending buffer ready to write */
    return 0;
    }

    /* get the first buffer off the queue */
    in = jqueue_pull(s->wbufq);
    if(in == NULL) {
        /* if there was a write event, and something is interested,
       we still have to tell the plugins */
        in = _sx_buffer_new(NULL, 0, NULL, NULL);
    }

    /* if there's more to write, we want to make sure we get it */
    s->want_write = jqueue_size(s->wbufq);

    /* make a copy for processing */
    out = _sx_buffer_new(in->data, in->len, in->notify, in->notify_arg);

    _sx_debug(ZONE, "encoding %d bytes for writing: %.*s", in->len, in->len, in->data);

    /* run it by the plugins */
    ret = _sx_chain_io_write(s, out);
    if(ret <= 0) {
    /* TODO/!!!: Are we leaking the 'out' buffer here? How about the 'in' buffer? */
        if(ret == -1) {
            /* temporary failure, push it back on the queue */
            jqueue_push(s->wbufq, in, (s->wbufq->front != NULL) ? s->wbufq->front->priority : 0);
            s->want_write = 1;
        } else if(ret == -2) {
            /* permanent failure, its all over */
            /* !!! shut down */
            s->want_read = s->want_write = 0;
            return -1;
        }

        /* done */
        return 0;
    }

    _sx_buffer_free(in);

    if (out->len == 0)
    /* if there's nothing to write, then we're done */
        _sx_buffer_free(out);
    else
        s->wbufpending = out;

    return 0;
}

int sx_can_write(sx_t s) {
    sx_buf_t out;
    int ret, written;

    assert((int) (s != NULL));

    /* do we care? */
    if(!s->want_write && s->state < state_CLOSING)
        return 0;           /* no more thanks */

    _sx_debug(ZONE, "%d ready for writing", s->tag);

    ret = _sx_get_pending_write(s);
    if (ret < 0) {
        /* fatal error */
        _sx_debug(ZONE, "fatal error after attempt to write on fd %d", s->tag);
        /* permanent error so inform the app it can kill us */
        sx_kill(s);
        return 0;
    }

    /* if there's nothing to write, then we're done */
    if(s->wbufpending == NULL) {
        if(s->want_read) _sx_event(s, event_WANT_READ, NULL);
        return s->want_write;
    }

    out = s->wbufpending;
    s->wbufpending = NULL;

    /* get the callback to do the write */
    _sx_debug(ZONE, "handing app %d bytes to write", out->len);
    written = _sx_event(s, event_WRITE, (void *) out);

    if(written < 0) {
        /* bail if something went wrong */
        _sx_buffer_free(out);
        s->want_read = 0;
        s->want_write = 0;
        return 0;
    } else if(written < out->len) {
        /* if not fully written, this buffer is still pending */
        out->len -= written;
        out->data += written;
        s->wbufpending = out;
        s->want_write ++;
    } else {
        /* notify */
        if(out->notify != NULL)
            (out->notify)(s, out->notify_arg);

        /* done with this */
        _sx_buffer_free(out);
    }

    /* if we've written everything, and we're closed, then inform the app it can kill us */
    if(s->want_write == 0 && s->state == state_CLOSING) {
        _sx_state(s, state_CLOSED);
        _sx_event(s, event_CLOSED, NULL);
        return 0;
    }

    if(s->state == state_CLOSED)
        return 0;

    if(s->want_read) _sx_event(s, event_WANT_READ, NULL);
    return s->want_write;
}

/** send a new nad out */
int _sx_nad_write(sx_t s, nad_t nad, int elem) {
    const char *out;
    int len;

    /* silently drop it if we're closing or closed */
    if(s->state >= state_CLOSING) {
        log_debug(ZONE, "stream closed, dropping outgoing packet");
        nad_free(nad);
        return 1;
    }

    /* run it through the plugins */
    if(_sx_chain_nad_write(s, nad, elem) == 0)
        return 1;

    /* serialise it */
    nad_print(nad, elem, &out, &len);

    _sx_debug(ZONE, "queueing for write: %.*s", len, out);

    /* ready to go */
    jqueue_push(s->wbufq, _sx_buffer_new(out, len, NULL, NULL), 0);

    nad_free(nad);

    /* things to write */
    s->want_write = 1;

    return 0;
}

/** app version */
void sx_nad_write_elem(sx_t s, nad_t nad, int elem) {
    assert((int) (s != NULL));
    assert((int) (nad != NULL));

    if(_sx_nad_write(s, nad, elem) == 1)
        return;

    /* things to write */
    s->want_write = 1;
    _sx_event(s, event_WANT_WRITE, NULL);

    if(s->want_read) _sx_event(s, event_WANT_READ, NULL);
}

/** send raw data out */
int _sx_raw_write(sx_t s, const char *buf, int len) {
    /* siltently drop it if we're closing or closed */
    if(s->state >= state_CLOSING) {
        log_debug(ZONE, "stream closed, dropping outgoing raw data");
        return 1;
    }

    _sx_debug(ZONE, "queuing for write: %.*s", len, buf);

    /* ready to go */
    jqueue_push(s->wbufq, _sx_buffer_new(buf, len, NULL, NULL), 0);

    /* things to write */
    s->want_write = 1;

    return 0;
}

/** app version */
void sx_raw_write(sx_t s, const char *buf, int len) {
    assert((int) (s != NULL));
    assert((int) (buf != NULL));
    assert(len);

    if(_sx_raw_write(s, buf, len) == 1)
        return;

    /* things to write */
    s->want_write = 1;
    _sx_event(s, event_WANT_WRITE, NULL);

    if(s->want_read) _sx_event(s, event_WANT_READ, NULL);
}

/** close a stream */
void _sx_close(sx_t s) {
    /* close the stream if necessary */
    if(s->state >= state_STREAM_SENT) {
        jqueue_push(s->wbufq, _sx_buffer_new("</stream:stream>", 16, NULL, NULL), 0);
        s->want_write = 1;
    }

    _sx_state(s, state_CLOSING);
}

void sx_close(sx_t s) {
    assert((int) (s != NULL));

    if(s->state >= state_CLOSING)
        return;

    if(s->state >= state_STREAM_SENT && s->state < state_CLOSING) {
        _sx_close(s);
        _sx_event(s, event_WANT_WRITE, NULL);
    } else {
        _sx_state(s, state_CLOSED);
        _sx_event(s, event_CLOSED, NULL);
    }
}

void sx_kill(sx_t s) {
    assert((int) (s != NULL));

    _sx_state(s, state_CLOSED);
    _sx_event(s, event_CLOSED, NULL);
}
