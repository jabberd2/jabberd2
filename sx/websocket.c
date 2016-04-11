/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2015 Tomasz Sterna
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
 * this plugin implements WebSocket C2S access
 * RFC 7395 : An Extensible Messaging and Presence Protocol (XMPP) Subprotocol for WebSocket
 * http://tools.ietf.org/html/rfc7395
 */

#include "sx.h"
#include <stdarg.h>
#include <string.h>

static const char websocket_guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static http_parser_settings settings;

/* parts of github.com/payden src/websock.c by Payden Sutherland follow */
#define MASK_LENGTH 4
#define FRAME_CHUNK_LENGTH 1024

#define WS_OPCODE_CONTINUE 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xa

#define WS_FRAGMENT_FIN (1 << 7)

#define WS_CLOSE_NORMAL 1000
#define WS_CLOSE_GOING_AWAY 1001
#define WS_CLOSE_PROTOCOL_ERROR 1002
#define WS_CLOSE_NOT_ALLOWED 1003
#define WS_CLOSE_RESERVED 1004
#define WS_CLOSE_NO_CODE 1005
#define WS_CLOSE_DIRTY 1006
#define WS_CLOSE_WRONG_TYPE 1007
#define WS_CLOSE_POLICY_VIOLATION 1008
#define WS_CLOSE_MESSAGE_TOO_BIG 1009
#define WS_CLOSE_UNEXPECTED_ERROR 1011

enum WS_FRAME_STATE {
        sw_start = 0,
        sw_got_two,
        sw_got_short_len,
        sw_got_full_len,
        sw_loaded_mask
};

typedef struct _libwebsock_frame {
        unsigned int fin;
        unsigned int opcode;
        unsigned int mask_offset;
        unsigned int payload_offset;
        unsigned int rawdata_idx;
        unsigned int rawdata_sz;
        unsigned int size;
        unsigned int payload_len_short;
        unsigned int payload_len;
        char *rawdata;
        unsigned char mask[4];
        enum WS_FRAME_STATE state;
} libwebsock_frame;

static inline int libwebsock_read_header(libwebsock_frame *frame) {
    int i, new_size;
    enum WS_FRAME_STATE state;

    state = frame->state;
    switch (state) {
    case sw_start:
        if (frame->rawdata_idx < 2) {
            return 0;
        }
        frame->state = sw_got_two;
    case sw_got_two:
        frame->mask_offset = 2;
        frame->fin = (*(frame->rawdata) & 0x80) == 0x80 ? 1 : 0;
        frame->opcode = *(frame->rawdata) & 0xf;
        frame->payload_len_short = *(frame->rawdata + 1) & 0x7f;
        frame->state = sw_got_short_len;
    case sw_got_short_len:
        switch (frame->payload_len_short) {
        case 126:
            if (frame->rawdata_idx < 4) {
                return 0;
            }
            frame->mask_offset += 2;
            frame->payload_offset = frame->mask_offset + MASK_LENGTH;
            frame->payload_len = ntohs(
                    *((unsigned short int *) (frame->rawdata + 2)));
            frame->state = sw_got_full_len;
            break;
        case 127:
            if (frame->rawdata_idx < 10) {
                return 0;
            }
            frame->mask_offset += 8;
            frame->payload_offset = frame->mask_offset + MASK_LENGTH;
            frame->payload_len = ntohl(*((unsigned int *) (frame->rawdata + 6)));
            frame->state = sw_got_full_len;
            break;
        default:
            frame->payload_len = frame->payload_len_short;
            frame->payload_offset = frame->mask_offset + MASK_LENGTH;
            frame->state = sw_got_full_len;
            break;
        }
    case sw_got_full_len:
        if (frame->rawdata_idx < frame->payload_offset) {
            return 0;
        }
        for (i = 0; i < MASK_LENGTH; i++) {
            frame->mask[i] = *(frame->rawdata + frame->mask_offset + i) & 0xff;
        }
        frame->state = sw_loaded_mask;
        frame->size = frame->payload_offset + frame->payload_len;
        if (frame->size > frame->rawdata_sz) {
            new_size = frame->size;
            new_size--;
            new_size |= new_size >> 1;
            new_size |= new_size >> 2;
            new_size |= new_size >> 4;
            new_size |= new_size >> 8;
            new_size |= new_size >> 16;
            new_size++;
            frame->rawdata_sz = new_size;
            frame->rawdata = (char *) realloc(frame->rawdata, new_size);
        }
        return 1;
    case sw_loaded_mask:
        return 1;
    }
    return 0;
}

sx_buf_t libwebsock_fragment_buffer(const char *data, unsigned int len, int flags) {
    unsigned int *payload_len_32_be;
    unsigned short int *payload_len_short_be;
    unsigned char finNopcode, payload_len_small;
    unsigned int payload_offset = 2;
    unsigned int frame_size;
    char *frame;

    finNopcode = flags & 0xff;
    if (len <= 125) {
        frame_size = 2 + len;
        payload_len_small = len & 0xff;
    } else if (len > 125 && len <= 0xffff) {
        frame_size = 4 + len;
        payload_len_small = 126;
        payload_offset += 2;
    } else if (len > 0xffff && len <= 0xfffffff0) {
        frame_size = 10 + len;
        payload_len_small = 127;
        payload_offset += 8;
    } else {
        _sx_debug(ZONE,
                "libwebsock does not support frame payload sizes over %u bytes long\n",
                0xfffffff0);
        return NULL;
    }
    sx_buf_t buf = _sx_buffer_new(NULL, frame_size, NULL, NULL);
    frame = buf->data;
    payload_len_small &= 0x7f;
    *frame = finNopcode;
    *(frame + 1) = payload_len_small;
    if (payload_len_small == 126) {
        len &= 0xffff;
        payload_len_short_be = (unsigned short *) ((char *) frame + 2);
        *payload_len_short_be = htons(len);
    }
    if (payload_len_small == 127) {
        payload_len_32_be = (unsigned int *) ((char *) frame + 2);
        *payload_len_32_be++ = 0;
        *payload_len_32_be = htonl(len);
    }
    memcpy(frame + payload_offset, data, len);

    return buf;
}

int libwebsock_close_with_reason(sx_t s, _sx_websocket_conn_t sc, unsigned short code, const char *reason);

int libwebsock_send_fragment(sx_t s, _sx_websocket_conn_t sc, const char *data, unsigned int len, int flags) {
    sx_buf_t buf = libwebsock_fragment_buffer(data, len, flags);
    if (buf == NULL) {
        return libwebsock_close_with_reason(s, sc, WS_CLOSE_UNEXPECTED_ERROR, "Internal server error");
    }
    jqueue_push(s->wbufq, buf, 0);
    s->want_write = 1;
    return _sx_event(s, event_WANT_WRITE, NULL);
}

int libwebsock_close_with_reason(sx_t s, _sx_websocket_conn_t sc, unsigned short code, const char *reason)
{
    unsigned int len;
    unsigned short code_be;
    char buf[128]; //w3 spec on WebSockets API (http://dev.w3.org/html5/websockets/) says reason shouldn't be over 123 bytes.  I concur.
    len = 2;
    code_be = htobe16(code);
    memcpy(buf, &code_be, 2);
    if (reason) {
        len += snprintf(buf + 2, 124, "%s", reason);
    }

    sc->state = websocket_CLOSING;
    int ret = libwebsock_send_fragment(s, sc, buf, len, WS_FRAGMENT_FIN | WS_OPCODE_CLOSE);

    sx_close(s);
    return ret;
}

int libwebsock_close(sx_t s, _sx_websocket_conn_t sc)
{
    return libwebsock_close_with_reason(s, sc, WS_CLOSE_NORMAL, NULL);
}

void libwebsock_fail_connection(sx_t s, _sx_websocket_conn_t sc, unsigned short close_code) {
    char close_frame[4] = { 0x88, 0x02, 0x00, 0x00 };
    unsigned short *code_be = (unsigned short *) &close_frame[2];
    *code_be = htobe16(WS_CLOSE_PROTOCOL_ERROR);

    sx_buf_t buf = _sx_buffer_new(NULL, sizeof(close_frame), NULL, NULL);
    memcpy(buf->data, close_frame, buf->len);

    sc->state = websocket_CLOSING;
    s->want_write = 1;
    _sx_event(s, event_WANT_WRITE, NULL);

    sx_close(s);
}

static int _sx_websocket_http_header_field(http_parser *parser, const char *chars, size_t length) {
    _sx_debug(ZONE, "HTTP header field '%.*s'", length, chars);
    _sx_websocket_conn_t sc = (_sx_websocket_conn_t) parser->data;
    if(sc->header_value) {
        // new field incoming
        xhash_put(sc->headers,
                  strunescape(sc->p, spool_print(sc->field)),
                  strunescape(sc->p, spool_print(sc->value)));
        sc->header_value = 0;
        sc->field = spool_new(sc->p);
    }
    spool_escape(sc->field, chars, length);
    return 0;
}

static int _sx_websocket_http_header_value(http_parser *parser, const char *chars, size_t length) {
    _sx_debug(ZONE, "HTTP header value '%.*s'", length, chars);
    _sx_websocket_conn_t sc = (_sx_websocket_conn_t) parser->data;
    if(!sc->header_value) {
        // field name complete
        sc->header_value = 1;
        sc->value = spool_new(sc->p);
    }
    spool_escape(sc->value, chars, length);
    return 0;
}

static int _sx_websocket_http_headers_complete(http_parser *parser) {
    _sx_websocket_conn_t sc = (_sx_websocket_conn_t) parser->data;
    _sx_debug(ZONE, "HTTP headers complete: %d %s HTTP/%d.%d", parser->status_code, http_method_str(parser->method), parser->http_major, parser->http_minor);
    if (sc->header_value) {
        /* pull last value by switching to field parser */
        _sx_websocket_http_header_field(parser, "", 0);
    }
    return 1;
}

static void _sx_websocket_http_return(sx_t s, char *status, char *headers_format, ...) {
    char* http =
        "HTTP/1.1 %s\r\n"
        "%s"
        "Server: " PACKAGE_STRING "\r\n"
        "Expires: Fri, 10 Oct 1997 10:10:10 GMT\r\n"
        "Pragma: no-cache\r\n"
        "Cache-control: private\r\n"
        "\r\n";

    /* build additional headers */
    char headers[1024];
    va_list args;
    va_start(args, headers_format);
    vsnprintf(headers, sizeof(headers), headers_format, args);
    va_end(args);

    /* build HTTP answer */
    sx_buf_t buf = _sx_buffer_new(NULL, j_strlen(http) + j_strlen(status) + j_strlen(headers), NULL, NULL);
    buf->len = sprintf(buf->data, http, status, headers);
    jqueue_push(s->wbufq, buf, 0);

    /* stuff to write */
    s->want_write = 1;
    _sx_event(s, event_WANT_WRITE, NULL);
}

static int _sx_websocket_rio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    _sx_websocket_conn_t sc = (_sx_websocket_conn_t) s->plugin_data[p->index];
    int i, j, ret, err;
    char *newbuf;
    sha1_state_t sha1;
    unsigned char hash[20];

    /* if not wrapped yet */
    if(!(s->flags & SX_WEBSOCKET_WRAPPER)) {
        /* look for HTTP handshake */
        if(s->state == state_NONE && sc->state == websocket_PRE && buf->len >= 5 && strncmp("GET /", buf->data, 5) == 0) {
            _sx_debug(ZONE, "got HTTP handshake");
            sc->state = websocket_HEADERS;
        }

        /* pass buffers through http_parser */
        if(s->state == state_NONE && sc->state == websocket_HEADERS) {
            _sx_debug(ZONE, "parsing HTTP headers");
            if(buf->len > 0) {
                _sx_debug(ZONE, "loading %d bytes into http_parser %.*s", buf->len, buf->len, buf->data);

                ret = http_parser_execute(&sc->parser, &settings, buf->data, buf->len);

                if (sc->parser.upgrade) {
                    /* check for required websocket upgrade headers */
                    char *upgrade = xhash_get(sc->headers, "Upgrade");
                    char *connection = xhash_get(sc->headers, "Connection");
                    char *key = xhash_get(sc->headers, "Sec-WebSocket-Key");
                    char *proto = xhash_get(sc->headers, "Sec-WebSocket-Protocol");
                    int version = j_atoi(xhash_get(sc->headers, "Sec-WebSocket-Version"), -1);
                    if(j_strcmp(upgrade, "websocket") || connection == NULL || strcasestr(connection, "Upgrade") == NULL || j_strcmp(proto, "xmpp") || version != 13) {
                        _sx_debug(ZONE, "Upgrade: %s", upgrade);
                        _sx_debug(ZONE, "Connection: %s", connection);
                        _sx_debug(ZONE, "Sec-WebSocket-Key: %s", key);
                        _sx_debug(ZONE, "Sec-WebSocket-Protocol: %s", proto);
                        _sx_debug(ZONE, "Sec-WebSocket-Version: %d", version);
                        _sx_websocket_http_return(s, "400 Bad Request", "");
                        sx_close(s);
                        return -2;
                    }

                    /* we're good to go */

                    sha1_init(&sha1);
                    sha1_append(&sha1, key, j_strlen(key));
                    sha1_append(&sha1, websocket_guid, sizeof(websocket_guid) -1);
                    sha1_finish(&sha1, hash);
                    char * accept = b64_encode(hash, sizeof(hash));

                    /* switch protocols */
                    _sx_websocket_http_return(s, "101 Switching Protocols",
                                              "Upgrade: websocket\r\n"
                                              "Connection: Upgrade\r\n"
                                              "Sec-WebSocket-Accept: %s\r\n"
                                              "Sec-WebSocket-Protocol: xmpp\r\n",
                                              accept);
                    free(accept);

                    /* and move past headers */
                    sc->state = websocket_ACTIVE;
                    s->flags |= SX_WEBSOCKET_WRAPPER;

                    return 0;
                } else if (ret != buf->len) {
                    /* throw an error */
                    sx_error(s, stream_err_BAD_FORMAT, http_errno_description(sc->parser.http_errno));
                    sx_close(s);
                    return -2;
                } else if (p->private) {
                    char *http_forward = p->private;
                    _sx_debug(ZONE, "bouncing HTTP request to %s", http_forward);
                    _sx_websocket_http_return(s, "301 Found", "Location: %s\r\nConnection: close\r\n", http_forward);
                    sx_close(s);
                    return -1;
                }

                _sx_debug(ZONE, "unhandling HTTP request");
                _sx_websocket_http_return(s, "403 Forbidden", "Connection: close\r\n");
                sx_close(s);
                return -1;
            }

            _sx_buffer_clear(buf);
            /* flag we want to read */
            s->want_read = 1;

            return 0;
        }
    }

    /* only bothering if it is active websocket */
    if(!(s->flags & SX_WEBSOCKET_WRAPPER) || sc->state != websocket_ACTIVE)
        return 1;

    _sx_debug(ZONE, "Unwraping WebSocket frame: %d bytes", buf->len);

    char *data = buf->data;
    for (i = 0; i < buf->len;) {
        libwebsock_frame *frame;
        if (sc->frame == NULL) {
            frame = (libwebsock_frame *) calloc(1, sizeof(libwebsock_frame));
            frame->payload_len = -1;
            frame->rawdata_sz = FRAME_CHUNK_LENGTH;
            frame->rawdata = (char *) malloc(FRAME_CHUNK_LENGTH);
            sc->frame = frame;
        } else {
            frame = sc->frame;
        }

        *(frame->rawdata + frame->rawdata_idx++) = *data++;
        i++;

        if (frame->state != sw_loaded_mask) {
            err = libwebsock_read_header(frame);
            if (err == -1) {
                if (sc->state != websocket_CLOSING) {
                    libwebsock_fail_connection(s, sc, WS_CLOSE_PROTOCOL_ERROR);
                }
                return -2;
            }
            if (err == 0) {
                continue;
            }
        }

        if (frame->rawdata_idx < frame->size) {
            if (buf->len - i >= frame->size - frame->rawdata_idx) {
                //remaining in current vector completes frame.  Copy remaining frame size
                memcpy(frame->rawdata + frame->rawdata_idx, data,
                       frame->size - frame->rawdata_idx);
                data += frame->size - frame->rawdata_idx;
                i += frame->size - frame->rawdata_idx;
                frame->rawdata_idx = frame->size;
            } else {
                //not complete frame, copy the rest of this vector into frame.
                memcpy(frame->rawdata + frame->rawdata_idx, data, buf->len - i);
                frame->rawdata_idx += buf->len - i;
                i = buf->len;
                _sx_debug(ZONE, "more frame data to come");
                continue;
            }
        }

        //have full frame at this point
        _sx_debug(ZONE, "FIN: %d", frame->fin);
        _sx_debug(ZONE, "Opcode: %x", frame->opcode);
        _sx_debug(ZONE, "mask_offset: %d", frame->mask_offset);
        _sx_debug(ZONE, "payload_offset: %d", frame->payload_offset);
        _sx_debug(ZONE, "rawdata_idx: %d", frame->rawdata_idx);
        _sx_debug(ZONE, "rawdata_sz: %d", frame->rawdata_sz);
        _sx_debug(ZONE, "payload_len: %u", frame->payload_len);

        if (frame->opcode != WS_OPCODE_CONTINUE) {
            sc->opcode = frame->opcode;
        }

        switch (sc->opcode) {
        case WS_OPCODE_TEXT:
            /* unmask content */
            for (j = 0; j < frame->payload_len; j++)
                frame->rawdata[frame->payload_offset + j] ^= frame->mask[j % 4];
            _sx_debug(ZONE, "payload: %.*s", frame->payload_len, frame->rawdata + frame->payload_offset);
            sc->buf = realloc(sc->buf, sc->buf_len + frame->payload_len);
            newbuf = sc->buf + sc->buf_len;
            strncpy(newbuf, frame->rawdata + frame->payload_offset, frame->payload_len);
            sc->buf_len += frame->payload_len;
            /* hack unclose <open ... /> */
            if (frame->payload_len >= 7 && strncmp(newbuf, "<open", 5) == 0 && strncmp(newbuf + frame->payload_len - 2, "/>", 2) == 0) {
                sc->buf_len--;
                sc->buf[sc->buf_len - 1] = '>';
            }
            break;
        case WS_OPCODE_CLOSE:
            libwebsock_close(s, sc);
            break;
        case WS_OPCODE_PING:
            libwebsock_send_fragment(s, sc, frame->rawdata + frame->payload_offset, frame->payload_len, WS_FRAGMENT_FIN | WS_OPCODE_PONG);
            break;
        case WS_OPCODE_PONG:
            s->want_read = 1;
        default:
            _sx_debug(ZONE, "unhandled opcode: %x", frame->opcode);
            break;
        }

        free(frame->rawdata);
        free(frame);
        sc->frame = NULL;

        if (sc->state == websocket_CLOSING) {
            _sx_buffer_clear(buf);
            return 0;
        }
    }

    _sx_debug(ZONE, "passing buffer: %.*s", sc->buf_len, sc->buf);
    _sx_buffer_set(buf, sc->buf, sc->buf_len, NULL);
    sc->buf_len = 0;

    return 1;
}

static int _sx_websocket_wio(sx_t s, sx_plugin_t p, sx_buf_t buf) {
    _sx_websocket_conn_t sc = (_sx_websocket_conn_t) s->plugin_data[p->index];

    /* only bothering if it is active websocket */
    if(!(s->flags & SX_WEBSOCKET_WRAPPER))
        return 1;

    _sx_debug(ZONE, "in _sx_websocket_wio");

    if(buf->len > 0) {
        _sx_debug(ZONE, "wrapping %d bytes in WebSocket frame", buf->len);
        sx_buf_t frame = libwebsock_fragment_buffer(buf->data, buf->len, WS_FRAGMENT_FIN | WS_OPCODE_TEXT);
        if (frame == NULL) {
            return libwebsock_close_with_reason(s, sc, WS_CLOSE_UNEXPECTED_ERROR, "Internal server error");
        }
        _sx_buffer_set(buf, frame->data, frame->len, frame->data);
        free(frame);
    }
    _sx_debug(ZONE, "passing %d bytes frame", buf->len);

    return 1;
}

static void _sx_websocket_new(sx_t s, sx_plugin_t p) {
    _sx_websocket_conn_t sc = (_sx_websocket_conn_t) s->plugin_data[p->index];

    if(sc != NULL)
        return;

    _sx_debug(ZONE, "preparing for HTTP websocket connect for %d", s->tag);

    sc = (_sx_websocket_conn_t) calloc(1, sizeof(struct _sx_websocket_conn_st));

    sc->state   = websocket_PRE;
    sc->p       = pool_new();
    sc->field   = spool_new(sc->p);
    sc->value   = spool_new(sc->p);
    sc->headers = xhash_new(11);
    sc->buf     = malloc(1024);
    sc->parser.data = sc;

    /* initialize parser */
    http_parser_init(&sc->parser, HTTP_REQUEST);

    s->plugin_data[p->index] = (void *) sc;

    /* bring the plugin online */
    _sx_chain_io_plugin(s, p);
}

/** cleanup */
static void _sx_websocket_free(sx_t s, sx_plugin_t p) {
    _sx_websocket_conn_t sc = (_sx_websocket_conn_t) s->plugin_data[p->index];

    if(sc == NULL)
        return;

    log_debug(ZONE, "cleaning up websocket state");

    pool_free(sc->p);

    if (sc->frame) free(((libwebsock_frame *)sc->frame)->rawdata);
    free(sc->frame);
    free(sc);

    s->plugin_data[p->index] = NULL;
}

/** args: none */
int sx_websocket_init(sx_env_t env, sx_plugin_t p, va_list args) {

    _sx_debug(ZONE, "initialising websocket plugin");

    p->server = _sx_websocket_new;
    p->rio = _sx_websocket_rio;
    p->wio = _sx_websocket_wio;
    p->free = _sx_websocket_free;

    char *http_forward = va_arg(args, char*);
    p->private = http_forward;

    settings.on_headers_complete = _sx_websocket_http_headers_complete;
    settings.on_header_field = _sx_websocket_http_header_field;
    settings.on_header_value = _sx_websocket_http_header_value;

    return 0;
}
