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

#ifndef INCL_SX_H
#define INCL_SX_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "ac-stdint.h"

#include <expat.h>
#include <util/util.h>

/* jabberd2 Windows DLL */
#ifndef JABBERD2_API
# ifdef _WIN32
#  ifdef JABBERD2_EXPORTS
#   define JABBERD2_API  __declspec(dllexport)
#  else /* JABBERD2_EXPORTS */
#   define JABBERD2_API  __declspec(dllimport)
#  endif /* JABBERD2_EXPORTS */
# else /* _WIN32 */
#  define JABBERD2_API extern
# endif /* _WIN32 */
#endif /* JABBERD2_API */

#ifdef __cplusplus
extern "C" {
#endif

/* forward declarations */
typedef struct _sx_st           *sx_t;
typedef struct _sx_env_st       *sx_env_t;
typedef struct _sx_plugin_st    *sx_plugin_t;

/** things that can happen */
typedef enum {
    event_WANT_READ,        /* we want read actions */
    event_WANT_WRITE,       /* we want write actions */
    event_READ,             /* read some stuff for me */
    event_WRITE,            /* write this to the fd */
    event_STREAM,           /* stream is ready to go */
    event_OPEN,             /* normal operation */
    event_PACKET,           /* got a packet */
    event_CLOSED,           /* its over */
    event_ERROR             /* something's wrong */
} sx_event_t;

/** connection states */
typedef enum {
    state_NONE,             /* pre-init */
    state_STREAM_RECEIVED,  /* stream start received (server) */
    state_STREAM_SENT,      /* stream start sent (client) */
    state_STREAM,           /* stream established */
    state_OPEN,             /* auth completed (normal stream operation) */
    state_CLOSING,          /* ready to close (send event_CLOSED to app) */
    state_CLOSED            /* closed (same as NONE, but can't be used any more) */
} _sx_state_t;

/** connection types */
typedef enum {
    type_NONE,
    type_CLIENT,            /* we initiated the connection */
    type_SERVER             /* they initiated */
} _sx_type_t;

/** event callback */
typedef int (*sx_callback_t)(sx_t s, sx_event_t e, void *data, void *arg);

/** plugin init */
typedef int (*sx_plugin_init_t)(sx_env_t env, sx_plugin_t p, va_list args);

/* errors */
#define SX_SUCCESS          (0x00)
#define SX_ERR_STREAM       (0x01)
#define SX_ERR_AUTH         (0x02)
#define SX_ERR_XML_PARSE    (0x03)

/** error info for event_ERROR */
typedef struct _sx_error_st {
    int                     code;
    const char              *generic;
    const char              *specific;
} sx_error_t;

/** helper macro to populate this struct */
#define _sx_gen_error(e,c,g,s)  do { e.code = c; e.generic = g; e.specific = s; } while(0);

/** prototype for the write notify function */
typedef void (*_sx_notify_t)(sx_t s, void *arg);

/** utility: buffer */
typedef struct _sx_buf_st *sx_buf_t;
struct _sx_buf_st {
    char           *data;     /* pointer to buffer's data */
    unsigned int   len;       /* length of buffer's data */
    char           *heap;     /* beginning of malloc() block containing data, if non-NULL */

    /* function to call when this buffer gets written */
    _sx_notify_t            notify;
    void                    *notify_arg;
};

/* stream errors */
#define stream_err_BAD_FORMAT               (0)
#define stream_err_BAD_NAMESPACE_PREFIX     (1)
#define stream_err_CONFLICT                 (2)
#define stream_err_CONNECTION_TIMEOUT       (3)
#define stream_err_HOST_GONE                (4)
#define stream_err_HOST_UNKNOWN             (5)
#define stream_err_IMPROPER_ADDRESSING      (6)
#define stream_err_INTERNAL_SERVER_ERROR    (7)
#define stream_err_INVALID_FROM             (8)
#define stream_err_INVALID_ID               (9)
#define stream_err_INVALID_NAMESPACE        (10)
#define stream_err_INVALID_XML              (11)
#define stream_err_NOT_AUTHORIZED           (12)
#define stream_err_POLICY_VIOLATION         (13)
#define stream_err_REMOTE_CONNECTION_FAILED (14)
#define stream_err_RESTRICTED_XML           (15)
#define stream_err_RESOURCE_CONSTRAINT      (16)
#define stream_err_SEE_OTHER_HOST           (17)
#define stream_err_SYSTEM_SHUTDOWN          (18)
#define stream_err_UNDEFINED_CONDITION      (19)
#define stream_err_UNSUPPORTED_ENCODING     (20)
#define stream_err_UNSUPPORTED_STANZA_TYPE  (21)
#define stream_err_UNSUPPORTED_VERSION      (22)
#define stream_err_XML_NOT_WELL_FORMED      (23)
#define stream_err_LAST                     (24)

/* exported functions */

/* make/break */
JABBERD2_API sx_t                        sx_new(sx_env_t env, int tag, sx_callback_t cb, void *arg);
JABBERD2_API void                        sx_free(sx_t s);

/* get things ready */
JABBERD2_API void                        sx_client_init(sx_t s, unsigned int flags, const char *ns, const char *to, const char *from, const char *version);
JABBERD2_API void                        sx_server_init(sx_t s, unsigned int flags);

/* activity on socket, do stuff! (returns 1 if more read/write actions wanted, 0 otherwise) */
JABBERD2_API int                         sx_can_read(sx_t s);
JABBERD2_API int                         sx_can_write(sx_t s);

/** sending a nad */
JABBERD2_API void                        sx_nad_write_elem(sx_t s, nad_t nad, int elem);
#define sx_nad_write(s,nad) sx_nad_write_elem(s, nad, 0)

/** sending raw data */
JABBERD2_API void                        sx_raw_write(sx_t s, const char *buf, int len);

/** authenticate the stream and move to the auth'd state */
JABBERD2_API void                        sx_auth(sx_t s, const char *auth_method, const char *auth_id);

/* make/break an environment */
JABBERD2_API sx_env_t                    sx_env_new(void);
JABBERD2_API void                        sx_env_free(sx_env_t env);

/** load a plugin into the environment */
JABBERD2_API sx_plugin_t                 sx_env_plugin(sx_env_t env, sx_plugin_init_t init, ...);

/* send errors and close stuff */
JABBERD2_API void                        sx_error(sx_t s, int err, const char *text);
JABBERD2_API void                        sx_error_extended(sx_t s, int err, const char *content);
JABBERD2_API void                        sx_close(sx_t s);
JABBERD2_API void                        sx_kill(sx_t s);


/* internal functions */

/* primary expat callbacks */
JABBERD2_API void                        _sx_element_start(void *arg, const char *name, const char **atts);
JABBERD2_API void                        _sx_element_end(void *arg, const char *name);
JABBERD2_API void                        _sx_cdata(void *arg, const char *str, int len);
JABBERD2_API void                        _sx_namespace_start(void *arg, const char *prefix, const char *uri);
#ifdef HAVE_XML_STOPPARSER
JABBERD2_API void                        _sx_entity_declaration(void *arg, const char *entityName,
                                                                int is_parameter_entity, const char *value,
                                                                int value_length, const char *base,
                                                                const char *systemId, const char *publicId,
                                                                const char *notationName);
#endif

/** processor for incoming wire data */
JABBERD2_API void                        _sx_process_read(sx_t s, sx_buf_t buf);

/** main nad processor */
JABBERD2_API void                        _sx_nad_process(sx_t s, nad_t nad);

/* chain management */
JABBERD2_API void                        _sx_chain_io_plugin(sx_t s, sx_plugin_t p);
JABBERD2_API void                        _sx_chain_nad_plugin(sx_t s, sx_plugin_t p);

/* chain running */
JABBERD2_API int                         _sx_chain_io_write(sx_t s, sx_buf_t buf);
JABBERD2_API int                         _sx_chain_io_read(sx_t s, sx_buf_t buf);

JABBERD2_API int                         _sx_chain_nad_write(sx_t s, nad_t nad, int elem);
JABBERD2_API int                         _sx_chain_nad_read(sx_t s, nad_t nad);

/* buffer utilities */
JABBERD2_API sx_buf_t                     _sx_buffer_new(const char *data, int len, _sx_notify_t notify, void *notify_arg);
JABBERD2_API void                        _sx_buffer_free(sx_buf_t buf);
JABBERD2_API void                        _sx_buffer_clear(sx_buf_t buf);
JABBERD2_API void                        _sx_buffer_alloc_margin(sx_buf_t buf, int before, int after);
JABBERD2_API void                        _sx_buffer_set(sx_buf_t buf, char *newdata, int newlength, char *newheap);

/** sending a nad (internal) */
JABBERD2_API int                         _sx_nad_write(sx_t s, nad_t nad, int elem);

/** sending raw data (internal) */
JABBERD2_API void                        sx_raw_write(sx_t s, const char *buf, int len);

/** reset stream state without informing the app */
JABBERD2_API void                        _sx_reset(sx_t s);

/* send errors and close stuff */
JABBERD2_API void                        _sx_error(sx_t s, int err, const char *text);
JABBERD2_API void                        _sx_error_extended(sx_t s, int err, const char *content);
JABBERD2_API void                        _sx_close(sx_t s);

/** read/write plugin chain */
typedef struct _sx_chain_st *_sx_chain_t;
struct _sx_chain_st {
    sx_plugin_t              p;

    _sx_chain_t              wnext;          /* -> write */
    _sx_chain_t              rnext;          /* <- read */
};

/** holds the state for a single stream */
struct _sx_st {
    /* environment */
    sx_env_t                 env;

    /* tag, for logging */
    int                      tag;

	/* IP address of the connection */
	/* pointing to sess.ip and owned by sess structure */
	const char              *ip;

	/* TCP port of the connection */
	/* pointing to sess.port and owned by sess structure */
    int                     port;

    /* callback */
    sx_callback_t            cb;
    void                    *cb_arg;

    /* type */
    _sx_type_t               type;

    /* flags */
    unsigned int             flags;

    /* application namespace */
    const char              *ns;

    /* requested stream properties */
    const char              *req_to;
    const char              *req_from;
    const char              *req_version;

    /* responded stream properties */
    const char              *res_to;
    const char              *res_from;
    const char              *res_version;

    /* stream id */
    const char              *id;

    /* io chain */
    _sx_chain_t              wio, rio;

    /* nad chain */
    _sx_chain_t              wnad, rnad;

    /* internal queues */
    jqueue_t                 wbufq;              /* buffers waiting to go to wio */
    sx_buf_t                 wbufpending;        /* buffer passed through wio but not written yet */
    jqueue_t                 rnadq;              /* completed nads waiting to go to rnad */

    /* do we want to read or write? */
    int                      want_read, want_write;

    /* bytes read from socket */
    int                      rbytes;

    /* read bytes maximum */
    int                      rbytesmax;

    /* current state */
    _sx_state_t              state;

    /* parser */
    XML_Parser               expat;
    int                      depth;
    int                      fail;

    /* nad currently being built */
    nad_t                    nad;

    /* plugin storage */
    void                   **plugin_data;

    /* type and id of auth */
    const char              *auth_method;
    const char              *auth_id;

    /* if true, then we were called from the callback */
    int                     reentry;

    /* this is true after a stream resets - applications should check this before doing per-stream init */
    int                     has_reset;

    /* security strength factor (in sasl parlance) - roughly equivalent to key strength */
    int                     ssf;

    /* is stream compressed */
    int                     compressed;
};

/** a plugin */
struct _sx_plugin_st {
    sx_env_t                env;

    int                     magic;              /* unique id so that plugins can find each other */

    int                     index;

    void                    *private;

    void                    (*new)(sx_t s, sx_plugin_t p);                          /* pre-run init */
    void                    (*free)(sx_t s, sx_plugin_t p);                         /* conn being freed */

    void                    (*client)(sx_t s, sx_plugin_t p);                       /* client init */
    void                    (*server)(sx_t s, sx_plugin_t p);                       /* server init */

    /* return -2 == failed (permanent), -1 == failed (temporary), 0 == handled, 1 == pass */
    int                     (*wio)(sx_t s, sx_plugin_t p, sx_buf_t buf);            /* before being written */
    int                     (*rio)(sx_t s, sx_plugin_t p, sx_buf_t buf);            /* after being read */

    /* return 0 == handled, 1 == pass */
    int                     (*wnad)(sx_t s, sx_plugin_t p, nad_t nad, int elem);    /* before being written */
    int                     (*rnad)(sx_t s, sx_plugin_t p, nad_t nad);              /* after being read */

    void                    (*header)(sx_t s, sx_plugin_t p, sx_buf_t buf);         /* before header req/res write */
    void                    (*stream)(sx_t s, sx_plugin_t p);                       /* after-stream init */

    void                    (*features)(sx_t s, sx_plugin_t p, nad_t nad);          /* offer features */

    /* return 0 == handled, 1 == pass */
    int                     (*process)(sx_t s, sx_plugin_t p, nad_t nad);           /* process completed nads */

    void                    (*unload)(sx_plugin_t p);                               /* plugin unloading */
};

/** an environment */
struct _sx_env_st {
    sx_plugin_t             *plugins;
    int                     nplugins;
};

/** debugging macros */
#define ZONE __FILE__,__LINE__

/** helper functions for macros when we're debugging */
JABBERD2_API void        __sx_debug(const char *file, int line, const char *msgfmt, ...);

/** helper and internal macro for firing the callback */
JABBERD2_API int         __sx_event(const char *file, int line, sx_t s, sx_event_t e, void *data);
#define _sx_event(s,e,data) __sx_event(ZONE, s, e, data)

#ifdef SX_DEBUG

/** print debug output */
#define _sx_debug if(get_debug_flag()) __sx_debug

/** state changes with output */
#define _sx_state(s,st) do { _sx_debug(ZONE, "%d state change from %d to %d", s->tag, s->state, st); s->state = st; } while(0)

#else

/* clean and efficient versions */
#define _sx_debug if(0) __sx_debug
#define _sx_state(s,st) s->state = st

#endif

#ifdef __cplusplus
}
#endif

/* now include sx envplugins datatypes */
#include "plugins.h"

#endif
