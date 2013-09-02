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

/*! \mainpage jabberd - Jabber Open Source Server
 *
 * \section intro Introduction
 *
 * The jabberd project aims to provide an open-source server
 * implementation of the Jabber protocols for instant messaging
 * and XML routing. The goal of this project is to provide a
 * scalable, reliable, efficient and extensible server that
 * provides a complete set of features and is up to date with
 * the latest protocol revisions.
 *
 * The project web page:\n
 * http://jabberd2.xiaoka.com/
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "sx/sx.h"
#include "mio/mio.h"
#include "util/util.h"

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

typedef struct router_st         *router_t;
typedef struct remote_routers_st *remote_routers_t;
typedef struct component_st      *component_t;
typedef struct routes_st         *routes_t;
typedef struct ids_st            *ids_t;
typedef struct route_elem_st     *route_elem_t;
typedef struct graph_elem_st     *graph_elem_t;
typedef struct alias_st          *alias_t;
typedef struct acl_s             *acl_t;

struct acl_s {
    int error;
    char *redirect;
    int redirect_len;
    char *what;
    char *from;
    char *to;
    int log;
    acl_t next;
};

struct router_st {
    /** our id */
    const char          *id;

    /** config */
    config_t            config;

    /** user table */
    xht                 users;
    time_t              users_load;

    /** user table */
    acl_t               filter;
    time_t              filter_load;

    /** remote-routers table */
    remote_routers_t    remote_routers;
    time_t              remote_routers_load;

    /** logging */
    log_t               log;

    /** log data */
    log_type_t          log_type;
    const char          *log_facility;
    const char          *log_ident;

    /** how we listen for stuff */
    const char          *local_ip;
    int                 local_port;
    const char          *local_secret;
    const char          *local_pemfile;

    /** max file descriptors */
    int                 io_max_fds;

    /** access controls */
    access_t            access;

    /** connection rates */
    int                 conn_rate_total;
    int                 conn_rate_seconds;
    int                 conn_rate_wait;

    xht                 conn_rates;

    /** default byte rates (karma) */
    int                 byte_rate_total;
    int                 byte_rate_seconds;
    int                 byte_rate_wait;

    /** sx environment */
    sx_env_t            sx_env;
    sx_plugin_t         sx_ssl;
    sx_plugin_t         sx_sasl;

    /** managed io */
    mio_t               mio;

    /** listening socket */
    mio_fd_t            fd;

    /** time checks */
    int                 check_interval;
    int                 check_keepalive;

    time_t              next_check;

    /** attached components, key is 'ip:port', var is component_t */
    xht                 components;

    /** valid components IDs, key is ID, var is route_t */
    xht                 rids;

    /** valid domain routes, key is domain, var is route_t */
    xht                 domains;

    /** valid IDs routes, key is bare_jid, var is xht domainbares */
    xht                 bare_jids;

    /** valid IDs, key is ID, var is ids_t */
    xht                 ids;

    /** head of neighbours graph */
    graph_elem_t        graph;

    /** log sinks, key is route name, var is component_t */
    xht                 log_sinks;

    /** configured aliases */
    alias_t             aliases;

    /** access control lists */
    xht                 aci;

    /** list of sx_t waiting to be cleaned up */
    jqueue_t            dead;

    /** list of mio_fd_t waiting to be closed */
    jqueue_t            closefd;

    /** list of routes_t waiting to be cleaned up */
    jqueue_t            dead_routes;

    /** list of route_elem_t waiting to be cleaned up */
    jqueue_t            dead_route_elems;

    /** list of remote_routers_t waiting to be cleaned up */
    jqueue_t            dead_remote_routers;

    /** list of remote_routers_t waiting to be connected */
    jqueue_t            new_remote_routers;

    /** simple message logging */
    int                 message_logging_enabled;
    const char          *message_logging_file;
};

/** a single component */
struct component_st {
    router_t            r;

    /** file descriptor */
    mio_fd_t            fd;

    /** remote ip and port */
    char                ip[INET6_ADDRSTRLEN];
    int                 port;

    /** ip:port pair */
    char                ipport[INET6_ADDRSTRLEN + 6];

    /** our stream */
    sx_t                s;

    /** rate limits */
    rate_t              rate;
    int                 rate_log;

    /** valid routes to this component, key is route name */
    xht                 routes;

    /** true if this is an old component:accept stream */
    unsigned int        legacy;

    /** component ID */
    char                *id;

    /** only if this is a remote router */
    remote_routers_t    remote_router;

    /** throttle queue */
    jqueue_t            tq;

    /** timestamps for idle timeouts */
    time_t              last_activity;
};

/** route list header */
struct routes_st {
    unsigned int        nb_routes;
    unsigned int        legacy;
    remote_routers_t    remote_router;

    route_elem_t        head;
};

/** route list element */
struct route_elem_st {
    char                *id;     // ID of neighbour
    unsigned int        metric;  // metric to dest
    component_t         comp;    // neighbour component
    
    route_elem_t        next;    // next route for this ID
};

/** ID list element */
struct ids_st {
    char                *id;      // ID
    unsigned int        refcount; // reference count
};

/** graph list element */
struct graph_elem_st {
    char                *id;             // ID of neighbour
    
    graph_elem_t        neighbour_next;  // next neighbour
    graph_elem_t        neighbours_head; // head of neighbours's neighbours
};

struct remote_routers_st {
    component_t         comp;
    unsigned int        seen;
    unsigned int        outbound;
    unsigned int        metric;
    char                *user;
    char                *pass;
    char                *pemfile;
    int                 retry_init;
    int                 retry_sleep;
    int                 retry_left;
    time_t              last_connect;
    unsigned int        online;

    remote_routers_t    next;
};

struct alias_st {
    const char          *name;
    const char          *target;

    alias_t             next;
};

int     router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
void    router_sx_handshake(sx_t s, sx_buf_t buf, void *arg);
int     router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg);

xht     aci_load(router_t r);
void    aci_unload(xht aci);
int     aci_check(xht acls, const char *type, const char *name);

int     user_table_load(router_t r);
void    user_table_unload(router_t r);

int     remote_routers_table_load(router_t r, unsigned int reload);
void    remote_routers_table_unload(router_t r);
void    remote_router_free(remote_routers_t remote);
int     remote_router_connect(router_t r, remote_routers_t remote);

int     filter_load(router_t r);
void    filter_unload(router_t r);
int     filter_packet(router_t r, nad_t nad);

int     message_log(nad_t nad, router_t r, const char *msg_from, const char *msg_to);

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
    void **val;
    char **char_val;
    component_t *comp_val;
    rate_t *rt_val;
};
