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

typedef struct router_st    *router_t;
typedef struct component_st *component_t;
typedef struct routes_st    *routes_t;
typedef struct alias_st     *alias_t;

typedef struct acl_s *acl_t;
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
    const char          *local_private_key_password;

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

    /** valid routes, key is route name (packet "to" address), var is component_t */
    xht                 routes;

    /** default route, only one */
    const char          *default_route;

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
    jqueue_t            deadroutes;

    /** simple message logging */
	int message_logging_enabled;
	const char *message_logging_file;
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
    int                 legacy;

    /** throttle queue */
    jqueue_t            tq;

    /** timestamps for idle timeouts */
    time_t              last_activity;
};

/** route types */
typedef enum {
    route_SINGLE = 0x00,         /**< single component route */
    route_MULTI_TO = 0x10,       /**< multi component route - route by 'to' */
    route_MULTI_FROM = 0x11,     /**< multi component route - route by 'from' */
} route_type_t;

struct routes_st
{
    const char          *name;
    route_type_t        rtype;
    component_t         *comp;
    int                 ncomp;
};

struct alias_st {
    const char          *name;
    const char          *target;

    alias_t             next;
};

int     router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
void    router_sx_handshake(sx_t s, sx_buf_t buf, void *arg);

xht     aci_load(router_t r);
void    aci_unload(xht aci);
int     aci_check(xht acls, const char *type, const char *name);

int     user_table_load(router_t r);
void    user_table_unload(router_t r);

int     filter_load(router_t r);
void    filter_unload(router_t r);
int     filter_packet(router_t r, nad_t nad);

int     message_log(nad_t nad, router_t r, const char *msg_from, const char *msg_to);

void routes_free(routes_t routes);

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  char **char_val;
  component_t *comp_val;
  rate_t *rt_val;
};
