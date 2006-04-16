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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "mio/mio.h"
#include "sx/sx.h"
#include "sx/ssl.h"
#include "sx/sasl.h"
#include "util/util.h"
#include "dns.h"

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

typedef struct resolver_st {
    /** our id (hostname) with the router */
    char                *id;

    /** how to connect to the router */
    char                *router_ip;
    int                 router_port;
    char                *router_user;
    char                *router_pass;
    char                *router_pemfile;

    /** mio context */
    mio_t               mio;

    /** sx environment */
    sx_env_t            sx_env;
    sx_plugin_t         sx_ssl;
    sx_plugin_t         sx_sasl;

    /** router's conn */
    sx_t                router;
    int                 fd;

    /** config */
    config_t            config;

    /** logging */
    log_t               log;

    /** log data */
    log_type_t          log_type;
    char                *log_facility;
    char                *log_ident;

    /** connect retry */
    int                 retry_init;
    int                 retry_lost;
    int                 retry_sleep;
    int                 retry_left;

    /** srvs to lookup */
    char                **lookup_srv;
    int                 lookup_nsrv;
    
    /** if we resolve AAAA records */
    int                 resolve_aaaa;

    /** this is true if we've connected to the router at least once */
    int                 started;

    /** true if we're currently bound in the router */
    int                 online;
} *resolver_t;

