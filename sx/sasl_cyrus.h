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

#ifndef INCL_SX_SASL_CYRUS_H
#define INCL_SX_SASL_CYRUS_H

/* Gack - need this otherwise SASL's MD5 definitions conflict with OpenSSLs */
#ifdef HEADER_MD5_H
#  define MD5_H
#endif
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <sasl/saslplug.h>

/** trigger for client auth */
int                         sx_sasl_auth(sx_plugin_t p, sx_t s, char *appname, char *mech, char *user, char *pass);

/** our context */
typedef struct _sx_sasl_st {
    char                        *appname;
    sasl_security_properties_t  sec_props;

    sx_sasl_callback_t          cb;
    void                        *cbarg;

    sasl_callback_t		*saslcallbacks;
} *_sx_sasl_t;

/* data for per-conncetion sasl handshakes */
typedef struct _sx_sasl_data_st {
    char                        *user;
    sasl_secret_t               *psecret;

    sasl_callback_t             *callbacks;

    _sx_sasl_t	                ctx;
    sasl_conn_t                 *sasl;
    sx_t                        stream;
} *_sx_sasl_data_t;

#endif
