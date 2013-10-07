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

#ifndef INCL_SX_SASL_H
#define INCL_SX_SASL_H

/* RFC 3290 defines a number of failure messages */
#define _sasl_err_ABORTED               "aborted"
#define _sasl_err_INCORRECT_ENCODING    "incorrect-encoding"
#define _sasl_err_INVALID_AUTHZID       "invalid-authzid"
#define _sasl_err_INVALID_MECHANISM     "invalid-mechanism"
#define _sasl_err_MALFORMED_REQUEST     "malformed-request"
#define _sasl_err_MECH_TOO_WEAK         "mechanism-too-weak"
#define _sasl_err_NOT_AUTHORIZED        "not-authorized"
#define _sasl_err_TEMPORARY_FAILURE     "temporary-auth-failure"
#define _sasl_err_INTERNAL_SERVER_ERROR  "internal-server-error"

#endif
