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

#ifndef INCL_UTIL_STANZA_H
#define INCL_UTIL_STANZA_H 1

#include "util.h"
#include "nad.h"

/* stanza manipulation */
enum {
    stanza_err_BAD_REQUEST = 100,
    stanza_err_CONFLICT,
    stanza_err_FEATURE_NOT_IMPLEMENTED,
    stanza_err_FORBIDDEN,
    stanza_err_GONE,
    stanza_err_INTERNAL_SERVER_ERROR,
    stanza_err_ITEM_NOT_FOUND,
    stanza_err_JID_MALFORMED,
    stanza_err_NOT_ACCEPTABLE,
    stanza_err_NOT_ALLOWED,
    stanza_err_PAYMENT_REQUIRED,
    stanza_err_RECIPIENT_UNAVAILABLE,
    stanza_err_REDIRECT,
    stanza_err_REGISTRATION_REQUIRED,
    stanza_err_REMOTE_SERVER_NOT_FOUND,
    stanza_err_REMOTE_SERVER_TIMEOUT,
    stanza_err_RESOURCE_CONSTRAINT,
    stanza_err_SERVICE_UNAVAILABLE,
    stanza_err_SUBSCRIPTION_REQUIRED,
    stanza_err_UNDEFINED_CONDITION,
    stanza_err_UNEXPECTED_REQUEST,
    stanza_err_OLD_UNAUTH,
    stanza_err_UNKNOWN_SENDER,
    stanza_err_LAST
};

JABBERD2_API nad_t *stanza_error(nad_t *nad, int elem, int err);
JABBERD2_API nad_t *stanza_tofrom(nad_t *nad, int elem);

typedef struct _stanza_error_st {
    const char  *name;
    const char  *type;
    const char  *code;
} *stanza_error_t;

JABBERD2_API struct _stanza_error_st _stanza_errors[];

#endif    /* INCL_UTIL_STANZA_H */
