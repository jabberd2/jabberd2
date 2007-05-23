/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2004 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/** @file util/jid.h
  * @brief Jabber identifiers
  * @author Robert Norris
  * $Date: 2004/05/01 00:51:10 $
  * $Revision: 1.1 $
  *
  * JID manipulation. Validity is checked via stringprep (if available), using
  * the "nodeprep", "nameprep" and "resourceprep" profiles (see xmpp-core
  * section 3).
  *
  * The application should fill out node, domain and resource directly, then
  * call jid_expand(), or set the dirty flag.
  */

#ifndef INCL_UTIL_JID_H
#define INCL_UTIL_JID_H 1

#include "pool.h"

/* opaque decl */
typedef struct _prep_cache_st   *prep_cache_t;

JABBERD2_API prep_cache_t    prep_cache_new(pool_t p);

/** these sizings come from xmpp-core */
typedef struct _jid_st {
    pool_t          p;

    /* cache for prep, if any */
    prep_cache_t    pc;

    /* basic components of the jid */
    unsigned char   node[1024];
    unsigned char   domain[1024];
    unsigned char   resource[1024];

    /* the "user" part of the jid (sans resource) */
    unsigned char   *user;
    int             ulen;

    /* the complete jid */
    unsigned char   *full;
    int             flen;

    /* application should set to 1 if user/full need regenerating */
    int             dirty;

    /* for lists of jids */
    struct _jid_st  *next;
} *jid_t;

/** make a new jid, and call jid_reset() to populate it */
JABBERD2_API jid_t               jid_new(pool_t p, prep_cache_t pc, const unsigned char *id, int len);

/** clear and populate the jid with the given id. if id == NULL, just clears the jid to 0 */
JABBERD2_API jid_t               jid_reset(jid_t jid, const unsigned char *id, int len);

/** do string preparation on a jid */
JABBERD2_API int                 jid_prep(jid_t jid);

/** expands user and full if the dirty flag is set */
JABBERD2_API void                jid_expand(jid_t jid);

/** return the user or full jid. these call jid_expand to make sure the user and
 * full jid are up to date */
const unsigned char *jid_user(jid_t jid);
const unsigned char *jid_full(jid_t jid);

/** compare two user or full jids. these call jid_expand, then strcmp. returns
 * 0 if they're the same, < 0 if a < b, > 0 if a > b */
JABBERD2_API int                 jid_compare_user(jid_t a, jid_t b);
JABBERD2_API int                 jid_compare_full(jid_t a, jid_t b);

/** duplicate a jid */
JABBERD2_API jid_t               jid_dup(jid_t jid, pool_t p);

/** list helpers */

/** see if a jid is present in a list */
JABBERD2_API int                 jid_search(jid_t list, jid_t jid);

/** remove a jid from a list, and return the new list */
JABBERD2_API jid_t               jid_zap(jid_t list, jid_t jid);

/** insert of a copy of jid into list, avoiding dups */
JABBERD2_API jid_t               jid_append(jid_t list, jid_t jid);


#endif
