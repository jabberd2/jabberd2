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
  * JID manipulation. Validity is checked via stringprep, using
  * the "nodeprep", "nameprep" and "resourceprep" profiles (see xmpp-core
  * section 3).
  *
  * The application should fill out node, domain and resource directly, then
  * call jid_expand(), or set the dirty flag.
  */

#ifndef INCL_UTIL_JID_H
#define INCL_UTIL_JID_H 1

/** these sizings come from xmpp-core */
#define MAXLEN_JID_COMP  1023    /* XMPP (RFC3920) 3.1 */
#define MAXLEN_JID       3071    /* nodename (1023) + '@' + domain (1023) + '/' + resource (1023) = 3071 */

typedef struct jid_st {
    /* basic components of the jid */
    char   *node;
    char   *domain;
    char   *resource;

    /* Points to jid broken with \0s into componets. node/domain/resource point
     * into this string (or to statically allocated empty string, if they are
     * empty) */
    char   *jid_data;
    /* Valid only when jid_data != NULL. When = 0, jid_data is statically
     * allocated. Otherwise it tells length of the allocated data. Used to
     * implement jid_dup() */
    size_t          jid_data_len;

    /* the "user" part of the jid (sans resource) */
    char   *_user;

    /* the complete jid */
    char   *_full;

    /* application should set to 1 if user/full need regenerating */
    int             dirty;

    /* for lists of jids */
    struct jid_st    *next;
} *jid_t;

typedef enum {
    jid_NODE    = 1,
    jid_DOMAIN  = 2,
    jid_RESOURCE = 3
} jid_part_t;

/** JID static buffer **/
typedef char jid_static_buf[3*1025];

/** make a new jid, and call jid_reset() to populate it */
JABBERD2_API jid_t               jid_new(const char *id, int len);

/** Make jid to use static buffer (jid data won't be allocated dynamically, but
 * given buffer will be always used. */
JABBERD2_API void                jid_static(jid_t jid, jid_static_buf *buf);

/** clear and populate the jid with the given id. if id == NULL, just clears the jid to 0 */
JABBERD2_API jid_t               jid_reset(jid_t jid, const char *id, int len);
JABBERD2_API jid_t               jid_reset_components(jid_t jid, const char *node, const char *domain, const char *resource);

/** free the jid */
JABBERD2_API void                jid_free(jid_t jid);

/** do string preparation on a jid */
JABBERD2_API int                 jid_prep(jid_t jid);

/** fill jid's resource with a random string **/
JABBERD2_API void                jid_random_part(jid_t jid, jid_part_t part);

/** expands user and full if the dirty flag is set */
JABBERD2_API void                jid_expand(jid_t jid);

/** return the user or full jid. these call jid_expand to make sure the user and
 * full jid are up to date */
JABBERD2_API const char *jid_user(jid_t jid);
JABBERD2_API const char *jid_full(jid_t jid);

/** compare two user or full jids. these call jid_expand, then strcmp. returns
 * 0 if they're the same, < 0 if a < b, > 0 if a > b */
JABBERD2_API int                 jid_compare_user(jid_t a, jid_t b);
JABBERD2_API int                 jid_compare_full(jid_t a, jid_t b);

/** duplicate a jid */
JABBERD2_API jid_t               jid_dup(jid_t jid);

/** list helpers */

/** see if a jid is present in a list */
JABBERD2_API int                 jid_search(jid_t list, jid_t jid);

/** remove a jid from a list, and return the new list */
JABBERD2_API jid_t               jid_zap(jid_t list, jid_t jid);

/** insert of a copy of jid into list, avoiding dups */
JABBERD2_API jid_t               jid_append(jid_t list, jid_t jid);

#endif
