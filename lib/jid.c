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

#include "jid.h"
#include "str.h"
#include "sha1.h"
#include <gc.h>
#include <stringprep.h>
#include <assert.h>
#include <stdio.h>

/** Forward declaration **/
static jid_t *jid_reset_components_internal(jid_t *jid, const char *node, const char *domain, const char *resource, int prepare);

/** do stringprep on the pieces */
static int jid_prep_pieces(char *node, char *domain, char *resource) {
    if (node[0] != '\0')
        if (stringprep_xmpp_nodeprep(node, 1024) != 0)
            return 1;

    if (stringprep_nameprep(domain, 1024) != 0)
        return 1;

    if (resource[0] != '\0')
        if (stringprep_xmpp_resourceprep(resource, 1024) != 0)
            return 1;

    return 0;
}

/** do stringprep on the piece **/
int jid_prep(jid_t *jid)
{
    char node[MAXLEN_JID_COMP+1];
    char domain[MAXLEN_JID_COMP+1];
    char resource[MAXLEN_JID_COMP+1];

    if (jid->node != NULL) {
        strncpy(node, jid->node, MAXLEN_JID_COMP);
        node[MAXLEN_JID_COMP]='\0';
    }
    else
        node[0] = '\0';

    if (jid->domain != NULL) {
        strncpy(domain, jid->domain, MAXLEN_JID_COMP);
        domain[MAXLEN_JID_COMP]='\0';
    }
    else
        domain[0] = '\0';

    if (jid->resource != NULL) {
        strncpy(resource, jid->resource, MAXLEN_JID_COMP);
        resource[MAXLEN_JID_COMP]='\0';
    }
    else
        resource[0] = '\0';

    if (jid_prep_pieces(node, domain, resource) != 0)
        return 1;

    /* put prepared components into jid */
    jid_reset_components_internal(jid, node, domain, resource, 0);

    return 0;
}

/** make a new jid */
jid_t *jid_new(const char *id, int len) {
    jid_t *jid, *ret;

    jid = GC_MALLOC(sizeof(jid_t));
    jid->jid_data = GC_MALLOC_ATOMIC(7); /* shortest possible jid: a@b.c/d */
    jid->_user = GC_MALLOC_ATOMIC(5);
    jid->_full = GC_MALLOC_ATOMIC(7);

    ret = jid_reset(jid, id, len);
    if (ret == NULL) {
        GC_FREE(jid);
    }

    return ret;
}

/** build a jid from an id */
jid_t *jid_reset(jid_t *jid, const char *id, int len) {
    char *myid, *cur;

    assert((int) (jid != NULL));

    GC_FREE(jid->jid_data);
    memset(jid, 0, sizeof(jid_t));
    jid->dirty = 1;
    jid->node = "";
    jid->domain = "";
    jid->resource = "";

    /* nice empty jid */
    if (id == NULL)
        return jid;

    if (len < 0)
        len = strlen(id);

    if ((len == 0) || (len > MAXLEN_JID))
        return NULL;

    jid->jid_data_len = sizeof(char) * (len + 1);
    myid = (char *) GC_MALLOC_ATOMIC(jid->jid_data_len);
    sprintf(myid, "%.*s", len, id);

    /* fail - only a resource or leading @ */
    if (myid[0] == '/' || myid[0] == '@') {
        return NULL;
    }

    /* get the resource first */
    cur = strstr(myid, "/");

    if (cur != NULL)
    {
        *cur = '\0';
        cur++;
        if (strlen(cur) > 0) {
            jid->resource = cur;
        } else {
            /* fail - a resource separator but nothing after it */
            return NULL;
        }
    }

    /* find the domain */
    cur = strstr(myid, "@");
    if (cur != NULL) {
        *cur = '\0';
        cur++;
        if (strlen(cur) == 0) {
            /* no domain part, bail out */
            return NULL;
        }
        jid->domain = cur;
        jid->node = myid;
    } else {
        /* no @, so it's a domain only */
        jid->domain = myid;
    }

    jid->jid_data = myid;

    if (jid_prep(jid) != 0) {
        jid->jid_data = NULL;
        return NULL;
    }

    return jid;
}

/** build a jid from components - internal version */
static jid_t *jid_reset_components_internal(jid_t *jid, const char *node, const char *domain, const char *resource, int prepare) {
    char *olddata=NULL;
    int node_l,domain_l,resource_l;

    assert((int) (jid != NULL));

    if (jid->jid_data != NULL)
        olddata = jid->jid_data; /* Store old data before clearing JID */

    GC_FREE(jid->_user);
    GC_FREE(jid->_full);

    memset(jid, 0, sizeof(jid_t));

    /* get lengths */
    node_l = strlen(node);
    domain_l = strlen(domain);
    resource_l = strlen(resource);

    if (node_l > MAXLEN_JID_COMP)
        node_l = MAXLEN_JID_COMP;

    if (domain_l > MAXLEN_JID_COMP)
        domain_l = MAXLEN_JID_COMP;

    if (resource_l > MAXLEN_JID_COMP)
        resource_l = MAXLEN_JID_COMP;

    /* allocate new data buffer */
    jid->jid_data_len = node_l+domain_l+resource_l+3;
    jid->jid_data = GC_REALLOC(jid->jid_data, jid->jid_data_len);

    /* copy to buffer */
    jid->node = jid->jid_data;
    strncpy(jid->node, node, node_l);
    jid->node[node_l] = 0;

    jid->domain = jid->node + node_l + 1;
    strncpy(jid->domain, domain, domain_l);
    jid->domain[domain_l] = 0;

    jid->resource = jid->domain + domain_l + 1;
    strncpy(jid->resource, resource, resource_l);
    jid->resource[resource_l] = 0;

    /* Free old data buffer. Postponed to this point so that arguments may point (in)to old jid data. */
    GC_FREE(olddata);

    if (prepare) {
        if (jid_prep(jid) != 0)
            return NULL;
    }

    jid->dirty = 1;

    return jid;
}

/** build a jid from components */
jid_t *jid_reset_components(jid_t *jid, const char *node, const char *domain, const char *resource) {
    return jid_reset_components_internal(jid, node, domain, resource, 1);
}

/** free a jid */
void jid_free(jid_t *jid)
{
    GC_FREE(jid->jid_data);
    GC_FREE(jid->_user);
    GC_FREE(jid->_full);
    GC_FREE(jid);
}

/** build user and full if they're out of date */
void jid_expand(jid_t *jid)
{
    int nlen, dlen, rlen, ulen;

    if ((!jid->dirty) && (jid->_full))
        return; /* Not dirty & already expanded */

    if (*jid->domain == '\0') {
      /* empty */
      jid->_full = (char*) GC_REALLOC(jid->_full, 1);
      jid->_full[0] = 0;
      return;
    }

    nlen = strlen(jid->node);
    dlen = strlen(jid->domain);
    rlen = strlen(jid->resource);

    if (nlen == 0) {
        ulen = dlen+1;
        jid->_user = (char*) GC_REALLOC(jid->_user, ulen);
        strcpy(jid->_user, jid->domain);
    } else {
        ulen = nlen+1+dlen+1;
        jid->_user = (char*) GC_REALLOC(jid->_user, ulen);
        snprintf(jid->_user, ulen, "%s@%s", jid->node, jid->domain);
    }

    if (rlen == 0) {
        jid->_full = (char*) GC_REALLOC(jid->_full, ulen);
        strcpy(jid->_full, jid->_user);
    } else {
        jid->_full = (char*) GC_REALLOC(jid->_full, ulen+1+rlen);
        snprintf(jid->_full, ulen+1+rlen, "%s/%s", jid->_user, jid->resource);
    }

    jid->dirty = 0;
}

/** expand and return the user */
const char *jid_user(jid_t *jid)
{
    jid_expand(jid);

    return jid->_user;
}

/** expand and return the full */
const char *jid_full(jid_t *jid)
{
    jid_expand(jid);

    return jid->_full;
}

/** compare the user portion of two jids */
int jid_compare_user(jid_t *a, jid_t *b)
{
    jid_expand(a);
    jid_expand(b);

    return strcmp(a->_user, b->_user);
}

/** compare two full jids */
int jid_compare_full(jid_t *a, jid_t *b)
{
    jid_expand(a);
    jid_expand(b);

    return strcmp(a->_full, b->_full);
}

/** duplicate a jid */
jid_t *jid_dup(jid_t *jid)
{
    jid_t *new;

    new = (jid_t *) GC_MALLOC(sizeof(jid_t));
    memcpy(new, jid, sizeof(jid_t));
    if (jid->jid_data != NULL) {

      /* allocate & populate new dynamic buffer */
      new->jid_data = GC_MALLOC_ATOMIC(new->jid_data_len);
      memcpy(new->jid_data, jid->jid_data, new->jid_data_len);

      /* relocate pointers */
      if (jid->node[0] == '\0')
          new->node = "";
      else
          new->node = new->jid_data + (jid->node - jid->jid_data);
      if (jid->domain[0] == '\0')
          new->domain = "";
      else
          new->domain = new->jid_data + (jid->domain - jid->jid_data);
      if (jid->resource[0] == '\0')
          new->resource = "";
      else
          new->resource = new->jid_data + (jid->resource - jid->jid_data);
    }
    if (jid->_user)
      new->_user = j_strdup(jid->_user);
    if (jid->_full)
      new->_full = j_strdup(jid->_full);

    return new;
}

/** util to search through jids */
int jid_search(jid_t *list, jid_t *jid)
{
    jid_t *cur;
    for (cur = list; cur != NULL; cur = cur->next)
        if (jid_compare_full(cur,jid) == 0)
            return 1;
    return 0;
}

/** remove a jid_t from a list, returning the new list */
jid_t *jid_zap(jid_t *list, jid_t *jid)
{
    jid_t *cur, *dead;

    if (jid == NULL || list == NULL)
        return NULL;

    /* check first */
    if (jid_compare_full(jid,list) == 0) {
        cur = list->next;
        jid_free(list);
        return cur;
    }

    /* check through the list, stopping at the previous list entry to a matching one */
    cur = list;
    while (cur != NULL)
    {
        if (cur->next == NULL)
            /* none match, so we're done */
            return list;

        if (jid_compare_full(cur->next, jid) == 0)
        {
            /* match, kill it */
            dead = cur->next;
            cur->next = cur->next->next;
            jid_free(dead);

            return list;
        }

        /* loop */
        cur = cur->next;
    }

    /* shouldn't get here */
    return list;
}

/** make a copy of jid, link into list (avoiding dups) */
jid_t *jid_append(jid_t *list, jid_t *jid)
{
    jid_t *scan;

    if (list == NULL)
        return jid_dup(jid);

    scan = list;
    while (scan != NULL)
    {
        /* check for dups */
        if (jid_compare_full(scan, jid) == 0)
            return list;

        /* tack it on to the end of the list */
        if (scan->next == NULL)
        {
            scan->next = jid_dup(jid);
            return list;
        }

        scan = scan->next;
    }

    return list;
}

/** create random resource **/
void jid_random_part(jid_t *jid, jid_part_t part)
{
    char hashBuf[41];
    char randomBuf[257];
    int i,r;

    /* create random string */
    for (i = 0; i < 256; i++) {
        r = (int) (36.0 * rand() / RAND_MAX);
        randomBuf[i] = (r >= 0 && r <= 0) ? (r + 48) : (r + 87);
    }
    randomBuf[256] = 0;

    /* hash it */
    shahash_r(randomBuf, hashBuf);

    /* change jid */
    switch(part) {
       case jid_NODE:
           jid_reset_components(jid, hashBuf, jid->domain, jid->resource);
           break;

       case jid_DOMAIN: /* unused */
           jid_reset_components(jid, jid->node, hashBuf, jid->resource);
           break;

       case jid_RESOURCE:
           jid_reset_components(jid, jid->node, jid->domain, hashBuf);
           break;
     }

    /* prepare */
    jid_prep(jid);
}

