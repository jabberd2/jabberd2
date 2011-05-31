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

#include "sx.h"

/** primary expat callbacks */
void _sx_element_start(void *arg, const char *name, const char **atts) {
    sx_t s = (sx_t) arg;
    char buf[1024];
    char *uri, *elem, *prefix;
    const char **attr;
    int ns;
    int el;

    if(s->fail) return;

    /* starting a new nad */
    if(s->nad == NULL)
        s->nad = nad_new();

    /* make a copy */
    strncpy(buf, name, 1024);
    buf[1023] = '\0';

    /* expat gives us:
         prefixed namespaced elem: uri|elem|prefix
          default namespaced elem: uri|elem
               un-namespaced elem: elem
     */

    /* extract all the bits */
    uri = buf;
    elem = strchr(uri, '|');
    if(elem != NULL) {
        *elem = '\0';
        elem++;
        prefix = strchr(elem, '|');
        if(prefix != NULL) {
            *prefix = '\0';
            prefix++;
        }
        ns = nad_add_namespace(s->nad, uri, prefix);
    } else {
        /* un-namespaced, just take it as-is */
        uri = NULL;
        elem = buf;
        prefix = NULL;
        ns = -1;
    }

    /* add it */
    el = nad_append_elem(s->nad, ns, elem, s->depth - 1);

    /* now the attributes, one at a time */
    attr = atts;
    while(attr[0] != NULL) {

        /* make a copy */
        strncpy(buf, attr[0], 1024);
        buf[1023] = '\0';

        /* extract all the bits */
        uri = buf;
        elem = strchr(uri, '|');
        if(elem != NULL) {
            *elem = '\0';
            elem++;
            prefix = strchr(elem, '|');
            if(prefix != NULL) {
                *prefix = '\0';
                prefix++;
            }
            ns = nad_append_namespace(s->nad, el, uri, prefix);
        } else {
            /* un-namespaced, just take it as-is */
            uri = NULL;
            elem = buf;
            prefix = NULL;
            ns = -1;
        }

        /* add it */
        nad_append_attr(s->nad, ns, elem, (char *) attr[1]);

        attr += 2;
    }

    s->depth++;
}

void _sx_element_end(void *arg, const char *name) {
    sx_t s = (sx_t) arg;

    if(s->fail) return;

    s->depth--;

    if(s->depth == 1) {
        /* completed nad, save it for later processing */
        jqueue_push(s->rnadq, s->nad, 0);
        s->nad = NULL;

        /* and reset read bytes counter */
        s->rbytes = 0;
    }

    /* close received */
    else if(s->depth == 0)
        s->depth = -1;
}

void _sx_cdata(void *arg, const char *str, int len) {
    sx_t s = (sx_t) arg;

    if(s->fail) return;

    /* no nad? no cdata */
    if(s->nad == NULL)
        return;

    /* go */
    nad_append_cdata(s->nad, (char *) str, len, s->depth - 1);
}

void _sx_namespace_start(void *arg, const char *prefix, const char *uri) {
    sx_t s = (sx_t) arg;
    int ns;

    if(s->fail) return;

    /* some versions of MSXML send xmlns='' occassionaally. it seems safe to ignore it */
    if(uri == NULL) return;

    /* starting a new nad */
    if(s->nad == NULL)
        s->nad = nad_new();

    ns = nad_add_namespace(s->nad, (char *) uri, (char *) prefix);

    /* Always set the namespace (to catch cases where nad_add_namespace doesn't add it) */
    s->nad->scope = ns;
}

#ifdef HAVE_XML_STOPPARSER
/* Stop the parser if an entity declaration is hit. */
void _sx_entity_declaration(void *arg, const char *entityName,
                            int is_parameter_entity, const char *value,
                            int value_length, const char *base,
                            const char *systemId, const char *publicId,
                            const char *notationName)
{
    sx_t s = (sx_t) arg;

    XML_StopParser(s->expat, XML_FALSE);
}
#endif

