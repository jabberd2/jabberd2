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

#include "c2s.h"

/** generate a new session request id */
static void _sm_generate_id(sess_t sess, const char *type) {
    char str[3094];   /* JID=3071 chars max + time = 12 chars max + type = 10 chars max + terminator = 3094 */

    snprintf(str, 3094, "%s%d%s", type, (int) time(NULL), jid_full(sess->jid));
    str[3093] = '\0';

    shahash_r(str, sess->sm_request);
}

/** make a new action route */
static nad_t _sm_build_route(sess_t sess, const char *action, const char *target, char *id) {
    nad_t nad;
    int ns, ans;

    nad = nad_new(sess->c2s->router->nad_cache);

    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
    nad_append_elem(nad, ns, "route", 0);
    
    nad_append_attr(nad, -1, "to", sess->jid->domain);
    nad_append_attr(nad, -1, "from", sess->c2s->id);

    ans = nad_add_namespace(nad, uri_SESSION, "sc");
    nad_append_elem(nad, ans, "session", 1);

    if(sess->c2s_id[0] != '\0')
        nad_append_attr(nad, ans, "c2s", sess->c2s_id);
    if(sess->sm_id[0] != '\0')
        nad_append_attr(nad, ans, "sm", sess->sm_id);

    nad_append_attr(nad, -1, "action", action);

    if(target != NULL)
        nad_append_attr(nad, -1, "target", target);
    if(id != NULL)
        nad_append_attr(nad, -1, "id", id);

    log_debug(ZONE, "built new route nad for %s action %s target %s id %s", jid_full(sess->jid), action, target, id);

    return nad;
}

void sm_start(sess_t sess) {
    _sm_generate_id(sess, "start");

    sx_nad_write(sess->c2s->router, _sm_build_route(sess, "start", jid_full(sess->jid), sess->sm_request));
}

void sm_end(sess_t sess) {
    sx_nad_write(sess->c2s->router, _sm_build_route(sess, "end", NULL, NULL));
}

void sm_create(sess_t sess) {
    _sm_generate_id(sess, "create");

    sx_nad_write(sess->c2s->router, _sm_build_route(sess, "create", jid_user(sess->jid), sess->sm_request));
}

void sm_delete(sess_t sess) {
    sx_nad_write(sess->c2s->router, _sm_build_route(sess, "delete", jid_user(sess->jid), NULL));
}

void sm_packet(sess_t sess, nad_t nad) {
    int ns;

    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
    nad_wrap_elem(nad, 0, ns, "route");

    nad_set_attr(nad, 0, -1, "to", sess->jid->domain, 0);
    nad_set_attr(nad, 0, -1, "from", sess->c2s->id, 0);

    ns = nad_append_namespace(nad, 1, uri_SESSION, "sc");

    nad_set_attr(nad, 1, ns, "c2s", sess->c2s_id, 0);
    if(sess->c2s_id[0] != '\0')
        nad_set_attr(nad, 1, ns, "sm", sess->sm_id, 0);

    sx_nad_write(sess->c2s->router, nad);
}
