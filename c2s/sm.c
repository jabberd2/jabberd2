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
static void _sm_generate_id(sess_t sess, bres_t res, const char *type) {
    char str[3094];   /* JID=3071 chars max + time = 12 chars max + type = 10 chars max + terminator = 3094 */

    snprintf(str, 3094, "%s%d%s", type, (int) time(NULL), jid_full(res->jid));
    str[3093] = '\0';

    shahash_r(str, res->sm_request);
}

/** make a new action route */
static nad_t _sm_build_route(sess_t sess, bres_t res, const char *action, const char *target, const char *id) {
    nad_t nad;
    int ns, ans;

    nad = nad_new();

    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
    nad_append_elem(nad, ns, "route", 0);

    nad_append_attr(nad, -1, "to", sess->smcomp?sess->smcomp:((char *) res->jid->domain));
    nad_append_attr(nad, -1, "from", sess->c2s->id);

    ans = nad_add_namespace(nad, uri_SESSION, "sc");
    nad_append_elem(nad, ans, "session", 1);

    if(res->c2s_id[0] != '\0')
        nad_append_attr(nad, ans, "c2s", res->c2s_id);
    if(res->sm_id[0] != '\0')
        nad_append_attr(nad, ans, "sm", res->sm_id);

    nad_append_attr(nad, -1, "action", action);

    if(target != NULL)
        nad_append_attr(nad, -1, "target", target);
    if(id != NULL)
        nad_append_attr(nad, -1, "id", id);

    log_debug(ZONE, "built new route nad for %s action %s target %s id %s", jid_full(res->jid), action, target, id);

    return nad;
}

void sm_start(sess_t sess, bres_t res) {
    _sm_generate_id(sess, res, "start");

    sx_nad_write(sess->c2s->router, _sm_build_route(sess, res, "start", jid_full(res->jid), res->sm_request));
}

void sm_end(sess_t sess, bres_t res) {
    sx_nad_write(sess->c2s->router, _sm_build_route(sess, res, "end", NULL, NULL));
}

void sm_create(sess_t sess, bres_t res) {
    _sm_generate_id(sess, res, "create");

    sx_nad_write(sess->c2s->router, _sm_build_route(sess, res, "create", jid_user(res->jid), res->sm_request));
}

void sm_delete(sess_t sess, bres_t res) {
    sx_nad_write(sess->c2s->router, _sm_build_route(sess, res, "delete", jid_user(res->jid), NULL));
}

void sm_packet(sess_t sess, bres_t res, nad_t nad) {
    int ns;

    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
    nad_wrap_elem(nad, 0, ns, "route");

    nad_set_attr(nad, 0, -1, "to", sess->smcomp?sess->smcomp:((char *) res->jid->domain), 0);
    nad_set_attr(nad, 0, -1, "from", sess->c2s->id, 0);

    ns = nad_append_namespace(nad, 1, uri_SESSION, "sc");

    nad_set_attr(nad, 1, ns, "c2s", res->c2s_id, 0);
    if(res->c2s_id[0] != '\0')
        nad_set_attr(nad, 1, ns, "sm", res->sm_id, 0);

    sx_nad_write(sess->c2s->router, nad);
}
