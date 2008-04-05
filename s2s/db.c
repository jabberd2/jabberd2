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

/*
 * this is a minimal sx plugin that hacks the "jabber:server:dialback"
 * onto outgoing connections and adds "urn:xmpp:features:dialback" feature
 */

#include "s2s.h"

#define S2S_DB_NS_DECL      " xmlns:db='" uri_DIALBACK "'"
#define S2S_DB_NS_DECL_LEN  (uri_DIALBACK_L + 12)

static void _s2s_db_header(sx_t s, sx_plugin_t p, sx_buf_t buf) {

    if(!(s->flags & S2S_DB_HEADER))
        return;

    log_debug(ZONE, "hacking dialback namespace decl onto stream header");

    /* get enough space */
    _sx_buffer_alloc_margin(buf, 0, S2S_DB_NS_DECL_LEN + 2);

    /* overwrite the trailing ">" with a decl followed by a new ">" */
    memcpy(&buf->data[buf->len - 1], S2S_DB_NS_DECL ">", S2S_DB_NS_DECL_LEN+1);
    buf->len += S2S_DB_NS_DECL_LEN;
}

/** sx features callback */
static void _s2s_db_features(sx_t s, sx_plugin_t p, nad_t nad) {
    int ns;

    ns = nad_add_namespace(nad, uri_URN_DIALBACK, NULL);
    nad_append_elem(nad, ns, "dialback", 1);
    nad_append_elem(nad, -1, "required", 2);
}

int s2s_db_init(sx_env_t env, sx_plugin_t p, va_list args) {
    log_debug(ZONE, "initialising dialback sx plugin");

    p->header = _s2s_db_header;
    p->features = _s2s_db_features;

    return 0;
}
