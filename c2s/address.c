/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2007 Tomasz Sterna
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License
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
 * this sx plugin implements My IP Address extension
 * as described in http://delta.affinix.com/specs/xmppstream.html#myip
 */

#include "c2s.h"

/** sx features callback */
static void _address_features(sx_t s, sx_plugin_t p, nad_t nad) {
    int ns;

    /* offer feature only when not authenticated yet */
    if(s->state >= state_OPEN)
        return;

    _sx_debug(ZONE, "adding address feature");

    ns = nad_add_namespace(nad, uri_ADDRESS_FEATURE, NULL);
    nad_append_elem(nad, ns, "address", 1);
    nad_append_cdata(nad, s->ip, strlen(s->ip), 2);
}

/** args: none */
int address_init(sx_env_t env, sx_plugin_t p, va_list args) {
    log_debug(ZONE, "initialising address sx plugin");

    p->features = _address_features;

    return 0;
}
