/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
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

/** @file c2s/bind.c
  * @brief xmpp resource binding
  * @author Robert Norris
  * $Date: 2005/06/02 04:48:24 $
  * $Revision: 1.9 $
  */

#include "c2s.h"

/** sx features callback */
static void _bind_features(sx_t s, sx_plugin_t p, nad_t nad) {
    int ns;

    if(s->auth_id == NULL) {
        log_debug(ZONE, "not auth'd, not offering resource bind");

        return;
    }

    log_debug(ZONE, "offering resource bind and session");

    ns = nad_add_namespace(nad, uri_BIND, NULL);
    nad_append_elem(nad, ns, "bind", 1);

    ns = nad_add_namespace(nad, uri_XSESSION, NULL);
    nad_append_elem(nad, ns, "session", 1);
}

/** plugin initialiser */
int bind_init(sx_env_t env, sx_plugin_t p, va_list args) {
    log_debug(ZONE, "initialising resource bind sx plugin");

    p->features = _bind_features;

    return 0;
}
