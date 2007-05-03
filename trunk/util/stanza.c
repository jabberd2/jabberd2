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

#include "util.h"

/** error the packet */
nad_t stanza_error(nad_t nad, int elem, int err) {
    int ns;

    assert((int) (nad != NULL));
    assert((int) (elem >= 0));
    assert((int) (err >= stanza_err_BAD_REQUEST && err < stanza_err_LAST));

    err = err - stanza_err_BAD_REQUEST;

    nad_set_attr(nad, elem, -1, "type", "error", 5);

    elem = nad_insert_elem(nad, elem, NAD_ENS(nad, elem), "error", NULL);
    if(_stanza_errors[err].code != NULL)
    nad_set_attr(nad, elem, -1, "code", _stanza_errors[err].code, 0);
    if(_stanza_errors[err].type != NULL)
        nad_set_attr(nad, elem, -1, "type", _stanza_errors[err].type, 0);

    if(_stanza_errors[err].name != NULL) {
        ns = nad_add_namespace(nad, uri_STANZA_ERR, NULL);
        nad_insert_elem(nad, elem, ns, _stanza_errors[err].name, NULL);
    }

    return nad;
}

/** flip the to and from attributes on this elem */
nad_t stanza_tofrom(nad_t nad, int elem) {
    int attr;
    char to[3072], from[3072];

    assert((int) (nad != NULL));

    to[0] = '\0';
    from[0] = '\0';

    attr = nad_find_attr(nad, elem, -1, "to", NULL);
    if(attr >= 0)
        snprintf(to, 3072, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
    
    attr = nad_find_attr(nad, elem, -1, "from", NULL);
    if(attr >= 0)
        snprintf(from, 3072, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

    nad_set_attr(nad, elem, -1, "to", from[0] != '\0' ? from : NULL, 0);
    nad_set_attr(nad, elem, -1, "from", to[0] != '\0' ? to : NULL, 0);

    return nad;
}
