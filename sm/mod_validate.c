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

#include "sm.h"

/** @file sm/mod_validate.c
  * @brief packet validator
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.15 $
  */

static mod_ret_t _validate_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt)
{
    /* only want message, presence and iq */
    if(!(pkt->type & pkt_MESSAGE || pkt->type & pkt_PRESENCE || pkt->type & pkt_IQ || pkt->type & pkt_S10N)) {
        log_debug(ZONE, "we only take message, presence and iq packets");
        return -stanza_err_BAD_REQUEST;
    }

    return mod_PASS;
}

static mod_ret_t _validate_in_router(mod_instance_t mi, pkt_t pkt)
{
    return _validate_in_sess(mi, NULL, pkt);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->in_sess = _validate_in_sess;
    mod->in_router = _validate_in_router;

    return 0;
}
