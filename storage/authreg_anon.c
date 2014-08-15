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

/* this is a simple anonymous plugin. It uses the check_password method to
 * force authentication to succeed regardless of what credentials the client
 * provides
 */

#include "c2s.h"

static int _ar_anon_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    /* always exists */
    return 1;
}

static int _ar_anon_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    /* always correct */
    return 0;
}

/** start me up */
DLLEXPORT int ar_init(authreg_t ar)
{
    ar->user_exists = _ar_anon_user_exists;
    ar->check_password = _ar_anon_check_password;

    return 0;
}
