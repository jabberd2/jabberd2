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

#define _GNU_SOURCE
#include <string.h>

#include "s2s.h"

/** generate a local/remote route key */
char *s2s_route_key(pool_t p, const char *local, const char *remote) {
    char *key;

    if(local == NULL) local = "";
    if(remote == NULL) remote = "";

    if(p == NULL)
        key = (char *) malloc(strlen(local) + strlen(remote) + 2);
    else
        key = (char *) pmalloc(p, strlen(local) + strlen(remote) + 2);

    sprintf(key, "%s/%s", local, remote);

    return key;
}

/** match route key - used for searching route hash */
int s2s_route_key_match(char *local, const char *remote, const char *rkey, int rkeylen) {
    char *klocal, *kremote;
    int ret;

    klocal = strndup(rkey, rkeylen);
    kremote = strchr(klocal, '/');
    if(kremote != NULL) *kremote++ = '\0';

    ret  = (local == NULL || (klocal != NULL && !strcmp(local, klocal)))
    	&& (remote == NULL || (kremote != NULL && !strcmp(remote, kremote)));

    free(klocal);

    return ret;
}

/** generate a dialback key */
char *s2s_db_key(pool_t p, const char *secret, const char *remote, const char *id) {
    char hash[41], buf[1024];

    _sx_debug(ZONE, "generating dialback key, secret %s, remote %s, id %s", secret, remote, id);

    shahash_r(secret, hash);

    snprintf(buf, 1024, "%s%s", hash, remote);
    shahash_r(buf, hash);

    snprintf(buf, 1024, "%s%s", hash, id);
    shahash_r(buf, hash);

    _sx_debug(ZONE, "dialback key generated: %s", hash);

    if(p == NULL)
        return strdup(hash);
    else
        return pstrdup(p, hash);
}
