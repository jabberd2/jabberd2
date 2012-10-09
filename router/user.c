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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#include "router.h"

/** user table manager */

int user_table_load(router_t r) {
    const char *userfile;
    FILE *f;
    long size;
    char *buf;
    nad_t nad;
    int nusers, user, name, secret;

    log_debug(ZONE, "loading user table");
    
    if(r->users != NULL)
        xhash_free(r->users);

    r->users = xhash_new(51);

    userfile = config_get_one(r->config, "local.users", 0);
    if(userfile == NULL)
        userfile = CONFIG_DIR "/router-users.xml";

    f = fopen(userfile, "rb");
    if(f == NULL) {
        log_write(r->log, LOG_ERR, "couldn't open user table file %s: %s", userfile, strerror(errno));
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = (char *) malloc(sizeof(char) * size);

    if (fread(buf, 1, size, f) != size || ferror(f)) {
        log_write(r->log, LOG_ERR, "couldn't read from user table file: %s", strerror(errno));
        free(buf);
        fclose(f);
        return 1;
    }

    fclose(f);

    nad = nad_parse(buf, size);
    if(nad == NULL) {
        log_write(r->log, LOG_ERR, "couldn't parse user table");
        free(buf);
        return 1;
    }

    free(buf);

    nusers = 0;
    user = nad_find_elem(nad, 0, -1, "user", 1);
    while(user >= 0) {
        name = nad_find_elem(nad, user, -1, "name", 1);
        secret = nad_find_elem(nad, user, -1, "secret", 1);

        if(name < 0 || secret < 0 || NAD_CDATA_L(nad, name) <= 0 || NAD_CDATA_L(nad, secret) <= 0) {
            log_write(r->log, LOG_ERR, "malformed user entry in user table file, skipping");
            continue;
        }

        log_debug(ZONE, "remembering user '%.*s'", NAD_CDATA_L(nad, name), NAD_CDATA(nad, name));

        xhash_put(r->users, pstrdupx(xhash_pool(r->users), NAD_CDATA(nad, name), NAD_CDATA_L(nad, name)), pstrdupx(xhash_pool(r->users), NAD_CDATA(nad, secret), NAD_CDATA_L(nad, secret)));

        nusers++;
        
        user = nad_find_elem(nad, user, -1, "user", 0);
    }

    nad_free(nad);

    log_write(r->log, LOG_NOTICE, "loaded user table (%d users)", nusers);

    r->users_load = time(NULL);

    return 0;
}

void user_table_unload(router_t r) {

    if(r->users != NULL)
        xhash_free(r->users);
	r->users = NULL;

    return;
} 
