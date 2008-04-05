/*
 * scod - a minimal sasl implementation for jabberd2
 * Copyright (c) 2003 Robert Norris
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

/* ANONYMOUS mechanism */

#include "scod.h"

static int _anonymous_client_start(scod_mech_t mech, scod_t sd, char **resp, int *resplen) {
    log_debug(ZONE, "ANONYMOUS client start");

    return sd_SUCCESS;
}

static int _anonymous_server_start(scod_mech_t mech, scod_t sd, const char *resp, int resplen, char **chal, int *challen) {
    char authzid[3072];

    log_debug(ZONE, "ANONYMOUS server start");

    if((mech->ctx->cb)(sd, sd_cb_ANONYMOUS_GEN_AUTHZID, NULL, (void **) authzid, mech->ctx->cbarg) != 0) {
        log_debug(ZONE, "app failed to generate authzid, auth failed");
        return sd_auth_AUTH_FAILED;
    }

    sd->authzid = strdup(authzid);

    return sd_SUCCESS;
}

int scod_mech_anonymous_init(scod_mech_t mech) {
    log_debug(ZONE, "initialising ANONYMOUS mechanism");

    mech->name = "ANONYMOUS";

    mech->client_start = _anonymous_client_start;
    mech->server_start = _anonymous_server_start;

    return 0;
}
