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

/* PLAIN mechanism */

#include "scod.h"

static int _plain_client_start(scod_mech_t mech, scod_t sd, char **resp, int *resplen) {
    int pos = 0;

    log_debug(ZONE, "PLAIN client start");

    *resplen = (sd->authzid != NULL ? strlen(sd->authzid) : 0) + strlen(sd->authnid) + strlen(sd->pass) + 2;
    *resp = (char *) malloc(sizeof(char) * *resplen);

    if(sd->authzid != NULL) {
        snprintf(*resp, *resplen, "%s", sd->authzid);
        pos = strlen(sd->authzid) + 1;
    }
    snprintf(&(*resp)[pos], *resplen - pos, "%s", sd->authnid);
    pos += strlen(sd->authnid) + 1;
    snprintf(&(*resp)[pos], *resplen - pos + 1, "%s", sd->pass);

    return sd_SUCCESS;
}

static int _plain_server_start(scod_mech_t mech, scod_t sd, const char *resp, int resplen, char **chal, int *challen) {
    char *c, authzid[3072], *authnid, *pass;
    struct _scod_cb_creds_st creds;

    log_debug(ZONE, "PLAIN server start");

    c = j_strnchr(resp, '\0', resplen);
    if(c == NULL) {
        log_debug(ZONE, "first null not found, this is bogus");
        return sd_auth_MALFORMED_DATA;
    }
    c++;
    authnid = c;
    
    strncpy(authzid, resp, sizeof(authzid));

    c = j_strnchr(c, '\0', resplen - (strlen(authzid) + 1));
    if(c == NULL) {
        log_debug(ZONE, "second null not found, this is bogus");
        return sd_auth_MALFORMED_DATA;
    }
    c++;

    pass = (char *) malloc(sizeof(char) * (resplen - ((int) (c - resp)) + 1));
    strncpy(pass, c, (resplen - ((int) (c - resp))));
    pass[resplen - ((int) (c - resp))] = '\0';

    log_debug(ZONE, "got authzid=%s, authnid=%s, pass=%s", authzid, authnid, pass);

    /* check pass */
    creds.authnid = authnid;
    creds.pass = pass;
    creds.realm = sd->realm;
    if((mech->ctx->cb)(sd, sd_cb_CHECK_PASS, &creds, NULL, mech->ctx->cbarg) != 0) {
        log_debug(ZONE, "password doesn't match, auth failed");
        free(pass);
        return sd_auth_AUTH_FAILED;
    }

    /* check authzid */
    creds.authnid = authnid;
    creds.pass = NULL;
    creds.authzid = authzid;
    creds.realm = sd->realm;
    if((mech->ctx->cb)(sd, sd_cb_CHECK_AUTHZID, &creds, NULL, mech->ctx->cbarg) != 0) {
        log_debug(ZONE, "authzid is invalid (app policy said so)");
        free(pass);
        return sd_auth_AUTHZID_POLICY;
    }

    sd->authzid = strdup(authzid);
    sd->authnid = strdup(authnid);
    sd->pass = pass;

    return sd_SUCCESS;
}

int scod_mech_plain_init(scod_mech_t mech) {
    log_debug(ZONE, "initialising PLAIN mechanism");

    mech->name = "PLAIN";

    mech->flags = sd_flag_CHECK_PASS;

    mech->client_start = _plain_client_start;
    mech->server_start = _plain_server_start;

    return 0;
}
