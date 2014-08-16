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

/* this plugin uses PAM for authentication */

#include "c2s.h"
#include <security/pam_appl.h>

static int _ar_pam_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm) {
    /* we can't check if a user exists, so we just assume we have them all the time */
    return 1;
}

static int _ar_pam_conversation(int nmsg, const struct pam_message **msg, struct pam_response **res, void *arg) {
    int i;
    struct pam_response *reply;

    if(nmsg <= 0)
        return PAM_CONV_ERR;

    reply = (struct pam_response *) calloc(1, sizeof(struct pam_response) * nmsg);

    for(i = 0; i < nmsg; i++) {
        if(msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            reply[i].resp = strdup((char *) arg);
            reply[i].resp_retcode = 0;
        }
    }

    *res = reply;

    return PAM_SUCCESS;
}

#ifdef PAM_FAIL_DELAY
static int _ar_pam_delay(int ret, unsigned int usec, void *arg) {
    /* !!! hack the current byterate limit to throttle the connection */
    return PAM_SUCCESS;
}
#endif

static int _ar_pam_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257]) {
    struct pam_conv conv;
    pam_handle_t *pam;
    int ret, user_len, realm_len;
    char *user_realm = 0;

    conv.conv = _ar_pam_conversation;
    conv.appdata_ptr = password;

    if (realm) {
	realm_len = strlen(realm);
	if (realm_len > 0) {
	    user_len = strlen(username);
	    user_realm = malloc(user_len + realm_len + 2);
	    strcpy(user_realm, username);
	    *(user_realm + user_len) = '@';
	    strcpy(user_realm + user_len + 1, realm);
	}
    }
    if (user_realm) {
	ret = pam_start("jabberd", user_realm, &conv, &pam);
    } else {
	ret = pam_start("jabberd", username, &conv, &pam);
    }
    if (user_realm) free(user_realm);
    if(ret != PAM_SUCCESS) {
        log_write(ar->c2s->log, LOG_ERR, "pam: couldn't initialise PAM: %s", pam_strerror(NULL, ret));
        return 1;
    }

#ifdef PAM_FAIL_DELAY
    ret = pam_set_item(pam, PAM_FAIL_DELAY, _ar_pam_delay);
    if(ret != PAM_SUCCESS) {
        log_write(ar->c2s->log, LOG_ERR, "pam: couldn't disable fail delay: %s", pam_strerror(NULL, ret));
        return 1;
    }
#endif

    ret = pam_authenticate(pam, 0);
    if(ret == PAM_AUTHINFO_UNAVAIL || ret == PAM_USER_UNKNOWN) {
        pam_end(pam, ret);
        return 1;
    }

    if(ret != PAM_SUCCESS) {
        log_write(ar->c2s->log, LOG_ERR, "pam: couldn't authenticate: %s", pam_strerror(NULL, ret));
        pam_end(pam, ret);
        return 1;
    }

    ret = pam_acct_mgmt(pam, 0);
    if(ret != PAM_SUCCESS) {
        log_write(ar->c2s->log, LOG_ERR, "pam: authentication succeeded, but can't use account: %s", pam_strerror(NULL, ret));
        pam_end(pam, ret);
        return 1;
    }

    pam_end(pam, ret);

    return 0;
}

/** start me up */
int ar_init(authreg_t ar) {
    ar->user_exists = _ar_pam_user_exists;
    ar->check_password = _ar_pam_check_password;

    return 0;
}
