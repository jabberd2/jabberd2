/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2009 Reinhard Max
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

#include <sys/types.h>
#include <regex.h>
#include <string.h>

#include "sm.h"

/** @file sm/mod_verify.c
  * @brief verify users using e-mail
  * @author Reinhard Max
  */

typedef struct _verify_st {
    enum {UNVERIFIED = 0, VERIFIED} state;
    char *email;
    char *code;
} verify_t;

static void print_instructions(pkt_t res);


static void send_email(verify_t *v, user_t user, pkt_t res, char *message)
{
    FILE *pipe;
    regex_t preg;
    regmatch_t match[1];
    int result;
    os_t os;
    os_object_t o;

    message = strdup(message);
    result = regcomp(&preg, "[a-z0-9._+-]+@[a-z0-9.-]+", REG_EXTENDED|REG_ICASE);
    result |= regexec(&preg, message, 1, match, 0);
    regfree(&preg);

    if (result != 0 || match[0].rm_so == -1) {
        print_instructions(res);
        goto free;
    }

    v->state = UNVERIFIED;
    if (v->email != NULL)
        free(v->email);
    *(message + match[0].rm_eo) = '\0';
    v->email = strdup(message + match[0].rm_so);
    log_debug(ZONE, "email: >%s<", v->email);

    if (v->code != NULL)
        free(v->code);
    v->code = calloc(1,11);
    if ((pipe = popen("pwgen 10 1", "r")) == NULL) {
        log_write(user->sm->log, LOG_ERR, "Error generating email code for %s using 'pwgen'. %d:%s", v->email, errno, strerror(errno));
        goto error;
    }
    if (fgets(v->code, 11, pipe) == NULL) {
        log_write(user->sm->log, LOG_ERR, "Error getting email code for %s from 'pwgen'. %d:%s", v->email, errno, strerror(errno));
        pclose(pipe);
        goto error;
    }
    if (pclose(pipe) == -1) {
        log_write(user->sm->log, LOG_ERR, "Error closing email code for %s from 'pwgen'. %d:%s", v->email, errno, strerror(errno));
        goto error;
    }
    log_debug(ZONE, "code: >%s<", v->code);
    if ((pipe = popen("sendmail -t -F 'Jabber Server'", "w")) == NULL) {
        log_write(user->sm->log, LOG_ERR, "Error starting sendmail to %s. %d:%s", v->email, errno, strerror(errno));
        goto error;
    }

    os = os_new();
    o = os_object_new(os);
    os_object_put(o, "email", v->email, os_type_STRING);
    os_object_put(o, "code",  v->code, os_type_STRING);
    os_object_put(o, "state", &v->state, os_type_INTEGER);
    if (storage_replace(user->sm->st, "verify", jid_user(user->jid), NULL, os) != st_SUCCESS) {
        log_write(user->sm->log, LOG_ERR, "Error writing email code to DB for %s", v->email);
        free(v->email);
        free(v->code);
        v->email=NULL;
        v->code=NULL;
    }
    os_free(os);

    if (fprintf(pipe,
                "To: %s\n"
                "Subject: Jabberd email verification\n"
                "\n"
                "Please reply the following line to the jabber server to confirm your email address.\n\n"
                "code: %s\n"
                ".\n", v->email, v->code) < 0) {
        log_write(user->sm->log, LOG_ERR, "Error writing sendmail to %s. %d:%s", v->email, errno, strerror(errno));
        pclose(pipe);
        goto error;
    }
    if (pclose(pipe) == -1) {
        log_write(user->sm->log, LOG_ERR, "Error closing sendmail to %s. %d:%s", v->email, errno, strerror(errno));
        goto error;
    }
    nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1),
                    "subject", "Verification email sent");
    nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1), "body",
                    "A verification email has been sent to the specified "
                    "address. Please check your inbox and follow the "
                    "instructions given in the mail.");
    goto free;

error:
    nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1),
                    "subject", "Error");
    nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1), "body",
                    "An error occured while trying to send the verification email to you.\n"
                    "Please try again later. If the problem persists, please contact the\n"
                    "server admin.");
free:
    free(message);
    return;
}

static void check_code(verify_t *v, user_t user, pkt_t res, char *message)
{
    os_t os;
    os_object_t o;

    if (v->code == NULL) {
        print_instructions(res);
        return;
    }
    if (strstr(message, v->code) != NULL) {
        v->state = VERIFIED;
        log_debug(ZONE, "check_code: VERIFIED");

        os = os_new();
        o = os_object_new(os);
        os_object_put(o, "email", v->email, os_type_STRING);
        os_object_put(o, "code",  v->code, os_type_STRING);
        os_object_put(o, "state", &v->state, os_type_INTEGER);
        if (storage_replace(user->sm->st, "verify", jid_user(user->jid), NULL, os) != st_SUCCESS) {
            log_write(user->sm->log, LOG_ERR, "Error writing verification state to DB for %s", v->email);
        }
        os_free(os);
        nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1),
                        "subject", "Code accepted");
        nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1), "body",
                        "Your verification code has been accepted.\n"
                        "You are now a verified user.");
    } else {
        nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1),
                        "subject", "Code rejected");
        nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1), "body",
                        "Your verification code did not match.\n"
                        "Please try to re-submit it, or send another \n"
                        "\"email: \" line to gat a new code sent to you.");
    }
}

static void print_instructions(pkt_t res)
{
    nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1),
                    "subject", "Please enter your email address");
    nad_insert_elem(res->nad, 1, NAD_ENS(res->nad, 1), "body",
                    "You are blocked from this jabber server until "
                    "you have entered and validated your email adddress! "
                    "To do this, please type in \"email: \" followed by "
                    "your email address as a reply to this message, e.g.\n\n"
                    "email: johndoe@example.com\n\n"
                    "A verification code with further instructions will then "
                    "be sent to that email address.");
}

static mod_ret_t _verify_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt)
{
    pkt_t res;
    nad_t nad = pkt->nad;
    int body, message;
    char *cdata= NULL;
    verify_t *v = sess->user->module_data[mi->mod->index];

    log_debug(ZONE, "_verify_in_sess: %d", v->state);

    if(v->state == VERIFIED || !(pkt->type & pkt_MESSAGE))
        return mod_PASS;

    log_debug(ZONE, "blocking message from from %s", jid_full(sess->jid));

    message = nad_find_elem(nad, 0, -1, "message", 1);
    log_debug(ZONE, "message: %d", message);
    if (message >= 0) {
        body = nad_find_elem(nad, message, -1, "body", 1);
        log_debug(ZONE, "body: %d", body);
        if (body >= 0) {
            size_t len = NAD_CDATA_L(nad, body);
            cdata = malloc(len+1);
            strncpy(cdata, NAD_CDATA(nad, body), len);
            cdata[len] = '\0';
            log_debug(ZONE, "---> %s <---", cdata);
            res = pkt_create(mi->mod->mm->sm, "message", NULL, jid_full(sess->jid),
                             mi->mod->mm->sm->id);
            if (strstr(cdata, "email: ") == cdata) {
                send_email(v, sess->user, res, cdata);
            } else if (strstr(cdata, "code: ") == cdata) {
                check_code(v, sess->user, res, cdata);
            } else {
                print_instructions(res);
            }
            pkt_router(res);
            free(cdata);
        }
    }

    pkt_free(pkt);
    return mod_HANDLED;
}

static void _verify_user_free(verify_t *v)
{
    log_debug(ZONE, "_verify_user_free");
    if (v->email != NULL)
        free(v->email);
    if (v->code != NULL)
        free(v->code);
    free(v);
}

static void _verify_user_delete(mod_instance_t mi, jid_t jid)
{
    log_debug(ZONE, "deleting email verification for %s", jid_user(jid));
    storage_delete(mi->sm->st, "verify", jid_user(jid), NULL);
}

static int _verify_user_load(mod_instance_t mi, user_t user)
{
    verify_t *v;
    os_t os;
    os_object_t o;
    int state;

    log_debug(ZONE, "_verify_user_load: >%s<", jid_user(user->jid));
    v = calloc(1, sizeof(struct _verify_st));
    user->module_data[mi->mod->index] = v;
    if (storage_get(user->sm->st, "verify", jid_user(user->jid), NULL, &os) == st_SUCCESS) {
        if (os_iter_first(os)) {
            o = os_iter_object(os);
            if (os_object_get_str(os, o, "email", &v->email) &&
                    os_object_get_str(os, o, "code", &v->code) &&
                    os_object_get_int(os, o, "state", &state)) {
                v->email = strdup(v->email);
                v->code = strdup(v->code);
                v->state = ( state == VERIFIED ) ? VERIFIED : UNVERIFIED;
            } else {
                v->state = UNVERIFIED;
                v->email = NULL;
                v->code = NULL;
            }
        }
        os_free(os);
    }
    log_debug(ZONE, "_verify_user_load: state=%d<", v->state);
    pool_cleanup(user->p, (void (*))(void *) _verify_user_free, v);
    return 0;
}

DLLEXPORT int module_init(mod_instance_t mi, char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    log_debug(ZONE, "mod_verify:init: %p", mi);
    mod->in_sess = _verify_in_sess;
    mod->user_load = _verify_user_load;
    mod->user_delete = _verify_user_delete;

    return 0;
}
