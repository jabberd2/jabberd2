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

#include "c2s.h"

#ifdef HAVE_IDN
#include <stringprep.h>
#endif

/* authreg module manager */

/* if you add a module, you'll need to update these arrays */

#ifdef STORAGE_MYSQL
extern int ar_mysql_init(authreg_t);
#endif
#ifdef STORAGE_PGSQL
extern int ar_pgsql_init(authreg_t);
#endif
#ifdef STORAGE_DB
extern int ar_db_init(authreg_t);
#endif
#ifdef STORAGE_LDAP
extern int ar_ldap_init(authreg_t);
#endif
#ifdef STORAGE_PAM
extern int ar_pam_init(authreg_t);
#endif
#ifdef STORAGE_PIPE
extern int ar_pipe_init(authreg_t);
#endif
#ifdef STORAGE_ANON
extern int ar_anon_init(authreg_t);
#endif
#ifdef STORAGE_SQLITE
extern int ar_sqlite_init(authreg_t);
#endif

static const char *module_names[] = {
#ifdef STORAGE_MYSQL
    "mysql",
#endif
#ifdef STORAGE_PGSQL
    "pgsql",
#endif
#ifdef STORAGE_DB
    "db",
#endif
#ifdef STORAGE_LDAP
    "ldap",
#endif
#ifdef STORAGE_PAM
    "pam",
#endif
#ifdef STORAGE_PIPE
    "pipe",
#endif
#ifdef STORAGE_ANON
    "anon",
#endif
#ifdef STORAGE_SQLITE
    "sqlite",
#endif
    NULL
};

ar_module_init_fn module_inits[] = {
#ifdef STORAGE_MYSQL
    ar_mysql_init,
#endif
#ifdef STORAGE_PGSQL
    ar_pgsql_init,
#endif
#ifdef STORAGE_DB
    ar_db_init,
#endif
#ifdef STORAGE_LDAP
    ar_ldap_init,
#endif
#ifdef STORAGE_PAM
    ar_pam_init,
#endif
#ifdef STORAGE_PIPE
    ar_pipe_init,
#endif
#ifdef STORAGE_ANON
    ar_anon_init,
#endif
#ifdef STORAGE_SQLITE
    ar_sqlite_init,
#endif
    NULL
};

typedef struct _authreg_error_st {
    char        *class;
    char        *name;
    char        *code;
    char        *uri;
} *authreg_error_t;

/** get a handle for the named module */
authreg_t authreg_init(c2s_t c2s, char *name) {
    int n;
    ar_module_init_fn init = NULL;
    authreg_t ar;

    /* hunt it down */
    n = 0;
    while(module_names[n] != NULL)
    {
        if(strcmp(module_names[n], name) == 0)
        {
            init = module_inits[n];
            break;
        }
        n++;
    }

    if(init == NULL)
    {
        log_write(c2s->log, LOG_ERR, "no such auth module '%s'", name);
        return NULL;
    }

    /* make a new one */
    ar = (authreg_t) malloc(sizeof(struct authreg_st));
    memset(ar, 0, sizeof(struct authreg_st));

    ar->c2s = c2s;

    /* call the initialiser */
    if((init)(ar) != 0)
    {
        log_write(c2s->log, LOG_ERR, "failed to initialise auth module '%s'", name);
        authreg_free(ar);
        return NULL;
    }

    /* we need user_exists(), at the very least */
    if(ar->user_exists == NULL)
    {
        log_write(c2s->log, LOG_ERR, "auth module '%s' has no check for user existence", name);
        authreg_free(ar);
        return NULL;
    }
    
    /* its good */
    log_write(c2s->log, LOG_NOTICE, "initialised auth module '%s'", name);

    return ar;
}

/** shutdown the authreg system */
void authreg_free(authreg_t ar) {
    if(ar->free != NULL) (ar->free)(ar);
    free(ar);
}

/** auth get handler */
static void _authreg_auth_get(c2s_t c2s, sess_t sess, nad_t nad) {
    int ns, elem, ssequence, attr;
    char username[1024], shash[41], stoken[11], seqs[10], id[128];
    int ar_mechs;

    /* can't auth if they're active */
    if(sess->active) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    /* sort out the username */
    ns = nad_find_scoped_namespace(nad, "jabber:iq:auth", NULL);
    elem = nad_find_elem(nad, 1, ns, "username", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "auth get with no username, bouncing it");

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));

        return;
    }

    snprintf(username, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
#ifdef HAVE_IDN
    if(stringprep_xmpp_nodeprep(username, 1024) != 0) {
        log_debug(ZONE, "auth get username failed nodeprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }
#endif

    ar_mechs = c2s->ar_mechanisms;
    if (sess->s->ssf>0) 
        ar_mechs = ar_mechs | c2s->ar_ssl_mechanisms;
        
    /* no point going on if we have no mechanisms */
    if(!(ar_mechs & (AR_MECH_TRAD_PLAIN | AR_MECH_TRAD_DIGEST | AR_MECH_TRAD_ZEROK))) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_FORBIDDEN), 0));
        return;
    }
    
    /* do we have the user? */
    if((c2s->ar->user_exists)(c2s->ar, username, sess->host->realm) == 0) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));
        return;
    }

    /* extract the id */
    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr >= 0)
        snprintf(id, 128, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

    nad_free(nad);

    /* build a result packet */
    nad = nad_new(sess->s->nad_cache);

    ns = nad_add_namespace(nad, uri_CLIENT, NULL);

    nad_append_elem(nad, ns, "iq", 0);
    nad_append_attr(nad, -1, "type", "result");

    if(attr >= 0)
        nad_append_attr(nad, -1, "id", id);

    ns = nad_add_namespace(nad, "jabber:iq:auth", NULL);
    nad_append_elem(nad, ns, "query", 1);
    
    nad_append_elem(nad, ns, "username", 2);
    nad_append_cdata(nad, username, strlen(username), 3);

    nad_append_elem(nad, ns, "resource", 2);

    /* fill out the packet with available auth mechanisms */
    if(ar_mechs & AR_MECH_TRAD_PLAIN && (c2s->ar->get_password != NULL || c2s->ar->check_password != NULL))
        nad_append_elem(nad, ns, "password", 2);

    if(ar_mechs & AR_MECH_TRAD_DIGEST && c2s->ar->get_password != NULL)
        nad_append_elem(nad, ns, "digest", 2);

    /* don't offer zerok if the sequence is zero */
    if(ar_mechs & AR_MECH_TRAD_ZEROK && c2s->ar->get_zerok != NULL && c2s->ar->set_zerok != NULL && (c2s->ar->get_zerok)(c2s->ar, username, sess->host->realm, shash, stoken, &ssequence) == 0 && ssequence > 0)
    {
        snprintf(seqs, 10, "%d", ssequence - 1);
        nad_append_elem(nad, ns, "sequence", 2);
        nad_append_cdata(nad, seqs, strlen(seqs), 3);

        nad_append_elem(nad, ns, "token", 2);
        nad_append_cdata(nad, stoken, strlen(stoken), 3);
    }

    /* give it back to the client */
    sx_nad_write(sess->s, nad);

    return;
}

/** auth set handler */
static void _authreg_auth_set(c2s_t c2s, sess_t sess, nad_t nad) {
    int ns, elem, attr, authd = 0, ssequence;
    char username[1024], resource[1024], str[1024], shash[41], stoken[11], hash[280];
    int ar_mechs;

    /* can't auth if they're active */
    if(sess->active) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    ns = nad_find_scoped_namespace(nad, "jabber:iq:auth", NULL);

    /* sort out the username */
    elem = nad_find_elem(nad, 1, ns, "username", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "auth set with no username, bouncing it");

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));

        return;
    }

    snprintf(username, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
#ifdef HAVE_IDN
    if(stringprep_xmpp_nodeprep(username, 1024) != 0) {
        log_debug(ZONE, "auth set username failed nodeprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }
#endif

    /* make sure we have the resource */
    elem = nad_find_elem(nad, 1, ns, "resource", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "auth set with no resource, bouncing it");

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));

        return;
    }

    snprintf(resource, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
#ifdef HAVE_IDN
    if(stringprep_xmpp_resourceprep(resource, 1024) != 0) {
        log_debug(ZONE, "auth set resource failed resourceprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }
#endif

    ar_mechs = c2s->ar_mechanisms;
    if (sess->s->ssf > 0)
        ar_mechs = ar_mechs | c2s->ar_ssl_mechanisms;
    
    /* no point going on if we have no mechanisms */
    if(!(ar_mechs & (AR_MECH_TRAD_PLAIN | AR_MECH_TRAD_DIGEST | AR_MECH_TRAD_ZEROK))) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_FORBIDDEN), 0));
        return;
    }
    
    /* do we have the user? */
    if((c2s->ar->user_exists)(c2s->ar, username, sess->host->realm) == 0) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));
        return;
    }
    
    /* zerok auth */
    if(!authd && ar_mechs & AR_MECH_TRAD_ZEROK && c2s->ar->get_zerok != NULL && c2s->ar->set_zerok != NULL && (c2s->ar->get_zerok)(c2s->ar, username, sess->host->realm, shash, stoken, &ssequence) == 0)
    {
        elem = nad_find_elem(nad, 1, ns, "hash", 1);
        if(elem >= 0)
        {
            snprintf(hash, 41, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
            shahash_r(hash, hash);

            if(strcmp(hash, shash) == 0)
            {
                /* update the auth creds */
                ssequence--;

                /* don't auth them if we can't update their auth creds */
                snprintf(str, 41, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
                if((c2s->ar->set_zerok)(c2s->ar, username, sess->host->realm, str, stoken, ssequence) == 0)
                {
                    authd = 1;
                    log_debug(ZONE, "zerok auth succeeded");
                }
                else
                    log_debug(ZONE, "couldn't update auth creds, not allowing zerok auth");
            }
        }
    }

    /* digest auth */
    if(!authd && ar_mechs & AR_MECH_TRAD_DIGEST && c2s->ar->get_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "digest", 1);
        if(elem >= 0)
        {
            if((c2s->ar->get_password)(c2s->ar, username, sess->host->realm, str) == 0)
            {
                snprintf(hash, 280, "%s%s", sess->s->id, str);
                shahash_r(hash, hash);

                if(strlen(hash) == NAD_CDATA_L(nad, elem) && strncmp(hash, NAD_CDATA(nad, elem), NAD_CDATA_L(nad, elem)) == 0)
                {
                    log_debug(ZONE, "digest auth succeeded");
                    authd = 1;
                }
            }
        }
    }

    /* plaintext auth (compare) */
    if(!authd && ar_mechs & AR_MECH_TRAD_PLAIN && c2s->ar->get_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "password", 1);
        if(elem >= 0)
        {
            if((c2s->ar->get_password)(c2s->ar, username, sess->host->realm, str) == 0 && strlen(str) == NAD_CDATA_L(nad, elem) && strncmp(str, NAD_CDATA(nad, elem), NAD_CDATA_L(nad, elem)) == 0)
            {
                log_debug(ZONE, "plaintext auth (compare) succeeded");
                authd = 1;
            }
        }
    }

    /* plaintext auth (check) */
    if(!authd && ar_mechs & AR_MECH_TRAD_PLAIN && c2s->ar->check_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "password", 1);
        if(elem >= 0)
        {
            snprintf(str, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
            if((c2s->ar->check_password)(c2s->ar, username, sess->host->realm, str) == 0)
            {
                log_debug(ZONE, "plaintext auth (check) succeded");
                authd = 1;
            }
        }
    }

    /* now, are they authenticated? */
    if(authd)
    {
        log_write(c2s->log, LOG_NOTICE, "[%d] auth succeeded: username=%s, resource=%s", sess->s->tag, username, resource);

        /* our local id */
        sprintf(sess->c2s_id, "%d", sess->s->tag);

        /* the full user jid for this session */
        sess->jid = jid_new(c2s->pc, sess->s->req_to, -1);
        jid_reset_components(sess->jid, username, sess->jid->domain, resource);

        log_write(sess->c2s->log, LOG_NOTICE, "[%d] requesting session: jid=%s", sess->s->tag, jid_full(sess->jid));

        /* build a result packet, we'll send this back to the client after we have a session for them */
        sess->result = nad_new(sess->s->nad_cache);

        ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

        nad_append_elem(sess->result, ns, "iq", 0);
        nad_set_attr(sess->result, 0, -1, "type", "result", 6);

        attr = nad_find_attr(nad, 0, -1, "id", NULL);
        if(attr >= 0)
            nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

        /* start a session with the sm */
        sm_start(sess);

        /* finished with the nad */
        nad_free(nad);

        return;
    }

    log_write(c2s->log, LOG_NOTICE, "[%d] auth failed: username=%s, resource=%s", sess->s->tag, username, resource);

    /* auth failed, so error */
    sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));

    return;
}

/** register get handler */
static void _authreg_register_get(c2s_t c2s, sess_t sess, nad_t nad) {
    int attr, ns;
    char id[128];

    /* registrations can happen if reg is enabled and we can create users and set passwords */
    if(sess->active || !(c2s->ar->set_password != NULL && c2s->ar->create_user != NULL && sess->host->ar_register_enable)) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    /* extract the id */
    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr >= 0)
        snprintf(id, 128, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

    nad_free(nad);

    /* build a result packet */
    nad = nad_new(sess->s->nad_cache);

    ns = nad_add_namespace(nad, uri_CLIENT, NULL);

    nad_append_elem(nad, ns, "iq", 0);
    nad_append_attr(nad, -1, "type", "result");

    if(attr >= 0)
        nad_append_attr(nad, -1, "id", id);

    ns = nad_add_namespace(nad, "jabber:iq:register", NULL);
    nad_append_elem(nad, ns, "query", 1);
    
    nad_append_elem(nad, ns, "username", 2);
    nad_append_elem(nad, ns, "password", 2);

    nad_append_elem(nad, ns, "instructions", 2);
    nad_append_cdata(nad, sess->host->ar_register_instructions, strlen(sess->host->ar_register_instructions), 3);

    /* give it back to the client */
    sx_nad_write(sess->s, nad);
}

/** register set handler */
static void _authreg_register_set(c2s_t c2s, sess_t sess, nad_t nad)
{
    int ns = 0, elem, attr, sequence = 500, i;
    char username[1024], password[1024], hash[41], token[11], str[51];

    /* if we're not configured for registration (or pw changes), or we can't set passwords, fail outright */
    if(!(sess->host->ar_register_enable || sess->host->ar_register_password) || c2s->ar->set_password == NULL) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    ns = nad_find_scoped_namespace(nad, "jabber:iq:register", NULL);

    /* removals */
    if(sess->active && nad_find_elem(nad, 1, ns, "remove", 1) >= 0) {
        /* only if full reg is enabled */
        if(!sess->host->ar_register_enable) {
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
            return;
        }

        log_debug(ZONE, "user remove requested");

        /* make sure we can delete them */
        if(c2s->ar->delete_user == NULL) {
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
            return;
        }

        /* otherwise, delete them */
        if((c2s->ar->delete_user)(c2s->ar, sess->jid->node, sess->host->realm) != 0) {
            log_debug(ZONE, "user delete failed");
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_INTERNAL_SERVER_ERROR), 0));
            return;
        }

        log_write(c2s->log, LOG_NOTICE, "[%d] deleted user: user=%s; realm=%s", sess->s->tag, sess->jid->node, sess->host->realm);

        log_write(c2s->log, LOG_NOTICE, "[%d] registration remove succeeded, requesting user deletion: jid=%s", sess->s->tag, jid_user(sess->jid));

        /* make a result nad */
        sess->result = nad_new(sess->s->nad_cache);

        ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

        nad_append_elem(sess->result, ns, "iq", 0);
        nad_set_attr(sess->result, 0, -1, "type", "result", 6);

        /* extract the id */
        attr = nad_find_attr(nad, 0, -1, "id", NULL);
        if(attr >= 0)
            nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

        nad_free(nad);

        sx_nad_write(sess->s, sess->result);
        sess->result = NULL;

        /* get the sm to delete them (it will force their sessions to end) */
        sm_delete(sess);

        return;
    }

    /* username is required */
    elem = nad_find_elem(nad, 1, ns, "username", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "register set with no username, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));
        return;
    }

    snprintf(username, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
#ifdef HAVE_IDN
    if(stringprep_xmpp_nodeprep(username, 1024) != 0) {
        log_debug(ZONE, "register set username failed nodeprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }
#endif

    elem = nad_find_elem(nad, 1, ns, "password", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "register set with no password, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));
        return;
    }

    /* if they're already auth'd, its a password change */
    if(sess->active)
    {
        /* confirm that the username matches their auth id */
        if(strcmp(username, sess->jid->node) != 0)
        {
            log_debug(ZONE, "%s is trying to change password for %s, bouncing it", jid_full(sess->jid), username);
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));
            return;
        }
    }

    /* can't go on if we're not doing full reg */
    else if(!sess->host->ar_register_enable) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    /* if they exist, bounce */
    else if((c2s->ar->user_exists)(c2s->ar, username, sess->host->realm))
    {
        log_debug(ZONE, "attempt to register %s, but they already exist", username);
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_CONFLICT), 0));
        return;
    }

    /* make sure we can create them */
    else if(c2s->ar->create_user == NULL)
    {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    /* otherwise, create them */
    else if((c2s->ar->create_user)(c2s->ar, username, sess->host->realm) != 0)
    {
        log_debug(ZONE, "user create failed");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_INTERNAL_SERVER_ERROR), 0));
        return;
    }

    else
        log_write(c2s->log, LOG_NOTICE, "[%d] created user: user=%s; realm=%s", sess->s->tag, username, sess->host->realm);

    /* extract the password */
    snprintf(password, 257, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));

    /* change it */
    if((c2s->ar->set_password)(c2s->ar, username, sess->host->realm, password) != 0)
    {
        log_debug(ZONE, "password store failed");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_INTERNAL_SERVER_ERROR), 0));
        return;
    }

    /* store zerok data if we can */
    if(((c2s->ar_mechanisms & AR_MECH_TRAD_ZEROK) ||
        (c2s->ar_ssl_mechanisms & AR_MECH_TRAD_ZEROK)) && 
       c2s->ar->set_zerok != NULL)
    {
        snprintf(token, 11, "%X", (unsigned int) time(NULL));

        shahash_r(password, hash);
        snprintf(str, 51, "%s%s", hash, token);
        shahash_r(str, hash);

        for(i = 0; i < sequence; i++)
            shahash_r(hash, hash);

        hash[40] = '\0';
    
        if((c2s->ar->set_zerok)(c2s->ar, username, sess->host->realm, hash, token, sequence) != 0)
        {
            log_debug(ZONE, "zerok store failed");
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_INTERNAL_SERVER_ERROR), 0));
            return;
        }
    }

    log_debug(ZONE, "updated auth creds for %s", username);

    /* make a result nad */
    sess->result = nad_new(sess->s->nad_cache);

    ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

    nad_append_elem(sess->result, ns, "iq", 0);
    nad_set_attr(sess->result, 0, -1, "type", "result", 6);

    /* extract the id */
    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr >= 0)
        nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

    /* if they're active, then this was just a password change, and we're done */
    if(sess->active) {
        log_write(c2s->log, LOG_NOTICE, "[%d] password changed: jid=%s", sess->s->tag, jid_user(sess->jid));
        sx_nad_write(sess->s, sess->result);
        sess->result = NULL;
        return;
    }

    /* our local id */
    sprintf(sess->c2s_id, "%d", sess->s->tag);

    /* the user jid for this transaction */
    sess->jid = jid_new(c2s->pc, sess->s->req_to, -1);
    jid_reset_components(sess->jid, username, sess->jid->domain, sess->jid->resource);

    log_write(c2s->log, LOG_NOTICE, "[%d] registration succeeded, requesting user creation: jid=%s", sess->s->tag, jid_user(sess->jid));

    /* get the sm to create them */
    sm_create(sess);

    nad_free(nad);

    return;
}

/**
 * processor for iq:auth and iq:register packets
 * return 0 if handled, 1 if not handled
 */
int authreg_process(c2s_t c2s, sess_t sess, nad_t nad) {
    int ns, query, type, authreg = -1, getset = -1;

    /* need iq */
    if(NAD_ENAME_L(nad, 0) != 2 || strncmp("iq", NAD_ENAME(nad, 0), 2) != 0)
        return 1;

    /* only want auth or register packets */
    if((ns = nad_find_scoped_namespace(nad, "jabber:iq:auth", NULL)) >= 0 && (query = nad_find_elem(nad, 0, ns, "query", 1)) >= 0)
        authreg = 0;
    else if((ns = nad_find_scoped_namespace(nad, "jabber:iq:register", NULL)) >= 0 && (query = nad_find_elem(nad, 0, ns, "query", 1)) >= 0)
        authreg = 1;
    else
        return 1;

    /* if its to someone else, pass it */
    if(nad_find_attr(nad, 0, -1, "to", NULL) >= 0 && nad_find_attr(nad, 0, -1, "to", sess->s->req_to) < 0)
        return 1;

    /* need a type */
    if((type = nad_find_attr(nad, 0, -1, "type", NULL)) < 0 || NAD_AVAL_L(nad, type) != 3)
    {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));
        return 0;
    }

    /* get or set? */
    if(strncmp("get", NAD_AVAL(nad, type), NAD_AVAL_L(nad, type)) == 0)
        getset = 0;
    else if(strncmp("set", NAD_AVAL(nad, type), NAD_AVAL_L(nad, type)) == 0)
        getset = 1;
    else
    {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));
        return 0;
    }

    /* hand to the correct handler */
    if(authreg == 0) {
        /* can't do iq:auth after sasl auth */
        if(sess->sasl_authd) {
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
            return 0;
        }

        if(getset == 0) {
            log_debug(ZONE, "auth get");
            _authreg_auth_get(c2s, sess, nad);
        } else if(getset == 1) {
            log_debug(ZONE, "auth set");
            _authreg_auth_set(c2s, sess, nad);
        }
    }

    if(authreg == 1) {
        if(getset == 0) {
            log_debug(ZONE, "register get");
            _authreg_register_get(c2s, sess, nad);
        } else if(getset == 1) {
            log_debug(ZONE, "register set");
            _authreg_register_set(c2s, sess, nad);
        }
    }

    /* handled */
    return 0;
}
