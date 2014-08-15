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
#include <stringprep.h>
#ifdef _WIN32
  #include <windows.h>
  #define LIBRARY_DIR "."
#else
  #include <dlfcn.h>
#endif

/* authreg module manager */

typedef struct _authreg_error_st {
    char        *class;
    char        *name;
    char        *code;
    char        *uri;
} *authreg_error_t;

/** get a handle for the named module */
authreg_t authreg_init(c2s_t c2s, const char *name) {
    char mod_fullpath[PATH_MAX];
    const char *modules_path;
    ar_module_init_fn init_fn = NULL;
    authreg_t ar;
    void *handle;

    /* load authreg module */
    modules_path = config_get_one(c2s->config, "authreg.path", 0);
    if (modules_path != NULL)
        log_write(c2s->log, LOG_NOTICE, "modules search path: %s", modules_path);
    else
        log_write(c2s->log, LOG_NOTICE, "modules search path undefined, using default: "LIBRARY_DIR);

    log_write(c2s->log, LOG_INFO, "loading '%s' authreg module", name);
#ifndef _WIN32
    if (modules_path != NULL)
        snprintf(mod_fullpath, PATH_MAX, "%s/authreg_%s.so", modules_path, name);
    else
        snprintf(mod_fullpath, PATH_MAX, "%s/authreg_%s.so", LIBRARY_DIR, name);
    handle = dlopen(mod_fullpath, RTLD_LAZY);
    if (handle != NULL)
        init_fn = dlsym(handle, "ar_init");
#else
    if (modules_path != NULL)
        snprintf(mod_fullpath, PATH_MAX, "%s\\authreg_%s.dll", modules_path, name);
    else
        snprintf(mod_fullpath, PATH_MAX, "authreg_%s.dll", name);
    handle = (void*) LoadLibrary(mod_fullpath);
    if (handle != NULL)
        init_fn = (ar_module_init_fn)GetProcAddress((HMODULE) handle, "ar_init");
#endif

    if (handle != NULL && init_fn != NULL) {
        log_debug(ZONE, "preloaded module '%s' (not initialized yet)", name);
    } else {
#ifndef _WIN32
        log_write(c2s->log, LOG_ERR, "failed loading authreg module '%s' (%s)", name, dlerror());
        if (handle != NULL)
            dlclose(handle);
#else
        log_write(c2s->log, LOG_ERR, "failed loading authreg module '%s' (errcode: %x)", name, GetLastError());
        if (handle != NULL)
            FreeLibrary((HMODULE) handle);
#endif
        return NULL;
    }

    /* make a new one */
    ar = (authreg_t) calloc(1, sizeof(struct authreg_st));

    ar->c2s = c2s;

    /* call the initialiser */
    if((init_fn)(ar) != 0)
    {
        log_write(c2s->log, LOG_ERR, "failed to initialize auth module '%s'", name);
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
    log_write(c2s->log, LOG_NOTICE, "initialized auth module '%s'", name);

    return ar;
}

/** shutdown the authreg system */
void authreg_free(authreg_t ar) {
    if (ar) {
        if(ar->free != NULL) (ar->free)(ar);
        free(ar);
    }
}

/** auth logger */
inline static void _authreg_auth_log(c2s_t c2s, sess_t sess, const char *method, const char *username, const char *resource, int success) {
    log_write(c2s->log, LOG_NOTICE, "[%d] %s authentication %s: %s@%s/%s %s:%d%s%s",
        sess->s->tag, method, success ? "succeeded" : "failed",
        username, sess->host->realm, resource,
        sess->s->ip, sess->s->port,
        sess->s->ssf ? " TLS" : "", sess->s->compressed ? " ZLIB" : ""
    );
}

/** auth get handler */
static void _authreg_auth_get(c2s_t c2s, sess_t sess, nad_t nad) {
    int ns, elem, attr, err;
    char username[1024], id[128];
    int ar_mechs;

    /* can't auth if they're active */
    if(sess->active) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    /* sort out the username */
    ns = nad_find_scoped_namespace(nad, uri_AUTH, NULL);
    elem = nad_find_elem(nad, 1, ns, "username", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "auth get with no username, bouncing it");

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));

        return;
    }

    snprintf(username, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
    if(stringprep_xmpp_nodeprep(username, 1024) != 0) {
        log_debug(ZONE, "auth get username failed nodeprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }

    ar_mechs = c2s->ar_mechanisms;
    if (sess->s->ssf>0) 
        ar_mechs = ar_mechs | c2s->ar_ssl_mechanisms;
        
    /* no point going on if we have no mechanisms */
    if(!(ar_mechs & (AR_MECH_TRAD_PLAIN | AR_MECH_TRAD_DIGEST | AR_MECH_TRAD_CRAMMD5))) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_FORBIDDEN), 0));
        return;
    }
    
    /* do we have the user? */
    if((c2s->ar->user_exists)(c2s->ar, sess, username, sess->host->realm) == 0) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));
        return;
    }

    /* extract the id */
    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr >= 0)
        snprintf(id, 128, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

    nad_free(nad);

    /* build a result packet */
    nad = nad_new();

    ns = nad_add_namespace(nad, uri_CLIENT, NULL);

    nad_append_elem(nad, ns, "iq", 0);
    nad_append_attr(nad, -1, "type", "result");

    if(attr >= 0)
        nad_append_attr(nad, -1, "id", id);

    ns = nad_add_namespace(nad, uri_AUTH, NULL);
    nad_append_elem(nad, ns, "query", 1);
    
    nad_append_elem(nad, ns, "username", 2);
    nad_append_cdata(nad, username, strlen(username), 3);

    nad_append_elem(nad, ns, "resource", 2);

    /* fill out the packet with available auth mechanisms */
    if(ar_mechs & AR_MECH_TRAD_PLAIN && (c2s->ar->get_password != NULL || c2s->ar->check_password != NULL))
        nad_append_elem(nad, ns, "password", 2);

    if(ar_mechs & AR_MECH_TRAD_DIGEST && c2s->ar->get_password != NULL)
        nad_append_elem(nad, ns, "digest", 2);

    if (ar_mechs & AR_MECH_TRAD_CRAMMD5 && c2s->ar->create_challenge != NULL) {
        err = (c2s->ar->create_challenge)(c2s->ar, sess, (char *) username, sess->host->realm,
                (char *) sess->auth_challenge, sizeof(sess->auth_challenge));
        if (0 == err) { /* operation failed */
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_INTERNAL_SERVER_ERROR), 0));
            return;
        }
        else if (1 == err) { /* operation succeeded */
            nad_append_elem(nad, ns, "crammd5", 2);
            nad_append_attr(nad, -1, "challenge", sess->auth_challenge);
        }
        else ; /* auth method unsupported for user */
    }

    /* give it back to the client */
    sx_nad_write(sess->s, nad);

    return;
}

/** auth set handler */
static void _authreg_auth_set(c2s_t c2s, sess_t sess, nad_t nad) {
    int ns, elem, attr, authd = 0;
    char username[1024], resource[1024], str[1024], hash[280];
    int ar_mechs;

    /* can't auth if they're active */
    if(sess->active) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    ns = nad_find_scoped_namespace(nad, uri_AUTH, NULL);

    /* sort out the username */
    elem = nad_find_elem(nad, 1, ns, "username", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "auth set with no username, bouncing it");

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));

        return;
    }

    snprintf(username, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
    if(stringprep_xmpp_nodeprep(username, 1024) != 0) {
        log_debug(ZONE, "auth set username failed nodeprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }

    /* make sure we have the resource */
    elem = nad_find_elem(nad, 1, ns, "resource", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "auth set with no resource, bouncing it");

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));

        return;
    }

    snprintf(resource, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
    if(stringprep_xmpp_resourceprep(resource, 1024) != 0) {
        log_debug(ZONE, "auth set resource failed resourceprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }

    ar_mechs = c2s->ar_mechanisms;
    if (sess->s->ssf > 0)
        ar_mechs = ar_mechs | c2s->ar_ssl_mechanisms;
    
    /* no point going on if we have no mechanisms */
    if(!(ar_mechs & (AR_MECH_TRAD_PLAIN | AR_MECH_TRAD_DIGEST | AR_MECH_TRAD_CRAMMD5))) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_FORBIDDEN), 0));
        return;
    }
    
    /* do we have the user? */
    if((c2s->ar->user_exists)(c2s->ar, sess, username, sess->host->realm) == 0) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));
        return;
    }
    
    /* handle CRAM-MD5 response */
    if(!authd && ar_mechs & AR_MECH_TRAD_CRAMMD5 && c2s->ar->check_response != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "crammd5", 1);
        if(elem >= 0)
        {
            snprintf(str, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
            if((c2s->ar->check_response)(c2s->ar, sess, username, sess->host->realm, sess->auth_challenge, str) == 0)
            {
                log_debug(ZONE, "crammd5 auth (check) succeded");
                authd = 1;
                _authreg_auth_log(c2s, sess, "traditional.cram-md5", username, resource, TRUE);
            } else {
                _authreg_auth_log(c2s, sess, "traditional.cram-md5", username, resource, FALSE);
            }
        }
    }

    /* digest auth */
    if(!authd && ar_mechs & AR_MECH_TRAD_DIGEST && c2s->ar->get_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "digest", 1);
        if(elem >= 0)
        {
            if((c2s->ar->get_password)(c2s->ar, sess, username, sess->host->realm, str) == 0)
            {
                snprintf(hash, 280, "%s%s", sess->s->id, str);
                shahash_r(hash, hash);

                if(strlen(hash) == NAD_CDATA_L(nad, elem) && strncmp(hash, NAD_CDATA(nad, elem), NAD_CDATA_L(nad, elem)) == 0)
                {
                    log_debug(ZONE, "digest auth succeeded");
                    authd = 1;
                    _authreg_auth_log(c2s, sess, "traditional.digest", username, resource, TRUE);
                } else {
                    _authreg_auth_log(c2s, sess, "traditional.digest", username, resource, FALSE);
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
            if((c2s->ar->get_password)(c2s->ar, sess, username, sess->host->realm, str) == 0 &&
                    strlen(str) == NAD_CDATA_L(nad, elem) && strncmp(str, NAD_CDATA(nad, elem), NAD_CDATA_L(nad, elem)) == 0)
            {
                log_debug(ZONE, "plaintext auth (compare) succeeded");
                authd = 1;
                _authreg_auth_log(c2s, sess, "traditional.plain(compare)", username, resource, TRUE);
            } else {
                _authreg_auth_log(c2s, sess, "traditional.plain(compare)", username, resource, FALSE);
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
            if((c2s->ar->check_password)(c2s->ar, sess, username, sess->host->realm, str) == 0)
            {
                log_debug(ZONE, "plaintext auth (check) succeded");
                authd = 1;
                _authreg_auth_log(c2s, sess, "traditional.plain", username, resource, TRUE);
            } else {
                _authreg_auth_log(c2s, sess, "traditional.plain", username, resource, FALSE);
            }
        }
    }

    /* now, are they authenticated? */
    if(authd)
    {
        /* create new bound jid holder */
        if(sess->resources == NULL) {
            sess->resources = (bres_t) calloc(1, sizeof(struct bres_st));
        }

        /* our local id */
        sprintf(sess->resources->c2s_id, "%d", sess->s->tag);

        /* the full user jid for this session */
        sess->resources->jid = jid_new(sess->s->req_to, -1);
        jid_reset_components(sess->resources->jid, username, sess->resources->jid->domain, resource);

        log_write(sess->c2s->log, LOG_NOTICE, "[%d] requesting session: jid=%s", sess->s->tag, jid_full(sess->resources->jid));

        /* build a result packet, we'll send this back to the client after we have a session for them */
        sess->result = nad_new();

        ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

        nad_append_elem(sess->result, ns, "iq", 0);
        nad_set_attr(sess->result, 0, -1, "type", "result", 6);

        attr = nad_find_attr(nad, 0, -1, "id", NULL);
        if(attr >= 0)
            nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

        /* start a session with the sm */
        sm_start(sess, sess->resources);

        /* finished with the nad */
        nad_free(nad);

        return;
    }

    _authreg_auth_log(c2s, sess, "traditional", username, resource, FALSE);

    /* auth failed, so error */
    sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));

    return;
}

/** register get handler */
static void _authreg_register_get(c2s_t c2s, sess_t sess, nad_t nad) {
    int attr, ns;
    char id[128];

    /* registrations can happen if reg is enabled and we can create users and set passwords */
    if(sess->active || !(c2s->ar->set_password != NULL && c2s->ar->create_user != NULL &&
        (sess->host->ar_register_enable || sess->host->ar_register_oob))) {

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    /* extract the id */
    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr >= 0)
        snprintf(id, 128, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

    nad_free(nad);

    /* build a result packet */
    nad = nad_new();

    ns = nad_add_namespace(nad, uri_CLIENT, NULL);

    nad_append_elem(nad, ns, "iq", 0);
    nad_append_attr(nad, -1, "type", "result");

    if(attr >= 0)
        nad_append_attr(nad, -1, "id", id);

    ns = nad_add_namespace(nad, uri_REGISTER, NULL);
    nad_append_elem(nad, ns, "query", 1);
    
    nad_append_elem(nad, ns, "instructions", 2);
    nad_append_cdata(nad, sess->host->ar_register_instructions, strlen(sess->host->ar_register_instructions), 3);

    if(sess->host->ar_register_enable) {
        nad_append_elem(nad, ns, "username", 2);
        nad_append_elem(nad, ns, "password", 2);
    }

    if(sess->host->ar_register_oob) {
        int ns = nad_add_namespace(nad, uri_OOB, NULL);
        nad_append_elem(nad, ns, "x", 2);
        nad_append_elem(nad, ns, "url", 3);
        nad_append_cdata(nad, sess->host->ar_register_oob, strlen(sess->host->ar_register_oob), 4);
    }

    /* give it back to the client */
    sx_nad_write(sess->s, nad);
}

/** register set handler */
static void _authreg_register_set(c2s_t c2s, sess_t sess, nad_t nad)
{
    int ns = 0, elem, attr;
    char username[1024], password[1024];

    /* if we're not configured for registration (or pw changes), or we can't set passwords, fail outright */
    if(!(sess->host->ar_register_enable || sess->host->ar_register_password) || c2s->ar->set_password == NULL) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    ns = nad_find_scoped_namespace(nad, uri_REGISTER, NULL);

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
        if((c2s->ar->delete_user)(c2s->ar, sess, sess->resources->jid->node, sess->host->realm) != 0) {
            log_debug(ZONE, "user delete failed");
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_INTERNAL_SERVER_ERROR), 0));
            return;
        }

        log_write(c2s->log, LOG_NOTICE, "[%d] deleted user: user=%s; realm=%s", sess->s->tag, sess->resources->jid->node, sess->host->realm);

        log_write(c2s->log, LOG_NOTICE, "[%d] registration remove succeeded, requesting user deletion: jid=%s", sess->s->tag, jid_user(sess->resources->jid));

        /* make a result nad */
        sess->result = nad_new();

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
        sm_delete(sess, sess->resources);

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
    if(stringprep_xmpp_nodeprep(username, 1024) != 0) {
        log_debug(ZONE, "register set username failed nodeprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }

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
        if(strcmp(username, sess->resources->jid->node) != 0)
        {
            log_debug(ZONE, "%s is trying to change password for %s, bouncing it", jid_full(sess->resources->jid), username);
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
    else if((c2s->ar->user_exists)(c2s->ar, sess, username, sess->host->realm))
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
    else if((c2s->ar->create_user)(c2s->ar, sess, username, sess->host->realm) != 0)
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
    if((c2s->ar->set_password)(c2s->ar, sess, username, sess->host->realm, password) != 0)
    {
        log_debug(ZONE, "password store failed");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_INTERNAL_SERVER_ERROR), 0));
        return;
    }

    log_debug(ZONE, "updated auth creds for %s", username);

    /* make a result nad */
    sess->result = nad_new();

    ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

    nad_append_elem(sess->result, ns, "iq", 0);
    nad_set_attr(sess->result, 0, -1, "type", "result", 6);

    /* extract the id */
    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr >= 0)
        nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

    /* if they're active, then this was just a password change, and we're done */
    if(sess->active) {
        log_write(c2s->log, LOG_NOTICE, "[%d] password changed: jid=%s", sess->s->tag, jid_user(sess->resources->jid));
        sx_nad_write(sess->s, sess->result);
        sess->result = NULL;
        return;
    }

    /* create new bound jid holder */
    if(sess->resources == NULL) {
        sess->resources = (bres_t) calloc(1, sizeof(struct bres_st));
    }

    /* our local id */
    sprintf(sess->resources->c2s_id, "%d", sess->s->tag);

    /* the user jid for this transaction */
    sess->resources->jid = jid_new(sess->s->req_to, -1);
    jid_reset_components(sess->resources->jid, username, sess->resources->jid->domain, sess->resources->jid->resource);

    log_write(c2s->log, LOG_NOTICE, "[%d] registration succeeded, requesting user creation: jid=%s", sess->s->tag, jid_user(sess->resources->jid));

    /* get the sm to create them */
    sm_create(sess, sess->resources);

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
    if((ns = nad_find_scoped_namespace(nad, uri_AUTH, NULL)) >= 0 && (query = nad_find_elem(nad, 0, ns, "query", 1)) >= 0)
        authreg = 0;
    else if((ns = nad_find_scoped_namespace(nad, uri_REGISTER, NULL)) >= 0 && (query = nad_find_elem(nad, 0, ns, "query", 1)) >= 0)
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
