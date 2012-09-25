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

#include "sm.h"

/** @file sm/mod_session.c
  * @brief session control
  * @author Robert Norris
  * $Date: 2006/03/09 09:08:14 $
  * $Revision: 1.12 $
  */

/** session packet handling
 *
 * - if packet has session namespace on first element, its from a c2s
 *
 *   - if its pkt_SESSION, then its some session action
 *     - if its pkt_SESSION_START, start a session, reply, done
 *     - get the sm id, find the corresponding session
 *     - do the action, reply, done
 *
 *   - otherwise, its a normal message/presence/iq for a session
 *     - get the sm id, find the corresponding session
 *     - hand to in_sess chain
 *
 */

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  sess_t *sess_val;
};

static mod_ret_t _session_in_router(mod_instance_t mi, pkt_t pkt) {
    sm_t sm = mi->mod->mm->sm;
    int ns, iq, elem, attr;
    jid_t jid;
    sess_t sess = (sess_t) NULL;
    mod_ret_t ret;

    /* if we've got this namespace, its from a c2s */
    if(pkt->nad->ecur <= 1 || (ns = nad_find_namespace(pkt->nad, 1, uri_SESSION, NULL)) < 0)
        return mod_PASS;

    /* don't bother if its a failure */
    if(pkt->type & pkt_SESS_FAILED) {
        /* !!! check failed=1, handle */
        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* session commands */
    if(pkt->type & pkt_SESS) {

        ns = nad_find_namespace(pkt->nad, 1, uri_SESSION, NULL);

        /* only end can get away without a target */
        attr = nad_find_attr(pkt->nad, 1, -1, "target", NULL);
        if(attr < 0 && pkt->type != pkt_SESS_END) {
            nad_set_attr(pkt->nad, 1, ns, "failed", "1", 1);
            sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

            pkt->nad = NULL;
            pkt_free(pkt);

            return mod_HANDLED;
        }

        /* session start */
        if(pkt->type == pkt_SESS) {
            jid = jid_new(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));

            if(jid != NULL)
                sess = sess_start(sm, jid);

            if(jid == NULL || sess == NULL) {
                nad_set_attr(pkt->nad, 1, ns, "failed", "1", 1);
                sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

                pkt->nad = NULL;
                pkt_free(pkt);
                if(jid != NULL)
                    jid_free(jid);

                return mod_HANDLED;
            }

            /* c2s component that is handling this session */
            strcpy(sess->c2s, pkt->rfrom->domain);

            /* remember what c2s calls us */
            attr = nad_find_attr(pkt->nad, 1, ns, "c2s", NULL);
            snprintf(sess->c2s_id, sizeof(sess->c2s_id), "%.*s", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));

            /* mark PBX session as fake */
            if(!strncmp("PBX", sess->c2s_id, 3)) {
                sess->fake = 1;
            }

            /* add our id */
            nad_set_attr(pkt->nad, 1, ns, "sm", sess->sm_id, 0);

            /* mark that it started OK */
            nad_set_attr(pkt->nad, 1, -1, "action", "started", 7);

			/* set this SM name */
			nad_set_attr(pkt->nad, 0, -1, "to", sm->id, 0);

			/* inform c2s */
            sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

            pkt->nad = NULL;
            pkt_free(pkt);
            jid_free(jid);

            return mod_HANDLED;
        }

        /* user create */
        if(pkt->type == pkt_SESS_CREATE) {
            jid = jid_new(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));

            if(jid == NULL || user_create(sm, jid) != 0) {
                nad_set_attr(pkt->nad, 1, ns, "failed", "1", 1);
                sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

                pkt->nad = NULL;
                pkt_free(pkt);
                if(jid != NULL)
                    jid_free(jid);

                return mod_HANDLED;
            }

            /* inform c2s */
            nad_set_attr(pkt->nad, 1, -1, "action", "created", 7);
            sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

            pkt->nad = NULL;
            pkt_free(pkt);
            jid_free(jid);

            return mod_HANDLED;
        }

        /* user delete */
        if(pkt->type == pkt_SESS_DELETE) {
            jid = jid_new(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
            if(jid == NULL) {
                pkt_free(pkt);
                return mod_HANDLED;
            }

            user_delete(sm, jid);

            /* inform c2s */
            nad_set_attr(pkt->nad, 1, -1, "action", "deleted", 7);
            sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

            pkt->nad = NULL;
            pkt_free(pkt);
            jid_free(jid);

            return mod_HANDLED;
        }

        /* get the session id */
        attr = nad_find_attr(pkt->nad, 1, ns, "sm", NULL);
        if(attr < 0) {
            log_debug(ZONE, "no session id, bouncing");
            nad_set_attr(pkt->nad, 1, ns, "failed", "1", 1);
            sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

            pkt->nad = NULL;
            pkt_free(pkt);

            return mod_HANDLED;
        }

        /* find the corresponding session */
        sess = xhash_getx(sm->sessions, NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));

        /* active check */
        if(sess == NULL) {
            log_debug(ZONE, "session %.*s doesn't exist, bouncing", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));
            nad_set_attr(pkt->nad, 1, ns, "failed", "1", 1);
            sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

            pkt->nad = NULL;
            pkt_free(pkt);

            return mod_HANDLED;
        }

        /* make sure its from them */
        attr = nad_find_attr(pkt->nad, 1, ns, "c2s", NULL);
        if(attr >= 0 && (strlen(sess->c2s_id) != NAD_AVAL_L(pkt->nad, attr) || strncmp(sess->c2s_id, NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr)) != 0)) {
            log_debug(ZONE, "invalid sender on route from %s for session %s (should be %s)", pkt->rfrom->domain, sess->sm_id, sess->c2s_id);
            pkt_free(pkt);
            return mod_HANDLED;
        }

        /* session end */
        if(pkt->type == pkt_SESS_END) {
            sm_c2s_action(sess, "ended", NULL);
            sess_end(sess);

            pkt_free(pkt);
            return mod_HANDLED;
        }

        log_debug(ZONE, "unknown session packet, dropping");
        pkt_free(pkt);

        return mod_HANDLED;
    }

    /* otherwise, its a normal packet for the session */

/* #ifdef ENABLE_SUPERSEDED       // FIXME XXX TODO clients are not yet ready for this */
        /* check for RFC3920 session request *
         * with RFC3920bis it is unneeded *
         * session is activated by bind, so we just return back result */
        if((ns = nad_find_scoped_namespace(pkt->nad, uri_XSESSION, NULL)) >= 0 &&
           (iq = nad_find_elem(pkt->nad, 0, -1, "iq", 1)) >= 0 &&
           (elem = nad_find_elem(pkt->nad, iq, ns, "session", 1)) >= 0) {
            log_debug(ZONE, "session create request");
    
            /* build a result packet */
            nad_drop_elem(pkt->nad, elem);
            nad_set_attr(pkt->nad, iq, -1, "type", "result", 6);
    
            /* return the result */
            sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));
    
            pkt->nad = NULL;
            pkt_free(pkt);
    
            return mod_HANDLED;
        }
/* #endif */
    /* get the session id */
    attr = nad_find_attr(pkt->nad, 1, ns, "sm", NULL);
    if(attr < 0) {
        log_debug(ZONE, "no session id, bouncing");
        nad_set_attr(pkt->nad, 1, ns, "failed", "1", 1);
        sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

        pkt->nad = NULL;
        pkt_free(pkt);

        return mod_HANDLED;
    }

    /* find the corresponding session */
    sess = xhash_getx(sm->sessions, NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));

    /* active check */
    if(sess == NULL) {
        log_debug(ZONE, "session %.*s doesn't exist, bouncing", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));
        nad_set_attr(pkt->nad, 1, ns, "failed", "1", 1);
        sx_nad_write(sm->router, stanza_tofrom(pkt->nad, 0));

        pkt->nad = NULL;
        pkt_free(pkt);

        return mod_HANDLED;
    }

    /* make sure its from them */
    attr = nad_find_attr(pkt->nad, 1, ns, "c2s", NULL);
    if(attr >= 0 && (strlen(sess->c2s_id) != NAD_AVAL_L(pkt->nad, attr) || strncmp(sess->c2s_id, NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr)) != 0)) {
        log_debug(ZONE, "invalid sender on route from %s for session %s (should be %s)", jid_full(pkt->rfrom), sess->sm_id, sess->c2s_id);
        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* where it came from */
    pkt->source = sess;

    /* hand it to the modules */
    ret = mm_in_sess(pkt->sm->mm, sess, pkt);
    switch(ret) {
        case mod_HANDLED:
            break;

        case mod_PASS:
            /* ignore IQ result packets that haven't been handled - XMPP 9.2.3.4 */
            if(pkt->type == pkt_IQ_RESULT)
               break;
            else
               ret = -stanza_err_FEATURE_NOT_IMPLEMENTED;

        default:
            pkt_sess(pkt_error(pkt, -ret), sess);

            break;
    }

    return mod_HANDLED;
}

static mod_ret_t _session_pkt_router(mod_instance_t mi, pkt_t pkt) {
    sess_t sess;
    union xhashv xhv;

    /* we want unadvertisments */
    if(pkt->from == NULL || !(pkt->rtype & route_ADV) || pkt->rtype != route_ADV_UN)
        return mod_PASS;

    log_debug(ZONE, "component '%s' went offline, checking for sessions held there", jid_full(pkt->from));

    /* this is fairly inefficient, especially if we have a lot of sessions
     * online, but it shouldn't be called that often (components are usually
     * long-running) */

    xhv.sess_val = &sess;
    if(xhash_iter_first(mi->mod->mm->sm->sessions))
        do {
            xhash_iter_get(mi->mod->mm->sm->sessions, NULL, NULL, xhv.val);
            if(sess && strcmp(sess->c2s, pkt->from->domain) == 0)
                sess_end(sess);
        } while (xhash_iter_next(mi->mod->mm->sm->sessions));

    return mod_PASS;
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    if(mi->mod->init) return 0;

    mi->mod->in_router = _session_in_router;
    mi->mod->pkt_router = _session_pkt_router;

    return 0;
}
