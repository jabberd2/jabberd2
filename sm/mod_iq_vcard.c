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

#include "sm.h"

/** @file sm/mod_iq_vcard.c
  * @brief user profiles (vcard)
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.25 $
  */

#define uri_VCARD    "vcard-temp"
static int ns_VCARD = 0;

#define VCARD_MAX_FIELD_SIZE    (16384)

typedef struct _mod_iq_vcard_st {
    size_t vcard_max_field_size_default;
    size_t vcard_max_field_size_avatar;
} *mod_iq_vcard_t;

/**
 * these are the vcard attributes that gabber supports. they're also
 * all strings, and thus easy to automate. there might be more in
 * regular use, we need to check that out. one day, when we're all
 * using real foaf profiles, we'll have bigger things to worry about :)
 *
 * darco(2005-09-15): Added quite a few more fields, including those
 * necessary for vCard avatar support. 
 */

static const char *_iq_vcard_map[] = {
    "FN",           "fn",
    "N/FAMILY",     "n-family",
    "N/GIVEN",      "n-given",
    "N/MIDDLE",     "n-middle",
    "N/PREFIX",     "n-prefix",
    "N/SUFFIX",     "n-suffix",
    "NICKNAME",     "nickname",
    "PHOTO/TYPE",   "photo-type",
    "PHOTO/BINVAL", "photo-binval",
    "PHOTO/EXTVAL", "photo-extval",
    "BDAY",         "bday",
    "ADR/POBOX",    "adr-pobox",
    "ADR/EXTADD",   "adr-extadd",
    "ADR/STREET",   "adr-street",
    "ADR/LOCALITY", "adr-locality",
    "ADR/REGION",   "adr-region",
    "ADR/PCODE",    "adr-pcode",
    "ADR/CTRY",     "adr-country",
    "TEL/NUMBER",   "tel",
    "EMAIL/USERID", "email",
    "JABBERID",     "jabberid",
    "MAILER",       "mailer",
    "TZ",           "tz",
    "GEO/LAT",      "geo-lat",
    "GEO/LON",      "geo-lon",
    "TITLE",        "title",
    "ROLE",         "role",
    "LOGO/TYPE",    "logo-type",
    "LOGO/BINVAL",  "logo-binval",
    "LOGO/EXTVAL",  "logo-extval",
    "AGENT/EXTVAL", "agent-extval",
    "ORG/ORGNAME",  "org-orgname",
    "ORG/ORGUNIT",  "org-orgunit",
    "NOTE",         "note",
    "REV",          "rev",
    "SORT-STRING",  "sort-string",
    "SOUND/PHONETIC","sound-phonetic",
    "SOUND/BINVAL", "sound-binval",
    "SOUND/EXTVAL", "sound-extval",
    "UID",          "uid",
    "URL",          "url",
    "DESC",         "desc",
    "KEY/TYPE",     "key-type",
    "KEY/CRED",     "key-cred",
    NULL,           NULL
};

static os_t _iq_vcard_to_object(mod_instance_t mi, pkt_t pkt) {
    os_t os;
    os_object_t o;
    int i = 0, elem;
    char ekey[10], *cdata;
    const char *vkey, *dkey, *vskey;
    size_t fieldsize;
    mod_iq_vcard_t iq_vcard = (mod_iq_vcard_t) mi->mod->private;

    log_debug(ZONE, "building object from packet");

    os = os_new();
    o = os_object_new(os);
    
    while(_iq_vcard_map[i] != NULL) {
        vkey = _iq_vcard_map[i];
        dkey = _iq_vcard_map[i + 1];

        i += 2;

        if( !strcmp(vkey, "PHOTO/BINVAL") ) {
            fieldsize = iq_vcard->vcard_max_field_size_avatar;
        } else {
            fieldsize = iq_vcard->vcard_max_field_size_default;
        }

        vskey = strchr(vkey, '/');
        if(vskey == NULL) {
            vskey = vkey;
            elem = 2;
        } else {
            sprintf(ekey, "%.*s", (int) (vskey - vkey), vkey);
            elem = nad_find_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 2), ekey, 1);
            if(elem < 0)
                continue;
            vskey++;
        }

        elem = nad_find_elem(pkt->nad, elem, NAD_ENS(pkt->nad, 2), vskey, 1);
        if(elem < 0 || NAD_CDATA_L(pkt->nad, elem) == 0)
            continue;

        log_debug(ZONE, "extracted vcard key %s val '%.*s' for db key %s", vkey, NAD_CDATA_L(pkt->nad, elem), NAD_CDATA(pkt->nad, elem), dkey);

        cdata = malloc(fieldsize);
        if(cdata) {
            snprintf(cdata, fieldsize, "%.*s", NAD_CDATA_L(pkt->nad, elem), NAD_CDATA(pkt->nad, elem));
            cdata[fieldsize-1] = '\0';
            os_object_put(o, dkey, cdata, os_type_STRING);
            free(cdata);
        }
    }

    return os;
}

static pkt_t _iq_vcard_to_pkt(sm_t sm, os_t os) {
    pkt_t pkt;
    os_object_t o;
    int i = 0, elem;
    char ekey[10], *dval;
    const char *vkey, *dkey, *vskey;
    
    log_debug(ZONE, "building packet from object");

    pkt = pkt_create(sm, "iq", "result", NULL, NULL);
    nad_append_elem(pkt->nad, nad_add_namespace(pkt->nad, uri_VCARD, NULL), "vCard", 2);

    if(!os_iter_first(os))
        return pkt;
    o = os_iter_object(os);

    while(_iq_vcard_map[i] != NULL) {
        vkey = _iq_vcard_map[i];
        dkey = _iq_vcard_map[i + 1];

        i += 2;

        if(!os_object_get_str(os, o, dkey, &dval))
            continue;

        vskey = strchr(vkey, '/');
        if(vskey == NULL) {
            vskey = vkey;
            elem = 2;
        } else {
            sprintf(ekey, "%.*s", (int) (vskey - vkey), vkey);
            elem = nad_find_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 2), ekey, 1);
            if(elem < 0)
                elem = nad_append_elem(pkt->nad, NAD_ENS(pkt->nad, 2), ekey, 3);
            vskey++;
        }

        log_debug(ZONE, "extracted dbkey %s val '%s' for vcard key %s", dkey, dval, vkey);

        if (!strcmp(dkey, "tel")) {
            nad_append_elem(pkt->nad, NAD_ENS(pkt->nad, 2), "VOICE", pkt->nad->elems[elem].depth + 1);
        }
        nad_append_elem(pkt->nad, NAD_ENS(pkt->nad, 2), vskey, pkt->nad->elems[elem].depth + 1);
        nad_append_cdata(pkt->nad, dval, strlen(dval), pkt->nad->elems[elem].depth + 2);
    }

    return pkt;
}

static mod_ret_t _iq_vcard_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    os_t os;
    st_ret_t ret;
    pkt_t result;

    /* only handle vcard sets and gets that aren't to anyone */
    if(pkt->to != NULL || (pkt->type != pkt_IQ && pkt->type != pkt_IQ_SET) || pkt->ns != ns_VCARD)
        return mod_PASS;

    /* get */
    if(pkt->type == pkt_IQ) {
        if (sm_storage_rate_limit(sess->user->sm, jid_user(sess->jid)))
            return -stanza_err_RESOURCE_CONSTRAINT;

        ret = storage_get(sess->user->sm->st, "vcard", jid_user(sess->jid), NULL, &os);
        switch(ret) {
            case st_FAILED:
                return -stanza_err_INTERNAL_SERVER_ERROR;

            case st_NOTIMPL:
                return -stanza_err_FEATURE_NOT_IMPLEMENTED;

            case st_NOTFOUND:
                nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);
                nad_set_attr(pkt->nad, 1, -1, "to", NULL, 0);
                nad_set_attr(pkt->nad, 1, -1, "from", NULL, 0);

                pkt_sess(pkt, sess);

                return mod_HANDLED;

            case st_SUCCESS:
                result = _iq_vcard_to_pkt(sess->user->sm, os);
                os_free(os);

                nad_set_attr(result->nad, 1, -1, "type", "result", 6);
                pkt_id(pkt, result);

                pkt_sess(result, sess);

                pkt_free(pkt);

                return mod_HANDLED;
        }

        /* we never get here */
        pkt_free(pkt);
        return mod_HANDLED;
    }

    os = _iq_vcard_to_object(mi, pkt);
    
    if (sm_storage_rate_limit(sess->user->sm, jid_user(sess->jid)))
        return -stanza_err_RESOURCE_CONSTRAINT;

    ret = storage_replace(sess->user->sm->st, "vcard", jid_user(sess->jid), NULL, os);
    os_free(os);

    switch(ret) {
        case st_FAILED:
            return -stanza_err_INTERNAL_SERVER_ERROR;

        case st_NOTIMPL:
            return -stanza_err_FEATURE_NOT_IMPLEMENTED;

        default:
            result = pkt_create(sess->user->sm, "iq", "result", NULL, NULL);

            pkt_id(pkt, result);

            pkt_sess(result, sess);
            
            pkt_free(pkt);

            return mod_HANDLED;
    }

    /* we never get here */
    pkt_free(pkt);
    return mod_HANDLED;
}

/* for the special JID of your jabber server bare domain.
 * You can have one for every virtual host
 * you can populate it using your DBMS frontend
 */
static mod_ret_t _iq_vcard_pkt_sm(mod_instance_t mi, pkt_t pkt) {
    os_t os;
    st_ret_t ret;
    pkt_t result;

    /* only handle vcard sets and gets */
    if((pkt->type != pkt_IQ && pkt->type != pkt_IQ_SET) || pkt->ns != ns_VCARD)
        return mod_PASS;

    /* error them if they're trying to do a set */
    if(pkt->type == pkt_IQ_SET)
        return -stanza_err_FORBIDDEN;

    /* a vcard for the server */
    ret = storage_get(mi->sm->st, "vcard", pkt->to->domain, NULL, &os);
    switch(ret) {
        case st_FAILED:
            return -stanza_err_INTERNAL_SERVER_ERROR;

        case st_NOTIMPL:
            return -stanza_err_FEATURE_NOT_IMPLEMENTED;

        case st_NOTFOUND:
            return -stanza_err_ITEM_NOT_FOUND;

        case st_SUCCESS:
            result = _iq_vcard_to_pkt(mi->sm, os);
            os_free(os);

            result->to = jid_dup(pkt->from);
            result->from = jid_dup(pkt->to);

            nad_set_attr(result->nad, 1, -1, "to", jid_full(result->to), 0);
            nad_set_attr(result->nad, 1, -1, "from", jid_full(result->from), 0);

            pkt_id(pkt, result);

            pkt_router(result);

            pkt_free(pkt);

            return mod_HANDLED;
    }

    /* we never get here */
    pkt_free(pkt);
    return mod_HANDLED;
}

static mod_ret_t _iq_vcard_pkt_user(mod_instance_t mi, user_t user, pkt_t pkt) {
    os_t os;
    st_ret_t ret;
    pkt_t result;

    /* only handle vcard sets and gets, without resource */
    if((pkt->type != pkt_IQ && pkt->type != pkt_IQ_SET) || pkt->ns != ns_VCARD || pkt->to->resource[0] !='\0')
        return mod_PASS;

    /* error them if they're trying to do a set */
    if(pkt->type == pkt_IQ_SET)
        return -stanza_err_FORBIDDEN;

    if (sm_storage_rate_limit(user->sm, jid_user(pkt->from)))
        return -stanza_err_RESOURCE_CONSTRAINT;

    ret = storage_get(user->sm->st, "vcard", jid_user(user->jid), NULL, &os);
    switch(ret) {
        case st_FAILED:
            return -stanza_err_INTERNAL_SERVER_ERROR;

        case st_NOTIMPL:
            return -stanza_err_FEATURE_NOT_IMPLEMENTED;

        case st_NOTFOUND:
            return -stanza_err_SERVICE_UNAVAILABLE;

        case st_SUCCESS:
            result = _iq_vcard_to_pkt(user->sm, os);
            os_free(os);

            result->to = jid_dup(pkt->from);
            result->from = jid_dup(pkt->to);

            nad_set_attr(result->nad, 1, -1, "to", jid_full(result->to), 0);
            nad_set_attr(result->nad, 1, -1, "from", jid_full(result->from), 0);

            pkt_id(pkt, result);

            pkt_router(result);

            pkt_free(pkt);

            return mod_HANDLED;
    }

    /* we never get here */
    pkt_free(pkt);
    return mod_HANDLED;
}

static void _iq_vcard_user_delete(mod_instance_t mi, jid_t jid) {
    log_debug(ZONE, "deleting vcard for %s", jid_user(jid));

    storage_delete(mi->sm->st, "vcard", jid_user(jid), NULL);
}

static void _iq_vcard_free(module_t mod) {
    sm_unregister_ns(mod->mm->sm, uri_VCARD);
    feature_unregister(mod->mm->sm, uri_VCARD);
    free(mod->private);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;
    mod_iq_vcard_t iq_vcard;

    if(mod->init) return 0;

    mod->pkt_sm = _iq_vcard_pkt_sm;
    mod->in_sess = _iq_vcard_in_sess;
    mod->pkt_user = _iq_vcard_pkt_user;
    mod->user_delete = _iq_vcard_user_delete;
    mod->free = _iq_vcard_free;

    ns_VCARD = sm_register_ns(mod->mm->sm, uri_VCARD);
    feature_register(mod->mm->sm, uri_VCARD);

    iq_vcard = (mod_iq_vcard_t) calloc(1, sizeof(struct _mod_iq_vcard_st));
    iq_vcard->vcard_max_field_size_default = j_atoi(config_get_one(mod->mm->sm->config, "user.vcard.max-field-size.default", 0), VCARD_MAX_FIELD_SIZE);
    iq_vcard->vcard_max_field_size_avatar = j_atoi(config_get_one(mod->mm->sm->config, "user.vcard.max-field-size.avatar", 0), VCARD_MAX_FIELD_SIZE);
    mod->private = iq_vcard;

    return 0;
}
