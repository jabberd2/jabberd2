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

/** @file sm/mod_disco.c
  * @brief service discovery
  * @author Robert Norris
  * $Date: 2005/09/09 05:34:13 $
  * $Revision: 1.35 $
  */

#define ACTIVE_SESSIONS_NAME "Active sessions"

/** holder for a single service */
typedef struct service_st *service_t;
struct service_st {
    jid_t       jid;

    char        name[257];

    char        category[257];
    char        type[257];

    xht         features;
};

/** all the current disco data */
typedef struct disco_st *disco_t;
struct disco_st {
    /** identity */
    const char  *category;
    const char  *type;
    const char  *name;

    /** compatibility */
    int         agents;

    /** the lists */
    xht         dyn;
    xht         stat;

    /** unified list */
    xht         un;

    /** cached result packets */
    pkt_t       disco_info_result;
    pkt_t       disco_items_result;
    pkt_t       agents_result;
};

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  service_t *svc_val;
  sess_t *sess_val;
  const char **char_val;
};

/** put val into arg */
static void _disco_unify_walker(const char *key, int keylen, void *val, void *arg) {
    service_t svc = (service_t) val;
    xht dest = (xht) arg;

    /* if its already there, skip this one */
    if(xhash_get(dest, jid_full(svc->jid)) != NULL)
        return;

    log_debug(ZONE, "unify: %s", jid_full(svc->jid));

    xhash_put(dest, jid_full(svc->jid), (void *) svc);
}

/** unify the contents of dyn and stat */
static void _disco_unify_lists(disco_t d) {
    log_debug(ZONE, "unifying lists");

    if(d->un != NULL)
        xhash_free(d->un);
    
    d->un = xhash_new(101);

    /* dynamic overrieds static */
    xhash_walk(d->dyn, _disco_unify_walker, (void *) d->un);
    xhash_walk(d->stat, _disco_unify_walker, (void *) d->un);
}

/** build a disco items result, known services */
static pkt_t _disco_items_result(module_t mod, disco_t d) {
    pkt_t pkt;
    int ns;
    service_t svc;
    union xhashv xhv;

    pkt = pkt_create(mod->mm->sm, "iq", "result", NULL, NULL);
    ns = nad_add_namespace(pkt->nad, uri_DISCO_ITEMS, NULL);
    nad_append_elem(pkt->nad, ns, "query", 2);

    if(xhash_iter_first(d->un))
        do {
            xhv.svc_val = &svc;
            xhash_iter_get(d->un, NULL, NULL, xhv.val);

            nad_append_elem(pkt->nad, ns, "item", 3);
            nad_append_attr(pkt->nad, -1, "jid", jid_full(svc->jid));

            if(svc->name[0] != '\0')
                nad_append_attr(pkt->nad, -1, "name", svc->name);
        } while(xhash_iter_next(d->un));

    return pkt;
}

/** build a disco info result */
static pkt_t _disco_info_result(module_t mod, disco_t d) {
    pkt_t pkt;
    int el, ns;
    const char *key;
    int keylen;

    pkt = pkt_create(mod->mm->sm, "iq", "result", NULL, NULL);
    ns = nad_add_namespace(pkt->nad, uri_DISCO_INFO, NULL);
    nad_append_elem(pkt->nad, ns, "query", 2);

    /* identity */
    nad_append_elem(pkt->nad, ns, "identity", 3);
    nad_append_attr(pkt->nad, -1, "category", d->category);
    nad_append_attr(pkt->nad, -1, "type", d->type);
    nad_append_attr(pkt->nad, -1, "name", d->name);

    /* fill in our features */
    if(xhash_iter_first(mod->mm->sm->features))
        do {
            xhash_iter_get(mod->mm->sm->features, &key, &keylen, NULL);
            
            el = nad_append_elem(pkt->nad, ns, "feature", 3);
            nad_set_attr(pkt->nad, el, -1, "var", (char *) key, keylen);
        } while(xhash_iter_next(mod->mm->sm->features));

    /* put it throuhg disco_extend chain to add
     * XEP-0128 Service Discovery Extensions */
    mm_disco_extend(mod->mm, pkt);

    return pkt;
}

/** build an agents result */
static pkt_t _disco_agents_result(module_t mod, disco_t d) {
    pkt_t pkt;
    int ns;
    const char *key;
    int keylen;
    service_t svc;
    union xhashv xhv;

    pkt = pkt_create(mod->mm->sm, "iq", "result", NULL, NULL);
    ns = nad_add_namespace(pkt->nad, uri_AGENTS, NULL);
    nad_append_elem(pkt->nad, ns, "query", 2);

    /* fill in the items */
    if(xhash_iter_first(d->un))
        do {
            xhv.svc_val = &svc;
            xhash_iter_get(d->un, &key, &keylen, xhv.val);

            nad_append_elem(pkt->nad, ns, "agent", 3);
            nad_append_attr(pkt->nad, -1, "jid", jid_full(svc->jid));

            if(svc->name[0] != '\0') {
                nad_append_elem(pkt->nad, ns, "name", 4);
                nad_append_cdata(pkt->nad, svc->name, strlen(svc->name), 5);
            }

            nad_append_elem(pkt->nad, ns, "service", 4);
            nad_append_cdata(pkt->nad, svc->type, strlen(svc->type), 5);

            /* map features to the old agent flags */
            if(xhash_get(svc->features, uri_REGISTER) != NULL)
                nad_append_elem(pkt->nad, ns, "register", 4);
            if(xhash_get(svc->features, uri_SEARCH) != NULL)
                nad_append_elem(pkt->nad, ns, "search", 4);
            if(xhash_get(svc->features, uri_GATEWAY) != NULL)
                nad_append_elem(pkt->nad, ns, "transport", 4);

            /* conference gets special treatment */
            if(strcmp(svc->category, "conference") == 0)
                nad_append_elem(pkt->nad, ns, "groupchat", 4);
        } while(xhash_iter_next(d->un));

    return pkt;
}

/** generate cached result packets */
static void _disco_generate_packets(module_t mod, disco_t d) {
    log_debug(ZONE, "regenerating packets");

    if(d->disco_items_result != NULL)
        pkt_free(d->disco_items_result);
    d->disco_items_result = _disco_items_result(mod, d);

    if(d->disco_info_result != NULL)
        pkt_free(d->disco_info_result);
    d->disco_info_result = _disco_info_result(mod, d);

    if(d->agents) {
        if(d->agents_result != NULL)
            pkt_free(d->agents_result);
        d->agents_result = _disco_agents_result(mod, d);
    }

}

/** catch responses and populate the table */
static mod_ret_t _disco_pkt_sm_populate(mod_instance_t mi, pkt_t pkt)
{
    module_t mod = mi->mod;
    disco_t d = (disco_t) mod->private;
    int ns, qelem, elem, attr;
    service_t svc;

    /* it has to come from the service itself - don't want any old user messing with the table */
    if(pkt->from->node[0] != '\0' || pkt->from->resource[0] != '\0')
    {
        log_debug(ZONE, "disco response from %s, not allowed", jid_full(pkt->from));
        return -stanza_err_NOT_ALLOWED;
    }

    ns = nad_find_scoped_namespace(pkt->nad, uri_DISCO_INFO, NULL);
    qelem = nad_find_elem(pkt->nad, 1, ns, "query", 1);
    
    elem = nad_find_elem(pkt->nad, qelem, ns, "identity", 1);
    if(elem < 0)
        return -stanza_err_BAD_REQUEST;

    /* we don't want to list other im servers on the router */
    if(nad_find_attr(pkt->nad, elem, -1, "category", "server") >= 0
    && nad_find_attr(pkt->nad, elem, -1, "type", "im") >= 0) {
        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* see if we already have this service */
    svc = xhash_get(d->dyn, jid_full(pkt->from));
    if(svc == NULL)
    {
        /* make a new one */
        svc = (service_t) calloc(1, sizeof(struct service_st));

        svc->jid = jid_dup(pkt->from);

        svc->features = xhash_new(11);

        /* link it in */
        xhash_put(d->dyn, jid_full(svc->jid), (void *) svc);

        /* unify */
        _disco_unify_lists(d);
    }

    /* fill in the name */
    attr = nad_find_attr(pkt->nad, elem, -1, "name", NULL);
    if(attr < 0)
        svc->name[0] = '\0';
    else
        snprintf(svc->name, 257, "%.*s", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));

    /* category and type */
    attr = nad_find_attr(pkt->nad, elem, -1, "category", NULL);
    if(attr >= 0)
        snprintf(svc->category, 257, "%.*s", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));
    else
        strcpy(svc->category, "unknown");

    attr = nad_find_attr(pkt->nad, elem, -1, "type", NULL);
    if(attr >= 0)
        snprintf(svc->type, 257, "%.*s", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));
    else
        strcpy(svc->type, "unknown");

    /* features */
    elem = nad_find_elem(pkt->nad, qelem, -1, "feature", 1);
    while(elem >= 0)
    {
        attr = nad_find_attr(pkt->nad, elem, -1, "var", NULL);
        if(attr < 0)
        {
            elem = nad_find_elem(pkt->nad, elem, -1, "feature", 0);
            continue;
        }

        xhash_put(svc->features, pstrdupx(xhash_pool(svc->features), NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr)), (void *) 1);

        elem = nad_find_elem(pkt->nad, elem, -1, "feature", 0);
    }

    /* regenerate packets */
    _disco_generate_packets(mod, d);

    pkt_free(pkt);

    return mod_HANDLED;
}

/** respond to user quering its JID */
static mod_ret_t _disco_in_sess_result(mod_instance_t mi, sess_t sess, pkt_t pkt)
{
    /* it has to have no to address or self bare jid */
    if(pkt->to != NULL && strcmp(jid_user(sess->jid), jid_full(pkt->to)))
    {
        return mod_PASS;
    }

    /* identity */
    nad_append_elem(pkt->nad, -1, "identity", 3);
    nad_append_attr(pkt->nad, -1, "category", "account");
    nad_append_attr(pkt->nad, -1, "type", "registered");

    /* tell them */
    nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);
    pkt_sess(pkt_tofrom(pkt), sess);

    return mod_HANDLED;
}

/** build a disco items result, active sessions */
static void _disco_sessions_result(module_t mod, disco_t d, pkt_t pkt) {
    int ns;
    sess_t sess;
    union xhashv xhv;

    ns = nad_add_namespace(pkt->nad, uri_DISCO_ITEMS, NULL);
    nad_append_elem(pkt->nad, ns, "query", 2);
    nad_append_attr(pkt->nad, -1, "node", "sessions");

    if(xhash_iter_first(mod->mm->sm->sessions))
        do {
            xhv.sess_val = &sess;
            xhash_iter_get(mod->mm->sm->sessions, NULL, NULL, xhv.val);

            nad_append_elem(pkt->nad, ns, "item", 3);
            nad_append_attr(pkt->nad, -1, "jid", jid_full(sess->jid));
            nad_append_attr(pkt->nad, -1, "name", "Active session");
        } while(xhash_iter_next(mod->mm->sm->sessions));
}

/** catch responses and populate the table; respond to requests */
static mod_ret_t _disco_pkt_sm(mod_instance_t mi, pkt_t pkt) {
    module_t mod = mi->mod;
    disco_t d = (disco_t) mod->private;
    pkt_t result;
    int node, ns;
    
    /* disco info results go to a seperate function */
    if(pkt->type == pkt_IQ_RESULT && pkt->ns == ns_DISCO_INFO)
        return _disco_pkt_sm_populate(mi, pkt);

    /* check whether the requested domain is serviced here */
    if(xhash_get(mod->mm->sm->hosts, pkt->to->domain) == NULL)
        return -stanza_err_ITEM_NOT_FOUND;

    /* we want disco or agents gets */
    if(pkt->type != pkt_IQ || !(pkt->ns == ns_DISCO_INFO || pkt->ns == ns_DISCO_ITEMS || pkt->ns == ns_AGENTS))
        return mod_PASS;

    /* generate the caches if we haven't yet */
    if(d->disco_info_result == NULL)
        _disco_generate_packets(mod, d);

    node = nad_find_attr(pkt->nad, 2, -1, "node", NULL);

    /* they want to know about us */
    if(pkt->ns == ns_DISCO_INFO) {
        /* respond with cached disco info packet if no node given */
        if(node < 0) {
            result = pkt_dup(d->disco_info_result, jid_full(pkt->from), jid_full(pkt->to));

            node = nad_find_attr(pkt->nad, 2, -1, "node", NULL);
            if(node >= 0) {
                nad_set_attr(result->nad, 2, -1, "node", NAD_AVAL(pkt->nad, node), NAD_AVAL_L(pkt->nad, node));
            }

            pkt_id(pkt, result);
            pkt_free(pkt);

            /* off it goes */
            pkt_router(result);

            return mod_HANDLED;
        }
        else if(NAD_AVAL_L(pkt->nad, node) == 8 && strncmp("sessions", NAD_AVAL(pkt->nad, node), 8) == 0) {
            /* priviliged op, make sure they're allowed */
            if(!aci_check(mod->mm->sm->acls, "disco", pkt->from))
                return -stanza_err_ITEM_NOT_FOUND;  /* we never advertised it, so we can pretend its not here */

            result = pkt_create(mod->mm->sm, "iq", "result", jid_full(pkt->from), jid_full(pkt->to));
            pkt_id(pkt, result);
            pkt_free(pkt);

            ns = nad_add_namespace(result->nad, uri_DISCO_INFO, NULL);
            nad_append_elem(result->nad, ns, "query", 2);
            nad_append_elem(result->nad, ns, "identity", 3);
            nad_append_attr(result->nad, -1, "category", "hierarchy");
            nad_append_attr(result->nad, -1, "type", "branch");
            nad_append_attr(result->nad, -1, "name", ACTIVE_SESSIONS_NAME);
            nad_append_elem(result->nad, -1, "feature", 3);
            nad_append_attr(result->nad, -1, "var", uri_DISCO_INFO);
            nad_append_elem(result->nad, -1, "feature", 3);
            nad_append_attr(result->nad, -1, "var", uri_DISCO_ITEMS);

            /* off it goes */
            pkt_router(result);

            return mod_HANDLED;
        }
        else
            return -stanza_err_ITEM_NOT_FOUND;
    }

    /* handle agents */
    if(pkt->ns == ns_AGENTS) {
        /* make sure we're supporting compat */
        if(!d->agents)
            return -stanza_err_NOT_ALLOWED;

        result = pkt_dup(d->agents_result, jid_full(pkt->from), jid_full(pkt->to));
        pkt_id(pkt, result);
        pkt_free(pkt);

        /* off it goes */
        pkt_router(result);

        return mod_HANDLED;
    }

    /* they want to know who we know about */
    if(node < 0) {
        /* no node, so toplevel services */
        result = pkt_dup(d->disco_items_result, jid_full(pkt->from), jid_full(pkt->to));
        pkt_id(pkt, result);
        pkt_free(pkt);

        /* if they have privs, then show them any administrative things they can disco to */
        if(aci_check(mod->mm->sm->acls, "disco", result->to)) {
            nad_append_elem(result->nad, NAD_ENS(result->nad, 2), "item", 3);
            nad_append_attr(result->nad, -1, "jid", jid_full(result->from));
            nad_append_attr(result->nad, -1, "node", "sessions");
            nad_append_attr(result->nad, -1, "name", ACTIVE_SESSIONS_NAME);
        }

        pkt_router(result);

        return mod_HANDLED;
    }

    /* active sessions */
    if(NAD_AVAL_L(pkt->nad, node) == 8 && strncmp("sessions", NAD_AVAL(pkt->nad, node), 8) == 0) {
        /* priviliged op, make sure they're allowed */
        if(!aci_check(mod->mm->sm->acls, "disco", pkt->from))
            return -stanza_err_ITEM_NOT_FOUND;  /* we never advertised it, so we can pretend its not here */

        result = pkt_create(mod->mm->sm, "iq", "result", jid_full(pkt->from), jid_full(pkt->to));
        pkt_id(pkt, result);
        pkt_free(pkt);

        _disco_sessions_result(mod, d, result);

        /* off it goes */
        pkt_router(result);

        return mod_HANDLED;
    }

    /* I dunno what they're asking for */
    return -stanza_err_ITEM_NOT_FOUND;
}

/** legacy support for agents requests from sessions */
static mod_ret_t _disco_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    module_t mod = mi->mod;
    disco_t d = (disco_t) mod->private;
    pkt_t result;

    /* disco info requests go to a seperate function */
    if(pkt->type == pkt_IQ && pkt->ns == ns_DISCO_INFO)
        return _disco_in_sess_result(mi, sess, pkt);

    /* we want agents gets */
    if(pkt->type != pkt_IQ || pkt->ns != ns_AGENTS || pkt->to != NULL)
        return mod_PASS;

    /* fail if its not enabled */
    if(!d->agents)
        return -stanza_err_NOT_ALLOWED;

    /* generate the caches if we haven't yet */
    if(d->disco_info_result == NULL)
        _disco_generate_packets(mod, d);

    /* pre-canned response */
    result = pkt_dup(d->agents_result, NULL, NULL);
    pkt_id(pkt, result);
    pkt_free(pkt);

    /* off it goes */
    pkt_sess(result, sess);

    return mod_HANDLED;
}

/** update the table for component changes */
static mod_ret_t _disco_pkt_router(mod_instance_t mi, pkt_t pkt)
{
    module_t mod = mi->mod;
    disco_t d = (disco_t) mod->private;
    service_t svc;
    pkt_t request;
    int ns;

    /* we want advertisements with a from address */
    if(pkt->from == NULL || !(pkt->rtype & route_ADV))
        return mod_PASS;

    /* component online */
    if(pkt->rtype == route_ADV)
    {
        log_debug(ZONE, "presence from component %s, issuing discovery request", jid_full(pkt->from));

        /* new disco get packet */
        request = pkt_create(mod->mm->sm, "iq", "get", jid_full(pkt->from), mod->mm->sm->id);
        pkt_id_new(request);
        ns = nad_add_namespace(request->nad, uri_DISCO_INFO, NULL);
        nad_append_elem(request->nad, ns, "query", 2);

        pkt_router(request);

        /* done with this */
        pkt_free(pkt);

        return mod_HANDLED;
    }

    /* it went away. find it and remove it */
    svc = xhash_get(d->dyn, jid_full(pkt->from));
    if(svc != NULL)
    {
        log_debug(ZONE, "dropping entry for %s", jid_full(pkt->from));

        xhash_zap(d->dyn, jid_full(pkt->from));

        jid_free(svc->jid);
        xhash_free(svc->features);
        free(svc);

        /* unify */
        _disco_unify_lists(d);
        _disco_generate_packets(mod, d);
    }
    
    /* done */
    pkt_free(pkt);

    return mod_HANDLED;
}

static void _disco_free_walker(const char *key, int keylen, void *val, void *arg) {
    service_t svc = (service_t) val;

    jid_free(svc->jid);
    xhash_free(svc->features);
    free(svc);
}

static void _disco_free(module_t mod) {
    disco_t d = (disco_t) mod->private;

    xhash_walk(d->stat, _disco_free_walker, NULL);
    xhash_walk(d->dyn, _disco_free_walker, NULL);

    xhash_free(d->stat);
    xhash_free(d->dyn);
    xhash_free(d->un);

    if(d->disco_info_result != NULL) pkt_free(d->disco_info_result);
    if(d->disco_items_result != NULL) pkt_free(d->disco_items_result);
    if(d->agents_result != NULL) pkt_free(d->agents_result);

    free(d);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg)
{
    module_t mod = mi->mod;
    disco_t d;
    nad_t nad;
    int items, item, jid, name, category, type, ns;
    service_t svc;

    if(mod->init) return 0;

    log_debug(ZONE, "disco module init");

    d = (disco_t) calloc(1, sizeof(struct disco_st));

    /* new hashes to store the lists in */
    d->dyn = xhash_new(51);
    d->stat = xhash_new(51);

    /* identity */
    d->category = config_get_one(mod->mm->sm->config, "discovery.identity.category", 0);
    if(d->category == NULL) d->category = "server";
    d->type = config_get_one(mod->mm->sm->config, "discovery.identity.type", 0);
    if(d->type == NULL) d->type = "im";
    d->name = config_get_one(mod->mm->sm->config, "discovery.identity.name", 0);
    if(d->name == NULL) d->name = "Jabber IM server";

    /* agents compatibility */
    d->agents = config_get(mod->mm->sm->config, "discovery.agents") != NULL;

    if(d->agents)
        log_debug(ZONE, "agents compat enabled");
    
    /* our data */
    mod->private = (void *) d;
    
    /* our handlers */
    mod->pkt_sm = _disco_pkt_sm;
    mod->in_sess = _disco_in_sess;
    mod->pkt_router = _disco_pkt_router;
    mod->free = _disco_free;

    nad = mod->mm->sm->config->nad;

    /* we support a number of things */
    feature_register(mod->mm->sm, uri_DISCO_INFO);
    feature_register(mod->mm->sm, uri_DISCO_ITEMS);
    if(d->agents)
        feature_register(mod->mm->sm, uri_AGENTS);

    /* populate the static list from the config file */
    if((items = nad_find_elem(nad, 0, -1, "discovery", 1)) < 0 || (items = nad_find_elem(nad, items, -1, "items", 1)) < 0)
        return 0;

    item = nad_find_elem(nad, items, -1, "item", 1);
    while(item >= 0)
    {
        /* jid is required */
        jid = nad_find_attr(nad, item, -1, "jid", NULL);
        if(jid < 0)
        {
            item = nad_find_elem(nad, item, -1, "item", 0);
            continue;
        }

        /* new service */
        svc = (service_t) calloc(1, sizeof(struct service_st));

        svc->features = xhash_new(13);

        svc->jid = jid_new(NAD_AVAL(nad, jid), NAD_AVAL_L(nad, jid));

        /* link it in */
        xhash_put(d->stat, jid_full(svc->jid), (void *) svc);

        /* copy the name */
        name = nad_find_attr(nad, item, -1, "name", NULL);
        if(name >= 0)
            snprintf(svc->name, 257, "%.*s", NAD_AVAL_L(nad, name), NAD_AVAL(nad, name));

        /* category and type */
        category = nad_find_attr(nad, item, -1, "category", NULL);
        if(category >= 0)
            snprintf(svc->category, 257, "%.*s", NAD_AVAL_L(nad, category), NAD_AVAL(nad, category));
        else
            strcpy(svc->category, "unknown");

        type = nad_find_attr(nad, item, -1, "type", NULL);
        if(type >= 0)
            snprintf(svc->type, 257, "%.*s", NAD_AVAL_L(nad, type), NAD_AVAL(nad, type));
        else
            strcpy(svc->type, "unknown");

        /* namespaces */
        ns = nad_find_elem(nad, item, -1, "ns", 1);
        while(ns >= 0)
        {
            if(NAD_CDATA_L(nad, ns) > 0)
                xhash_put(svc->features, pstrdupx(xhash_pool(svc->features), NAD_CDATA(nad, ns), NAD_CDATA_L(nad, ns)), (void *) 1);

            ns = nad_find_elem(nad, ns, -1, "ns", 0);
        }

        item = nad_find_elem(nad, item, -1, "item", 0);

        log_debug(ZONE, "added %s to static list", jid_full(svc->jid));
    }

    /* generate the initial union list */
    _disco_unify_lists(d);

    /* we don't generate the packets here, because the router conn isn't up yet, and so we don't have a nad cache */

    return 0;
}
