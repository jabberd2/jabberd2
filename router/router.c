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

#include "router.h"

#define MAX_JID 3072    // node(1023) + '@'(1) + domain(1023) + '/'(1) + resource(1023) + '\0'(1)
#define MAX_MESSAGE 65535
#define SECS_PER_DAY 86400
#define BYTES_PER_MEG 1048576

static component_t _select_domain_comp(routes_t routes) {
    unsigned int metric, nb = 1;
    route_elem_t scan = routes->head;

    if(routes->nb_routes == 1)
	return scan->comp;

    metric = scan->metric;

    for(scan = scan->next; scan != NULL && scan->metric == metric; scan = scan->next)
	nb++;

    nb = rand() % nb;

    for(scan = routes->head; nb--; scan = scan->next)
	;

    return scan->comp;
}

static void _get_id_from_ids(router_t r, char *id_test, char **id) {
    ids_t idt;

    log_debug(ZONE, "************** _get_id_from_ids: id_test=%s", id_test);
    idt = (ids_t) xhash_get(r->ids, id_test);

    if(idt == NULL) {
	idt = (ids_t) malloc(sizeof(struct ids_st));
	idt->id = strdup(id_test);
	idt->refcount = 1;
	xhash_put(r->ids, pstrdup(xhash_pool(r->ids), idt->id), (void *) idt);
    }
    else
	idt->refcount++;

    *id = idt->id;
}

static unsigned int _get_id_from_bare_jid(router_t r, jid_t jid, char **id, component_t *target_comp) {
    char *id_test;
    routes_t domain_targets = NULL;
    unsigned int ret = 1;
    xht domain_bares;

    log_debug(ZONE, "************** _get_id_from_bare_jid: jid=%s", jid_full(jid));
    domain_targets = (routes_t) xhash_get(r->domains, jid->domain);

    if(domain_targets == NULL) {
	log_write(r->log, LOG_ERR, "cannot find domain '%s' to store bare_jid", jid->domain);
	return 0;
    }

    domain_bares = (xht) xhash_get(r->bare_jids, jid->domain);
    if (domain_bares == NULL) {
	domain_bares = xhash_new(1023);
	xhash_put(r->bare_jids, pstrdup(xhash_pool(r->bare_jids), jid->domain), (void *) domain_bares);
	ret = 0;
    }

    id_test = (char *) xhash_get(domain_bares, jid_user(jid));

    if(id_test == NULL) {
	ret = 0;

	*target_comp = _select_domain_comp(domain_targets);
	id_test = domain_targets->head->id;
    } else
	*target_comp = ((routes_t) xhash_get(r->rids, id_test))->head->comp;

    _get_id_from_ids(r, id_test, id);

    return ret;
}

static void _store_bare_jid(router_t r, jid_t jid, char *id) {
    xht domain_bares;

    log_debug(ZONE, "************** _store_bare_jid: storing jid=%s (%s)", jid_user(jid), id);
    domain_bares = (xht) xhash_get(r->bare_jids, jid->domain);
    if (domain_bares == NULL) {
	domain_bares = xhash_new(1023);
	xhash_put(r->bare_jids, pstrdup(xhash_pool(r->bare_jids), jid->domain), (void *) domain_bares);
    }

    xhash_put(domain_bares, pstrdup(xhash_pool(domain_bares), jid_user(jid)), (void *) id);
}

static void _zap_bare_jid(router_t r, jid_t jid) {
    ids_t idt;
    routes_t domain_targets = NULL;
    xht domain_bares;

    domain_targets = (routes_t) xhash_get(r->domains, jid->domain);
//    domain_targets = (routes_t) xhash_get(r->rids, jid->domain);
    if(domain_targets == NULL) {
	log_write(r->log, LOG_ERR, "cannot find domain '%s' to zap bare_jid", jid->domain);
	return;
    }

    domain_bares = (xht) xhash_get(r->bare_jids, jid->domain);
    if (domain_bares == NULL)
	return;

    xhash_zap(domain_bares, jid_user(jid));

    idt = (ids_t) xhash_get(r->ids, jid_user(jid));

    if (idt != NULL && --idt->refcount == 0) {
	xhash_zap(r->ids, idt->id);
	free(idt->id);
	free(idt);
    }
}

/** info for broadcasts to components */
typedef struct broadcast_comp_st {
    component_t   src;
    nad_t         nad_routers;
    nad_t         nad_leaves;
} *broadcast_comp_t;

/** broadcast a packet to all components */
static void _router_broadcast_comps(const char *key, int keylen, void *val, void *arg) {
    broadcast_comp_t bcc = (broadcast_comp_t) arg;
    routes_t routes = (routes_t) val;
    component_t comp_by = _select_domain_comp(routes);

    if (comp_by == bcc->src)
	return;

    if (comp_by->remote_router != NULL) {
	if (bcc->nad_routers != NULL) {
	    nad_set_attr(bcc->nad_routers, 0, -1, "to", key, keylen);
	    log_debug(ZONE, "_router_broadcast_comps: ROUTER TO = %.*s", keylen, key);
	    sx_nad_write(comp_by->s, nad_copy(bcc->nad_routers));
	}
    } else if (bcc->nad_leaves != NULL) {
	log_debug(ZONE, "_router_broadcast_comps: LEAF TO = %.*s", keylen, key);
	sx_nad_write(comp_by->s, nad_copy(bcc->nad_leaves));
    }
}

/** domain/id advertisement */
static void _router_advertise(router_t r, const char *new_id, component_t src, int unavail, int leaves_only) {
    struct broadcast_comp_st bcc;
    int ns;

    log_debug(ZONE, "advertising %s to all ids (unavail=%d)", new_id, unavail);

    bcc.src = src;

    /* create new packets */
    bcc.nad_leaves = nad_new();
    ns = nad_add_namespace(bcc.nad_leaves, uri_COMPONENT, NULL);
    nad_append_elem(bcc.nad_leaves, ns, "presence", 0);
    nad_append_attr(bcc.nad_leaves, -1, "from", new_id);

    if (leaves_only == 0) {
	bcc.nad_routers = nad_new();
	ns = nad_add_namespace(bcc.nad_routers, uri_COMPONENT, NULL);
	if(unavail)
	    nad_append_elem(bcc.nad_routers, ns, "unbind", 0);
	else
	    nad_append_elem(bcc.nad_routers, ns, "bind", 0);
	nad_append_attr(bcc.nad_routers, -1, "name", new_id);
	nad_append_attr(bcc.nad_routers, -1, "id", src->id);
    } else
	bcc.nad_routers = NULL;

    if(unavail)
	nad_append_attr(bcc.nad_leaves, -1, "type", "unavailable");

    xhash_walk(r->rids, _router_broadcast_comps, (void *) &bcc);

    nad_free(bcc.nad_leaves);

    if (leaves_only == 0)
	nad_free(bcc.nad_routers);
}

/** domain/id advertisement */
static void _router_advertise_user(router_t r, const jid_t jid, int unavail) {
    routes_t domain_targets;
    route_elem_t relem;
    nad_t nad;
    int ns;

    log_debug(ZONE, "advertising %s to all domains '%s' (unavail=%d)", jid_user(jid), jid->domain, unavail);

    domain_targets = (routes_t) xhash_get(r->domains, jid->domain);

    /* create new packets */
    nad = nad_new();
    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
    nad_append_elem(nad, ns, "presence", 0);
    nad_append_attr(nad, -1, "from", jid_user(jid));
    if(unavail)
	nad_append_attr(nad, -1, "type", "unavailable");

    for(relem = domain_targets->head; relem != NULL; relem = relem->next)
	if (relem->comp->remote_router == NULL)
	    sx_nad_write(relem->comp->s, nad_copy(nad));

    nad_free(nad);
}

/** tell a component about all the others */
static void _router_advertise_reverse(const char *key, int keylen, void *val, void *arg) {
    routes_t routes = (routes_t) val;
    component_t dest = (component_t) arg;
    int el, ns;
    nad_t nad;

    log_debug(ZONE, "informing component '%s' about %.*s *********** route->nb_routes = %d, route->head->comp = %p, dest = %p", dest->id, keylen, key, routes->nb_routes, routes->head->comp, dest);
    if(routes->nb_routes == 1 && routes->head->comp == dest)
	return;

    log_debug(ZONE, "informing component '%s' about %.*s", dest->id, keylen, key);

    /* create a new packet */
    nad = nad_new();
    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);

    if(routes->remote_router == NULL) {
	el = nad_append_elem(nad, ns, "presence", 0);
	nad_set_attr(nad, el, -1, "from", key, keylen);
    } else {
	el = nad_append_elem(nad, ns, "bind", 0);
	nad_set_attr(nad, el, -1, "name", key, keylen);
    }

    sx_nad_write(dest->s, nad);
}

/** info for broadcasts to ids */
typedef struct broadcast_id_st {
    char  *src;
    nad_t nad;
    router_t r;
} *broadcast_id_t;

/** broadcast a packet to all rids */
static void _router_broadcast_ids(const char *key, int keylen, void *val, void *arg) {
    broadcast_id_t bci = (broadcast_id_t) arg;
    routes_t routes = (routes_t) val;
    component_t comp;
	    
    if(strlen(bci->src) == keylen && strncmp(key, bci->src, keylen) != 0) {
	nad_set_attr(bci->nad, 0, -1, "to", key, keylen);
	comp = _select_domain_comp(routes);
	sx_nad_write(comp->s, nad_copy(bci->nad));
    }
}

static void _router_process_handshake(component_t comp, nad_t nad) {
    char *hash;
    int hashlen;

    /* must have a hash as cdata */
    if(NAD_CDATA_L(nad, 0) != 40) {
        log_debug(ZONE, "handshake isn't long enough to be a sha1 hash");
        sx_error(comp->s, stream_err_NOT_AUTHORIZED, "handshake isn't long enough to be a sha1 hash");
        sx_close(comp->s);

        nad_free(nad);
        return;
    }

    /* make room for shahash_r to work .. needs at least 41 chars */
    hashlen = strlen(comp->s->id) + strlen(comp->r->local_secret) + 1;
    if(hashlen < 41)
        hashlen = 41;

    /* build the creds and hash them */
    hash = (char *) malloc(sizeof(char) * hashlen);
    sprintf(hash, "%s%s", comp->s->id, comp->r->local_secret);
    shahash_r(hash, hash);

    /* check */
    log_debug(ZONE, "checking their hash %.*s against our hash %s", 40, NAD_CDATA(nad, 0), hash);

    if(strncmp(hash, NAD_CDATA(nad, 0), 40) == 0) {
        log_debug(ZONE, "handshake succeeded");

        free(hash);

        /* respond */
        nad->elems[0].icdata = nad->elems[0].itail = -1;
        nad->elems[0].lcdata = nad->elems[0].ltail = 0;
        sx_nad_write(comp->s, nad);

        sx_auth(comp->s, "handshake", comp->s->req_to);
        
        return;
    }
    
    log_debug(ZONE, "auth failed");

    free(hash);

    /* failed, let them know */
    sx_error(comp->s, stream_err_NOT_AUTHORIZED, "hash didn't match, auth failed");
    sx_close(comp->s);

    nad_free(nad);
}

static int _route_add(const char *name, component_t comp, unsigned int metric, char *id, unsigned int legacy) {
    routes_t routes;
    route_elem_t relem_new, scan, *prev_next_ptr;
    xht target_hash;
    int is_domain = 0;

    log_debug(ZONE, " *********** _route_add name=%s, id=%s", name, id);

    if (strchr(name, '.') == NULL)
    	target_hash = comp->r->rids;
    else {
	target_hash = comp->r->domains;
	is_domain = 1;
    }

    routes = (routes_t) xhash_get(target_hash, name);

    if(routes == NULL) {
        routes = (routes_t) calloc(1, sizeof(struct routes_st));
        routes->legacy = legacy;
	routes->remote_router = comp->remote_router;

	xhash_put(target_hash, pstrdup(xhash_pool(target_hash), name), (void *) routes);
	log_debug(ZONE, " *********** NEW ROUTE name=%s", name);
    }

    scan = routes->head;
    prev_next_ptr = &routes->head;

    /* order by metric asc */
    while(scan != NULL && scan->metric < metric) {
	prev_next_ptr = &scan->next;
	scan = scan->next;
    }

    if(scan == NULL || scan->comp != comp) {
	log_debug(ZONE, " *********** NEW RELEM id=%s", id);
	relem_new = (route_elem_t) calloc(1, sizeof(struct route_elem_st));
	relem_new->metric = metric;
	relem_new->comp = comp;
	relem_new->id = strdup(id);

	*prev_next_ptr = relem_new;
	relem_new->next = scan; // may be NULL

	routes->nb_routes++;
    }

    if(routes->nb_routes > 1 && is_domain == 1) { // go to bareJID bind level
	route_elem_t dest;
	nad_t nad_bindlevel = nad_new();
	int ns = nad_add_namespace(nad_bindlevel, uri_COMPONENT, NULL);
	nad_append_elem(nad_bindlevel, ns, "bind-level", 0);
	nad_append_attr(nad_bindlevel, -1, "level", "barejid");
	nad_append_attr(nad_bindlevel, -1, "to", name);
	nad_append_attr(nad_bindlevel, -1, "via", id);
	sx_nad_write(comp->s, nad_copy(nad_bindlevel));

	if(routes->nb_routes == 2) { // inform the already bound domain
	    dest = routes->head;
	    log_debug(ZONE, " *********** routes = %p, routes->head = %p", routes, routes->head);

	    if(strcmp(dest->id, name) == 0) // not the new bound (depends on metric)
		dest = dest->next;

	    nad_set_attr(nad_bindlevel, 0, -1, "to",  name, 0);
	    nad_set_attr(nad_bindlevel, 0, -1, "via", dest->id, 0);
	    sx_nad_write(dest->comp->s, nad_bindlevel);
	} else
	    nad_free(nad_bindlevel);
    }

    return routes->nb_routes;
}

static void _send_new_neighbour(component_t comp, const char *name) {
    graph_elem_t scan_ngb;

    log_debug(ZONE, " *********** _send_new_neighbour: NAME = %s", name);

    for(scan_ngb = comp->r->graph; scan_ngb != NULL && strcmp(name, scan_ngb->id) != 0; scan_ngb = scan_ngb->neighbour_next)
	log_debug(ZONE, " *********** NAME = %s, SCAN_NGB->id = %s", name, scan_ngb->id);

    if(scan_ngb == NULL) { // new node
	remote_routers_t rem;
	nad_t nad;
	int ns, elem;

	log_debug(ZONE, " *********** NEW NODE");
	scan_ngb = (graph_elem_t) calloc(1, sizeof(struct graph_elem_st));
	scan_ngb->id = strdup(name);
	scan_ngb->neighbour_next = comp->r->graph;
	comp->r->graph = scan_ngb;

	nad = nad_new();
	ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
	nad_append_elem(nad, ns, "path", 0);
	nad_append_attr(nad, -1, "id", comp->r->id);

	elem = nad_insert_elem(nad, 0, ns, "hop", NULL);
	nad_set_attr(nad, elem, -1, "id", name, 0);
	nad_set_attr(nad, elem, -1, "add", "1", 0);
	nad_set_attr(nad, elem, -1, "metric", "1", 0); // FIXME: metricstr

	elem = nad_insert_elem(nad, 0, ns, "hop", NULL);
	nad_set_attr(nad, elem, -1, "id", comp->r->id, 0);
	nad_set_attr(nad, elem, -1, "add", "1", 0);
	nad_set_attr(nad, elem, -1, "metric", "1", 0); // FIXME: metricstr

	for(rem = comp->r->remote_routers; rem != NULL; rem = rem->next)
	    if(rem->comp != comp && rem->online == 1)
		sx_nad_write(rem->comp->s, nad_copy(nad));

	nad_free(nad);
    }

}

static void _route_remove_all(const char *name, component_t comp) {
    routes_t routes;
    route_elem_t scan, *prev_next_ptr;
    int removed = 0;
    xht target_hash;
    graph_elem_t scan_ngb;

    /* if (strchr(name, '.') == NULL) */
    	target_hash = comp->r->rids;
    /* else */
//	target_hash = comp->r->domains;

    routes = (routes_t) xhash_get(target_hash, name);

    scan = routes->head;
    prev_next_ptr = &routes->head;

    while(scan != NULL) {
        prev_next_ptr = &scan->next;

	if(scan->comp == comp) {
	    *prev_next_ptr = scan->next;
	    routes->nb_routes--;

	    jqueue_push(comp->r->dead_route_elems, (void *) scan, 0);

	    for(scan_ngb = comp->r->graph; scan_ngb != NULL && strcmp(scan_ngb->id, scan->id) != 0; scan_ngb = scan_ngb->neighbour_next)
		;

	    if(scan_ngb != NULL) { // remove node
		comp->r->graph = scan_ngb->neighbour_next;
		free(scan_ngb->id);
		free(scan_ngb);
	    }

	    removed = 1;
	}

	scan = scan->next;
    }

    if(removed && routes->nb_routes == 1) { // go back to domain bind level
	nad_t nad_bindlevel = nad_new();
	int ns = nad_add_namespace(nad_bindlevel, uri_COMPONENT, NULL);
	nad_append_elem(nad_bindlevel, ns, "bind-level", 0);
	nad_append_attr(nad_bindlevel, -1, "level", "domain");
	nad_append_attr(nad_bindlevel, -1, "to", routes->head->id);

	sx_nad_write(routes->head->comp->s, nad_bindlevel);
    }

    if(routes->nb_routes == 0) {
        jqueue_push(comp->r->dead_routes, (void *) routes, 0);
        xhash_zap(target_hash, name);
    }
}

static void _route_remove(const char *name, component_t comp, unsigned int metric, char *id) {
    routes_t routes;
    route_elem_t scan, *prev_next_ptr;
    xht target_hash;
    graph_elem_t scan_ngb;

    /* if (strchr(name, '.') == NULL) */
    	target_hash = comp->r->rids;
    /* else */
//	target_hash = comp->r->domains;

    routes = (routes_t) xhash_get(target_hash, name);

    assert(routes != NULL && routes->head != NULL);

    scan = routes->head;
    prev_next_ptr = &routes->head;

    while(scan != NULL && scan->metric < metric) {
        prev_next_ptr = &scan->next;
	scan = scan->next;
    }

    *prev_next_ptr = scan->next;
    routes->nb_routes--;

    jqueue_push(comp->r->dead_route_elems, (void *) scan, 0);

    for(scan_ngb = comp->r->graph; scan_ngb != NULL && strcmp(scan_ngb->id, scan->id) != 0; scan_ngb = scan_ngb->neighbour_next)
	;

    if(scan_ngb != NULL) { // remove node
	comp->r->graph = scan_ngb->neighbour_next;
	free(scan_ngb->id);
	free(scan_ngb);
    }

    if(routes->nb_routes == 1) { // go back to domain bind level
	nad_t nad_bindlevel = nad_new();
	int ns = nad_add_namespace(nad_bindlevel, uri_COMPONENT, NULL);
	nad_append_elem(nad_bindlevel, ns, "bind-level", 0);
	nad_append_attr(nad_bindlevel, -1, "level", "domain");
	nad_append_attr(nad_bindlevel, -1, "to", routes->head->id);

	sx_nad_write(routes->head->comp->s, nad_bindlevel);
    }

    if(routes->nb_routes == 0) {
        jqueue_push(comp->r->dead_routes, (void *) routes, 0);
        xhash_zap(target_hash, name);
    }
}

static void _router_send_path_from_graph(router_t r, graph_elem_t scan, component_t dest, nad_t nad) {
    graph_elem_t scan_ngb;
    char metric_str[11];
    unsigned int elem, metric;
    routes_t routes;

    if (scan != NULL) {
	while(scan != NULL) {
	    nad_t nad_ngb = nad_copy(nad);

	    // append scan->id and call recursively
	    elem = nad_append_elem(nad_ngb, -1, "hop", 1);
	    nad_set_attr(nad_ngb, elem, -1, "id", scan->id, 0);
	    log_debug(ZONE, "****** _router_send_path_from_graph: id=%s", scan->id);

	    routes = (routes_t) xhash_get(r->rids, scan->id);
	    if (routes == NULL)
		routes = (routes_t) xhash_get(r->domains, scan->id);

	    if(routes->remote_router)
		metric = routes->remote_router->metric;
	    else
		metric = 1;

	    snprintf(metric_str, 10, "%d", 1);
//	    snprintf(metric_str, 10, "%d", metric);
	    nad_set_attr(nad_ngb, elem, -1, "metric", metric_str, 0);

	    nad_set_attr(nad_ngb, elem, -1, "add", "1", 0);

	    scan_ngb = scan->neighbours_head;
	    while(1) {
		_router_send_path_from_graph(r, scan_ngb, dest, nad_ngb);
		if (scan_ngb == NULL)
		    break;
		scan_ngb = scan_ngb->neighbour_next;
	    }

	    scan = scan->neighbour_next;
	}
    } else if(dest->remote_router != NULL)
	sx_nad_write(dest->s, nad);
    else
	nad_free(nad);
}

static void _router_propagate_path(component_t comp) {
    char *id, metric_str[11];
    nad_t nad;
    int ns;

    nad = nad_new();
    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
    nad_append_elem(nad, ns, "path", 0);
    nad_append_attr(nad, -1, "id", comp->r->id);
    nad_insert_elem(nad, 0, ns, "hop", NULL);
    nad_append_attr(nad, -1, "id", comp->r->id);

    /* snprintf(metric_str, 10, "%d", rem->metric); */
    snprintf(metric_str, 10, "%d", 1);
    nad_append_attr(nad, -1, "metric", metric_str);

    nad_append_attr(nad, -1, "add", "1");

    _router_send_path_from_graph(comp->r, comp->r->graph, comp, nad);
}

static const char* _router_process_remote_router(component_t comp, nad_t nad, remote_routers_t rem) {
    int attr, ns;
    char metric_str[11];
    graph_elem_t gelem;

    log_debug(ZONE, "[%s, port=%d] '%s' remote router connection", comp->ip, comp->port, comp->id);

    if (rem == NULL) {
	rem = (remote_routers_t) calloc(1, sizeof(struct remote_routers_st));

	rem->next = comp->r->remote_routers;
	comp->r->remote_routers = rem;
    }

    rem->online = 1;
    rem->comp = comp;
    comp->remote_router = rem;
    comp->routes = xhash_new(51);

    log_debug(ZONE, "calling _route_add(%s, %p, 1, %s, 0)", comp->id, comp, comp->id);
    _route_add(comp->id, comp, 1, comp->id, 0);

    gelem = (graph_elem_t) calloc(1, sizeof(struct graph_elem_st));
    gelem->id = strdup(comp->id);
    gelem->neighbour_next = comp->r->graph;
    comp->r->graph = gelem;

    _router_propagate_path(comp);

    return NULL;
}

static void _router_prune_graph(router_t r, graph_elem_t scan, char *last_elem_id) {
    graph_elem_t scan_ngb;
    routes_t routes;
    route_elem_t relem, *prev_next_relem;

    if (scan == NULL)
	return;

    for(scan_ngb = scan->neighbours_head; scan_ngb != NULL; scan_ngb = scan_ngb->neighbour_next)
	if (scan_ngb != scan)
	    _router_prune_graph(r, scan_ngb, scan->id);

    routes = (routes_t) xhash_get(r->rids, scan->id);

    if(routes != NULL) { // should always happen, be tolerant
	relem = routes->head;
	prev_next_relem = &routes->head;

	while(relem != NULL && strcmp(relem->id, last_elem_id) != 0) {
	    prev_next_relem = &relem->next;
	    relem = relem->next;
	}

	if(relem != NULL) { // should always happen, be tolerant
	    *prev_next_relem = relem->next; // may be NULL
	    free(relem->id);
	    free(relem);

	    if(--routes->nb_routes == 0) {
		xhash_zap(r->rids, scan->id);
		free(routes);
		free(scan->id);
		free(scan);
	    }
	}
    }
}

static const char* _router_process_path(component_t comp, nad_t nad) {
    int attr, ns;
    int elem = 0;
    unsigned int metric = 0, metric_sum = 0;
    graph_elem_t scan = comp->r->graph, *prev_next_ptr = &comp->r->graph, scan_prev = NULL;
    routes_t routes;
    route_elem_t elem_list = NULL, scan_el, tmp_bl;
    char *id, *prev_id = NULL, metric_str[11];
    char *ret = NULL;

    log_debug(ZONE, " *********** prev_next_ptr=%p", prev_next_ptr);

    for(elem = nad_find_elem(nad, elem, -1, "hop", 1); elem > 0; elem = nad_find_elem(nad, elem, -1, "hop", 0)) {

	attr = nad_find_attr(nad, elem, -1, "id", NULL);
	
	if(attr < 0) {
	    log_debug(ZONE, "[%s, port=%d] no or invalid 'id' in <hop> (<path> packet) in elem %d, bouncing", comp->ip, comp->port, elem);
	    ret = "400";
	    goto free_el;
	}

	id = (char *) malloc(NAD_AVAL_L(nad, attr) + 1);
	sprintf(id, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

	if(strcmp(id, comp->r->id) == 0)
	    break;

	if(prev_id == NULL)
	    prev_id = id;

	attr = nad_find_attr(nad, elem, -1, "metric", NULL);
	if(attr >= 0)
	    metric = j_atoi(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));
	else
	    metric = 1;

	if(metric <= 0) {
	    log_debug(ZONE, "[%s, port=%d] from '%s', invalid metric in <hop id='%s'> (<path> packet, elem=%d),  bouncing", comp->ip, comp->port, comp->id, id, elem);
	    free(id);
	    ret = "400";
	    goto free_el;
	}

	metric_sum += metric;

	while(scan != NULL && strcmp(id, scan->id) != 0) {
	    prev_next_ptr = &scan->neighbour_next;
	    log_debug(ZONE, " *********** prev_next_ptr2=%p", prev_next_ptr);
	    scan = scan->neighbour_next;
	}

	attr = nad_find_attr(nad, elem, -1, "add", NULL);

	if(attr >= 0) {
	    if(scan == NULL) { // new node
		log_debug(ZONE, "[%s, port=%d] from '%s',  *********** _router_process_path: NEW NODE id=%s, prev_id = %s", comp->ip, comp->port, comp->id, id, prev_id);
		scan = (graph_elem_t) calloc(1, sizeof(struct graph_elem_st));
		scan->id = strdup(id);
//		scan->neighbours_head = scan_prev;
		*prev_next_ptr = scan;

		if(strcmp(id, comp->r->id) != 0) { // not ourselves
		    _route_add(id, comp, metric_sum, strdup(prev_id), 0);
		    _router_advertise(comp->r, id, comp, 0, 1);
		}
	    }
	} else {
	    log_debug(ZONE, " *********** _router_process_path: NODE DEL id=%s", id);

	    if(scan == NULL)
		break; // should not happen but be tolerant

	    attr = nad_find_attr(nad, elem, -1, "del", NULL);

	    if(attr >= 0) {
		_router_prune_graph(comp->r, scan, elem_list->id);

		routes = (routes_t) xhash_get(comp->r->rids, scan->id);
		if(routes == NULL) // should not happen...
		    break;

		_router_advertise(comp->r, scan->id, comp, 1, 1);

		break;
	    }
	}

	// populate elem_list, insert at beginning
	scan_el = (route_elem_t) calloc(1, sizeof(struct route_elem_st));

	scan_el->next = elem_list;
	elem_list = scan_el;
	scan_el->id = scan->id; // no strdup()

	scan_prev = scan;
	prev_next_ptr = &scan->neighbours_head;
	scan = scan->neighbours_head;
	log_debug(ZONE, " *********** prev_next_ptr3=%p", prev_next_ptr);

	prev_id = id;
    }

    /* at least 1 <hop> */
    if(metric_sum == 0) {
	log_debug(ZONE, "[%s, port=%d] from '%s', no or invalid <hop> (<path> packet),  bouncing", comp->ip, comp->port, comp->id);
	return "400";
    }

    // now, prepend ourselves and propagate
    ns = nad_find_scoped_namespace(nad, uri_COMPONENT, NULL);
//    elem = nad_append_elem(nad, ns, "hop", 0);
    elem = nad_insert_elem(nad, 0, ns, "hop", NULL);
    nad_set_attr(nad, elem, -1, "id", comp->r->id, 0);
    snprintf(metric_str, 10, "%d", 1); // FIXME!!! => metric
    nad_set_attr(nad, elem, -1, "metric", metric_str, 0);
    nad_set_attr(nad, elem, -1, "add", "1", 0);

    // propagate to neighbours except those in path
    for(scan = comp->r->graph; scan != NULL; scan = scan->neighbour_next) {
	log_debug(ZONE, "******* SCAN->id=%s", scan->id);
	for(scan_el = elem_list; scan_el != NULL; scan_el = scan_el->next) {
	    log_debug(ZONE, "******* SCAN->id=%s, scan_el->id=%s", scan->id, scan_el->id);
	    if(strcmp(scan->id, scan_el->id) == 0)
		break;
	}

	if(scan_el == NULL) {
	    routes_t routes = (routes_t) xhash_get(comp->r->rids, scan->id);
	    component_t dest;

	    if (routes == NULL)
	    	routes = (routes_t) xhash_get(comp->r->domains, scan->id);

	    if (routes == NULL || routes->remote_router == NULL) {
		log_debug(ZONE, "******* NOT SENDING TO id=%s, no route or not router", scan->id);
		goto free_el;
	    }

	    dest = _select_domain_comp(routes);
	    log_debug(ZONE, "******* SENDING TO id=%s", dest->id);
	    sx_nad_write(dest->s, nad_copy(nad));
	}
    }


free_el:
    // free elem_list
    scan_el = elem_list;
    while(scan_el != NULL) {
	tmp_bl = scan_el->next;
	// no free(scan_el->id);
	free(scan_el);
	scan_el = tmp_bl;
    }

    return ret;
}

static void _router_process_bind(component_t comp, nad_t nad) {
    int attr, n;
    unsigned int metric = 1;
    jid_t name = NULL;
    alias_t alias;
    char *user = NULL, *c;
    char *id = NULL, *ret = NULL;

    attr = nad_find_attr(nad, 0, -1, "name", NULL);
    if(attr < 0 || (name = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "[%s, port=%d] no or invalid 'name' on bind packet, bouncing", comp->ip, comp->port);
	ret = "400";
	goto bind_error;
    }

    user = strdup(comp->s->auth_id);
    c = strchr(user, '@');
    if(c != NULL) *c = '\0';

    if(strcmp(user, name->domain) != 0 && !aci_check(comp->r->aci, "bind", user)) {
        log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] tried to bind name '%s', but their username (%s) is not permitted to bind other names", comp->ip, comp->port, name->domain, user);
	ret = "403";
	goto bind_error;
    }

    /* ID */
    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr >= 0) {
	id = (char*) malloc(NAD_AVAL_L(nad, attr) + 1);
	snprintf(id, NAD_AVAL_L(nad, attr) + 1, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
    } else
	id = strdup(name->domain);

    /* metric */
    attr = nad_find_attr(nad, 0, -1, "metric", NULL);
    if(attr >= 0)
	metric = j_atoi(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

    if(name->node != NULL && name->node[0] != '\0') {
	char *final_id, *real_id = id;

	if(strcmp(id, comp->r->id) == 0) { // ourselves
	    routes_t routes = (routes_t) xhash_get(comp->r->domains, name->domain);
	    real_id = _select_domain_comp(routes)->id;
	}

        log_debug(ZONE, "************** storing jid=%s (%s)", jid_user(name), real_id);
	_get_id_from_ids(comp->r, real_id, &final_id);
    	_store_bare_jid(comp->r, name, final_id);

	/* advertise name */
	log_debug(ZONE, "advertising about %s", jid_user(name));
	_router_advertise_user(comp->r, name, 0);

//    	goto bind_bail;
    }

    attr = nad_find_attr(nad, 0, -1, "to", NULL);
    if(attr >= 0 && (name = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) != NULL) {
	routes_t routes;

	log_debug(ZONE, "[%s, port=%d] forwarding towards %s", comp->ip, comp->port, name->domain);
	routes = (routes_t) xhash_get(comp->r->rids, name->domain);
	if (routes != NULL) {
	    component_t target_comp = _select_domain_comp(routes);
	    sx_nad_write(target_comp->s, nad_copy(nad));
	} else
	    log_debug(ZONE, "[%s, port=%d] cannot forwarding towards %s, no route", comp->ip, comp->port, name->domain);

	goto bind_bail;
    }

    if(name->node != NULL && name->node[0] != '\0')
    	goto bind_bail;

    /* default route */
    if(nad_find_elem(nad, 0, NAD_ENS(nad, 0), "default", 1) >= 0) {
	if(!aci_check(comp->r->aci, "default-route", user)) {
	    log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] tried to bind '%s' as a default route, but their username (%s) is not permitted to set a default route", comp->ip, comp->port, name->domain, user);
	    ret = "403";
	    goto bind_error;
	}

	log_write(comp->r->log, LOG_NOTICE, "'%s' set as default route, metric %d", id, metric);
    }

    /* log sinks */
    if(nad_find_elem(nad, 0, NAD_ENS(nad, 0), "log", 1) >= 0) {
	if(!aci_check(comp->r->aci, "log", user)) {
	    log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] tried to bind '%s' as a log sink, but their username (%s) is not permitted to do this", comp->ip, comp->port, name->domain, user);
	    ret = "403";
	    goto bind_error;
	}

	log_write(comp->r->log, LOG_NOTICE, "[%s] set as log sink", name->domain);

	xhash_put(comp->r->log_sinks, pstrdup(xhash_pool(comp->r->log_sinks), name->domain), (void *) comp);
    }

    comp->id = id;

    n = _route_add(name->domain, comp, metric, id, 0);
    xhash_put(comp->routes, pstrdup(xhash_pool(comp->routes), name->domain), (void *) comp);
    if(comp->remote_router == NULL)
	_send_new_neighbour(comp, name->domain);

    log_write(comp->r->log, LOG_NOTICE, "[%s]:%d, metric=%d, online ('%s' bound to %s, port %d)", name->domain, n, metric, id, comp->ip, comp->port);

    /* bind aliases */
    for(alias = comp->r->aliases; alias != NULL; alias = alias->next) {
	if(strcmp(alias->target, name->domain) == 0) {
	    _route_add(alias->name, comp, metric, strdup(id), 0);
	    xhash_put(comp->routes, pstrdup(xhash_pool(comp->routes), alias->name), (void *) comp);
	    if(comp->remote_router == NULL)
		_send_new_neighbour(comp, alias->name);

	    log_write(comp->r->log, LOG_NOTICE, "[%s] online (alias of '%s', bound to %s, port %d)", alias->name, name->domain, comp->ip, comp->port);
	}
    }

bind_error:
    nad_set_attr(nad, 0, -1, "name", NULL, 0);
    if(ret)
	nad_set_attr(nad, 0, -1, "error", ret, 3);

    log_debug(ZONE, "sending bind response to %s: %s", comp->id, ret);
    sx_nad_write(comp->s, nad);

    if(ret)
	goto bind_bail;

    /* advertise name */
    log_debug(ZONE, "advertising about %s", comp->id);
    _router_advertise(comp->r, name->domain, comp, 0, 0);

    /* advertise aliases */
    for(alias = comp->r->aliases; alias != NULL; alias = alias->next)
	if(strcmp(alias->target, name->domain) == 0) {
	    log_debug(ZONE, "advertising about alias %s", alias->name);
	    _router_advertise(comp->r, alias->name, comp, 0, 0);
	}

    /* tell the new component about everyone else */
    /* log_debug(ZONE, "informing %s about rids", comp->id); */
    /* xhash_walk(comp->r->rids, _router_advertise_reverse, (void *) comp); */
    log_debug(ZONE, "informing %s about domains", comp->id);
    xhash_walk(comp->r->rids, _router_advertise_reverse, (void *) comp);
//    xhash_walk(comp->r->domains, _router_advertise_reverse, (void *) comp);

    id = NULL;

bind_bail:

    /* done with this */

    if (id != NULL)
	free(id);
    if (user != NULL)
	free(user);
    if (name != NULL)
	jid_free(name);

    return;
}

static const char* _router_process_unbind(component_t comp, nad_t nad) {
    int attr;
    jid_t name;
    char *id;
    unsigned int metric;

    attr = nad_find_attr(nad, 0, -1, "name", NULL);
    if(attr < 0 || (name = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "no or invalid 'name' on unbind packet, bouncing");
        return "400";
    }

    /* ID */
    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr >= 0) {
	id = (char*) malloc(NAD_AVAL_L(nad, attr) + 1);
	snprintf(id, NAD_AVAL_L(nad, attr) + 1, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
    } else
	id = name->domain;

    /* metric */
    attr = nad_find_attr(nad, 0, -1, "metric", NULL);
    if(attr >= 0)
	metric = j_atoi(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));
    else
	metric = 1;

    _route_remove(name->domain, comp, metric, id);

    xhash_zap(comp->routes, name->domain);
    xhash_zap(comp->r->log_sinks, name->domain);

    if(name->domain != NULL && name->domain[0] == '\0')
	log_write(comp->r->log, LOG_NOTICE, "[%s] default route offline", name->domain);
    else
	log_write(comp->r->log, LOG_NOTICE, "[%s] offline", name->domain);

    /* deadvertise name */
//    if(xhash_get(comp->r->domains, name->domain) == NULL)
    if(xhash_get(comp->r->rids, name->domain) == NULL)
	_router_advertise(comp->r, name->domain, comp, 1, 0);

    jid_free(name);
    free(id);

    return NULL;
}

static void _router_comp_write(component_t comp, nad_t nad) {
    int attr;

    if(comp->tq != NULL) {
        log_debug(ZONE, "%s port %d is throttled, jqueueing packet", comp->ip, comp->port);
        jqueue_push(comp->tq, nad, 0);
        return;
    }

    /* packets go raw to normal components */
    if(!comp->legacy) {
        sx_nad_write(comp->s, nad);
        return;
    }

    log_debug(ZONE, "packet for legacy component, munging");

    attr = nad_find_attr(nad, 0, -1, "error", NULL);
    if(attr >= 0) {
        if(NAD_AVAL_L(nad, attr) == 3 && strncmp("400", NAD_AVAL(nad, attr), 3) == 0)
            stanza_error(nad, 1, stanza_err_BAD_REQUEST);
        else
            stanza_error(nad, 1, stanza_err_SERVICE_UNAVAILABLE);
    }

    sx_nad_write_elem(comp->s, nad, 1);
}

static void _router_route_log_sink(const char *key, int keylen, void *val, void *arg) {
    component_t comp = (component_t) val;
    nad_t nad = (nad_t) arg;

    log_debug(ZONE, "copying route to '%.*s' (%s, port %d)", keylen, key, comp->ip, comp->port);

    nad = nad_copy(nad);
    nad_set_attr(nad, 0, -1, "type", "log", 3);
    _router_comp_write(comp, nad);
}

static const char* _router_process_bind_level(component_t comp, nad_t nad) {
    int ato, avia;
    struct jid_st sto;
    jid_static_buf sto_buf;
    jid_t to = NULL;
    routes_t domain_targets;
    component_t target_comp = NULL;

    /* init static jid */
    jid_static(&sto,&sto_buf);

    ato = nad_find_attr(nad, 0, -1, "to", NULL);
    avia = nad_find_attr(nad, 0, -1, "via", NULL);

    if(ato < 0)
	return "400";

    to = jid_reset(&sto, NAD_AVAL(nad, ato), NAD_AVAL_L(nad, ato));

    /* find a target */
    domain_targets = (routes_t) xhash_get(comp->r->domains, to->domain);
    if(domain_targets == NULL)
	return "404";
    else if(domain_targets->nb_routes == 1) {
	target_comp = domain_targets->head->comp;
    } else { // domain_targets->nb_routes > 1
	log_debug(ZONE, "*********** BIND-LEVEL nb_routes > 1 for %s (%d)", jid_user(to), domain_targets->nb_routes);

	if(avia >= 0) {
	    log_debug(ZONE, "via is %.*s", NAD_AVAL_L(nad, avia), NAD_AVAL(nad, avia));
	    if(strlen(comp->r->id) == NAD_AVAL_L(nad, avia) && strncmp(comp->r->id, NAD_AVAL(nad, avia), NAD_AVAL_L(nad, avia)) == 0) {
		log_debug(ZONE, "via is ME, so forward to %s", to->domain);
		domain_targets = xhash_get(comp->r->domains, to->domain);
		target_comp = domain_targets->head->comp; // FIXME: verify domain_targets != NULL
	    } else
		domain_targets = xhash_getx(comp->r->rids, NAD_AVAL(nad, avia), NAD_AVAL_L(nad, avia));

	    if(domain_targets == NULL) {
		log_debug(ZONE, "via '%.*s' is not found, bouncing", NAD_AVAL_L(nad, avia), NAD_AVAL(nad, avia));
		return "404";
	    }
	    if(target_comp == NULL)
		target_comp = _select_domain_comp(domain_targets);

	} else {
	    target_comp = _select_domain_comp(domain_targets);
	    const char *via = target_comp->id;
	    nad_set_attr(nad, 0, -1, "via", via, 0);
	}

	log_debug(ZONE, "*********** BIND-LEVEL goes to %s", target_comp->id);
    }     

    sx_nad_write(target_comp->s, nad);
    return NULL;
}

static const char* _router_process_route(component_t comp, nad_t nad) {
    int atype, ato, afrom, avia, atarget;
    struct jid_st sto, sfrom, starget;
    jid_static_buf sto_buf, sfrom_buf, starget_buf;
    jid_t to = NULL, from = NULL, target = NULL;
    routes_t domain_targets;
    component_t target_comp = NULL;
    union xhashv xhv;
    int is_domain = 1;

    /* init static jid */
    jid_static(&sto,&sto_buf);
    jid_static(&sfrom,&sfrom_buf);

    atype = nad_find_attr(nad, 0, -1, "type", NULL);
    ato = nad_find_attr(nad, 0, -1, "to", NULL);
    afrom = nad_find_attr(nad, 0, -1, "from", NULL);
    avia = nad_find_attr(nad, 0, -1, "via", NULL);
    atarget = nad_find_attr(nad, 0, -1, "target", NULL);

    if(ato >= 0) to = jid_reset(&sto, NAD_AVAL(nad, ato), NAD_AVAL_L(nad, ato));
    if(afrom >= 0) from = jid_reset(&sfrom, NAD_AVAL(nad, afrom), NAD_AVAL_L(nad, afrom));

    /* unicast */
    if(atype < 0) {
        if(to == NULL || from == NULL) {
            log_debug(ZONE, "unicast route with missing or invalid to or from, bouncing");
            return "400";
        }
        
        log_debug(ZONE, "unicast route from %s to %s", from->domain, to->domain);

        /* check the from */
        /* if(xhash_get(comp->routes, from->domain) == NULL) { */
        /*     log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] '%s' tried to send a packet from '%s', but that name is not bound to this component", comp->ip, comp->port, comp->id, from->domain); */
        /*     return "401"; */
        /* } */

        /* filter it */
        if(comp->r->filter != NULL) {
            int ret = filter_packet(comp->r, nad);
            if(ret == stanza_err_REDIRECT) {
                ato = nad_find_attr(nad, 0, -1, "to", NULL);
                if(ato >= 0) to = jid_reset(&sto, NAD_AVAL(nad, ato), NAD_AVAL_L(nad, ato));
            }
            else if(ret > 0) {
                log_debug(ZONE, "packet filtered out: %s (%s)", _stanza_errors[ret - stanza_err_BAD_REQUEST].name, _stanza_errors[ret - stanza_err_BAD_REQUEST].code);
                return _stanza_errors[ret - stanza_err_BAD_REQUEST].code;
            }
        }

        if((from->domain == NULL || from->domain[0] == '\0') && (to->domain == NULL || to->domain[0] == '\0')) {
            log_debug(ZONE, "%s is unbound, bouncing", from->domain);
            return "404";
        }

        /* find a target */
        domain_targets = (routes_t) xhash_get(comp->r->domains, to->domain);

        if(domain_targets == NULL) {
	    domain_targets = (routes_t) xhash_get(comp->r->rids, to->domain);
	    is_domain = 0;
	}

	if(domain_targets == NULL) {
	    domain_targets = (routes_t) xhash_get(comp->r->rids, ""); // default route
//	    domain_targets = (routes_t) xhash_get(comp->r->domains, ""); // default route

	    if(domain_targets == NULL) {
		log_debug(ZONE, "%s is unbound, and no default route, bouncing", to->domain);
		return "404";
	    }

            target_comp = _select_domain_comp(domain_targets);
        } else if(domain_targets->nb_routes == 1) {
	    target_comp = domain_targets->head->comp;
        } else { // domain_targets->nb_routes > 1
            if(domain_targets->legacy) {
                unsigned char hashval[20];
                unsigned int *val, dest;
                int i;
                route_elem_t scan;
                
                ato = nad_find_attr(nad, 1, -1, "from", NULL);
                if(ato < 0) {
                    const char *out; int len;
                    nad_print(nad, 0, &out, &len);
                    log_write(comp->r->log, LOG_ERR, "Cannot get source for legacy route: %.*s", len, out);
                    target_comp = _select_domain_comp(domain_targets); // what to do?
                } else {
                    to = jid_reset(&sto, NAD_AVAL(nad, ato), NAD_AVAL_L(nad, ato));
                    shahash_raw(jid_user(to), hashval);
                
                    val = (unsigned int *) hashval;
                    dest = *val;
                    for(i=1; i < 20 / (sizeof(unsigned int)/sizeof(unsigned char)); i++, val++) {
                        dest ^= *val;
                    }
                    dest >>= 2;
                    dest = dest % domain_targets->nb_routes;

                    for(scan = domain_targets->head; scan != NULL && dest > 0; scan = scan->next)
			--dest;

                    assert(scan != NULL);
                    target_comp = scan->comp;
                }
            } else {
		log_debug(ZONE, "*********** nb_routes > 1 for %s (%d)", jid_user(to), domain_targets->nb_routes);

                if(atarget < 0 && (to->node == NULL || to->node[0] == '\0')) {
		    if(avia >= 0) {
			log_debug(ZONE, "via is %.*s", NAD_AVAL_L(nad, avia), NAD_AVAL(nad, avia));
			if(strlen(comp->r->id) == NAD_AVAL_L(nad, avia) && strncmp(comp->r->id, NAD_AVAL(nad, avia), NAD_AVAL_L(nad, avia)) == 0) {
			    log_debug(ZONE, "via is ME, so forward to %s", to->domain);
			    domain_targets = xhash_get(comp->r->domains, to->domain);
			    target_comp = domain_targets->head->comp;
			} else
			    domain_targets = xhash_getx(comp->r->rids, NAD_AVAL(nad, avia), NAD_AVAL_L(nad, avia));

			if(domain_targets == NULL) {
			    log_debug(ZONE, "via '%.*s' is not found, bouncing", NAD_AVAL_L(nad, avia), NAD_AVAL(nad, avia));
			    return "404";
			}
			if(target_comp == NULL)
			    target_comp = _select_domain_comp(domain_targets);

		    } else if(is_domain) {
			target_comp = _select_domain_comp(domain_targets);
			const char *via = target_comp->id;
			nad_set_attr(nad, 0, -1, "via", via, 0);
		    } else
			target_comp = _select_domain_comp(domain_targets);
                } else {
                    char *id;

		    log_debug(ZONE, "*********** nb_routes > 1 && node or target exists for to=%s", jid_user(to));

		    jid_static(&starget, &starget_buf);
		    if(atarget >= 0) {
			target = jid_reset(&starget, NAD_AVAL(nad, atarget), NAD_AVAL_L(nad, atarget));
			nad_set_attr(nad, 0, -1, "target", NULL, 0);

			if(!_get_id_from_bare_jid(comp->r, target, &id, &target_comp)) { // auto-bind?
			    nad_t nad_bind;
			    route_elem_t relem;
			    int ns;

			    _store_bare_jid(comp->r, target, id);

			    log_debug(ZONE, "*********** AUTO-BIND %s", jid_user(target));

			    nad_bind = nad_new();
			    ns = nad_add_namespace(nad_bind, uri_COMPONENT, NULL);
			    nad_append_elem(nad_bind, ns, "bind", 0);
			    nad_append_attr(nad_bind, -1, "name", jid_user(target));
			    nad_append_attr(nad_bind, -1, "id", target_comp->id);

			    for(relem = domain_targets->head; relem != NULL; relem = relem->next) {
				if(relem->comp->remote_router != NULL) {
				    log_debug(ZONE, "*********** sending BIND to %s through %s", relem->id, relem->comp->id);
				    nad_set_attr(nad_bind, 0, -1, "to", relem->id, 0);
				    sx_nad_write(relem->comp->s, nad_copy(nad_bind));
				}
			    }

			    nad_free(nad_bind);
			}
			log_debug(ZONE, "*********** %s/%s goes to %s", jid_user(target), jid_user(to), target_comp->id);
		    } else if(to->node == NULL || to->node[0] == '\0') {
			target_comp = _select_domain_comp(domain_targets);
			log_debug(ZONE, "*********** %s goes(2) to %s", jid_user(to), target_comp->id);
		    } else {
			_get_id_from_bare_jid(comp->r, to, &id, &target_comp);
			log_debug(ZONE, "*********** %s goes(3) to %s", jid_user(to), target_comp->id);
		    }
                }
            }
        }

	if(target_comp->remote_router == NULL)
	    nad_set_attr(nad, 0, -1, "via", NULL, 0);

        /* copy to any log sinks */
        if(xhash_count(comp->r->log_sinks) > 0)
            xhash_walk(comp->r->log_sinks, _router_route_log_sink, (void *) nad);

        /* jid_user() calls jid_expand() which may allocate some memory in _user and _full */
        if(to->_user != NULL)
            free(to->_user);
        if(to->_full != NULL)
            free(to->_full);
	if(target != NULL) {
	    if(target->_user != NULL)
		free(target->_user);
	    if(target->_full != NULL)
		free(target->_full);
	}

        /* push it out */
        log_debug(ZONE, "writing route for '%s' to %s, port %d", to->domain, target_comp->ip, target_comp->port);

        /* if logging enabled, log messages that match our criteria */
        if (comp->r->message_logging_enabled && comp->r->message_logging_file != NULL) {
            int attr_msg_to;
            int attr_msg_from;
            int attr_route_to;
            int attr_route_from;
            jid_t jid_msg_from = NULL;
            jid_t jid_msg_to = NULL;
            jid_t jid_route_from = NULL;
            jid_t jid_route_to = NULL;

            if ((NAD_ENAME_L(nad, 1) == 7 && strncmp("message", NAD_ENAME(nad, 1), 7) == 0) &&          // has a "message" element 
                ((attr_route_from = nad_find_attr(nad, 0, -1, "from", NULL)) >= 0) &&
                ((attr_route_to = nad_find_attr(nad, 0, -1, "to", NULL)) >= 0) &&
                ((strncmp(NAD_AVAL(nad, attr_route_to), "c2s", 3)) != 0) &&                                                     // ignore messages to "c2s" or we'd have dups
                ((jid_route_from = jid_new(NAD_AVAL(nad, attr_route_from), NAD_AVAL_L(nad, attr_route_from))) != NULL) &&       // has valid JID source in route
                ((jid_route_to = jid_new(NAD_AVAL(nad, attr_route_to), NAD_AVAL_L(nad, attr_route_to))) != NULL) &&             // has valid JID destination in route
                ((attr_msg_from = nad_find_attr(nad, 1, -1, "from", NULL)) >= 0) &&
                ((attr_msg_to = nad_find_attr(nad, 1, -1, "to", NULL)) >= 0) &&
                ((jid_msg_from = jid_new(NAD_AVAL(nad, attr_msg_from), NAD_AVAL_L(nad, attr_msg_from))) != NULL) &&     // has valid JID source in message 
                ((jid_msg_to = jid_new(NAD_AVAL(nad, attr_msg_to), NAD_AVAL_L(nad, attr_msg_to))) != NULL))                     // has valid JID dest in message
            {
                message_log(nad, comp->r, jid_full(jid_msg_from), jid_full(jid_msg_to));
            }
            if (jid_msg_from != NULL)
                jid_free(jid_msg_from);
            if (jid_msg_to != NULL)
                jid_free(jid_msg_to);
            if (jid_route_from != NULL)
                jid_free(jid_route_from);
            if (jid_route_to != NULL)
                jid_free(jid_route_to);
        }

        _router_comp_write(target_comp, nad);

        return NULL;
    }

    /* broadcast */
    if(NAD_AVAL_L(nad, atype) == 9 && strncmp("broadcast", NAD_AVAL(nad, atype), 9) == 0) {
        if(from == NULL) {
            log_debug(ZONE, "broadcast route with missing or invalid from, bouncing");
            return "400";
        }
        
        log_debug(ZONE, "broadcast route from %s", from->domain);

        /* check the from */
        if(xhash_get(comp->routes, from->domain) == NULL) {
            log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] tried to send a packet from '%s', but that name is not bound to this component", comp->ip, comp->port, from->domain);
            return "401";
        }

        /* loop the components and distribute */
        if(xhash_iter_first(comp->r->components))
            do {
                xhv.comp_val = &target_comp;
                xhash_iter_get(comp->r->components, NULL, NULL, xhv.val);

                if(target_comp != comp) {
		    nad_t tmp_nad = nad_copy(nad);
                    log_debug(ZONE, "writing broadcast to '%s' (%s, port %d)", target_comp->id, target_comp->ip, target_comp->port);

		    nad_append_attr(tmp_nad, -1, "to", target_comp->id);
                    _router_comp_write(target_comp, tmp_nad);
                }
            } while(xhash_iter_next(comp->r->components));

        nad_free(nad);

        return NULL;
    }

    log_debug(ZONE, "unknown route type '%.*s', dropping", NAD_AVAL_L(nad, atype), NAD_AVAL(nad, atype));

    nad_free(nad);

    return NULL;
}

static void _router_process_throttle(component_t comp, nad_t nad) {
    jqueue_t tq;
    nad_t pkt;

    if(comp->tq == NULL) {
        _router_comp_write(comp, nad);

        log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] throttling packets on request", comp->ip, comp->port);
        comp->tq = jqueue_new();
    }

    else {
        log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] unthrottling packets on request", comp->ip, comp->port);
        tq = comp->tq;
        comp->tq = NULL;

        _router_comp_write(comp, nad);

        while((pkt = jqueue_pull(tq)) != NULL)
            _router_comp_write(comp, pkt);

        jqueue_free(tq);
    }
}

int router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    component_t comp = (component_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    int rlen, len, attr, ns, sns, n;
    sx_error_t *sxe;
    nad_t nad;
    struct jid_st sto, sfrom;
    jid_static_buf sto_buf, sfrom_buf;
    jid_t to, from;
    alias_t alias;

    /* init static jid */
    jid_static(&sto,&sto_buf);
    jid_static(&sfrom,&sfrom_buf);

    switch(e) {
        case event_WANT_READ:
            log_debug(ZONE, "want read");
            mio_read(comp->r->mio, comp->fd);
            break;

        case event_WANT_WRITE:
            log_debug(ZONE, "want write");
            mio_write(comp->r->mio, comp->fd);
            break;

        case event_READ:
            log_debug(ZONE, "reading from %d", comp->fd->fd);

            /* check rate limits */
            if(comp->rate != NULL) {
                if(rate_check(comp->rate) == 0) {

                    /* inform the app if we haven't already */
                    if(!comp->rate_log) {
                        log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] is being byte rate limited", comp->ip, comp->port);

                        comp->rate_log = 1;
                    }

                    log_debug(ZONE, "%d is throttled, delaying read", comp->fd->fd);

                    buf->len = 0;
                    return 0;
                }

                /* find out how much we can have */
                rlen = rate_left(comp->rate);
                if(rlen > buf->len)
                    rlen = buf->len;
            }

            /* no limit, just read as much as we can */
            else
                rlen = buf->len;
            
            /* do the read */
            len = recv(comp->fd->fd, buf->data, rlen, 0);

            /* update rate limits */
            if(comp->rate != NULL && len > 0) {
                comp->rate_log = 0;
                rate_add(comp->rate, len);
            }

            if(len < 0) {
                if(MIO_WOULDBLOCK) {
                    buf->len = 0;
                    return 0;
                }

                log_debug(ZONE, "read failed: %s", strerror(errno));

                sx_kill(comp->s);
                
                return -1;
            }

            else if(len == 0) {
                /* they went away */
                sx_kill(comp->s);

                return -1;
            }

            log_debug(ZONE, "read %d bytes", len);

            buf->len = len;

            return len;

        case event_WRITE:
            log_debug(ZONE, "writing to %d", comp->fd->fd);

            len = send(comp->fd->fd, buf->data, buf->len, 0);
            if(len >= 0) {
                log_debug(ZONE, "%d bytes written", len);
                return len;
            }

            if(MIO_WOULDBLOCK)
                return 0;

            log_debug(ZONE, "write failed: %s", strerror(errno));
        
            sx_kill(comp->s);
        
            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] error: %s (%s)", comp->ip, comp->port, sxe->generic, sxe->specific);

            break;

        case event_STREAM:
            
            /* legacy check */
            if(s->ns == NULL || strcmp("jabber:component:accept", s->ns) != 0)
                return 0;

            /* component, old skool */
            comp->legacy = 1;

            /* enabled? */
            if(comp->r->local_secret == NULL) {
                sx_error(s, stream_err_INVALID_NAMESPACE, "support for legacy components not available");      /* !!! correct error? */
                sx_close(s);
                return 0;
            }
            
            /* sanity */
            if(s->req_to == NULL) {
                sx_error(s, stream_err_HOST_UNKNOWN, "no 'to' attribute on stream header");
                sx_close(s);
                return 0;
            }

            break;

        case event_OPEN:
            
            log_write(comp->r->log, LOG_NOTICE, "[%s, port=%d] authenticated as %s", comp->ip, comp->port, comp->s->auth_id);

            /* make a route for legacy components */
            if(comp->legacy) {
                for(alias = comp->r->aliases; alias != NULL; alias = alias->next)
                    if(strcmp(alias->name, s->req_to) == 0) {
                        sx_error(s, stream_err_HOST_UNKNOWN, "requested name is aliased");   /* !!! correct error? */
                        sx_close(s);
                        return 0;
                    }


		comp->id = strdup(comp->s->auth_id);

                n = _route_add(s->req_to, comp, 1, comp->id, 0);
                xhash_put(comp->routes, pstrdup(xhash_pool(comp->routes), s->req_to), (void *) comp);
		_send_new_neighbour(comp, s->req_to);

		log_write(comp->r->log, LOG_NOTICE, "[%s]:%d online (bound to %s, port %d)", s->req_to, n, comp->ip, comp->port);

                /* advertise the name */
                _router_advertise(comp->r, s->req_to, comp, 0, 0);

                /* this is a legacy component, so we don't tell it about other routes */

                /* bind aliases */
                for(alias = comp->r->aliases; alias != NULL; alias = alias->next) {
                    if(strcmp(alias->target, s->req_to) == 0) {
                        _route_add(alias->name, comp, 1, comp->id, 1);
                        xhash_put(comp->routes, pstrdup(xhash_pool(comp->routes), alias->name), (void *) comp);
			_send_new_neighbour(comp, alias->name);
            
                        log_write(comp->r->log, LOG_NOTICE, "[%s] online (alias of '%s', bound to %s, port %d)", alias->name, s->req_to, comp->ip, comp->port);

                        /* advertise name */
                        _router_advertise(comp->r, alias->name, comp, 0, 0);
                    }
                }

		break;
            }

            /* remote routers */
            if(comp->remote_router) {
		log_write(comp->r->log, LOG_NOTICE, "connection to remote router established");

		nad = nad_new();
		ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
		nad_append_elem(nad, ns, "router", 0);
		nad_append_attr(nad, -1, "id", comp->r->id);

		log_debug(ZONE, "requesting remote router bind for '%s'", comp->r->id);

		sx_nad_write(comp->s, nad);
	    }

            break;

        case event_PACKET:
            nad = (nad_t) data;
	    routes_t to_routes;

            /* preauth */
            if(comp->s->state == state_STREAM) {
                /* non-legacy components can't do anything before auth */
                if(!comp->legacy && !comp->remote_router) {
                    log_debug(ZONE, "stream is preauth, dropping packet");
                    nad_free(nad);
                    return 0;
                }

		/* remote routers */
		if(comp->remote_router) {
		    if(comp->remote_router->outbound == 0)
			return 0;

		    if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_STREAMS) || strncmp(uri_STREAMS, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_STREAMS)) != 0 || NAD_ENAME_L(nad, 0) != 8 || strncmp("features", NAD_ENAME(nad, 0), 8) != 0) {
			log_debug(ZONE, "got a non-features packet on an unauth'd stream, dropping");
			nad_free(nad);
			return 0;
		    }

#ifdef HAVE_SSL
		    /* starttls if we can */
		    if(comp->r->sx_ssl != NULL && comp->remote_router->pemfile != NULL && s->ssf == 0) {
			ns = nad_find_scoped_namespace(nad, uri_TLS, NULL);
			if(ns >= 0) {
			    int elem = nad_find_elem(nad, 0, ns, "starttls", 1);
			    if(elem >= 0) {
				if(sx_ssl_client_starttls(comp->r->sx_ssl, s, comp->remote_router->pemfile) == 0) {
				    nad_free(nad);
				    return 0;
				}
				log_write(comp->r->log, LOG_NOTICE, "unable to establish encrypted session with router");
			    }
			}
		    }
#endif

		    /* !!! pull the list of mechanisms, and choose the best one.
		     *     if there isn't an appropriate one, error and bail */

		    /* authenticate */
		    sx_sasl_auth(comp->r->sx_sasl, s, "jabberd-router", "DIGEST-MD5", comp->remote_router->user, comp->remote_router->pass);

		    nad_free(nad);
		    return 0;
		}

                /* watch for handshake requests */
                if(NAD_ENAME_L(nad, 0) != 9 || strncmp("handshake", NAD_ENAME(nad, 0), NAD_ENAME_L(nad, 0)) != 0) { 
                    log_debug(ZONE, "unknown preauth packet %.*s, dropping", NAD_ENAME_L(nad, 0), NAD_ENAME(nad, 0));

                    nad_free(nad);
                    return 0;
                }

                /* process incoming handshakes */
                _router_process_handshake(comp, nad);

                return 0;
            }

            /* legacy processing */
            if(comp->legacy) {
                log_debug(ZONE, "packet from legacy component, munging it");

                attr = nad_find_attr(nad, 0, -1, "to", NULL);
                if(attr < 0 || (to = jid_reset(&sto, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
                    log_debug(ZONE, "invalid or missing 'to' address on legacy packet, dropping it");
                    nad_free(nad);
                    return 0;
                }

                attr = nad_find_attr(nad, 0, -1, "from", NULL);
                if(attr < 0 || (from = jid_reset(&sfrom, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
                    log_debug(ZONE, "invalid or missing 'from' address on legacy packet, dropping it");
                    nad_free(nad);
                    return 0;
                }

                /* rewrite component packets into client packets */
                ns = nad_find_namespace(nad, 0, "jabber:component:accept", NULL);
                if(ns >= 0) {
                    if(nad->elems[0].ns == ns)
                        nad->elems[0].ns = nad->nss[nad->elems[0].ns].next;
                    else {
                        for(sns = nad->elems[0].ns; sns >= 0 && nad->nss[sns].next != ns; sns = nad->nss[sns].next);
                        nad->nss[sns].next = nad->nss[nad->nss[sns].next].next;
                    }
                }

                ns = nad_find_namespace(nad, 0, uri_CLIENT, NULL);
                if(ns < 0) {
                    ns = nad_add_namespace(nad, uri_CLIENT, NULL);
                    nad->scope = -1;
                    nad->nss[ns].next = nad->elems[0].ns;
                    nad->elems[0].ns = ns;
                }
                nad->elems[0].my_ns = ns;

                /* wrap up the packet */
                ns = nad_add_namespace(nad, uri_COMPONENT, NULL);

                nad_wrap_elem(nad, 0, ns, "route");

                nad_set_attr(nad, 0, -1, "to", to->domain, 0);
                nad_set_attr(nad, 0, -1, "from", from->domain, 0);
            }

            /* top element must be router scoped */
            if(NAD_ENS(nad, 0) < 0 || NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT) || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0) {
                log_debug(ZONE, "invalid packet namespace, dropping");
                nad_free(nad);
                return 0;
            }

	    // !!! if (!comp->remote_router) // don't drop errors from remote routers?
	    if(nad_find_attr(nad, 0, -1, "error", NULL) >= 0) {
		log_debug(ZONE, "dropping error packet, trying to avoid loops");
		nad_free(nad);
		return 0;
	    }

            /* route packets */
            if(NAD_ENAME_L(nad, 0) == 5 && strncmp("route", NAD_ENAME(nad, 0), 5) == 0) {
                const char *ret = _router_process_route(comp, nad);

                if(ret) {
                    nad_set_attr(nad, 0, -1, "error", ret, 3);
		    _router_comp_write(comp, nad);
		}

                return 0;
            }

            /* route packets */
            if(NAD_ENAME_L(nad, 0) == 10 && strncmp("bind-level", NAD_ENAME(nad, 0), 10) == 0) {
                const char *ret = _router_process_bind_level(comp, nad);

                if(ret) {
                    nad_set_attr(nad, 0, -1, "error", ret, 3);
		    _router_comp_write(comp, nad);
		}

                return 0;
            }

            /* throttle packets */
            if(NAD_ENAME_L(nad, 0) == 8 && strncmp("throttle", NAD_ENAME(nad, 0), 8) == 0) {
                _router_process_throttle(comp, nad);
                return 0;
            }

	    /* /\* to *\/ */
	    /* attr = nad_find_attr(nad, 0, -1, "to", NULL); */
	    /* if(attr >= 0 && strncmp(NAD_AVAL(nad, attr), comp->r->id, NAD_AVAL_L(nad, attr)) != 0) { */
	    /* 	to_routes = xhash_getx(comp->r->rids, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr)); */
	    /* 	if (to_routes == NULL) */
	    /* 	    to_routes = xhash_getx(comp->r->domains, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr)); */
	    /* 	if (to_routes == NULL) */
	    /* 	    log_write(comp->r->log, LOG_ERR, "unable to route packet to '%.*s', unknown route", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr)); */
	    /* 	else */
	    /* 	    sx_nad_write(_select_domain_comp(to_routes)->s, nad); */
	    /* 	return 0; */
	    /* } */

            /* bind a name to this component */
            if(NAD_ENAME_L(nad, 0) == 4 && strncmp("bind", NAD_ENAME(nad, 0), 4) == 0) {
                _router_process_bind(comp, nad);

                return 0;
            }

            /* unbind a name from this component */
            if(NAD_ENAME_L(nad, 0) == 6 && strncmp("unbind", NAD_ENAME(nad, 0), 6) == 0) {
                const char *ret = _router_process_unbind(comp, nad);

		nad_set_attr(nad, 0, -1, "name", NULL, 0);
                if (ret)
                    nad_set_attr(nad, 0, -1, "error", ret, 3);

		sx_nad_write(comp->s, nad);
                return 0;
            }

            /* bulk-(un)bind names to this component */
            if((NAD_ENAME_L(nad, 0) == 9 && strncmp("bulk-bind", NAD_ENAME(nad, 0), 9) == 0) ||
	       (NAD_ENAME_L(nad, 0) == 11 && strncmp("bulk-unbind", NAD_ENAME(nad, 0), 11) == 0)) {
		jid_t name;
		int attr, elem = 0, unbind;
		char *id, *action;
		struct broadcast_id_st bci;

		if(NAD_ENAME_L(nad, 0) == 9) { // bulk-bind
		    action = "bulk-bind";
		    unbind = 0;
		} else {
		    action = "bulk-unbind";
		    unbind = 1;
		}

		// process the children
		for (elem = nad_find_elem(nad, elem, 0, "bind", 1); elem > 0; elem = nad_find_elem(nad, elem, 0, "bind", 0)) {
		    attr = nad_find_attr(nad, elem, -1, "name", NULL);

		    if(attr < 0 || (name = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
			log_debug(ZONE, "[%s, port=%d] no or invalid 'name' in %s packet in elem %d, bouncing", comp->ip, comp->port, action, elem);
			nad_set_attr(nad, elem, -1, "error", "400", 3);
		    } else if (unbind)
			_zap_bare_jid(comp->r, name);
		    else {
			component_t target_comp;
			char *id;

			_get_id_from_bare_jid(comp->r, name, &id, &target_comp);
			_store_bare_jid(comp->r, name, id);
		    }
		}

		if (comp->remote_router == NULL) {
		    bci.src = comp->id;
		    bci.nad = nad;
		    bci.r = comp->r;
		    xhash_walk(comp->r->rids, _router_broadcast_ids, (void *) &bci);
		}

                return 0;
            }

            /* bind a remote router to this component */
            if(NAD_ENAME_L(nad, 0) == 6 && strncmp("router", NAD_ENAME(nad, 0), 6) == 0) {
                const char *ret = NULL, *old_id = comp->id;
		int attr, response = 0;
		remote_routers_t rem = NULL;

		if((attr = nad_find_attr(nad, 0, -1, "id", NULL)) < 0) {
		    if((attr = nad_find_attr(nad, 0, -1, "other-id", NULL)) < 0) {
			log_debug(ZONE, "<router> without id nor other-id, dropping");
			nad_free(nad);
			return 0;
		    }
		    
		    log_debug(ZONE, "<router> with other-id was a response, old id = %s", old_id);
		    response = 1;

		    if(old_id == NULL) {
			comp->id = (char *) malloc(NAD_AVAL_L(nad, attr) + 1);
			sprintf(comp->id, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
			rem = comp->remote_router;

			log_debug(ZONE, "<router> with other-id='%s' was a response, remembering id", comp->id);
		    }
		} else {
		    comp->id = (char *) malloc(NAD_AVAL_L(nad, attr) + 1);
		    sprintf(comp->id, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
		}

                ret = _router_process_remote_router(comp, nad, rem);

		if(response) {
		    nad_free(nad);
		    return 0;
		}

                if(ret)
                    nad_set_attr(nad, 0, -1, "error", ret, 3);

		nad_set_attr(nad, 0, -1, "id", NULL, 0);
		nad_set_attr(nad, 0, -1, "other-id", comp->r->id, 0);

		sx_nad_write(comp->s, nad);
                return 0;
            }

            /* path info */
            if(NAD_ENAME_L(nad, 0) == 4 && strncmp("path", NAD_ENAME(nad, 0), 4) == 0) {
                const char *ret;
		int attr;

		attr = nad_find_attr(nad, 0, -1, "id", NULL);
		if(attr < 0) {
		    log_debug(ZONE, "<path> without id was a response, dropping");
		    nad_free(nad);
		    return 0;
		}

		if(strlen(comp->r->id) == NAD_AVAL_L(nad, attr) && strncmp(NAD_AVAL(nad, attr), comp->r->id, NAD_AVAL_L(nad, attr)) == 0) {
		    log_debug(ZONE, "<path> id was ours, dropping");
		    nad_free(nad);
		    return 0;
		}

                ret = _router_process_path(comp, nad);

                if(ret)
                    nad_set_attr(nad, 0, -1, "error", ret, 3);

		nad_set_attr(nad, 0, -1, "id", NULL, 0);
		sx_nad_write(comp->s, nad);
                return 0;
            }

            log_debug(ZONE, "unknown packet, dropping");

            nad_free(nad);
            return 0;

        case event_CLOSED:
        {
            /* close comp->fd by putting it in closefd ... unless it is already there */
            _jqueue_node_t n;
            for (n = comp->r->closefd->front; n != NULL; n = n->prev)
                if (n->data == comp->fd) break;
            if (!n) jqueue_push(comp->r->closefd, (void *) comp->fd, 0 /*priority*/);
            return 0;
        }
    }

    return 0;
}

static int _router_accept_check(router_t r, mio_fd_t fd, const char *ip) {
    rate_t rt;

    if(access_check(r->access, ip) == 0) {
        log_write(r->log, LOG_NOTICE, "[%d] [%s] access denied by configuration", fd->fd, ip);
        return 1;
    }

    if(r->conn_rate_total != 0) {
        rt = (rate_t) xhash_get(r->conn_rates, ip);
        if(rt == NULL) {
            rt = rate_new(r->conn_rate_total, r->conn_rate_seconds, r->conn_rate_wait);
            xhash_put(r->conn_rates, pstrdup(xhash_pool(r->conn_rates), ip), (void *) rt);
        }

        if(rate_check(rt) == 0) {
            log_write(r->log, LOG_NOTICE, "[%d] [%s] is being rate limited", fd->fd, ip);
            return 1;
        }

        rate_add(rt, 1);
    }

    return 0;
}

static void _router_route_unbind_walker(const char *key, int keylen, void *val, void *arg) {
    component_t comp = (component_t) arg;
    xht domain_bares;
    char * local_key;

    xhash_zapx(comp->r->log_sinks, key, keylen);
    local_key = (char *) malloc(keylen + 1);
    memcpy(local_key, key, keylen);
    local_key[keylen] = '\0';
    _route_remove_all(local_key, comp);
    xhash_zapx(comp->routes, key, keylen);

    if(keylen == 0)
        log_write(comp->r->log, LOG_NOTICE, "default route offline");
    else
        log_write(comp->r->log, LOG_NOTICE, "[%.*s] offline", keylen, key);

    /* deadvertise name */
//    if(xhash_getx(comp->r->domains, key, keylen) == NULL)
    if(xhash_getx(comp->r->rids, key, keylen) == NULL)
        _router_advertise(comp->r, local_key, comp, 1, 0);

    if((domain_bares = xhash_getx(comp->r->bare_jids, key, keylen)) != NULL) {
	struct broadcast_id_st bci;
	int ns, send_it = 0;
	nad_t nad = nad_new();

	ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
	nad_append_elem(nad, ns, "bulk-unbind", 0);
	nad_append_attr(nad, -1, "id", comp->r->id);

	if (xhash_iter_first(domain_bares))
	    do {
		char *bare_jid;
		ids_t idt;

		xhash_iter_get(domain_bares, NULL, NULL, (void *) &bare_jid);

		send_it = 1;
		nad_append_elem(nad, ns, "unbind", 0);
		nad_append_attr(nad, -1, "name", bare_jid);

		idt = (ids_t) xhash_get(comp->r->ids, bare_jid);

		if (idt != NULL && --idt->refcount == 0) {
		    xhash_zap(comp->r->ids, idt->id);
		    free(idt->id);
		    free(idt);
		}

	    } while(xhash_iter_next(comp->r->bare_jids));

	xhash_free(domain_bares);

	if (send_it) {
	    bci.src = comp->id;
	    bci.nad = nad;
	    bci.r = comp->r;
	    xhash_walk(comp->r->rids, _router_broadcast_ids, (void *) &bci);
	}

    }

    free(local_key);
}

int router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    component_t comp = (component_t) arg;
    router_t r = (router_t) arg;
    struct sockaddr_storage sa;
    socklen_t namelen = sizeof(sa);
    int port, nbytes;
    nad_t nad;
    int ns;
    unsigned metric;
    char metric_str[11];
    struct broadcast_comp_st bcc;

    switch(a) {
        case action_READ:
            log_debug(ZONE, "read action on fd %d", fd->fd);

            /* they did something */
            comp->last_activity = time(NULL);

            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(comp->s);
                return 0;
            }

            return sx_can_read(comp->s);

        case action_WRITE:
            log_debug(ZONE, "write action on fd %d", fd->fd);

           /* update activity timestamp */
            comp->last_activity = time(NULL);

            return sx_can_write(comp->s);

        case action_CLOSE:
            log_debug(ZONE, "close action on fd %d", fd->fd);

            r = comp->r;

            log_write(r->log, LOG_NOTICE, "[%s, port=%d] '%s' disconnect", comp->ip, comp->port, comp->id);

	    /* nad = nad_new(); */
	    /* ns = nad_add_namespace(nad, uri_COMPONENT, NULL); */
	    /* nad_append_elem(nad, ns, "path", 0); */
	    /* nad_append_attr(nad, -1, "id", comp->id); */
	    /* nad_insert_elem(nad, 0, ns, "hop", NULL); */
	    /* nad_append_attr(nad, -1, "id", comp->id); */

	    /* if(comp->remote_router) */
	    /* 	metric = comp->remote_router->metric; */
	    /* else */
	    /* 	metric = 1; */

	    /* snprintf(metric_str, 10, "%d", metric); */
	    /* nad_append_attr(nad, -1, "metric", metric_str); */

	    /* nad_append_attr(nad, -1, "del", "1"); */
	    
	    /* bcc.src = comp; */
	    /* bcc.nad_routers = nad; */
	    /* bcc.nad_leaves = NULL; */
	    /* xhash_walk(comp->r->rids, _router_broadcast_ids, (void *) &bcc); */

	    /* _router_prune_graph(r, r->graph, comp->id); */
	    /* if(comp->remote_router == NULL) */
	    /* 	_router_advertise(r, comp->id, NULL, 1, 1); */

            /* unbind names */
            xhash_walk(comp->routes, _router_route_unbind_walker, (void *) comp);

            /* deregister component */
            xhash_zap(r->components, comp->ipport);

            xhash_free(comp->routes);

            if(comp->tq != NULL)
                /* !!! bounce packets */
                jqueue_free(comp->tq);

            rate_free(comp->rate);

            jqueue_push(comp->r->dead, (void *) comp->s, 0);

	    if (comp->id)
		free((void *)comp->id);
            free(comp);

            break;

        case action_ACCEPT:
            log_debug(ZONE, "accept action on fd %d", fd->fd);

            getpeername(fd->fd, (struct sockaddr *) &sa, &namelen);
            port = j_inet_getport(&sa);

            log_write(r->log, LOG_NOTICE, "[%s, port=%d] connect", (char *) data, port);

            if(_router_accept_check(r, fd, (char *) data) != 0)
                return 1;

            comp = (component_t) calloc(1, sizeof(struct component_st));

            comp->r = r;

            comp->fd = fd;

            snprintf(comp->ip, INET6_ADDRSTRLEN, "%s", (char *) data);
            comp->port = port;

            snprintf(comp->ipport, INET6_ADDRSTRLEN + 6, "%s:%d", comp->ip, comp->port);

            comp->s = sx_new(r->sx_env, fd->fd, router_sx_callback, (void *) comp);
            mio_app(m, fd, router_mio_callback, (void *) comp);

            if(r->byte_rate_total != 0)
                comp->rate = rate_new(r->byte_rate_total, r->byte_rate_seconds, r->byte_rate_wait);

            comp->routes = xhash_new(51);

            /* register component */
            log_debug(ZONE, "new component (%p) \"%s\"", comp, comp->ipport);
	    xhash_put(r->components, pstrdup(xhash_pool(r->components), comp->ipport), (void *) comp);

#ifdef HAVE_SSL
            sx_server_init(comp->s, SX_SSL_STARTTLS_OFFER | SX_SASL_OFFER);
#else
            sx_server_init(comp->s, SX_SASL_OFFER);
#endif

            break;
    }

    return 0;
}


int message_log(nad_t nad, router_t r, const char *msg_from, const char *msg_to)
{
    time_t t;
    char *time_pos;
    int time_sz;
    struct stat filestat;
    FILE *message_file;
    short int new_msg_file = 0;
    int i;
    int nad_body_len = 0;
    const char *nad_body_start = 0;
    int body_count;
    const char *nad_body = NULL;
    char body[MAX_MESSAGE*2];

    assert((int) (nad != NULL));

    /* timestamp */
    t = time(NULL);
    time_pos = ctime(&t);
    time_sz = strlen(time_pos);
    /* chop off the \n */
    time_pos[time_sz-1]=' ';

    // Find the message body
    for (i = 0; NAD_ENAME_L(nad, i) > 0; i++)
    {
        if((NAD_ENAME_L(nad, i) == 4) && (strncmp("body", NAD_ENAME(nad, i), 4) == 0))
        {
            nad_body_len = NAD_CDATA_L(nad, i);
            if (nad_body_len > 0) {
                nad_body = NAD_CDATA(nad, i);
            } else {
                log_write(r->log, LOG_NOTICE, "message_log received a message with empty body");
                return 0;
            }
            break;
        }
    }

    // Don't log anything if we found no NAD body
    if (nad_body == NULL) {
        return 0;
    }

    // Store original pointer address so that we know when to stop iterating through nad_body
    nad_body_start = nad_body;

    // replace line endings with "\n"
    for (body_count = 0; (nad_body < nad_body_start + nad_body_len) && (body_count < (MAX_MESSAGE*2)-3); nad_body++) {
        if (*nad_body == '\n') {
            body[body_count++] = '\\';
            body[body_count++] = 'n';
        } else {
            body[body_count++] = *nad_body;
        }
    }
    body[body_count] = '\0';

    // Log our message
    umask((mode_t) 0077);
    if (stat(r->message_logging_file, &filestat)) {
        new_msg_file = 1;
    }

    if ((message_file = fopen(r->message_logging_file, "a")) == NULL)
    {
        log_write(r->log, LOG_ERR, "Unable to open message log for writing: %s", strerror(errno));
        return 1;
    }

    if (new_msg_file) {
        if (! fprintf(message_file, "# This message log is created by the jabberd router.\n"))
        {
            log_write(r->log, LOG_ERR, "Unable to write to message log: %s", strerror(errno));
            return 1;
        }
        fprintf(message_file, "# See router.xml for logging options.\n");
        fprintf(message_file, "# Format: (Date)<tab>(From JID)<tab>(To JID)<tab>(Message Body)<line end>\n");
    }

    if (! fprintf(message_file, "%s\t%s\t%s\t%s\n", time_pos, msg_from, msg_to, body))
    {
        log_write(r->log, LOG_ERR, "Unable to write to message log: %s", strerror(errno));
        return 1;
    }

    fclose(message_file);

    return 0;
}
