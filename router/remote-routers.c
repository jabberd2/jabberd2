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

#include "router.h"

/** remote_routers table manager */

int remote_routers_table_load(router_t r, unsigned int reload) {
    const char *routersfile;
    char ipstr[INET6_ADDRSTRLEN];
    int portnb, metricnb;
    char ipport[INET6_ADDRSTRLEN + 6];
    FILE *f;
    long size;
    char *buf;
    nad_t nad;
    int nrouters, nrrouters, router, ip, port, user, pass, pemfile, metric, retry_init, retry_sleep;
    remote_routers_t new_router, list_tail = NULL, scan, tmp;

    if (reload) {
	log_debug(ZONE, "reloading remote_routers table");
    } else
	log_debug(ZONE, "loading remote_routers table");
    
    if(r->remote_routers != NULL) {
	if(reload) {
	    scan = list_tail = r->remote_routers;
	    while(scan != NULL) {
		scan->seen = 0;
		list_tail = scan;
		scan = scan->next;
	    }
	} else
	    remote_routers_table_unload(r);
    }

    routersfile = config_get_one(r->config, "remote-routers", 0);
    if(routersfile == NULL)
        routersfile = CONFIG_DIR "/remote-routers.xml";

    f = fopen(routersfile, "rb");
    if(f == NULL) {
        log_write(r->log, LOG_INFO, "couldn't open remote-routers table file %s: %s", routersfile, strerror(errno));
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = (char *) malloc(sizeof(char) * size);

    if (fread(buf, 1, size, f) != size || ferror(f)) {
        log_write(r->log, LOG_ERR, "couldn't read from remote-routers table file: %s", strerror(errno));
        free(buf);
        fclose(f);
        return 1;
    }

    fclose(f);

    nad = nad_parse(buf, size);
    if(nad == NULL) {
        log_write(r->log, LOG_ERR, "couldn't parse remote-routers table");
        free(buf);
        return 1;
    }

    free(buf);

    nrouters = 0;
    router = 0;

    for(router = nad_find_elem(nad, router, -1, "remote-router", 1); router >= 0; router = nad_find_elem(nad, router, -1, "remote-router", 0)) {
        ip = nad_find_elem(nad, router, -1, "ip", 1);
        port = nad_find_elem(nad, router, -1, "port", 1);
        metric = nad_find_elem(nad, router, -1, "metric", 1);
        user = nad_find_elem(nad, router, -1, "user", 1);
        pass = nad_find_elem(nad, router, -1, "pass", 1);
        pemfile = nad_find_elem(nad, router, -1, "pemfile", 1);
        retry_init = nad_find_elem(nad, router, -1, "retry-init", 1);
        retry_sleep = nad_find_elem(nad, router, -1, "retry-sleep", 1);

        if(ip < 0 || port < 0 || user < 0 || pass < 0 || NAD_CDATA_L(nad, ip) <= 0 || NAD_CDATA_L(nad, port) <= 0 || NAD_CDATA_L(nad, user) <= 0 || NAD_CDATA_L(nad, pass) <= 0) {
            log_write(r->log, LOG_ERR, "malformed remote-router entry in remote-routers table file, skipping");
            continue;
        }

	sprintf(ipstr, "%.*s", NAD_CDATA_L(nad, ip), NAD_CDATA(nad, ip));
	portnb = j_atoi(NAD_CDATA(nad, port), 5347);
	snprintf(ipport, INET6_ADDRSTRLEN + 6, "%s:%d", ipstr, portnb);

	metricnb = j_atoi(NAD_CDATA(nad, metric), 1);

	for(scan = r->remote_routers; scan != NULL; scan = scan->next)
	    if(strncmp(ipport, scan->comp->ipport, INET6_ADDRSTRLEN + 6) == 0) {
		scan->seen++;
		if (scan->seen > 1)
		    log_write(r->log, LOG_ERR, "remote router '%s' already seen, ignoring", ipport);
		else if(reload)
		    log_debug(ZONE, "remote router '%s' unchanged", ipport);

		break;
	    }
	
	if (scan != NULL)
	    continue;

	new_router = (remote_routers_t) calloc(1, sizeof(struct remote_routers_st));
	new_router->comp = (component_t) calloc(1, sizeof(struct component_st));
	new_router->metric = metricnb;
	new_router->comp->remote_router = new_router;
	new_router->comp->r = r;
	new_router->outbound = 1;

	strncpy(new_router->comp->ip, ipstr, INET6_ADDRSTRLEN);
	new_router->comp->port = portnb;
	strncpy(new_router->comp->ipport, ipport, INET6_ADDRSTRLEN + 6);

	new_router->user = (char *) malloc(NAD_CDATA_L(nad, user) + 1);
	sprintf(new_router->user, "%.*s", NAD_CDATA_L(nad, user), NAD_CDATA(nad, user));

	new_router->pass = (char *) malloc(NAD_CDATA_L(nad, pass) + 1);
	sprintf(new_router->pass, "%.*s", NAD_CDATA_L(nad, pass), NAD_CDATA(nad, pass));

	if(pemfile >= 0 && NAD_CDATA_L(nad, pemfile) > 0) {
	    new_router->pemfile = (char *) malloc(NAD_CDATA_L(nad, pemfile) + 1);
	    sprintf(new_router->pemfile, "%.*s", NAD_CDATA_L(nad, pemfile), NAD_CDATA(nad, pemfile));
	}

	if(retry_init >= 0)
	    new_router->retry_init = j_atoi(NAD_CDATA(nad, retry_init), 3);
	else
	    new_router->retry_init = 3;

	if(retry_sleep >= 0)
	    new_router->retry_sleep = j_atoi(NAD_CDATA(nad, retry_sleep), 3);
	else
	    new_router->retry_sleep = 3;

	new_router->retry_left = new_router->retry_init;

	log_debug(ZONE, "remembering remote router '%s'", ipport);

	if(list_tail != NULL) {
	    list_tail->next = new_router;
	    list_tail = new_router;
	}

	if(r->remote_routers == NULL) {
	    r->remote_routers = new_router;
	    list_tail = new_router;
	}

	jqueue_push(r->new_remote_routers, (void *) new_router, 0);

	nrouters++;
    }

    nad_free(nad);

    if(reload) {
	nrrouters = 0;
	scan = r->remote_routers;
	r->remote_routers = list_tail = NULL;
	while(scan != NULL) {
	    tmp = scan->next;

	    if(scan->seen > 0) {
		if(list_tail != NULL) {
		    list_tail->next = scan;
		    list_tail = scan;
		}

		if(r->remote_routers == NULL) {
		    r->remote_routers = scan;
		    list_tail = scan;
		}
	    } else {
		nrrouters++;
		log_debug(ZONE, "forgetting remote router '%s'", scan->comp->ipport);
		sx_close(scan->comp->s);
		jqueue_push(r->dead_remote_routers, (void *) scan, 0 /*priority*/);
	    }

	    scan = tmp;
	}

	log_write(r->log, LOG_NOTICE, "reloaded remote-routers table, added %d and removed %d remote routers", nrouters, nrrouters);
    } else
	log_write(r->log, LOG_NOTICE, "loaded remote-routers table, found %d remote routers", nrouters);

    r->remote_routers_load = time(NULL);

    return 0;
}

void remote_routers_table_unload(router_t r)
{
    remote_routers_t router, tmp;

    router = r->remote_routers;

    while(router != NULL) {
        tmp = router->next;
        if(router->comp != NULL) {
	    sx_close(router->comp->s);
	    free(router->comp);
	}
        free(router);
        router = tmp;
    }

    r->remote_routers = NULL;
} 

void remote_router_free(remote_routers_t remote)
{
    if (remote->comp->id)
	free(remote->comp->id);
    free(remote->comp);
    if (remote->user)
	free(remote->user);
    if (remote->pass)
	free(remote->pass);
    if (remote->pemfile)
	free(remote->pemfile);
    free(remote);
}

int remote_router_connect(router_t r, remote_routers_t remote)
{
    remote_routers_t scan;

    for(scan = r->remote_routers; scan != NULL; scan = scan->next)
	if(scan->outbound == 0 && strcmp(scan->comp->ipport, remote->comp->ipport) == 0) {
	    remote->retry_left = remote->retry_init;
	    log_write(r->log, LOG_NOTICE, "not attempting connection to remote router at %s, port=%d (already connected)", remote->comp->ip, remote->comp->port);
	    return 1;
	}
    
    log_write(r->log, LOG_NOTICE, "attempting connection to remote router at %s, port=%d", remote->comp->ip, remote->comp->port);

    remote->comp->fd = mio_connect(r->mio, remote->comp->port, remote->comp->ip, NULL, router_mio_callback, (void *) remote->comp);
    if(remote->comp->fd == NULL) {
        /* if(errno == ECONNREFUSED) */
        /*     remote->lost_router = 1; */
	log_write(r->log, LOG_NOTICE, "connection attempt to router failed: %s (%d)", MIO_STRERROR(MIO_ERROR), MIO_ERROR);
	return 1;
    }

    remote->comp->s = sx_new(r->sx_env, remote->comp->fd->fd, router_sx_callback, (void *) remote->comp);
    sx_client_init(remote->comp->s, 0, NULL, NULL, NULL, "1.0");

    remote->retry_left = remote->retry_init;

    return 0;
}
