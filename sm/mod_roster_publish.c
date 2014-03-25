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

/** @file sm/mod_roster_publish.c
  * @brief roster publishing
  * @author Nikita Smirnov
  */

#ifndef NO_SM_CACHE
typedef struct _roster_publish_active_cache_st *_roster_publish_active_cache_t;
struct _roster_publish_active_cache_st {
    time_t time; // when cache was updated
    time_t active;
    char *jid_user;
};
typedef struct _roster_publish_group_cache_st *_roster_publish_group_cache_t;
struct _roster_publish_group_cache_st {
    time_t time; // when cache was updated
    char *groupid;
    char *groupname;
};
#endif

typedef struct _roster_publish_st {
    int publish, forcegroups, fixsubs, overridenames, mappedgroups, fixexist;
    const char *fetchdomain, *fetchuser, *fetchfixed, *dbtable;
    const char *groupprefix, *groupsuffix, *removedomain;
    int groupprefixlen, groupsuffixlen;
    time_t active_cache_ttl;
    time_t group_cache_ttl;
#ifndef NO_SM_CACHE
    xht active_cache; // cache of values from 'active' storage,
                      // used to check that user exists in sm database
    xht group_cache; // cache of values from published-roster-groups storage
                     // used to map group id to group name
#endif
} *roster_publish_t;

#ifndef NO_SM_CACHE
/* free single item of active cache */
static void _roster_publish_free_active_cache_walker(const char *key, int keylen, void *val, void *arg) {
    _roster_publish_active_cache_t item = (_roster_publish_active_cache_t)val;
    free(item->jid_user);
    free(item);
}
/* free single item of group cache */
static void _roster_publish_free_group_cache_walker(const char *key, int keylen, void *val, void *arg) {
    _roster_publish_group_cache_t item = (_roster_publish_group_cache_t)val;
    free(item->groupid);
    free(item->groupname);
    free(item);
}
#endif

/*
 * get group's descriptive name by it's text id
 * returned value needs to be freed by caller
 */
static const char *_roster_publish_get_group_name(sm_t sm, roster_publish_t rp, const char *groupid)
{
    os_t os;
    os_object_t o;
    char *str;
    char *group;

#ifndef NO_SM_CACHE
    _roster_publish_group_cache_t group_cached;
#endif

    if(!groupid) return groupid;

#ifndef NO_SM_CACHE
    /* check for remembered group value in cache */
    if( rp->group_cache_ttl ) {
        if( rp->group_cache ) {
            group_cached = xhash_get(rp->group_cache, groupid);
            if( group_cached != NULL ) {
                if( (time(NULL) - group_cached->time) >= rp->group_cache_ttl ) {
                    log_debug(ZONE,"group cache: expiring cached value for %s",groupid);
                    xhash_zap(rp->group_cache, groupid);
                    free(group_cached);
                } else {
                    log_debug(ZONE,"group cache: returning cached value for %s",groupid);
                    return strdup(group_cached->groupname);
                }
            }
        } else {
            log_debug(ZONE,"group cache: creating cache");
            rp->group_cache = xhash_new(401);
        }
    }
#endif

    if(storage_get(sm->st, "published-roster-groups", groupid, NULL, &os) == st_SUCCESS && os_iter_first(os)) {
        o = os_iter_object(os);
        os_object_get_str(os, o, "groupname", &str);
        if( str ) {
            group=strdup(str);
        } else {
            group=NULL;
        }
        os_free(os);
#ifndef NO_SM_CACHE
        if( rp->group_cache_ttl && group ) {
            log_debug(ZONE,"group cache: updating cache value for %s",groupid);
            group_cached = calloc(1, sizeof(struct _roster_publish_group_cache_st));
            group_cached->time = time(NULL);
            group_cached->groupid = strdup(groupid);
            group_cached->groupname = strdup(group);
            xhash_put(rp->group_cache, group_cached->groupid, group_cached);
        }
#endif
        return group;
    } else {
        return NULL;
    }
}

/* free a single roster item */
static void _roster_publish_free_walker(xht roster, const char *key, void *val, void *arg)
{
    item_t item = (item_t) val;
    int i;

    jid_free(item->jid);
    
    if(item->name != NULL)
        free((void*)item->name);

    for(i = 0; i < item->ngroups; i++)
        free((void*)item->groups[i]);
    free(item->groups);

    free(item);
}

static void _roster_publish_save_item(user_t user, item_t item) {
    os_t os;
    os_object_t o;
    char filter[4096];
    int i;

    log_debug(ZONE, "saving roster item %s for %s", jid_full(item->jid), jid_user(user->jid));

    os = os_new();
    o = os_object_new(os);

    os_object_put(o, "jid", jid_full(item->jid), os_type_STRING);

    if(item->name != NULL)
        os_object_put(o, "name", item->name, os_type_STRING);

    os_object_put(o, "to", &item->to, os_type_BOOLEAN);
    os_object_put(o, "from", &item->from, os_type_BOOLEAN);
    os_object_put(o, "ask", &item->ask, os_type_INTEGER);

    snprintf(filter, 4096, "(jid=%s)", jid_full(item->jid));

    storage_replace(user->sm->st, "roster-items", jid_user(user->jid), filter, os);

    os_free(os);

    snprintf(filter, 4096, "(jid=%s)", jid_full(item->jid));

    if(item->ngroups == 0) {
        storage_delete(user->sm->st, "roster-groups", jid_user(user->jid), filter);
        return;
    }

    os = os_new();
    
    for(i = 0; i < item->ngroups; i++) {
        o = os_object_new(os);

        os_object_put(o, "jid", jid_full(item->jid), os_type_STRING);
        os_object_put(o, "group", item->groups[i], os_type_STRING);
    }

    storage_replace(user->sm->st, "roster-groups", jid_user(user->jid), filter, os);

    os_free(os);
}

/** publish the roster from the database */
static int _roster_publish_user_load(mod_instance_t mi, user_t user) {
    roster_publish_t roster_publish = (roster_publish_t) mi->mod->private;
    os_t os, os_active;
    os_object_t o, o_active;
    char *str;
    const char *group;
    char filter[4096];
    const char *fetchkey;
    int i,j,gpos,found,delete,checksm,tmp_to,tmp_from,tmp_do_change;
    item_t item;
    jid_t jid;

    /* update roster to match published roster */
    if( roster_publish->publish) {
        /* free if necessary */
        if(user->roster == NULL) {
            log_write(user->sm->log, LOG_NOTICE, "roster_publish: no roster for %s",jid_user(user->jid));
            return 0;
        }

        log_debug(ZONE, "publishing roster for %s",jid_user(user->jid));
        /* get published roster */
        if(roster_publish->fetchfixed)
            fetchkey = roster_publish->fetchfixed;
        else if(roster_publish->fetchuser)
            fetchkey = jid_user(user->jid);
        else if(roster_publish->fetchdomain)
            fetchkey = user->jid->domain;
        else
            fetchkey = "";

        if( storage_get(user->sm->st, (roster_publish->dbtable ? roster_publish->dbtable : "published-roster"), fetchkey, NULL, &os) == st_SUCCESS ) {
            if(os_iter_first(os)) {
                /* iterate on published roster */
                jid = NULL;
                do {
                    o = os_iter_object(os);
                    if(os_object_get_str(os, o, "jid", &str)) {
                        int userinsm;
#ifndef NO_SM_CACHE
                        _roster_publish_active_cache_t active_cached = 0;
#endif
                        log_debug(ZONE, "got %s item for inserting in", str);
                        if( strcmp(str,jid_user(user->jid)) == 0 ) {
                            /* not adding self */
                            continue; /* do { } while( os_iter_next ) */
                        }
                        /* check that published item exists in sm database */
                        checksm=0;
                        if( jid ) jid_free(jid);
                        jid = jid_new(str, -1);
                        if( roster_publish->removedomain ) {
                            if( strcmp("1", roster_publish->removedomain) == 0 || /* XXX HACKY!!! "1" is very config.c dependant */
                                strcmp(jid->domain, roster_publish->removedomain) == 0 ) {
                                checksm = 1;
                            }
                        }
                        if( checksm ) {
                            /* is this a hack? but i want to know was the user activated in sm or no? */
#ifndef NO_SM_CACHE
                            /* check for remembered active value in cache */
                            userinsm = -1;
                            if( roster_publish->active_cache_ttl ) {
                                if( roster_publish->active_cache ) {
                                    active_cached = xhash_get(roster_publish->active_cache, jid_user(jid));
                                    if( active_cached != NULL ) {
                                        if( (time(NULL) - active_cached->time) >= roster_publish->active_cache_ttl ) {
                                            xhash_zap(roster_publish->active_cache, jid_user(jid));
                                            free(active_cached);
                                        } else {
                                            if( active_cached->active ) {
                                                userinsm = 1;
                                            } else {
                                                userinsm = 0;
                                            }
                                        }
                                    }
                                } else {
                                    roster_publish->active_cache = xhash_new(401);
                                }
                            }
                            if( userinsm == -1 ) {
                                if( roster_publish->active_cache_ttl ) {
                                    active_cached = calloc(1, sizeof(struct _roster_publish_active_cache_st));
                                    active_cached->time = time(NULL);
                                }
#endif
                                if(storage_get(user->sm->st, "active", jid_user(jid), NULL, &os_active) == st_SUCCESS
                                        && os_iter_first(os_active)) {
#ifndef NO_SM_CACHE
                                    if( roster_publish->active_cache_ttl ) {
                                        o_active = os_iter_object(os_active);
                                        os_object_get_time(os_active, o_active, "time", &active_cached->active);
                                    }
#endif
                                    os_free(os_active);
                                    userinsm = 1;
                                } else {
#ifndef NO_SM_CACHE
                                    if( roster_publish->active_cache_ttl ) {
                                        active_cached->active = 0;
                                    }
#endif
                                    userinsm = 0;
                                }
#ifndef NO_SM_CACHE
                                if( roster_publish->active_cache_ttl ) {
                                    active_cached->jid_user = strdup(jid_user(jid));
                                    xhash_put(roster_publish->active_cache, active_cached->jid_user, active_cached);
                                }
                            } // if( userinsm == -1 )
#endif
                        } else userinsm = 0; // if( checksm )
                        item = xhash_get(user->roster,jid_user(jid));
                        if( item == NULL ) {
                            /* user has no this jid in his roster */
                            /* if we checking sm database and user is not in it, not adding */
                            if( checksm && !userinsm ) {
                                log_debug(ZONE, "published user %s has no record in sm, not adding", jid_user(jid));
                                continue; /* do { } while( os_iter_next ) */
                            }
                            log_debug(ZONE, "user has no %s in roster, adding", jid_user(jid));
                            item = (item_t) calloc(1, sizeof(struct item_st));

                            item->jid = jid_new(jid_user(jid), -1);
                            if(item->jid == NULL) {
                                log_debug(ZONE, "eek! invalid jid %s, skipping it", jid_user(jid));
                                log_write(user->sm->log, LOG_ERR, "roster_publish: eek! invalid jid %s, skipping it", jid_user(jid));
                                /* nvs: is it needed? */
                                free(item);
                                /* nvs: is it needed? */
                            } else {
                                os_object_get_str(os, o, "group", &str);
                                if( roster_publish->mappedgroups ) {
                                    group = _roster_publish_get_group_name(user->sm, roster_publish, str); // don't forget to free group
                                } else {
                                    if(str)
                                        group = strdup(str);
                                    else
                                        group = NULL;
                                }
                                if( group ) {
                                    item->groups = realloc(item->groups, sizeof(char *) * (item->ngroups + 1));
                                    item->groups[item->ngroups] = group;
                                    item->ngroups++;

                                    if(os_object_get_str(os, o, "name", &str))
                                        item->name = strdup(str);

                                    os_object_get_bool(os, o, "to", &item->to);
                                    os_object_get_bool(os, o, "from", &item->from);
                                    os_object_get_int(os, o, "ask", &item->ask);

                                    log_debug(ZONE, "adding %s to roster from template (to %d from %d ask %d name %s)", jid_full(item->jid), item->to, item->from, item->ask, item->name);

                                    /* its good */
                                    xhash_put(user->roster, jid_full(item->jid), (void *) item);
                                    _roster_publish_save_item(user,item);
                                } else {
                                    log_write(user->sm->log, LOG_ERR, "roster_publish: unknown published group id '%s' for %s",str,jid_full(item->jid));
                                    free(item);
                                }
                                if (roster_publish->fixexist &&
                                     ( (checksm && !userinsm) ||
                                       (!checksm && storage_get(user->sm->st, "active", jid_user(jid), NULL, &os_active) == st_SUCCESS && os_iter_first(os_active))
                                     )
                                   ) {
                                    /* Add thise jid to active table*/
                                    log_debug(ZONE, "adding published user %s to sm", jid_user(jid));
                                    time_t tfe;
                                    os_t osfe;

                                    os_object_t ofe;
                                    tfe = time(NULL);
                                    osfe = os_new();
                                    ofe = os_object_new(osfe);
                                    os_object_put_time(ofe, "time", &tfe);
                                    storage_put(mi->sm->st, "active", jid_user(jid), osfe);
                                    os_free(osfe);
                                }
                            }
                        }
                        else /* if( item == NULL ) else ... : here item != NULL : user has this jid in his roster */
                        {
                            /* if we checking sm database and user is not in it, remove it from roster */
                            if( checksm && !userinsm ) {
                                log_debug(ZONE, "published user %s has no record in sm, deleting from roster", jid_user(jid));
                                snprintf(filter, 4096, "(jid=%s)", jid_full(jid));
                                storage_delete(user->sm->st, "roster-items", jid_user(user->jid), filter);
                                snprintf(filter, 4096, "(jid=%s)", jid_full(jid));
                                storage_delete(user->sm->st, "roster-groups", jid_user(user->jid), filter);

                                xhash_zap(user->roster, jid_full(jid));
                                _roster_publish_free_walker(NULL, (const char *) jid_full(jid), (void *) item, NULL);
                                continue; /* do { } while( os_iter_next ) */
                            }
                            if( roster_publish->fixsubs ) {
                                /* check subscriptions and correct if needed */
                                os_object_get_bool(os, o, "to", &tmp_to);
                                os_object_get_bool(os, o, "from", &tmp_from);
                                if( item->to != tmp_to || item->from != tmp_from ) {
                                    item->to = tmp_to;
                                    item->from = tmp_from;
                                    log_debug(ZONE, "fixsubs in roster %s, item %s",jid_user(user->jid),jid_user(item->jid));
                                    xhash_put(user->roster, jid_full(item->jid), (void *) item);
                                    _roster_publish_save_item(user,item);
                                }
                            }
                            if( roster_publish->overridenames ) {
                                /* override display name if it differs */
                                if(os_object_get_str(os, o, "name", &str)) {
                                    if( str ) {
                                        tmp_do_change = 0;
                                        if( ! item->name ) {
                                            tmp_do_change = 1;
                                        } else {
                                            if( strcmp(item->name,str) != 0 ) {
                                                tmp_do_change = 1;
                                            }
                                        }
                                        if( tmp_do_change ) {
                                            log_debug(ZONE, "replacing name for %s in roster of %s", jid_full(item->jid),jid_user(user->jid));
                                            item->name = strdup(str);
                                            xhash_put(user->roster, jid_full(item->jid), (void *) item);
                                            _roster_publish_save_item(user,item);
                                        }
                                    } else {
                                        log_debug(ZONE,"warning: name is null in published roster for item %s",jid_full(item->jid));
                                    }
                                }
                            }
                            if( roster_publish->forcegroups ) {
                                /* item already in roster, check groups if needed */
                                os_object_get_str(os, o, "group", &str);
                                if( roster_publish->mappedgroups ) {
                                    group = _roster_publish_get_group_name(user->sm, roster_publish, str); // don't forget to free group
                                    if( !group ) {
                                        log_write(user->sm->log, LOG_ERR, "roster_publish: unknown published group id '%s' for %s",str, jid_full(item->jid));
                                        continue; /* do { } while( os_iter_next ) */
                                    }
                                } else {
                                    group = strdup(str);
                                }
                                /* find published roster item's group in user's roster */
                                found = 0;
                                for(i = 0; i < item->ngroups; i++) {
                                    if( strcmp(item->groups[i],group) == 0 ) {
                                        found = 1;
                                        /* do not break loop, give groups that matches
                                         * prefix and suffix to be deleted
                                         */
                                    } else {
                                        /* check if user's roster group matches
                                         * prefix or suffix given in config
                                         * and delete such groups (and thus they will be replaced)
                                         */
                                        delete = 0;
                                        if( roster_publish->groupprefix ) {
                                            if( strncmp(item->groups[i],roster_publish->groupprefix,roster_publish->groupprefixlen) == 0 ) {
                                                delete = 1;
                                            }
                                        }
                                        if( !delete && roster_publish->groupsuffix ) {
                                            gpos=strlen(item->groups[i])-roster_publish->groupsuffixlen;
                                            if( gpos > 0 ) {
                                                if( strcmp(item->groups[i]+gpos,roster_publish->groupsuffix) == 0 ) {
                                                    delete = 1;
                                                }
                                            }
                                        }
                                        /* remove group from roster item */
                                        if( delete ) {
                                            free((void*)item->groups[i]);
                                            for(j = i; j < item->ngroups-1; j++) {
                                                item->groups[j]=item->groups[j+1];
                                            }
                                            item->ngroups--;
                                            item->groups = realloc(item->groups, sizeof(char *) * (item->ngroups));
                                        }
                                    }
                                } /* for(i... */
                                if( !found ) {
                                    log_debug(ZONE, "adding group %s to item %s for user %s",group,jid_user(item->jid),jid_user(user->jid));
                                    item->groups = realloc(item->groups, sizeof(char *) * (item->ngroups + 1));
                                    item->groups[item->ngroups] = group; // will be freed
                                    item->ngroups++;
                                    /* replace item */
                                    xhash_put(user->roster, jid_full(item->jid), (void *) item);
                                    _roster_publish_save_item(user,item);
                                } else {
                                    free((void*)group);
                                }
                            } /* else if( roster_publish->forcegroups ) */
                        } /* end of if if( item == NULL ) */
                    } /* if( os_object_get(...) */
                } while(os_iter_next(os));
                if( jid ) jid_free(jid);
            }
            os_free(os);
        }
    }
    return 0;
}

static void _roster_publish_free(module_t mod) {
    roster_publish_t roster_publish = (roster_publish_t) mod->private;

#ifndef NO_SM_CACHE
    if( roster_publish->active_cache ) {
        xhash_walk(roster_publish->active_cache,_roster_publish_free_active_cache_walker,NULL);
        xhash_free(roster_publish->active_cache);
    }
    if( roster_publish->group_cache ) {
        xhash_walk(roster_publish->group_cache,_roster_publish_free_group_cache_walker,NULL);
        xhash_free(roster_publish->group_cache);
    }
#endif
    free(roster_publish);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;
    roster_publish_t roster_publish;

    if(mod->init) return 0;

    roster_publish = (roster_publish_t) calloc(1, sizeof(struct _roster_publish_st));

    if( config_get_one(mod->mm->sm->config, "user.template.publish", 0) ) {
        roster_publish->publish = 1;
        roster_publish->fetchdomain = config_get_one(mod->mm->sm->config, "user.template.publish.fetch-key.domain", 0);
        roster_publish->fetchuser = config_get_one(mod->mm->sm->config, "user.template.publish.fetch-key.user", 0);
        roster_publish->fetchfixed = config_get_one(mod->mm->sm->config, "user.template.publish.fetch-key.fixed", 0);
        roster_publish->dbtable = config_get_one(mod->mm->sm->config, "user.template.publish.db-table", 0);
        roster_publish->removedomain = config_get_one(mod->mm->sm->config, "user.template.publish.check-remove-domain", 0);
        roster_publish->fixsubs = j_atoi(config_get_one(mod->mm->sm->config, "user.template.publish.fix-subscriptions", 0), 0);
        roster_publish->overridenames = j_atoi(config_get_one(mod->mm->sm->config, "user.template.publish.override-names", 0), 0);
        roster_publish->mappedgroups = j_atoi(config_get_one(mod->mm->sm->config, "user.template.publish.mapped-groups.map-groups", 0), 0);
        roster_publish->fixexist = j_atoi(config_get_one(mod->mm->sm->config, "user.template.publish.force-create-contacts", 0), 0);
#ifndef NO_SM_CACHE
        roster_publish->active_cache_ttl = j_atoi(config_get_one(mod->mm->sm->config, "user.template.publish.active-cache-ttl", 0), 0);
        roster_publish->group_cache_ttl = j_atoi(config_get_one(mod->mm->sm->config, "user.template.publish.mapped-groups.group-cache-ttl", 0), 0);
#endif
        if( config_get_one(mod->mm->sm->config, "user.template.publish.force-groups", 0) ) {
            roster_publish->forcegroups = 1;
            roster_publish->groupprefix = config_get_one(mod->mm->sm->config, "user.template.publish.force-groups.prefix", 0);
            if( roster_publish->groupprefix ) {
                roster_publish->groupprefixlen = strlen(roster_publish->groupprefix);
            }
            roster_publish->groupsuffix = config_get_one(mod->mm->sm->config, "user.template.publish.force-groups.suffix", 0);
            if( roster_publish->groupsuffix ) {
                roster_publish->groupsuffixlen = strlen(roster_publish->groupsuffix);
            }
        } else {
            roster_publish->forcegroups = 0;
        }
    } else {
        roster_publish->publish = 0;
    }
    mod->private = roster_publish;

    mod->user_load = _roster_publish_user_load;
    mod->free = _roster_publish_free;

    return 0;
}

// vim: shiftwidth=4
