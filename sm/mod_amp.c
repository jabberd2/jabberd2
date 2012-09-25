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

#define _GNU_SOURCE
#include <string.h>
#include "sm.h"
#include "util/util.h"
#include <stringprep.h>

/** @file sm/mod_amp.c
  * @brief Advanced Message Processing (JEP-0079) module
  * @author Cedric Vivier
  * $Date: 2004/10/28 14:38:35 $
  */

typedef struct _mod_amp_config_st {
    sm_t   sm;
    int    disableActionDrop;
    int    disableActionError;
    int    disableActionAlert;    
    int    disableActionNotify;
    int    disableConditionDeliver;
    int    disableConditionExpireAt;
    int    disableConditionMatchResource;
    int    offlinestorageDisabled;
} *mod_amp_config_t;

#define AMP_TRIGGERED            1
#define AMP_INVALID_RULE         2
#define AMP_INVALID_CONDITION    3
#define AMP_INVALID_ACTION       4
#define AMP_INVALID_VALUE        5
#define AMP_NOT_ACCEPTABLE       6

typedef struct amp_rule_st {
	int result;
	char *condition;
	char *value;
	char *action;
	struct amp_rule_st *next;
} *amp_rule_t;


void amp_rule_free(amp_rule_t rule) {
    amp_rule_t rule_c = rule;
    amp_rule_t rule_tmp;
    while (rule_c != NULL) {
        if (rule_c->condition) free(rule_c->condition);
        if (rule_c->value) free(rule_c->value);
        if (rule_c->action) free(rule_c->action);
        rule_tmp = rule_c->next;
        free(rule_c);
        rule_c = rule_tmp;
    }
}

pkt_t amp_build_response_pkt(pkt_t pkt, amp_rule_t rule) {
    if (!pkt || !rule) return NULL;
    
    if (rule->result == AMP_TRIGGERED) {
        int ns;
        pkt_t res = pkt_create(pkt->sm, "message", NULL, jid_full(pkt->from), jid_full(pkt->to));
        pkt_id(pkt, res);
    
        ns = nad_add_namespace(res->nad, uri_AMP, NULL);
        nad_append_elem(res->nad, ns, "amp", 2);
        nad_append_attr(res->nad, -1, "status", rule->action);
        nad_append_attr(res->nad, -1, "from", jid_full(pkt->from));
        nad_append_attr(res->nad, -1, "to",  jid_full(pkt->to));
    
        nad_append_elem(res->nad, ns, "rule", 3);
        nad_append_attr(res->nad, -1, "condition", rule->condition);
        nad_append_attr(res->nad, -1, "value", rule->value);
        nad_append_attr(res->nad, -1, "action", rule->action);
        
        return res;
    }
    
    return NULL;   
}

void amp_error_pkt(pkt_t pkt, amp_rule_t rule) {
	/* TODO: implementation */
}


static mod_ret_t _amp_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    /* only handle messages */
    if (!(pkt->type & pkt_MESSAGE))
        return mod_PASS;

    /* we're only interested in no to, to our host, or to us */
    if (pkt->to != NULL && jid_compare_user(sess->jid, pkt->to) != 0 && strcmp(sess->jid->domain, jid_user(pkt->to)) != 0)
        return mod_PASS;

    /* TODO: implementation */

    return mod_PASS;
}

static mod_ret_t _amp_pkt_user(mod_instance_t mi, user_t user, pkt_t pkt) {
    mod_amp_config_t config = (mod_amp_config_t) mi->mod->private;
    int ns, elem, attr;
    amp_rule_t rule, rule_c;
	int errormode = 0;

    /* only handle messages */
    if (!(pkt->type & pkt_MESSAGE))
        return mod_PASS;

    /* does message have at least one rule for us? */
    ns = nad_find_scoped_namespace(pkt->nad, uri_AMP, NULL);
    elem = nad_find_elem(pkt->nad, 1, ns, "amp", 1);
    if (elem < 0
		|| nad_find_attr(pkt->nad, elem, -1, "status", NULL) >= 0
        || (elem = nad_find_elem(pkt->nad, elem, ns, "rule", 1)) < 0)
        return mod_PASS;

    /* loop for rules */
    rule = calloc(1, sizeof(struct amp_rule_st));
    rule_c = rule;
    while (elem >= 0) {

        /* actions */    
        if (nad_find_attr(pkt->nad, elem, -1, "action", "drop") >= 0
			&& !config->disableActionDrop)
            rule_c->action = strdup("drop");
        else if (nad_find_attr(pkt->nad, elem, -1, "action", "alert") >= 0
				 && !config->disableActionAlert)
            rule_c->action = strdup("alert");
        else if (nad_find_attr(pkt->nad, elem, -1, "action", "error") >= 0
				 && !config->disableActionError)
            rule_c->action = strdup("error");
        else if (nad_find_attr(pkt->nad, elem, -1, "action", "notify") >= 0
				 && !config->disableActionNotify)
            rule_c->action = strdup("notify");
    
        if (!rule_c->action) {
            if ((attr = nad_find_attr(pkt->nad, elem, -1, "action", NULL)) >= 0)
                rule_c->action = strndup(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
            rule_c->result = AMP_INVALID_ACTION;
        }        

        /* deliver condition */    
        if (nad_find_attr(pkt->nad, elem, -1, "condition", "deliver") >= 0
			&& !config->disableConditionDeliver) {
            rule_c->condition = strdup("deliver");

            /* direct */
            if (nad_find_attr(pkt->nad, elem, -1, "value", "direct") >= 0) {
                rule_c->value = strdup("direct");
                if (user->top != NULL) /* active session so it will be direct */
                    rule_c->result = AMP_TRIGGERED;
            }
            
            /* stored */
            else if (nad_find_attr(pkt->nad, elem, -1, "value", "stored") >= 0) {
                rule_c->value = strdup("none");
                if (!config->offlinestorageDisabled
                    && user->top == NULL) /* no active session so it will be stored */
                    rule_c->result = AMP_TRIGGERED;
            }

            /* none */
            else if (nad_find_attr(pkt->nad, elem, -1, "value", "none") >= 0) {
                rule_c->value = strdup("none");
                if (config->offlinestorageDisabled
                    && user->top == NULL) /* no active session and no offline storage */
                    rule_c->result = AMP_TRIGGERED;
            }

            if (!rule_c->value) {
                if ((attr = nad_find_attr(pkt->nad, elem, -1, "value", NULL)) >= 0)
                    rule_c->value = strndup(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
                rule_c->result = AMP_INVALID_VALUE;
            }
        }

        /* match-resource condition */    
        else if (nad_find_attr(pkt->nad, elem, -1, "condition", "match-resource") >= 0
				&& !config->disableConditionMatchResource) {
            rule_c->condition = strdup("match-resource");

            /* exact */
            if (nad_find_attr(pkt->nad, elem, -1, "value", "exact") >= 0) {
                rule_c->value = strdup("exact");
                if (sess_match(user, pkt->to->resource)) /* resource found */
                    rule_c->result = AMP_TRIGGERED;
            }
            
            /* any */
            else if (nad_find_attr(pkt->nad, elem, -1, "value", "any") >= 0) {
                rule_c->value = strdup("any");
                if (user->top == NULL) /* no active resource */
                    rule_c->result = AMP_TRIGGERED;
            }

            /* other */
            else if (nad_find_attr(pkt->nad, elem, -1, "value", "other") >= 0) {
                rule_c->value = strdup("other");
                if (!sess_match(user, pkt->to->resource)) /* resource not found */
                    rule_c->result = AMP_TRIGGERED;                
            }

            if (!rule_c->value) {
                if ((attr = nad_find_attr(pkt->nad, elem, -1, "value", NULL)) >= 0)
                    rule_c->value = strndup(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
                rule_c->result = AMP_INVALID_VALUE;
            }
        }

        /* expire-at condition */    
        else if (nad_find_attr(pkt->nad, elem, -1, "condition", "expire-at") >= 0
				&& !config->disableConditionExpireAt) {
            rule_c->condition = strdup("expire-at");

            if ((attr = nad_find_attr(pkt->nad, elem, -1, "value", NULL)) < 0)
				rule_c->result = AMP_INVALID_VALUE;
			else {
				time_t stamp;
				rule_c->value = strndup(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
				stamp = datetime_in(rule_c->value);
				if (stamp < 0)
					rule_c->result = AMP_INVALID_VALUE;
				else if (stamp < time(NULL)) /* expired! */
					rule_c->result = AMP_TRIGGERED;				
			}
        }

        if (!rule_c->condition) {
            if ((attr = nad_find_attr(pkt->nad, elem, -1, "condition", NULL)) >= 0)
                rule_c->condition = strndup(NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));
            rule_c->result = AMP_INVALID_CONDITION;
        }

		/* if an error is triggered, pass in error mode */
		if (rule_c->result > AMP_TRIGGERED)
			errormode = 1;

		/* processing stops at first rule triggerred */
        if (rule_c->result == AMP_TRIGGERED && !errormode)
            break;
       
        /* jump to next rule (if any) */
        if ((elem = nad_find_elem(pkt->nad, elem, ns, "rule", 0)) >= 0) {
            rule_c->next = calloc(1, sizeof(struct amp_rule_st));
            rule_c = rule_c->next;
        }
    }
    
    /* build result packet (if any) */
    if (rule_c->result != AMP_TRIGGERED || errormode)  
        rule_c = rule;
    while (rule_c != NULL) {
		if (rule_c->result > 0) {
	
			/* drop action */
			if (!strcmp(rule_c->action, "drop") && !errormode)
				goto handled;
	
			/* alert action */
			else if (!strcmp(rule_c->action, "alert") && !errormode) {
				pkt_t res = amp_build_response_pkt(pkt, rule_c);
				pkt_router(res);
				goto handled;
			}
	
			/* error action */
			else if (!strcmp(rule_c->action, "error") && !errormode) {
				pkt_t res = amp_build_response_pkt(pkt, rule_c);
				pkt_router(res);            
				goto handled;
			}
			
			/* notify action */
			else if (!strcmp(rule_c->action, "notify") && !errormode) {
				pkt_t res = amp_build_response_pkt(pkt, rule_c);
				pkt_router(res);
				goto pass; /* ...resume the pkt-user chain happily :) */
			}
		}
		
        rule_c = rule_c->next;
	}

	pass:
		amp_rule_free(rule);
		return mod_PASS;

    handled:        
        amp_rule_free(rule);
        pkt_free(pkt);
        return mod_HANDLED;
}

static mod_ret_t _amp_pkt_sm(mod_instance_t mi, pkt_t pkt) {
    mod_amp_config_t config = (mod_amp_config_t) mi->mod->private;
    pkt_t res;
    int ns, attr;
    
    /* we only want to play with iq disco#info gets */
    if(pkt->type != pkt_IQ || pkt->ns != ns_DISCO_INFO)
        return mod_PASS;

    /* is disco#info for us ? */
    if ((attr = nad_find_attr(pkt->nad, 2, -1, "node", NULL)) < 0
        || strncmp(NAD_AVAL(pkt->nad, attr), uri_AMP, NAD_AVAL_L(pkt->nad, attr)) != 0)
        return mod_PASS;

    res = pkt_create(config->sm, "iq", "result", jid_full(pkt->from), jid_full(pkt->to));
    pkt_id(pkt, res);
    pkt_free(pkt);

    ns = nad_add_namespace(res->nad, uri_DISCO_INFO, NULL);
    nad_append_elem(res->nad, ns, "query", 2);
    nad_append_attr(res->nad, -1, "node", uri_AMP);

    nad_append_elem(res->nad, ns, "identity", 3);
    nad_append_attr(res->nad, -1, "name", "Advanced Message Processing support");
    nad_append_attr(res->nad, -1, "category", "im");
    nad_append_attr(res->nad, -1, "type", "server");

    nad_append_elem(res->nad, ns, "feature", 3);
    nad_append_attr(res->nad, -1, "var", uri_AMP);
    if (!config->disableActionDrop) {
        nad_append_elem(res->nad, ns, "feature", 3);
        nad_append_attr(res->nad, -1, "var", uri_AMP_ACTION_DROP);
    }
    if (!config->disableActionError) {
        nad_append_elem(res->nad, ns, "feature", 3);
        nad_append_attr(res->nad, -1, "var", uri_AMP_ACTION_ERROR);
    }
    if (!config->disableActionNotify) {
        nad_append_elem(res->nad, ns, "feature", 3);
        nad_append_attr(res->nad, -1, "var", uri_AMP_ACTION_NOTIFY);
    }
    if (!config->disableConditionDeliver) {
        nad_append_elem(res->nad, ns, "feature", 3);
        nad_append_attr(res->nad, -1, "var", uri_AMP_CONDITION_DELIVER);
    }
    if (!config->disableConditionExpireAt) {
        nad_append_elem(res->nad, ns, "feature", 3);
        nad_append_attr(res->nad, -1, "var", uri_AMP_CONDITION_EXPIREAT);
    }
    if (!config->disableConditionMatchResource) {
        nad_append_elem(res->nad, ns, "feature", 3);
        nad_append_attr(res->nad, -1, "var", uri_AMP_CONDITION_MATCHRESOURCE);
    }    

    /* tell them */
    pkt_router(res);

    return mod_HANDLED;
}

static void _amp_free(module_t mod) {
    free(mod->private);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;
    mod_amp_config_t config;
    const char* option;

    if (mod->init) return 0;
    
    config = (mod_amp_config_t) calloc(1, sizeof(struct _mod_amp_config_st));

    config->sm = mod->mm->sm;
    option = config_get_one(mod->mm->sm->config, "amp.disableactions.drop", 0);
    if (option != NULL) {
        log_debug(ZONE, "action Drop disabled in config.");
        config->disableActionDrop = 1;
    }
    option = config_get_one(mod->mm->sm->config, "amp.disableactions.error", 0);
    if (option != NULL) {
        log_debug(ZONE, "action Error disabled in config.");
        config->disableActionError = 1;
    }
    option = config_get_one(mod->mm->sm->config, "amp.disableactions.alert", 0);
    if (option != NULL) {
        log_debug(ZONE, "action Alert disabled in config.");
        config->disableActionAlert = 1;
    }    
    option = config_get_one(mod->mm->sm->config, "amp.disableactions.notify", 0);
    if (option != NULL) {
        log_debug(ZONE, "action Notify disabled in config.");
        config->disableActionNotify = 1;
    }
    option = config_get_one(mod->mm->sm->config, "amp.disableconditions.deliver", 0);
    if (option != NULL) {
        log_debug(ZONE, "condition Deliver disabled in config.");
        config->disableConditionDeliver = 1;
    }
    option = config_get_one(mod->mm->sm->config, "amp.disableconditions.expireat", 0);
    if (option != NULL) {
        log_debug(ZONE, "condition Expire-At disabled in config.");
        config->disableConditionExpireAt = 1;
    }
    option = config_get_one(mod->mm->sm->config, "amp.disableconditions.matchresource", 0);
    if (option != NULL) {
        log_debug(ZONE, "condition Match-Resource disabled in config.");
        config->disableConditionMatchResource = 1;
    }
    option = config_get_one(mod->mm->sm->config, "amp.offlinestoragedisabled", 0);
    if (option != NULL) {
        log_debug(ZONE, "offline storage disabled in config.");
        config->offlinestorageDisabled = 1;
    }
    option = config_get_one(mod->mm->sm->config, "offline.dropmessages", 0);
    if (option != NULL) {
        log_debug(ZONE, "offline storage disabled in config.");
        config->offlinestorageDisabled = 1;
    }
    
    mod->private = config;    

    mod->in_sess = _amp_in_sess;
    mod->pkt_user = _amp_pkt_user;
    mod->pkt_sm = _amp_pkt_sm;
    mod->free = _amp_free;

    feature_register(mod->mm->sm, uri_AMP);

    return 0;
}
