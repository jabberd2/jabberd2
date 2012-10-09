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

/* for strndup */
#define _GNU_SOURCE
#include <string.h>
#include "sm.h"

/** @file sm/mod_help.c
  * @brief forward messages to administrators
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.9 $
  */

/* XEP-0157 serverinfo fields */
static const char *_serverinfo_fields[] = {
    "abuse-addresses",
    "admin-addresses",
    "feedback-addresses",
    "sales-addresses",
    "security-addresses",
    "support-addresses",
    NULL
};

static mod_ret_t _help_pkt_sm(mod_instance_t mi, pkt_t pkt)
{
    module_t mod = mi->mod;
    jid_t all, msg, jid, smjid;
    int subj, subjectl;
    char *org_subject;
    char *subject;
    char *resource = (char *) mod->private;

    smjid = jid_new(jid_user(pkt->to), -1);
    jid_reset_components(smjid, smjid->node, smjid->domain, resource);

    /* answer to probes and subscription requests */
    if(pkt->type == pkt_PRESENCE_PROBE || pkt->type == pkt_S10N) {
        log_debug(ZONE, "answering presence probe/sub from %s with /help resource", jid_full(pkt->from));

        /* send presence */
        pkt_router(pkt_create(mod->mm->sm, "presence", NULL, jid_user(pkt->from), jid_full(smjid)));
    }
    
    jid_free(smjid);

    /* we want messages addressed to the sm itself or /help resource */
    if(!(pkt->type & pkt_MESSAGE) || (pkt->to->resource[0] != '\0' && strcmp(pkt->to->resource, "help")))
        return mod_PASS;

    log_debug(ZONE, "help message from %s", jid_full(pkt->from));

    all = xhash_get(mod->mm->sm->acls, "all");
    msg = xhash_get(mod->mm->sm->acls, "messages");

    nad_set_attr(pkt->nad, 1, -1, "type", NULL, 0);
    subj = nad_find_elem(pkt->nad, 1, NAD_ENS(pkt->nad, 1), "subject", 1);
    if(subj >= 0 && NAD_CDATA_L(pkt->nad, subj) > 0)
    {
        org_subject = strndup(NAD_CDATA(pkt->nad, subj), NAD_CDATA_L(pkt->nad, subj));
    } else {
        org_subject = "(none)";
    }
    subjectl = strlen(org_subject) + strlen(jid_full(pkt->from)) + 8;
    subject = (char *) malloc(sizeof(char) * subjectl);
    snprintf(subject, subjectl, "Fwd[%s]: %s", jid_full(pkt->from), org_subject);
    if(subj >= 0 && NAD_CDATA_L(pkt->nad, subj) > 0)
    {
        free(org_subject);
        nad_drop_elem(pkt->nad, subj);
    }
    nad_insert_elem(pkt->nad, 1, NAD_ENS(pkt->nad, 1), "subject", subject);

    for(jid = all; jid != NULL; jid = jid->next)
    {
        if (jid_compare_full(pkt->from, jid) == 0) {
            /* make a copy of the nad so it can be dumped to a string */
            nad_t copy = nad_copy(pkt->nad);
            const char * xml;
            int len;
            if (!copy) {
                log_write(mod->mm->sm->log, LOG_ERR, "%s:%d help admin %s is messaging sm for help! packet dropped. (unable to print packet - out of memory?)", ZONE, jid_full(jid));
                continue;
            }
            nad_print(copy, 0, &xml, &len);
            log_write(mod->mm->sm->log, LOG_ERR, "%s:%d help admin %s is messaging sm for help! packet dropped: \"%.*s\"\n", ZONE, jid_full(jid), len, xml);
            nad_free(copy);
            continue;
        }
        log_debug(ZONE, "resending to %s", jid_full(jid));
        pkt_router(pkt_dup(pkt, jid_full(jid), jid_user(pkt->to)));
    }

    for(jid = msg; jid != NULL; jid = jid->next)
        if(!jid_search(all, jid))
        {
            log_debug(ZONE, "resending to %s", jid_full(jid));
            pkt_router(pkt_dup(pkt, jid_full(jid), jid_user(pkt->to)));
        }

    /* !!! autoreply */

    free(subject);
    pkt_free(pkt);

    return mod_HANDLED;
}

static void _help_disco_extend(mod_instance_t mi, pkt_t pkt)
{
    module_t mod = mi->mod;
    int ns, i, n;
    config_elem_t elem;
    char confelem[64];

    log_debug(ZONE, "in mod_help disco-extend");

    if(config_get(mod->mm->sm->config, "discovery.serverinfo") == NULL)
        return;

    ns = nad_add_namespace(pkt->nad, uri_XDATA, NULL);
    /* there may be several XDATA siblings, so need to enforce the NS */
    pkt->nad->scope = ns;

    nad_append_elem(pkt->nad, ns, "x", 3);
    nad_append_attr(pkt->nad, -1, "type", "result");
    /* hidden form type field*/
    nad_append_elem(pkt->nad, -1, "field", 4);
    nad_append_attr(pkt->nad, -1, "var", "FORM_TYPE");
    nad_append_attr(pkt->nad, -1, "type", "hidden");
    nad_append_elem(pkt->nad, -1, "value", 5);
    nad_append_cdata(pkt->nad, uri_SERVERINFO, strlen(uri_SERVERINFO), 6);

    /* loop over serverinfo fields */
    for(i = 0; _serverinfo_fields[i]; i++) {
        snprintf(confelem, 64, "discovery.serverinfo.%s.value", _serverinfo_fields[i]);
        elem = config_get(mod->mm->sm->config, confelem);

        if(elem != NULL) {
            nad_append_elem(pkt->nad, -1, "field", 4);
            nad_append_attr(pkt->nad, -1, "var", _serverinfo_fields[i]);
    
            for(n = 0; n < elem->nvalues; n++) {
                log_debug(ZONE, "adding %s: %s", confelem, elem->values[n]);
                nad_append_elem(pkt->nad, -1, "value", 5);
                nad_append_cdata(pkt->nad, elem->values[n], strlen(elem->values[n]), 6);
            }
        }
    }
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    /* store /help resource for use when answering probes */
    mod->private = "help";

    mod->pkt_sm = _help_pkt_sm;
    mod->disco_extend = _help_disco_extend;
    /* module data is static so nothing to free */
    /* mod->free = _help_free; */

    return 0;
}
