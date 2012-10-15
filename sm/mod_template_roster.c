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

/** @file sm/mod_template_roster.c
  * @brief user auto-population - roster
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.11 $
  */

/* user template - roster */

typedef struct _template_roster_st {
    sm_t       sm;
    const char *filename;
    time_t     mtime;
    xht        items;
} *template_roster_t;

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  item_t *item_val;
};

static int _template_roster_reload(template_roster_t tr) {
    struct stat st;
    FILE *f;
    long size;
    char *buf;
    nad_t nad;
    int nitems, eitem, ajid, as10n, aname, egroup;
    item_t item;

    if(stat(tr->filename, &st) < 0) {
        log_write(tr->sm->log, LOG_ERR, "couldn't stat roster template %s: %s", tr->filename, strerror(errno));
        return 1;
    }

    if(st.st_mtime <= tr->mtime)
        return 0;

    tr->mtime = st.st_mtime;

    if(tr->items != NULL)
        xhash_free(tr->items);

    tr->items = xhash_new(101);

    f = fopen(tr->filename, "r");
    if(f == NULL) {
        log_write(tr->sm->log, LOG_ERR, "couldn't open roster template %s: %s", tr->filename, strerror(errno));
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = (char *) malloc(sizeof(char) * size);

    if (fread(buf, 1, size, f) != size || ferror(f)) {
        log_write(tr->sm->log, LOG_ERR, "couldn't read from roster template %s: %s", tr->filename, strerror(errno));
        free(buf);
        fclose(f);
        return 1;
    }

    fclose(f);

    nad = nad_parse(buf, size);
    if(nad == NULL) {
        log_write(tr->sm->log, LOG_ERR, "couldn't parse roster template");
        free(buf);
        return 1;
    }

    free(buf);

    if(nad->ecur < 2) {
        log_write(tr->sm->log, LOG_NOTICE, "roster template has no elements");
    }

    nitems = 0;
    eitem = nad_find_elem(nad, 0, NAD_ENS(nad, 0), "item", 1);
    while(eitem >= 0) {
        ajid = nad_find_attr(nad, eitem, -1, "jid", NULL);
        if(ajid < 0) {
            log_write(tr->sm->log, LOG_ERR, "roster template has item with no jid, skipping");
            continue;
        }
        
        item = (item_t) pmalloco(xhash_pool(tr->items), sizeof(struct item_st));

        item->jid = jid_new(NAD_AVAL(nad, ajid), NAD_AVAL_L(nad, ajid));
        if(item->jid == NULL) {
            log_write(tr->sm->log, LOG_ERR, "roster template has item with invalid jid, skipping");
            continue;
        }
        pool_cleanup(xhash_pool(tr->items), (void (*)(void *)) jid_free, item->jid);

        as10n = nad_find_attr(nad, eitem, -1, "subscription", NULL);
        if(as10n >= 0) {
            if(NAD_AVAL_L(nad, as10n) == 2 && strncmp("to", NAD_AVAL(nad, as10n), 2) == 0)
                item->to = 1;
            else if(NAD_AVAL_L(nad, as10n) == 4 && strncmp("from", NAD_AVAL(nad, as10n), 4) == 0)
                item->from = 1;
            else if(NAD_AVAL_L(nad, as10n) == 4 && strncmp("both", NAD_AVAL(nad, as10n), 4) == 0)
                item->to = item->from = 1;
        }

        aname = nad_find_attr(nad, eitem, -1, "name", NULL);
        if(aname >= 0)
            item->name = pstrdupx(xhash_pool(tr->items), NAD_AVAL(nad, aname), NAD_AVAL_L(nad, aname));

        egroup = nad_find_elem(nad, eitem, NAD_ENS(nad, 0), "group", 1);
        while(egroup >= 0) {
            if(NAD_CDATA_L(nad, egroup) <= 0) {
                log_write(tr->sm->log, LOG_ERR, "roster template has zero-length group, skipping");
                continue;
            }

            item->groups = (const char **) realloc(item->groups, sizeof(char *) * (item->ngroups + 1));
            item->groups[item->ngroups] = pstrdupx(xhash_pool(tr->items), NAD_CDATA(nad, egroup), NAD_CDATA_L(nad, egroup));
            item->ngroups++;

            egroup = nad_find_elem(nad, egroup, NAD_ENS(nad, 0), "group", 0);
        }

        if(item->groups != NULL)
            pool_cleanup(xhash_pool(tr->items), free, item->groups);

        xhash_put(tr->items, jid_full(item->jid), item);

        log_debug(ZONE, "loaded roster template item %s, %d groups", jid_full(item->jid), item->ngroups);

        nitems++;
        
        eitem = nad_find_elem(nad, eitem, NAD_ENS(nad, 0), "item", 0);
    }

    log_write(tr->sm->log, LOG_NOTICE, "loaded %d items from roster template", nitems);

    return 0;
}

/** !!! this is a cut & paste of _roster_save_time - break it out */
static void _template_roster_save_item(sm_t sm, jid_t jid, item_t item) {
    os_t os;
    os_object_t o;
    char filter[4096];
    int i;

    log_debug(ZONE, "saving roster item %s for %s", jid_full(item->jid), jid_user(jid));

    os = os_new();
    o = os_object_new(os);

    os_object_put(o, "jid", jid_full(item->jid), os_type_STRING);

    if(item->name != NULL)
        os_object_put(o, "name", item->name, os_type_STRING);

    os_object_put(o, "to", &item->to, os_type_BOOLEAN);
    os_object_put(o, "from", &item->from, os_type_BOOLEAN);
    os_object_put(o, "ask", &item->ask, os_type_INTEGER);

    snprintf(filter, 4096, "(jid=%zu:%s)", strlen(jid_full(item->jid)), jid_full(item->jid));

    storage_replace(sm->st, "roster-items", jid_user(jid), filter, os);

    os_free(os);

    snprintf(filter, 4096, "(jid=%zu:%s)", strlen(jid_full(item->jid)), jid_full(item->jid));

    if(item->ngroups == 0) {
        storage_delete(sm->st, "roster-groups", jid_user(jid), filter);
        return;
    }

    os = os_new();
    
    for(i = 0; i < item->ngroups; i++) {
        o = os_object_new(os);

        os_object_put(o, "jid", jid_full(item->jid), os_type_STRING);
        os_object_put(o, "group", item->groups[i], os_type_STRING);
    }

    storage_replace(sm->st, "roster-groups", jid_user(jid), filter, os);

    os_free(os);
}

static int _template_roster_user_create(mod_instance_t mi, jid_t jid) {
    template_roster_t tr = (template_roster_t) mi->mod->private;
    item_t item;
    union xhashv xhv;

    if(_template_roster_reload(tr) != 0)
        return 0;

    log_debug(ZONE, "populating roster with items from template");

    if(xhash_iter_first(tr->items))
        do {
            xhv.item_val = &item;
            xhash_iter_get(tr->items, NULL, NULL, xhv.val);

            _template_roster_save_item(tr->sm, jid, item);
        } while(xhash_iter_next(tr->items));

    return 0;
}

static void _template_roster_free(module_t mod) {
    template_roster_t tr = (template_roster_t) mod->private;

    if(tr->items != NULL)
        xhash_free(tr->items);

    free(tr);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;
    const char *filename;
    template_roster_t tr;

    if(mod->init) return 0;

    filename = config_get_one(mod->mm->sm->config, "user.template.roster", 0);
    if(filename == NULL)
        return 0;

    tr = (template_roster_t) calloc(1, sizeof(struct _template_roster_st));

    tr->sm = mod->mm->sm;
    tr->filename = filename;

    mod->private = tr;

    mod->user_create = _template_roster_user_create;
    mod->free = _template_roster_free;

    return 0;
}
