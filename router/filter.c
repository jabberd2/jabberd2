/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2006 Tomasz Sterna
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
#include <fnmatch.h>

/** filter manager */

void filter_unload(router_t r) {
    acl_t acl, tmp;

    acl = r->filter;

    while(acl != NULL) {
        tmp = acl->next;
        if(acl->from != NULL) free(acl->from);
        if(acl->to != NULL) free(acl->to);
        if(acl->what != NULL) free(acl->what);
        if(acl->redirect != NULL) free(acl->redirect);
        free(acl);
        acl = tmp;
    }
    r->filter = NULL;
}

int filter_load(router_t r) {
    const char *filterfile;
    FILE *f;
    long size;
    char *buf;
    nad_t nad;
    int i, nfilters, filter, from, to, what, redirect, error, log;
    acl_t list_tail, acl;

    log_debug(ZONE, "loading filter");
    
    if(r->filter != NULL)
        filter_unload(r);

    filterfile = config_get_one(r->config, "aci.filter", 0);
    if(filterfile == NULL)
        filterfile = CONFIG_DIR "/router-filter.xml";

    f = fopen(filterfile, "rb");
    if(f == NULL) {
        log_write(r->log, LOG_NOTICE, "couldn't open filter file %s: %s", filterfile, strerror(errno));
        r->filter_load = time(NULL);
        return 0;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = (char *) malloc(sizeof(char) * size);

    if (fread(buf, 1, size, f) != size || ferror(f)) {
        log_write(r->log, LOG_ERR, "couldn't read from filter file: %s", strerror(errno));
        free(buf);
        fclose(f);
        return 1;
    }

    fclose(f);

    nad = nad_parse(buf, size);
    if(nad == NULL) {
        log_write(r->log, LOG_ERR, "couldn't parse filter file");
        free(buf);
        return 1;
    }

    free(buf);

    list_tail = NULL;

    log_debug(ZONE, "building filter list");

    nfilters = 0;
    filter = nad_find_elem(nad, 0, -1, "rule", 1);
    while(filter >= 0) {
        from = nad_find_attr(nad, filter, -1, "from", NULL);
        to = nad_find_attr(nad, filter, -1, "to", NULL);
        what = nad_find_attr(nad, filter, -1, "what", NULL);
        redirect = nad_find_attr(nad, filter, -1, "redirect", NULL);
        error = nad_find_attr(nad, filter, -1, "error", NULL);
        log = nad_find_attr(nad, filter, -1, "log", NULL);

        acl = (acl_t) calloc(1, sizeof(struct acl_s));

        if(from >= 0) {
            if (NAD_AVAL_L(nad, from) == 0 )
                acl->from = NULL;
            else {
                acl->from = (char *) malloc(sizeof(char) * (NAD_AVAL_L(nad, from) + 1));
                sprintf(acl->from, "%.*s", NAD_AVAL_L(nad, from), NAD_AVAL(nad, from));
            }
        }
        if(to >= 0) {
            if (NAD_AVAL_L(nad, to) == 0 )
                acl->to = NULL;
            else {
                acl->to = (char *) malloc(sizeof(char) * (NAD_AVAL_L(nad, to) + 1));
                sprintf(acl->to, "%.*s", NAD_AVAL_L(nad, to), NAD_AVAL(nad, to));
            }
        }
        if(what >= 0) {
            if (NAD_AVAL_L(nad, what) == 0 || strncmp(NAD_AVAL(nad, what), "*", NAD_AVAL_L(nad, what)) == 0)
                acl->what = NULL;
            else {
                acl->what = (char *) malloc(sizeof(char) * (NAD_AVAL_L(nad, what) + 1));
                sprintf(acl->what, "%.*s", NAD_AVAL_L(nad, what), NAD_AVAL(nad, what));
            }
        }
        if(redirect >= 0) {
            if (NAD_AVAL_L(nad, redirect) == 0)
                acl->redirect = NULL;
            else {
                acl->redirect_len = NAD_AVAL_L(nad, redirect);
                acl->redirect = (char *) malloc(sizeof(char) * (acl->redirect_len + 1));
                sprintf(acl->redirect, "%.*s", acl->redirect_len, NAD_AVAL(nad, redirect));
                acl->error = stanza_err_REDIRECT;
            }
        }
        if(error >= 0) {
            acl->error = stanza_err_NOT_ALLOWED;
            for(i=0; _stanza_errors[i].code != NULL; i++) {
                if(_stanza_errors[i].name != NULL && strncmp(_stanza_errors[i].name, NAD_AVAL(nad, error), NAD_AVAL_L(nad, error)) == 0) {
                    acl->error = stanza_err_BAD_REQUEST + i;
                    break;
                }
            }
        }
        if(log >= 0) {
            acl->log = ! strncasecmp(NAD_AVAL(nad, log), "YES", NAD_AVAL_L(nad, log));
            acl->log |= ! strncasecmp(NAD_AVAL(nad, log), "ON", NAD_AVAL_L(nad, log));
        }

        if(list_tail != NULL) {
           list_tail->next = acl;
           list_tail = acl;
        }

        /* record the head of the list */
        if(r->filter == NULL) {
           r->filter = acl;
           list_tail = acl;
        }
        
        log_debug(ZONE, "added %s rule: from=%s, to=%s, what=%s, redirect=%s, error=%d, log=%s", (acl->error?"deny":"allow"), acl->from, acl->to, acl->what, acl->redirect, acl->error, (acl->log?"yes":"no"));

        nfilters++;

        filter = nad_find_elem(nad, filter, -1, "rule", 0);
    }

    nad_free(nad);

    log_write(r->log, LOG_NOTICE, "loaded filters (%d rules)", nfilters);

    r->filter_load = time(NULL);

    return 0;
}

int filter_packet(router_t r, nad_t nad) {
    acl_t acl;
    int ato, afrom, error = 0;
    char *cur, *to = NULL, *from = NULL;

    ato = nad_find_attr(nad, 1, -1, "to", NULL);
    afrom = nad_find_attr(nad, 1, -1, "from", NULL);
    if(ato >= 0 && NAD_AVAL_L(nad,ato) > 0) {
        to = (char *) malloc(sizeof(char) * (NAD_AVAL_L(nad, ato) + 1));
        sprintf(to, "%.*s", NAD_AVAL_L(nad, ato), NAD_AVAL(nad, ato));
        cur = strstr(to, "@");       /* skip node part */
        if(cur != NULL)
            cur = strstr(cur, "/");
        else
            cur = strstr(to, "/");
        if(cur != NULL) *cur = '\0'; /* remove the resource part */
    }
    if(afrom >= 0 && NAD_AVAL_L(nad,afrom) > 0) {
        from = (char *) malloc(sizeof(char) * (NAD_AVAL_L(nad, afrom) + 1));
        sprintf(from, "%.*s", NAD_AVAL_L(nad, afrom), NAD_AVAL(nad, afrom));
        cur = strstr(from, "@");
        if(cur != NULL)
            cur = strstr(cur, "/");
        else
            cur = strstr(from, "/");
        if(cur != NULL) *cur = '\0';
    }

    for(acl = r->filter; acl != NULL; acl = acl->next) {
        if( from == NULL && acl->from != NULL) continue;        /* no match if NULL matched vs not-NULL */
        if( to == NULL && acl->to != NULL ) continue;
        if( from != NULL && acl->from == NULL) continue;        /* no match if not-NULL matched vs NULL */
        if( to != NULL && acl->to == NULL ) continue;
        if( from != NULL && acl->from != NULL && fnmatch(acl->from, from, 0) != 0 ) continue;        /* do filename-like match */
        if( to != NULL && acl->to != NULL && fnmatch(acl->to, to, 0) != 0 ) continue;
        if( acl->what != NULL && nad_find_elem_path(nad, 0, -1, acl->what) < 0 ) continue;        /* match packet type */
        log_debug(ZONE, "matched packet %s->%s vs rule (%s %s->%s)", from, to, acl->what, acl->from, acl->to);
        if (acl->log) {
            if (acl->redirect) log_write(r->log, LOG_NOTICE, "filter: redirect packet from=%s to=%s - rule (from=%s to=%s what=%s), new to=%s", from, to, acl->from, acl->to, acl->what, acl->redirect);
            else log_write(r->log, LOG_NOTICE, "filter: %s packet from=%s to=%s - rule (from=%s to=%s what=%s)",(acl->error?"deny":"allow"), from, to, acl->from, acl->to, acl->what);
        }
        if (acl->redirect) nad_set_attr(nad, 0, -1, "to", acl->redirect, acl->redirect_len);
        error = acl->error;
        break;
    }

    if(to != NULL) free(to);
    if(from != NULL) free(from);
    return error;
}

