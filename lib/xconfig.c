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

#include "xconfig.h"
#include "sds.h"
#include "str.h"
#include <gc.h>
#include <expat.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

/** holder for callback and its default value */
struct xconfig_callback_st
{
    xconfig_callback    *callback;
    void                *data;
};

struct build_data
{
    nad_t               *nad;
    int                 depth;
};

static void _config_startElement(void *arg, const char *name, const char **atts)
{
    struct build_data *bd = (struct build_data *) arg;
    int i = 0;

    nad_append_elem(bd->nad, -1, (char *) name, bd->depth);
    while(atts[i] != NULL)
    {
        nad_append_attr(bd->nad, -1, (char *) atts[i], (char *) atts[i + 1]);
        i += 2;
    }

    bd->depth++;
}

static void _config_endElement(void *arg, const char *name)
{
    struct build_data *bd = (struct build_data *) arg;

    bd->depth--;
}

static void _config_charData(void *arg, const char *str, int len)
{
    struct build_data *bd = (struct build_data *) arg;

    nad_append_cdata(bd->nad, (char *) str, len, bd->depth);
}

static char *_config_expandx(xconfig_t *c, const char *value, int l);

/** new config structure */
xconfig_t *xconfig_new(int prime, log_t *log)
{
    xconfig_t *c = (xconfig_t*) GC_MALLOC(sizeof(xconfig_t));
    c->hash = xhash_new(prime ? prime : 501);
    c->log = log;
    return c;
}

/** turn an xml file into a config hash */
int xconfig_load_id(xconfig_t *c, const char *id)
{
    if (!id)
        return 1;

    xconfig_elem_t *elem = GC_MALLOC(sizeof(xconfig_elem_t));
    xhash_put(c->hash, GC_STRDUP("id"), elem);
    elem->values = GC_MALLOC(sizeof(char *));
    elem->values[0] = GC_STRDUP(id);
    elem->nvalues = 1;

    return 0;
}

/** turn an xml file into a config hash */
int xconfig_load_file(xconfig_t *c, const char *prefix, const char *file)
{
    int done, len;
    char buf[1024];
    struct build_data bd;
    FILE *f;
    XML_Parser p;

    /* open the file */
    f = fopen(file, "r");
    if (f == NULL)
    {
        LOG_ERROR(c->log, "couldn't open %s for reading: %s", file, strerror(errno));
        return 1;
    }

    /* new parser */
    p = XML_ParserCreate(NULL);
    if (p == NULL)
    {
        LOG_ERROR(c->log, "couldn't allocate XML parser");
        fclose(f);
        return 1;
    }

    /* nice new nad to parse it into */
    bd.nad = nad_new();
    bd.depth = 0;

    /* setup the parser */
    XML_SetUserData(p, (void *) &bd);
    XML_SetElementHandler(p, _config_startElement, _config_endElement);
    XML_SetCharacterDataHandler(p, _config_charData);

    for (;;)
    {
        /* read that file */
        len = fread(buf, 1, 1024, f);
        if (ferror(f))
        {
            LOG_ERROR(c->log, "read error: %s", strerror(errno));
            XML_ParserFree(p);
            fclose(f);
            nad_free(bd.nad);
            return 1;
        }
        done = feof(f);

        /* parse it */
        if (!XML_Parse(p, buf, len, done))
        {
            LOG_ERROR(c->log, "parse error at line %llu: %s", (unsigned long long) XML_GetCurrentLineNumber(p), XML_ErrorString(XML_GetErrorCode(p)));
            XML_ParserFree(p);
            fclose(f);
            nad_free(bd.nad);
            return 1;
        }

        if (done)
            break;
    }

    /* done reading */
    XML_ParserFree(p);
    fclose(f);

    return xconfig_load_nad(c, prefix, bd.nad);
}

int xconfig_load_nad(xconfig_t *c, const char *prefix, const nad_t *nad)
{
    int len, end, i, j, attr;
    sds buf;
    char *next;
    struct nad_elem_st **path;
    xconfig_elem_t *elem;
    int rv = 0;

    buf = sdsnew(prefix);
    if (prefix) {
        buf = sdscat(buf, ".");
    }

    /* turn the nad into a config hash */
    path = NULL;
    len = 0, end = 0;
    /* start at 1, so we skip the root element */
    for (i = 1; i < nad->ecur && rv == 0; i++)
    {
        /* make sure we have enough room to add this element to our path */
        if (end <= nad->elems[i].depth)
        {
            end = nad->elems[i].depth + 1;
            path = (struct nad_elem_st **) GC_REALLOC((void *) path, sizeof(struct nad_elem_st *) * end);
        }

        /* save this path element */
        path[nad->elems[i].depth] = &nad->elems[i];
        len = nad->elems[i].depth + 1;

        /* construct the key from the current path */
        next = buf + sdslen(buf);
        for (j = 1; j < len; j++)
        {
            sdsgrowzero(buf, (next - buf) + path[j]->lname);
            strncpy(next, nad->cdata + path[j]->iname, path[j]->lname);
            next = next + path[j]->lname;
            *next = '.';
            next++;
        }
        next--;
        *next = '\0';

        /* find the config element for this key */
        elem = xhash_get(c->hash, buf);
        if (elem == NULL)
        {
            /* haven't seen it before, so create it */
            elem = GC_MALLOC(sizeof(xconfig_elem_t));
            xhash_put(c->hash, GC_STRDUP(buf), elem);
        }

        elem->values = GC_REALLOC((void *) elem->values, sizeof(char *) * (elem->nvalues + 1));

        /* and copy it in */
        if (NAD_CDATA_L(nad, i) > 0) {
            // Expand values

            const char *val = _config_expandx(c, NAD_CDATA(nad, i), NAD_CDATA_L(nad, i));

            if (!val) {
                rv = 1;
                break;
            }
            // Make a copy
            elem->values[elem->nvalues] = val;
        } else {
            elem->values[elem->nvalues] = "1";
        }

        /* make room for the attribute lists */
        elem->attrs = GC_REALLOC((void *) elem->attrs, sizeof(char **) * (elem->nvalues + 1));
        elem->attrs[elem->nvalues] = NULL;

        /* count the attributes */
        for (attr = nad->elems[i].attr, j = 0; attr >= 0; attr = nad->attrs[attr].next, j++);

        /* make space */
        elem->attrs[elem->nvalues] = GC_MALLOC(sizeof(char *) * (j * 2 + 2));

        /* if we have some */
        if (j > 0)
        {
            /* copy them in */
            j = 0;
            attr = nad->elems[i].attr;
            while(attr >= 0)
            {
                elem->attrs[elem->nvalues][j] = GC_STRNDUP(NAD_ANAME(nad, attr), NAD_ANAME_L(nad, attr));
                elem->attrs[elem->nvalues][j + 1] = GC_STRNDUP(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

        /*
         * pstrdupx(blob, 0) returns NULL - which means that later
         * there's no way of telling whether an attribute is defined
         * as empty, or just not defined. This fixes that by creating
         * an empty string for attributes which are defined empty
         */
                if (NAD_AVAL_L(nad, attr)==0) {
                    elem->attrs[elem->nvalues][j + 1] = GC_STRDUP("");
                } else {
                    elem->attrs[elem->nvalues][j + 1] = GC_STRNDUP(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));
                }
                j += 2;
                attr = nad->attrs[attr].next;
            }
        }

        /* do this and we can use j_attr */
        elem->attrs[elem->nvalues][j] = NULL;
        elem->attrs[elem->nvalues][j + 1] = NULL;

        /* insert nad reference */
        elem->nad = (nad_t*)nad;
        elem->nad_elem = i;

        elem->nvalues++;
    }

    if (path != NULL)
        GC_FREE(path);

    return rv;
}

/** get the config element for this key */
inline xconfig_elem_t *xconfig_get(xconfig_t *c, const char *key)
{
    return xhash_get(c->hash, key);
}

/** get config value n for this key */
const char *xconfig_get_one(xconfig_t *c, const char *key, int num, const char *default_value)
{
    xconfig_elem_t *elem = xconfig_get(c, key);

    if (elem == NULL)
        return NULL;

    return xconfig_elem_get_one(elem, num, default_value);
}

const char *xconfig_elem_get_one(xconfig_elem_t *elem, int num, const char *default_value)
{
    if (num >= elem->nvalues)
        return NULL;

    const char *rv = elem->values[num];

    if (!rv)
        rv = default_value;

    return rv;
}

/** how many values for this key? */
int xconfig_count(xconfig_t *c, const char *key)
{
    xconfig_elem_t *elem = xhash_get(c->hash, key);

    if (elem == NULL)
        return 0;

    return xconfig_elem_count(elem);
}

inline int xconfig_elem_count(xconfig_elem_t *elem)
{
    return elem->nvalues;
}

/** get an attr for this value */
const char *xconfig_get_attr(xconfig_t *c, const char *key, int num, const char *attr)
{
    xconfig_elem_t *elem = xhash_get(c->hash, key);

    if (elem == NULL)
        return 0;

    return xconfig_elem_get_attr(elem, num, attr);
}

const char *xconfig_elem_get_attr(xconfig_elem_t *elem, int num, const char *attr)
{
    if (num >= elem->nvalues || elem->attrs == NULL || elem->attrs[num] == NULL)
        return NULL;

    return j_attr((const char **) elem->attrs[num], attr);
}

/** cleanup helper */
static void _config_reaper(const char *key, int keylen, void *val, void *arg)
{
    xconfig_elem_t *elem = (xconfig_elem_t*) val;

    GC_FREE(elem->values);
    GC_FREE(elem->attrs);
    GC_FREE(elem->subs);
    /* and we cannot free elem->nad here, as no single elem owns it
     * Yay for GC! - it will take care of it eventually. */
}

char *xconfig_expand(xconfig_t *c, const char *value)
{
    return _config_expandx(c, value, strlen(value));
}

static char *_config_expandx(xconfig_t *c, const char *value, int l)
{
#ifdef CONFIGEXPAND_GUARDED
    static char guard[] = "deadbeaf";
#endif

    LOG_DEBUG(c->log, "Expanding '%.*s'", l, value);
    char *s = GC_STRNDUP(value, l);

    char *var_start, *var_end;

    while ((var_start = strstr(s, "${")) != 0) {
        LOG_TRACE(c->log, "processing '%s'", s);
        var_end = strstr(var_start + 2, "}");

        if (var_end) {
            char *tail = var_end + 1;
            char *var = var_start + 2;
            *var_end = 0;

            LOG_TRACE(c->log, "config_expand: Var '%s', tail is '%s'", var, tail);

            const char *var_value = xconfig_get_one(c, var, 0, NULL);

            if (var_value) {
                int len = (var_start - s) + strlen(tail) + strlen(var_value) + 1;

#ifdef CONFIGEXPAND_GUARDED
                len += sizeof(guard);
#endif
                char *expanded_str = GC_MALLOC_ATOMIC(len);

#ifdef CONFIGEXPAND_GUARDED
                char *p_guard = expanded_str + len - sizeof(guard);
                strncpy(p_guard, guard, sizeof(guard));
#endif

                char *p = expanded_str;
                strncpy(expanded_str, s, var_start - s);
                p += var_start - s;

                strcpy(p, var_value);
                p += strlen(var_value);

                strcpy(p, tail);

                GC_FREE(s);
                s = expanded_str;
            } else {
                LOG_NOTICE(c->log, "config_expand: Have no '%s' defined", var);
                GC_FREE(s);
                s = 0;
                break;
            }
        } else {
            LOG_NOTICE(c->log, "config_expand: } missmatch");
            GC_FREE(s);
            s = 0;
            break;
        }
    }

    if (s) {
        char *retval = GC_STRDUP(s);
        GC_FREE(s);
        return retval;
    } else {
        return 0;
    }
}

void xconfig_subscribe(xconfig_t *c, const char *key, xconfig_callback *handler, void *data)
{
    int n;
    xconfig_callback_t *subs;

    xconfig_elem_t *elem = xhash_get(c->hash, key);

    if (elem == NULL) {
        elem = xconfig_set(c, key, NULL, 0);
    }

    if (elem->subs != NULL) {
        for (subs = elem->subs; subs->callback != NULL; subs++) {
            if (subs->callback == handler) {
                /* already subscribed */
                subs->data = data;
                return;
            }
        }
        n = subs - elem->subs;
    } else {
        elem->subs = GC_MALLOC(sizeof(xconfig_callback_t));
        n = 0;
    }

    n++; /* space for new item */
    LOG_TRACE(c->log, "realloc elem '%s' to %d subs", key, n);
    n++; /* space for terminating NUL item */
    elem->subs = GC_REALLOC(elem->subs, n * sizeof(xconfig_callback_t));
    elem->subs[--n].callback = NULL;
    xconfig_callback_t *sub = &elem->subs[--n];
    sub->callback = handler;
    sub->data = data;

    LOG_DEBUG(c->log, "subscribed handler %p:%p for elem '%s'", handler, data, key);

    /* call newly added callback with current value */
    (*handler)(key, elem, data);
}

struct _unsubscribe_walker_data {
    xconfig_callback *handler;
    void *data;
};

static void _unsubscribe_walker(__attribute__ ((unused)) const char *key, __attribute__ ((unused)) int keylen, void *val, void *arg)
{
    xconfig_callback_t *subs, *subsrm = NULL;
    xconfig_elem_t * const elem = val;
    struct _unsubscribe_walker_data * const wd = arg;

    if (elem->subs != NULL) {
        for (subs = elem->subs; subs->callback != NULL; subs++) {
            if ((wd->handler == NULL || subs->callback == wd->handler)
             && (wd->data == NULL || subs->data == wd->data)) {
                subsrm = subs;
            }
        }
        if (subsrm != NULL) {
            /* replace found mod_instance with last one and NULLify last one */
            subs--;
            *subsrm = *subs;
            subs->callback = NULL;
        }
    }
}

void xconfig_unsubscribe(xconfig_t *c, xconfig_callback *handler, void *data)
{
    LOG_DEBUG(c->log, "unsubscribing handler %p(%p) from all elems", handler, data);
    struct _unsubscribe_walker_data walker_data;
    walker_data.handler = handler;
    walker_data.data = data;
    xhash_walk(c->hash, _unsubscribe_walker, &walker_data);
}

static void _call_subs(xconfig_t *c, const char *key, xconfig_elem_t *elem)
{
    xconfig_callback_t *subs;
    for (subs = elem->subs; subs != NULL && subs->callback != NULL; subs++) {
        (*subs->callback)(key, elem, subs->data);
    }
}

xconfig_elem_t *xconfig_set(xconfig_t *c, const char *key, const char **values, int num)
{
    LOG_DEBUG(c->log, "setting '%s' with %d values %p", key, num, values);

    xconfig_elem_t *elem = xhash_get(c->hash, key);

    if (elem == NULL) {
        elem = GC_MALLOC(sizeof(xconfig_elem_t));
        xhash_put(c->hash, GC_STRDUP(key), elem);
    }

    GC_FREE(elem->values);
    elem->values = values;
    elem->nvalues = num;

    _call_subs(c, key, elem);

    return elem;
}

xconfig_elem_t *xconfig_set_one(xconfig_t *c, const char *key, int num, const char *value)
{
    LOG_DEBUG(c->log, "setting '%s'[%d] with value '%s'", key, num, value);

    xconfig_elem_t *elem = xhash_get(c->hash, key);

    if (elem == NULL) {
        elem = GC_MALLOC(sizeof(xconfig_elem_t));
        xhash_put(c->hash, GC_STRDUP(key), elem);
    }

    if (elem->nvalues <= num) {
        elem->nvalues = num + 1;
        elem->values = GC_REALLOC((void *) elem->values, sizeof(char *) * (elem->nvalues));
    }

    elem->values[num] = value;

    _call_subs(c, key, elem);

    return elem;
}


/** cleanup */
void xconfig_free(xconfig_t *c)
{
    xhash_walk(c->hash, _config_reaper, NULL);
    xhash_free(c->hash);
    GC_FREE(c);
}
