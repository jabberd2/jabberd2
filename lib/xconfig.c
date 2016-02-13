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
#include "str.h"
#include <gc.h>
#include <expat.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/** new config structure */
xconfig_t *xconfig_new(void)
{
    xconfig_t *c = (xconfig_t*) GC_MALLOC(sizeof(xconfig_t));
    c->hash = xhash_new(501);
    return c;
}

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

/** turn an xml file into a config hash */
int xconfig_load(xconfig_t *c, const char *file)
{
    return xconfig_load_with_id(c, file, 0);
}

/** turn an xml file into a config hash */
int xconfig_load_with_id(xconfig_t *c, const char *file, const char *id)
{
    struct build_data bd;
    FILE *f;
    XML_Parser p;
    int done, len, end, i, j, attr;
    char buf[1024], *next;
    struct nad_elem_st **path;
    xconfig_elem_t *elem;
    int rv = 0;

    /* open the file */
    f = fopen(file, "r");
    if (f == NULL)
    {
        fprintf(stderr, "config_load: couldn't open %s for reading: %s\n", file, strerror(errno));
        return 1;
    }

    /* new parser */
    p = XML_ParserCreate(NULL);
    if (p == NULL)
    {
        fprintf(stderr, "config_load: couldn't allocate XML parser\n");
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
            fprintf(stderr, "config_load: read error: %s\n", strerror(errno));
            XML_ParserFree(p);
            fclose(f);
            nad_free(bd.nad);
            return 1;
        }
        done = feof(f);

        /* parse it */
        if (!XML_Parse(p, buf, len, done))
        {
            fprintf(stderr, "config_load: parse error at line %llu: %s\n", (unsigned long long) XML_GetCurrentLineNumber(p), XML_ErrorString(XML_GetErrorCode(p)));
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

    // Put id if specified
    if (id) {
        elem = GC_MALLOC(sizeof(xconfig_elem_t));
        xhash_put(c->hash, GC_STRDUP("id"), elem);
        elem->values = GC_MALLOC_ATOMIC(sizeof(char *));
        elem->values[0] = GC_STRDUP(id);
        elem->nvalues = 1;
    }

    /* now, turn the nad into a config hash */
    path = NULL;
    len = 0, end = 0;
    /* start at 1, so we skip the root element */
    for (i = 1; i < bd.nad->ecur && rv == 0; i++)
    {
        /* make sure we have enough room to add this element to our path */
        if (end <= bd.nad->elems[i].depth)
        {
            end = bd.nad->elems[i].depth + 1;
            path = (struct nad_elem_st **) GC_REALLOC((void *) path, sizeof(struct nad_elem_st *) * end);
        }

        /* save this path element */
        path[bd.nad->elems[i].depth] = &bd.nad->elems[i];
        len = bd.nad->elems[i].depth + 1;

        /* construct the key from the current path */
        next = buf;
        for (j = 1; j < len; j++)
        {
            strncpy(next, bd.nad->cdata + path[j]->iname, path[j]->lname);
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
        if (NAD_CDATA_L(bd.nad, i) > 0) {
            // Expand values

            const char *val = _config_expandx(c, NAD_CDATA(bd.nad, i), NAD_CDATA_L(bd.nad, i));

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
        for (attr = bd.nad->elems[i].attr, j = 0; attr >= 0; attr = bd.nad->attrs[attr].next, j++);

        /* make space */
        elem->attrs[elem->nvalues] = GC_MALLOC_ATOMIC(sizeof(char *) * (j * 2 + 2));

        /* if we have some */
        if (j > 0)
        {
            /* copy them in */
            j = 0;
            attr = bd.nad->elems[i].attr;
            while(attr >= 0)
            {
                elem->attrs[elem->nvalues][j] = GC_STRNDUP(NAD_ANAME(bd.nad, attr), NAD_ANAME_L(bd.nad, attr));
                elem->attrs[elem->nvalues][j + 1] = GC_STRNDUP(NAD_AVAL(bd.nad, attr), NAD_AVAL_L(bd.nad, attr));

        /*
         * pstrdupx(blob, 0) returns NULL - which means that later
         * there's no way of telling whether an attribute is defined
         * as empty, or just not defined. This fixes that by creating
         * an empty string for attributes which are defined empty
         */
                if (NAD_AVAL_L(bd.nad, attr)==0) {
                    elem->attrs[elem->nvalues][j + 1] = GC_STRDUP("");
                } else {
                    elem->attrs[elem->nvalues][j + 1] = GC_STRNDUP(NAD_AVAL(bd.nad, attr), NAD_AVAL_L(bd.nad, attr));
                }
                j += 2;
                attr = bd.nad->attrs[attr].next;
            }
        }

        /* do this and we can use j_attr */
        elem->attrs[elem->nvalues][j] = NULL;
        elem->attrs[elem->nvalues][j + 1] = NULL;

        elem->nvalues++;
    }

    if (path != NULL)
        GC_FREE(path);

    if (c->nad != NULL)
        nad_free(c->nad);
    c->nad = bd.nad;

    return rv;
}

/** get the config element for this key */
xconfig_elem_t *xconfig_get(xconfig_t *c, const char *key)
{
    return xhash_get(c->hash, key);
}

/** get config value n for this key */
const char *xconfig_get_one(xconfig_t *c, const char* key, int num)
{
    xconfig_elem_t *elem = xhash_get(c->hash, key);

    if (elem == NULL)
        return NULL;

    if (num >= elem->nvalues)
        return NULL;

    return elem->values[num];
}

/** get config value n for this key, returns default_value if not found */
const char *xconfig_get_one_default(xconfig_t *c, const char *key, int num, const char *default_value)
{
    const char *rv = xconfig_get_one(c, key, num);

    if (!rv)
        rv = default_value;

    return rv;
};


/** how many values for this key? */
int xconfig_count(xconfig_t *c, const char *key)
{
    xconfig_elem_t *elem = xhash_get(c->hash, key);

    if (elem == NULL)
        return 0;

    return elem->nvalues;
}

/** get an attr for this value */
char *xconfig_get_attr(xconfig_t *c, const char *key, int num, const char *attr)
{
    xconfig_elem_t *elem = xhash_get(c->hash, key);

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

//     fprintf(stderr, "config_expand: Expanding '%s'\n", value);
    char *s = GC_STRNDUP(value, l);

    char *var_start, *var_end;

    while ((var_start = strstr(s, "${")) != 0) {
//         fprintf(stderr, "config_expand: processing '%s'\n", s);
        var_end = strstr(var_start + 2, "}");

        if (var_end) {
            char *tail = var_end + 1;
            char *var = var_start + 2;
            *var_end = 0;

//             fprintf(stderr, "config_expand: Var '%s', tail is '%s'\n", var, tail);

            const char *var_value = xconfig_get_one(c, var, 0);

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
                fprintf(stderr, "config_expand: Have no '%s' defined\n", var);
                GC_FREE(s);
                s = 0;
                break;
            }
        } else {
            fprintf(stderr, "config_expand: } missmatch\n");
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

/** cleanup */
void xconfig_free(xconfig_t *c)
{
    xhash_walk(c->hash, _config_reaper, NULL);
    xhash_free(c->hash);
    nad_free(c->nad);
    GC_FREE(c);
}
