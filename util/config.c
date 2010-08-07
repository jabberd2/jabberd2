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

#include "util.h"
#include "expat.h"

/** new config structure */
config_t config_new(void)
{
    config_t c;

    c = (config_t) calloc(1, sizeof(struct config_st));

    c->hash = xhash_new(501);

    return c;
}

struct build_data
{
    nad_t               nad;
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

/** turn an xml file into a config hash */
int config_load(config_t c, const char *file)
{
    struct build_data bd;
    FILE *f;
    XML_Parser p;
    int done, len, end, i, j, attr;
    char buf[1024], *next;
    struct nad_elem_st **path;
    config_elem_t elem;

    /* open the file */
    f = fopen(file, "r");
    if(f == NULL)
    {
        fprintf(stderr, "config_load: couldn't open %s for reading: %s\n", file, strerror(errno));
        return 1;
    }

    /* new parser */
    p = XML_ParserCreate(NULL);
    if(p == NULL)
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

    for(;;)
    {
        /* read that file */
        len = fread(buf, 1, 1024, f);
        if(ferror(f))
        {
            fprintf(stderr, "config_load: read error: %s\n", strerror(errno));
            XML_ParserFree(p);
            fclose(f);
            nad_free(bd.nad);
            return 1;
        }
        done = feof(f);

        /* parse it */
        if(!XML_Parse(p, buf, len, done))
        {
            fprintf(stderr, "config_load: parse error at line %llu: %s\n", (unsigned long long) XML_GetCurrentLineNumber(p), XML_ErrorString(XML_GetErrorCode(p)));
            XML_ParserFree(p);
            fclose(f);
            nad_free(bd.nad);
            return 1;
        }

        if(done)
            break;
    }

    /* done reading */
    XML_ParserFree(p);
    fclose(f);

    /* now, turn the nad into a config hash */
    path = NULL;
    len = 0, end = 0;
    /* start at 1, so we skip the root element */
    for(i = 1; i < bd.nad->ecur; i++)
    {
        /* make sure we have enough room to add this element to our path */
        if(end <= bd.nad->elems[i].depth)
        {
            end = bd.nad->elems[i].depth + 1;
            path = (struct nad_elem_st **) realloc((void *) path, sizeof(struct nad_elem_st *) * end);
        }

        /* save this path element */
        path[bd.nad->elems[i].depth] = &bd.nad->elems[i];
        len = bd.nad->elems[i].depth + 1;

        /* construct the key from the current path */
        next = buf;
        for(j = 1; j < len; j++)
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
        if(elem == NULL)
        {
            /* haven't seen it before, so create it */
            elem = pmalloco(xhash_pool(c->hash), sizeof(struct config_elem_st));
            xhash_put(c->hash, pstrdup(xhash_pool(c->hash), buf), elem);
        }

        /* make room for this value .. can't easily realloc off a pool, so
         * we do it this way and let _config_reaper clean up */
        elem->values = realloc((void *) elem->values, sizeof(char *) * (elem->nvalues + 1));

        /* and copy it in */
        if(NAD_CDATA_L(bd.nad, i) > 0)
            elem->values[elem->nvalues] = pstrdupx(xhash_pool(c->hash), NAD_CDATA(bd.nad, i), NAD_CDATA_L(bd.nad, i));
        else
            elem->values[elem->nvalues] = "1";

        /* make room for the attribute lists */
        elem->attrs = realloc((void *) elem->attrs, sizeof(char **) * (elem->nvalues + 1));
        elem->attrs[elem->nvalues] = NULL;

        /* count the attributes */
        for(attr = bd.nad->elems[i].attr, j = 0; attr >= 0; attr = bd.nad->attrs[attr].next, j++);

        /* make space */
        elem->attrs[elem->nvalues] = pmalloc(xhash_pool(c->hash), sizeof(char *) * (j * 2 + 2));

        /* if we have some */
        if(j > 0)
        {
            /* copy them in */
            j = 0;
            attr = bd.nad->elems[i].attr;
            while(attr >= 0)
            {
                elem->attrs[elem->nvalues][j] = pstrdupx(xhash_pool(c->hash), NAD_ANAME(bd.nad, attr), NAD_ANAME_L(bd.nad, attr));
                elem->attrs[elem->nvalues][j + 1] = pstrdupx(xhash_pool(c->hash), NAD_AVAL(bd.nad, attr), NAD_AVAL_L(bd.nad, attr));

		/* 
		 * pstrdupx(blob, 0) returns NULL - which means that later
		 * there's no way of telling whether an attribute is defined
		 * as empty, or just not defined. This fixes that by creating
		 * an empty string for attributes which are defined empty
		 */
                if (NAD_AVAL_L(bd.nad, attr)==0) {
                    elem->attrs[elem->nvalues][j + 1] = pstrdup(xhash_pool(c->hash), "");
                } else {
                    elem->attrs[elem->nvalues][j + 1] = pstrdupx(xhash_pool(c->hash), NAD_AVAL(bd.nad, attr), NAD_AVAL_L(bd.nad, attr));
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

    if(path != NULL)
        free(path);

    if(c->nad != NULL)
        nad_free(c->nad);
    c->nad = bd.nad;

    return 0;
}

/** get the config element for this key */
config_elem_t config_get(config_t c, const char *key)
{
    return xhash_get(c->hash, key);
}

/** get config value n for this key */
char *config_get_one(config_t c, const char *key, int num)
{
    config_elem_t elem = xhash_get(c->hash, key);

    if(elem == NULL)
        return NULL;

    if(num >= elem->nvalues)
        return NULL;

    return elem->values[num];
}

/** how many values for this key? */
int config_count(config_t c, const char *key)
{
    config_elem_t elem = xhash_get(c->hash, key);

    if(elem == NULL)
        return 0;

    return elem->nvalues;
}

/** get an attr for this value */
char *config_get_attr(config_t c, const char *key, int num, const char *attr)
{
    config_elem_t elem = xhash_get(c->hash, key);

    if(num >= elem->nvalues || elem->attrs == NULL || elem->attrs[num] == NULL)
        return NULL;

    return j_attr((const char **) elem->attrs[num], attr);
}

/** cleanup helper */
static void _config_reaper(const char *key, int keylen, void *val, void *arg)
{
    config_elem_t elem = (config_elem_t) val;

    free(elem->values);
    free(elem->attrs);
}

/** cleanup */
void config_free(config_t c)
{
    xhash_walk(c->hash, _config_reaper, NULL);

    xhash_free(c->hash);

    nad_free(c->nad);

    free(c);
}
