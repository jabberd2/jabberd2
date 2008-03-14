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

#include "xhash.h"
#include "util.h"


/* Generates a hash code for a string.
 * This function uses the ELF hashing algorithm as reprinted in 
 * Andrew Binstock, "Hashing Rehashed," Dr. Dobb's Journal, April 1996.
 */
static int _xhasher(const char *s, int len)
{
    /* ELF hash uses unsigned chars and unsigned arithmetic for portability */
    const unsigned char *name = (const unsigned char *)s;
    unsigned long h = 0, g;
    int i;

    for(i=0;i<len;i++)
    { /* do some fancy bitwanking on the string */
        h = (h << 4) + (unsigned long)(name[i]);
        if ((g = (h & 0xF0000000UL))!=0)
            h ^= (g >> 24);
        h &= ~g;

    }

    return (int)h;
}


static xhn _xhash_node_new(xht h, int index)
{
    xhn n;
    int i = index % h->prime;

    /* track total */
    h->count++;

    /* get existing empty one */
    for(n = &h->zen[i]; n != NULL; n = n->next)
        if(n->key == NULL)
            return n;

    /* overflowing, new one! */
    n = pmalloco(h->p, sizeof(_xhn));
    n->next = h->zen[i].next;
    h->zen[i].next = n;
    return n;
}


static xhn _xhash_node_get(xht h, const char *key, int len, int index)
{
    xhn n;
    int i = index % h->prime;
    for(n = &h->zen[i]; n != NULL; n = n->next)
        if(n->key != NULL && (strlen(n->key)==len) && (strncmp(key, n->key, len) == 0))
            return n;
    return NULL;
}


xht xhash_new(int prime)
{
    xht xnew;
    pool_t p;

/*    log_debug(ZONE,"creating new hash table of size %d",prime); */

    p = pool_heap(sizeof(_xhn)*prime + sizeof(_xht));
    xnew = pmalloco(p, sizeof(_xht));
    xnew->prime = prime;
    xnew->p = p;
    xnew->zen = pmalloco(p, sizeof(_xhn)*prime); /* array of xhn size of prime */

    xnew->iter_bucket = -1;
    xnew->iter_node = NULL;

    return xnew;
}


void xhash_putx(xht h, const char *key, int len, void *val)
{
    int index;
    xhn n;

    if(h == NULL || key == NULL)
        return;

    index = _xhasher(key,len);

    /* dirty the xht */
    h->dirty++;

    /* if existing key, replace it */
    if((n = _xhash_node_get(h, key, len, index)) != NULL)
    {
/*        log_debug(ZONE,"replacing %s with new val %X",key,val); */

        n->key = key;
        n->val = val;
        return;
    }

/*    log_debug(ZONE,"saving %s val %X",key,val); */

    /* new node */
    n = _xhash_node_new(h, index);
    n->key = key;
    n->val = val;
}

void xhash_put(xht h, const char *key, void *val)
{
    if(h == NULL || key == NULL) return;
    xhash_putx(h,key,strlen(key),val);
}


void *xhash_getx(xht h, const char *key, int len)
{
    xhn n;

    if(h == NULL || key == NULL || len <= 0 || (n = _xhash_node_get(h, key, len, _xhasher(key,len))) == NULL)
    {
/*        log_debug(ZONE,"failed lookup of %s",key); */
        return NULL;
    }

/*    log_debug(ZONE,"found %s returning %X",key,n->val); */
    return n->val;
}

void *xhash_get(xht h, const char *key)
{
    if(h == NULL || key == NULL) return NULL;
    return xhash_getx(h,key,strlen(key));
}


void xhash_zapx(xht h, const char *key, int len)
{
    xhn n;

    if(h == NULL || key == NULL || (n = _xhash_node_get(h, key, len, _xhasher(key,len))) == NULL)
        return;

/*    log_debug(ZONE,"zapping %s",key); */

    /* kill an entry by zeroing out the key */
    n->key = NULL;
    n->val = NULL;

    /* dirty the xht and track the total */
    h->dirty++;
    h->count--;

    /* if we just killed the current iter, move to the next one */
    if(h->iter_node == n)
        xhash_iter_next(h);
}

void xhash_zap(xht h, const char *key)
{
    if(h == NULL || key == NULL) return;
    xhash_zapx(h,key,strlen(key));
}

void xhash_free(xht h)
{
/*    log_debug(ZONE,"hash free %X",h); */

    if(h != NULL)
        pool_free(h->p);
}

void xhash_walk(xht h, xhash_walker w, void *arg)
{
    int i;
    xhn n;

    if(h == NULL || w == NULL)
        return;

/*    log_debug(ZONE,"walking %X",h); */

    for(i = 0; i < h->prime; i++)
        for(n = &h->zen[i]; n != NULL; n = n->next)
            if(n->key != NULL && n->val != NULL)
                (*w)(h, n->key, n->val, arg);
}

/** return the dirty flag (and reset) */
int xhash_dirty(xht h)
{
    int dirty;

    if(h == NULL) return 1;

    dirty = h->dirty;
    h->dirty = 0;
    return dirty;
}

/** return the total number of entries in this xht */
int xhash_count(xht h)
{
    if(h == NULL) return 0;

    return h->count;
}

/** get our pool */
pool_t xhash_pool(xht h)
{
    return h->p;
}

/** iteration */
int xhash_iter_first(xht h) {
    if(h == NULL) return 0;

    h->iter_bucket = -1;
    h->iter_node = NULL;

    return xhash_iter_next(h);
}

int xhash_iter_next(xht h) {
    if(h == NULL) return 0;

    /* next in this bucket */
    while(h->iter_node != NULL) {
        h->iter_node = h->iter_node->next;

        if(h->iter_node != NULL && h->iter_node->key != NULL && h->iter_node->val != NULL)
            return 1;
    }

    /* next bucket */
    for(h->iter_bucket++; h->iter_bucket < h->prime; h->iter_bucket++) {
        h->iter_node = &h->zen[h->iter_bucket];

        while(h->iter_node != NULL) {
            if(h->iter_node->key != NULL && h->iter_node->val != NULL)
                return 1;

            h->iter_node = h->iter_node->next;
        }
    }

    /* there is no next */
    h->iter_bucket = -1;
    h->iter_node = NULL;

    return 0;
}

void xhash_iter_zap(xht h) {
    if(h == NULL) return;

    if(h->iter_node == NULL)
        return;

    /* pow */
    h->iter_node->key = NULL;
    h->iter_node->val = NULL;

    /* dirty the xht and track the total */
    h->dirty++;
    h->count--;

    /* next one */
    xhash_iter_next(h);
}

int xhash_iter_get(xht h, const char **key, void **val) {
    if(h == NULL || (key == NULL && val == NULL)) return 0;

    if(h->iter_node == NULL) {
        if(key != NULL) *key = NULL;
        if(val != NULL) *val = NULL;
        return 0;
    }

    if(key != NULL) *key = h->iter_node->key;
    if(val != NULL) *val = h->iter_node->val;

    return 1;
}
