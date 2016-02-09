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

#ifdef XHASH_DEBUG
    h->stat[i]++;
#endif
 
    // if the zen[i] is empty, reuse it, else get a new one.
    n = &h->zen[i];
    
    if( n->key != NULL ) 
    {
        if( h->free_list )
        {
            n = h->free_list;
            h->free_list = h->free_list->next;        
        }else
            n = pmalloco(h->p, sizeof(_xhn));

        //add it to the bucket list head.
        n->prev = &h->zen[i];
        n->next = h->zen[i].next;

        if( n->next ) n->next->prev = n;
        h->zen[i].next = n;
    }

    return n;
}


static xhn _xhash_node_get(xht h, const char *key, int len, int index)
{
    xhn n;
    int i = index % h->prime;
    for(n = &h->zen[i]; n != NULL; n = n->next)
        if(n->key != NULL && (n->keylen==len) && (strncmp(key, n->key, len) == 0))
            return n;
    return NULL;
}


xht xhash_new(int prime)
{
    xht xnew;
    pool_t p;

/*    log_debug(ZONE,"creating new hash table of size %d",prime); */

    /**
     * NOTE:
     * all xhash's memory should be allocated from the pool by using pmalloco()/pmallocx(),
     * so that the xhash_free() can just call pool_free() simply.
     */
    
    p = pool_heap(sizeof(_xhn)*prime + sizeof(_xht));
    xnew = pmalloco(p, sizeof(_xht));
    xnew->prime = prime;
    xnew->p = p;
    xnew->zen = pmalloco(p, sizeof(_xhn)*prime); /* array of xhn size of prime */

    xnew->free_list = NULL;
    
    xnew->iter_bucket = -1;
    xnew->iter_node = NULL;

#ifdef XHASH_DEBUG
    xnew->stat = pmalloco(p, sizeof(int)*prime );
#else
    xnew->stat = NULL;
#endif

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
        n->keylen = len;
        n->val = val;
        return;
    }

/*    log_debug(ZONE,"saving %s val %X",key,val); */

    /* new node */
    n = _xhash_node_new(h, index);
    n->key = key;
    n->keylen = len;
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

void xhash_zap_inner( xht h, xhn n, int index)
{
    int i = index % h->prime;

    // if element:n is in bucket list and it's not the current iter
    if( &h->zen[i] != n && h->iter_node != n )
    {
        if(n->prev) n->prev->next = n->next;
        if(n->next) n->next->prev = n->prev;

        // add it to the free_list head.
        n->prev = NULL;
        n->next = h->free_list;
        h->free_list = n;
    }

    //empty the value.
    n->key = NULL;
    n->val = NULL;

    /* dirty the xht and track the total */
    h->dirty++;
    h->count--;

#ifdef XHASH_DEBUG
    h->stat[i]--;
#endif
}

void xhash_zapx(xht h, const char *key, int len)
{
    xhn n;
    int index;

    if( !h || !key ) return;
    
    index = _xhasher(key,len);
    n = _xhash_node_get(h, key, len, index);
    if( !n ) return;

/*    log_debug(ZONE,"zapping %s",key); */

    xhash_zap_inner(h ,n, index );
}

void xhash_zap(xht h, const char *key)
{
    if(h == NULL || key == NULL) return;
    xhash_zapx(h,key,strlen(key));
}

void xhash_free(xht h)
{
/*    log_debug(ZONE,"hash free %X",h); */

    /// want to do more things? Please see the note in xhash_new() first.
    if(h) pool_free(h->p);

}

void xhash_stat( xht h )
{
#ifdef XHASH_DEBUG
    if( !h ) return;
    
    fprintf(stderr, "XHASH: table prime: %d , number of elements: %d\n", h->prime, h->count );

    int i;
    for( i = 0; i< h->prime ; ++i )
    {
        if( h->stat[i] > 1 )
            fprintf(stderr, "%d: %d\t", i, h->stat[i]);
    }
    fprintf(stderr, "\n");
    
#endif
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
                (*w)(n->key, n->keylen, n->val, arg);
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
    h->iter_node = h->iter_node ? h->iter_node->next : NULL;
    while(h->iter_node != NULL) {
        xhn n = h->iter_node;

        if(n->key != NULL && n->val != NULL)
            return 1;

        h->iter_node = n->next;

        if (n != &h->zen[h->iter_bucket]) {
            if(n->prev) n->prev->next = n->next;
            if(n->next) n->next->prev = n->prev;

            // add it to the free_list head.
            n->prev = NULL;
            n->next = h->free_list;
            h->free_list = n;
        }
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

void xhash_iter_zap(xht h)
{
    int index;

    if( !h || !h->iter_node ) return;

    index = _xhasher( h->iter_node->key, h->iter_node->keylen );

    xhash_zap_inner( h ,h->iter_node, index);
}

int xhash_iter_get(xht h, const char **key, int *keylen, void **val) {
    if(h == NULL || (key == NULL && val == NULL) || (key != NULL && keylen == NULL)) return 0;

    if(h->iter_node == NULL) {
        if(key != NULL) *key = NULL;
        if(val != NULL) *val = NULL;
        return 0;
    }

    if(key != NULL) {
        *key = h->iter_node->key;
        *keylen = h->iter_node->keylen;
    }
    if(val != NULL) *val = h->iter_node->val;

    return 1;
}
